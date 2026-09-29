// DPoP (RFC 9449) helpers for HeadloProviderV2.
//
// Design decisions locked in claude/headlo-auth-abs-phase0-spec.md:
//   - Algorithm: ECDSA P-256 (ES256) — verified in every target browser via /abs-spike
//   - Private key: extractable: false in IndexedDB — cannot be exfiltrated by XSS
//   - Public key: extractable: true — needed to send JWK to the server for registration
//   - Proof structure: RFC 9449 §4.2 (htu, htm, iat, jti)
//   - Access token binding: RFC 7800 cnf.jkt claim (JWK thumbprint)
//   - Key rotation: never mid-session; new session = new key
//
// This module is imported by HeadloProviderV2.tsx only. Zero React dependency
// here — pure WebCrypto + IndexedDB primitives.

import { idbPut, idbGet, idbDelete } from './idb'

// IndexedDB key layout for DPoP session keys.
//
// Wave 4 Phase 1 (2026-09-07) introduces per-pk keys so the same browser
// origin can hold multiple concurrent DPoP-bound sessions — one per
// publishable key. Before this change, a second sign-in with a different
// pk would overwrite the first pk's key and silently break its session
// with DPOP_KEY_WRONG_PK on every subsequent call.
//
// Layout:
//   session_key                          — legacy single-key slot (pre-Phase-1)
//   session_key:pk_live_xxxx…            — new per-pk slots
//
// Migration: when getExistingKeyPair(pk) misses the pk-scoped slot but the
// legacy slot has a value, we migrate it to the pk-scoped slot AND delete
// the legacy slot. Preserves existing signed-in users through the upgrade
// without forcing a re-sign-in. See getExistingKeyPair below.
const LEGACY_KEY_STORAGE_ID = 'session_key'

const keyStorageIdFor = (publishableKey?: string): string =>
  publishableKey ? `${LEGACY_KEY_STORAGE_ID}:${publishableKey}` : LEGACY_KEY_STORAGE_ID

// ── base64url encoding (spec-compliant, no padding) ───────────────────────

function base64url(input: ArrayBuffer | Uint8Array | string): string {
  const bytes = typeof input === 'string'
    ? new TextEncoder().encode(input)
    : input instanceof Uint8Array
      ? input
      : new Uint8Array(input)
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// ── key generation + persistence ──────────────────────────────────────────

// Generate a fresh ECDSA P-256 key pair with extractable: false on the private
// key. The private key is unextractable by JavaScript — even the code that
// created it cannot serialize it. This is the load-bearing security guarantee.
async function generateKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, // extractable — private key is NOT extractable
    ['sign', 'verify'],
  ) as Promise<CryptoKeyPair>
}

// Get the DPoP key pair for the given publishable key from IndexedDB.
// Generates a fresh pair and persists it under `session_key:<pk>` if none
// exists. Idempotent — calling this multiple times in the same session
// returns the same key pair.
//
// When `publishableKey` is omitted, falls back to the legacy 'session_key'
// slot for backward compatibility with any pre-Phase-1 consumers.
export async function getOrCreateKeyPair(publishableKey?: string): Promise<CryptoKeyPair> {
  const existing = await getExistingKeyPair(publishableKey)
  if (existing) return existing
  const fresh = await generateKeyPair()
  await idbPut(keyStorageIdFor(publishableKey), fresh)
  return fresh
}

// Get the DPoP key pair for the given publishable key ONLY if one exists —
// never creates. Used by the resurrection flow (POST /oauth/dpop/mint) and
// by external authFetch consumers that need the current key to sign proofs.
// Returns null when there's no key stored (never signed in for this pk).
//
// Migration path: if the pk-scoped slot is empty but the legacy 'session_key'
// slot has a value, we assume this is a pre-Phase-1 sign-in and migrate the
// key over to the pk-scoped slot (deleting the legacy slot). This keeps
// existing signed-in users through the upgrade without a re-auth prompt.
export async function getExistingKeyPair(publishableKey?: string): Promise<CryptoKeyPair | null> {
  const scopedId = keyStorageIdFor(publishableKey)
  const scoped   = await idbGet<CryptoKeyPair>(scopedId)
  if (scoped?.privateKey && scoped?.publicKey) return scoped

  // Legacy migration — only attempts when caller passed a pk (otherwise
  // scopedId === LEGACY_KEY_STORAGE_ID and we already read it above).
  if (publishableKey) {
    const legacy = await idbGet<CryptoKeyPair>(LEGACY_KEY_STORAGE_ID)
    if (legacy?.privateKey && legacy?.publicKey) {
      await idbPut(scopedId, legacy)
      await idbDelete(LEGACY_KEY_STORAGE_ID)
      return legacy
    }
  }
  return null
}

// Delete the stored key pair for the given publishable key. Called on
// sign-out — clears only that pk's session so the user stays signed into
// their other apps on the same origin (multi-pk SSO). When `publishableKey`
// is omitted, clears the legacy 'session_key' slot (back-compat only).
export async function clearKeyPair(publishableKey?: string): Promise<void> {
  await idbDelete(keyStorageIdFor(publishableKey))
}

// ── public JWK + thumbprint ───────────────────────────────────────────────

// Export the public key as a JWK — required for:
//   1. Sending to the server at DPoP registration time
//   2. Including in the DPoP proof header (RFC 9449 §4.2)
export async function exportPublicJwk(keyPair: CryptoKeyPair): Promise<JsonWebKey> {
  return crypto.subtle.exportKey('jwk', keyPair.publicKey)
}

// Compute the JWK thumbprint per RFC 7638. This is what appears in the
// access token's `cnf.jkt` claim. The canonical form for EC keys is:
//   {"crv":"P-256","kty":"EC","x":"...","y":"..."}
// — keys in this exact order, no whitespace, no extra fields.
export async function computeJwkThumbprint(jwk: JsonWebKey): Promise<string> {
  const canonical = JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x:   jwk.x,
    y:   jwk.y,
  })
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical))
  return base64url(digest)
}

// ── DPoP proof construction ───────────────────────────────────────────────

export interface DpopProofOptions {
  url:    string   // The full request URL (htu claim). Query string included.
  method: string   // HTTP method in uppercase (htm claim). e.g. 'POST'.
  nonce?: string   // Optional server-provided nonce for anti-replay (RFC 9449 §8).
}

// Sign a DPoP proof JWT bound to a specific HTTP request. The resulting string
// is what goes in the `DPoP` header of the outgoing fetch. Each proof is
// single-use (tied to method + URL + timestamp + jti) — server-side denylist
// prevents replay.
export async function signDpopProof(
  keyPair: CryptoKeyPair,
  opts:    DpopProofOptions,
): Promise<string> {
  const publicJwk = await exportPublicJwk(keyPair)

  const header = {
    alg: 'ES256',
    typ: 'dpop+jwt',
    jwk: publicJwk,
  }

  const payload: Record<string, unknown> = {
    htu: opts.url,
    htm: opts.method.toUpperCase(),
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
  }
  if (opts.nonce) payload.nonce = opts.nonce

  const signingInput = base64url(JSON.stringify(header)) + '.' + base64url(JSON.stringify(payload))

  // WebCrypto ECDSA sign returns raw r||s concatenation (64 bytes for P-256).
  // JWT ES256 signatures ARE raw r||s (RFC 7515) — no ASN.1 wrapping needed.
  const signatureBuf = await crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    keyPair.privateKey,
    new TextEncoder().encode(signingInput),
  )

  return signingInput + '.' + base64url(signatureBuf)
}

// ── convenience wrapper for authenticated fetch ────────────────────────────

export interface DpopFetchOptions extends RequestInit {
  keyPair:      CryptoKeyPair
  accessToken?: string       // If provided, adds `Authorization: Bearer <token>` header
  nonce?:       string       // Server-provided nonce, if the previous response carried DPoP-Nonce
}

// fetch() wrapper that attaches a fresh DPoP proof (and optionally a bearer
// token) to the request. Use this for every call to a DPoP-authenticated
// endpoint on the auth server. Returns the raw Response — caller handles JSON.
export async function dpopFetch(url: string, opts: DpopFetchOptions): Promise<Response> {
  const method = (opts.method ?? 'GET').toUpperCase()
  const proof  = await signDpopProof(opts.keyPair, { url, method, nonce: opts.nonce })

  const headers = new Headers(opts.headers ?? {})
  headers.set('DPoP', proof)
  if (opts.accessToken) headers.set('Authorization', `Bearer ${opts.accessToken}`)

  // Strip the DPoP-only options before passing to fetch
  const { keyPair: _kp, accessToken: _at, nonce: _n, ...init } = opts

  return fetch(url, { ...init, method, headers })
}

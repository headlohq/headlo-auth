// SSO Wave 4 B.6 — Encoded publishable keys.
//
// Clerk-style single-env-var integration. The pk encodes the issuer hostname
// inside the opaque string, so merchants only configure ONE value instead of
// two. Decodes client-side; the server treats the full pk as an opaque
// lookup key (no server work beyond new-pk generation).
//
// Format:
//   pk_{live|test}_<base64url(hostname + '$' + key_id)>
//
// Example (dev):
//   payload   = "127.0.0.1:8787$abc123def456"
//   encoded   = "pk_test_MTI3LjAuMC4xOjg3ODckYWJjMTIzZGVmNDU2"
//   decodes to:  { issuer: "http://127.0.0.1:8787", keyId: "abc123def456", prefix: "pk_test" }
//
// Example (prod):
//   payload   = "auth.headlo.com$a1b2c3d4e5f6"
//   encoded   = "pk_live_YXV0aC5oZWFkbG8uY29tJGExYjJjM2Q0ZTVmNg"
//   decodes to:  { issuer: "https://auth.headlo.com", keyId: "a1b2c3d4e5f6", prefix: "pk_live" }
//
// Backward compat — legacy raw-hex pks (`pk_live_<32-hex>`) are detected by
// their exact 32-char hex pattern and treated as "no embedded issuer." Callers
// of decodePublishableKey() get `{ issuer: null, keyId: <hex>, isEncoded: false }`
// and know to require an explicit `issuer` config.

const PREFIXES = ['pk_live', 'pk_test'] as const
export type PkPrefix = (typeof PREFIXES)[number]

export interface DecodedPk {
  /** Full issuer URL with scheme (https:// for prod hostnames, http:// for localhost/127.x), or null for legacy raw-hex pks. */
  issuer:    string | null
  /** The underlying key identifier. For legacy pks this is the raw 32-char hex; for encoded pks it's the part after '$' in the payload. */
  keyId:     string | null
  /** 'pk_live' or 'pk_test' — informational; both participate in the same lookup on the server. */
  prefix:    PkPrefix | null
  /** True when the pk is in the encoded form (issuer was derivable). False when it's legacy raw-hex (issuer must be supplied externally). */
  isEncoded: boolean
}

const LEGACY_HEX = /^[0-9a-f]{32}$/
const HOSTNAME   = /^[a-zA-Z0-9.:\-\[\]]+$/

function base64urlDecode(s: string): string | null {
  try {
    // Convert base64url → base64 and pad.
    const b64 = s.replace(/-/g, '+').replace(/_/g, '/')
    const pad = (4 - (b64.length % 4)) % 4
    return atob(b64 + '='.repeat(pad))
  } catch {
    return null
  }
}

function base64urlEncode(s: string): string {
  const bytes = new TextEncoder().encode(s)
  let bin = ''
  for (const b of bytes) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * Encode a hostname + keyId into a Headlo-shaped publishable key.
 *
 * Hostname should NOT include the scheme (e.g. `auth.headlo.com`, not
 * `https://auth.headlo.com`). Port is OK (`127.0.0.1:8787`). The SDK infers
 * the scheme at decode time (http for localhost / 127.x; https otherwise).
 *
 * ```ts
 * encodePublishableKey({ prefix: 'pk_live', hostname: 'auth.headlo.com', keyId: 'a1b2c3d4e5f6' })
 * // → 'pk_live_YXV0aC5oZWFkbG8uY29tJGExYjJjM2Q0ZTVmNg'
 * ```
 */
export function encodePublishableKey(opts: {
  prefix:   PkPrefix
  hostname: string
  keyId:    string
}): string {
  if (!HOSTNAME.test(opts.hostname)) {
    throw new Error(`encodePublishableKey: invalid hostname ${JSON.stringify(opts.hostname)} — expected bare host (optionally with :port), no scheme`)
  }
  if (!opts.keyId) {
    throw new Error('encodePublishableKey: keyId is required')
  }
  if (opts.keyId.includes('$')) {
    throw new Error('encodePublishableKey: keyId must not contain the "$" sentinel')
  }
  const body = base64urlEncode(`${opts.hostname}$${opts.keyId}`)
  return `${opts.prefix}_${body}`
}

/**
 * Decode a publishable key into its issuer URL + key identifier.
 *
 * Both legacy raw-hex pks (`pk_live_<32-hex>`) and encoded pks are accepted.
 * Legacy pks return `{ issuer: null, keyId: <hex>, isEncoded: false }` — the
 * caller must supply an `issuer` from somewhere else (env var, prop).
 *
 * Encoded pks return the full `https://host[:port]` URL — infer-the-scheme
 * rule: `localhost`, `127.*`, and `[::1]` get `http://`; everything else
 * `https://`.
 *
 * Never throws — returns a result object with `isEncoded: false` on any
 * decode failure so callers can fall back cleanly.
 */
export function decodePublishableKey(pk: string): DecodedPk {
  const empty: DecodedPk = { issuer: null, keyId: null, prefix: null, isEncoded: false }
  if (typeof pk !== 'string' || !pk) return empty

  const m = /^(pk_live|pk_test)_(.+)$/.exec(pk)
  if (!m) return empty
  const prefix = m[1] as PkPrefix
  const body   = m[2]!

  // Legacy format — exactly 32 hex chars after the prefix. Fast-path this
  // check so we don't accidentally decode valid hex as base64.
  if (LEGACY_HEX.test(body)) {
    return { issuer: null, keyId: body, prefix, isEncoded: false }
  }

  // Try the encoded form.
  const decoded = base64urlDecode(body)
  if (!decoded) return { ...empty, prefix, keyId: body }

  const idx = decoded.indexOf('$')
  // '$' must appear and not be first/last char (both host and keyId required).
  if (idx < 1 || idx >= decoded.length - 1) {
    return { ...empty, prefix, keyId: body }
  }

  const host  = decoded.slice(0, idx)
  const keyId = decoded.slice(idx + 1)

  // Hostname sanity-check. Rejects anything that doesn't look like a valid
  // bare host — catches the "random 32 hex chars happens to decode to garbage
  // with a $ in it" false positive.
  if (!HOSTNAME.test(host)) {
    return { ...empty, prefix, keyId: body }
  }

  const isLocal = /^(localhost|127\.|\[::1\])/.test(host)
  return {
    issuer:    `${isLocal ? 'http' : 'https'}://${host}`,
    keyId,
    prefix,
    isEncoded: true,
  }
}

/**
 * Resolve the issuer URL to use for a given pk + optional explicit issuer.
 *
 * Precedence: explicit `issuer` arg wins (back-compat for merchants on
 * legacy pks). Otherwise, decode the pk and return its embedded issuer.
 * Throws when neither path yields a usable URL — the error message walks
 * the caller through the fix.
 *
 * Called by HeadloProviderV2, ContinueAsModal, GoogleOneTap to normalize
 * their config once at mount time.
 */
export function resolveIssuer(pk: string, explicit?: string): string {
  if (explicit) return explicit
  const decoded = decodePublishableKey(pk)
  if (decoded.isEncoded && decoded.issuer) return decoded.issuer
  throw new Error(
    `headlo-auth: can't derive issuer URL from publishable key — ` +
    `either the pk is a legacy raw-hex form (upgrade to an encoded pk from the dashboard) ` +
    `OR pass an explicit \`issuer\` prop/config (e.g. "https://auth.headlo.com"). ` +
    `Got pk prefix "${pk.slice(0, 8)}…"`
  )
}

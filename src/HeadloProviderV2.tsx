import React from 'react'
import { generateCodeVerifier, generateCodeChallenge } from './pkce'
import { getOrCreateKeyPair, getExistingKeyPair, clearKeyPair, dpopFetch } from './dpop'
import { HeadloAuthContext } from './HeadloProvider'
import type { HeadloAuthContextValue, HeadloProviderProps, HeadloUser } from './types'

// HeadloProviderV2 — Anchor-Bound Session (ABS) React SDK.
//
// Design locked in claude/headlo-auth-abs-phase0-spec.md.
// Sibling to HeadloProvider v1 (cookie-based refresh). Same context, same hooks,
// same <SignedIn> / <SignedOut> / <SignInButton> / <SignOutButton> components —
// they all work identically with v2 because both providers expose HeadloAuthContext.
//
// Under the hood, v2 differs from v1 on three axes:
//   1. Access token in sessionStorage (per-tab) instead of memory-only.
//      Survives full-page navigation without a network round-trip.
//   2. Long-lived credential = DPoP private key in IndexedDB with
//      extractable: false. XSS cannot exfiltrate the key material.
//      Refresh cookie NOT used — cookie-less design.
//   3. Silent refresh calls POST /oauth/token/refresh-dpop with a fresh DPoP
//      proof signed by the private key. Works cross-origin in every browser
//      including Safari — no third-party cookie policy to fight.

const DEFAULT_ISSUER    = 'https://auth.headlo.com'
const VERIFIER_KEY      = 'headlo_pkce_verifier'
const USER_CACHE_KEY    = 'headlo_auth_user'          // shared with v1 — same profile cache
const SESSION_TOKEN_KEY = 'headlo_auth_v2_token'       // sessionStorage; per-tab; not shared with v1
const REFRESH_LEAD_MS   = 10 * 1000                    // refresh when access token has < 10s left
const BROADCAST_CHANNEL = 'headlo_auth'                // shared with v1 — cross-tab signout works either way
const DEBUG_LOG_KEY     = 'headlo_auth_v2_debug_log'   // persistent log ring buffer in localStorage
const DEBUG_LOG_MAX     = 200                          // keep last N entries

const HEADLO_AUTH_V2_VERSION = 'v2-abs-phase-a-1'
console.log(`%c[headlo-auth-v2]%c 📦 SDK build: ${HEADLO_AUTH_V2_VERSION}`, 'color:#7c3aed;font-weight:bold', 'color:inherit')

// Persistent log — writes each entry to localStorage as a ring buffer so
// entries survive page reload. Read via <AbsTestPage> or manually via
// `JSON.parse(localStorage.getItem('headlo_auth_v2_debug_log'))`. Clear via
// `localStorage.removeItem('headlo_auth_v2_debug_log')`.
type PersistedLog = { ts: number; msg: string; data?: Record<string, unknown> }
function persistLog(entry: PersistedLog): void {
  try {
    const raw = localStorage.getItem(DEBUG_LOG_KEY)
    const arr: PersistedLog[] = raw ? JSON.parse(raw) : []
    arr.push(entry)
    // Ring buffer — drop oldest if over limit
    const trimmed = arr.length > DEBUG_LOG_MAX ? arr.slice(-DEBUG_LOG_MAX) : arr
    localStorage.setItem(DEBUG_LOG_KEY, JSON.stringify(trimmed))
  } catch { /* localStorage full or unavailable — silently skip persist */ }
}

function log(msg: string, data?: Record<string, unknown>) {
  if (data) console.log(`%c[headlo-auth-v2]%c ${msg}`, 'color:#7c3aed;font-weight:bold', 'color:inherit', data)
  else      console.log(`%c[headlo-auth-v2]%c ${msg}`, 'color:#7c3aed;font-weight:bold', 'color:inherit')
  persistLog({ ts: Date.now(), msg, data })
}

// Fires the same-format persisted log for events that use direct console.log
// (write verification, clearSession trace, etc.) — call from those sites.
function logExternal(msg: string, data?: Record<string, unknown>) {
  persistLog({ ts: Date.now(), msg, data })
}

function decodeJwtPayload(jwt: string): { sub?: string; email?: string; name?: string; exp?: number; azp?: string } | null {
  try {
    const [, payload] = jwt.split('.')
    if (!payload) return null
    return JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')))
  } catch { return null }
}

function decodeJwtExp(jwt: string): number | null {
  const c = decodeJwtPayload(jwt)
  return c && typeof c.exp === 'number' ? c.exp * 1000 : null
}

function userFromJwt(jwt: string): HeadloUser | null {
  const c = decodeJwtPayload(jwt)
  if (!c?.sub || !c.email) return null
  return { id: c.sub, email: c.email, displayName: c.name ?? null }
}

function readCachedUser(): HeadloUser | null {
  try {
    const raw = localStorage.getItem(USER_CACHE_KEY)
    if (!raw) return null
    const u = JSON.parse(raw) as HeadloUser
    return u.id && u.email ? u : null
  } catch { return null }
}
function writeCachedUser(u: HeadloUser): void {
  try { localStorage.setItem(USER_CACHE_KEY, JSON.stringify(u)) } catch {}
}
function clearCachedUser(): void {
  try { localStorage.removeItem(USER_CACHE_KEY) } catch {}
}

// sessionStorage access token — per-tab, cleared on tab close. Survives
// full-page navigation within the same tab.
function readSessionToken(): string | null {
  try { return sessionStorage.getItem(SESSION_TOKEN_KEY) } catch { return null }
}
function writeSessionToken(token: string): void {
  try {
    sessionStorage.setItem(SESSION_TOKEN_KEY, token)
    const readback = sessionStorage.getItem(SESSION_TOKEN_KEY)
    if (readback !== token) {
      const msg = `⚠️ sessionStorage write verify FAILED — write:${token.length}b readback:${readback?.length ?? 'null'}`
      console.warn(`%c[headlo-auth-v2]%c ${msg}`, 'color:#7c3aed;font-weight:bold', 'color:inherit')
      logExternal(msg)
    } else {
      const msg = `💾 Wrote + verified sessionStorage (${token.length}b, key=${SESSION_TOKEN_KEY})`
      console.log(`%c[headlo-auth-v2]%c ${msg}`, 'color:#7c3aed;font-weight:bold', 'color:inherit')
      logExternal(msg)
    }
  } catch (e) {
    const msg = `💥 sessionStorage.setItem THREW: ${String(e)}`
    console.error(`%c[headlo-auth-v2]%c ${msg}`, 'color:#7c3aed;font-weight:bold', 'color:inherit', e)
    logExternal(msg)
  }
}
function clearSessionToken(): void {
  try {
    sessionStorage.removeItem(SESSION_TOKEN_KEY)
    const msg = `🗑️ Cleared sessionStorage token`
    console.log(`%c[headlo-auth-v2]%c ${msg}`, 'color:#7c3aed;font-weight:bold', 'color:inherit')
    logExternal(msg)
  } catch {}
}

export function HeadloProviderV2({
  publishableKey,
  issuer = DEFAULT_ISSUER,
  signInForceRedirectUrl,
  signInFallbackRedirectUrl,
  children,
}: HeadloProviderProps) {
  // Cross-tab consistency: sessionStorage is per-tab (access token) but
  // localStorage is shared across tabs (user profile cache). Opening a new
  // tab or private window has no sessionStorage token BUT the user profile
  // cache from the previous tab is still there. If we hydrated user from
  // cache without a token, isSignedIn = !!user would be true but getToken()
  // would return null — signed-in UI with dead credentials.
  //
  // Only paint signed-in state when we have BOTH:
  //   1. A session token in sessionStorage (per-tab)
  //   2. A user profile in localStorage (fills in display name / email)
  //
  // No token → this is a fresh tab or private window; treat as signed-out.
  // Do NOT clear the localStorage cache here — that would sign the user out
  // in ALL tabs including the one they're actively using.
  const initialToken = React.useMemo(() => readSessionToken(), [])
  const initialUser  = React.useMemo(() => initialToken ? readCachedUser() : null, [initialToken])

  const [user,     setUser]     = React.useState<HeadloUser | null>(initialUser)
  const [isLoaded, setIsLoaded] = React.useState<boolean>(() => initialUser !== null && initialToken !== null)
  const [token,    setToken]    = React.useState<string | null>(initialToken)

  const tokenRef      = React.useRef<string | null>(null)
  const inFlightRef   = React.useRef<Promise<string | null> | null>(null)
  const channelRef    = React.useRef<BroadcastChannel | null>(null)
  tokenRef.current    = token

  function clearSession() {
    // Capture caller stack to trace unexpected clearSession invocations
    // (e.g., BroadcastChannel signout leaking from v1, spurious refresh failure).
    // Trim the stack — we only care about who called clearSession, not V8 frames.
    const stack = new Error().stack?.split('\n').slice(1, 5).join(' | ') ?? '?'
    console.trace('[headlo-auth-v2] clearSession() called — stack trace')
    log(`🧹 Session cleared — caller: ${stack}`)
    setToken(null)
    setUser(null)
    clearSessionToken()
    clearCachedUser()
    void clearKeyPair()
  }

  // Resurrect a session from a stored DPoP key — used when we have no access
  // token in sessionStorage (new tab, browser restart) but IndexedDB still has
  // the DPoP key from a prior sign-in. Calls POST /oauth/dpop/mint which mints
  // a fresh access token given only a valid DPoP proof against a registered
  // key.
  //
  // Returns null if:
  //   - No DPoP key in IndexedDB (never signed in on this device, or explicitly
  //     signed out)
  //   - Server returns 401 (registration revoked from another tab or server-side)
  //   - Network error (transient — caller can retry on next mount)
  async function mintFromDpopKey(): Promise<string | null> {
    log(`🔮 Attempting resurrection via /oauth/dpop/mint`)
    const startMs = Date.now()

    const keyPair = await getExistingKeyPair()
    if (!keyPair) {
      log(`💤 No DPoP key in IndexedDB — nothing to resurrect`)
      return null
    }

    try {
      const url = `${issuer}/oauth/dpop/mint`
      const res = await dpopFetch(url, {
        method:  'POST',
        keyPair,
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ client_id: publishableKey }),
      })
      const took = Date.now() - startMs

      if (res.status === 401 || res.status === 403) {
        // Registration revoked or invalid — clear local key so we don't keep
        // trying on subsequent mounts. User must sign in explicitly.
        log(`❌ /oauth/dpop/mint → ${res.status} — key revoked, clearing local`, { tookMs: took })
        clearSession()
        return null
      }
      if (!res.ok) {
        log(`⚠️ /oauth/dpop/mint → ${res.status} — transient, keeping key`, { tookMs: took })
        return null
      }

      const { access_token } = await res.json() as { access_token: string }
      const expMs = decodeJwtExp(access_token)
      log(`✅ /oauth/dpop/mint → 200 — session resurrected`, {
        tookMs:    took,
        tokenLife: expMs ? `${Math.floor((expMs - Date.now()) / 1000)}s` : '?',
      })
      setToken(access_token)
      writeSessionToken(access_token)
      const u = userFromJwt(access_token)
      if (u) { setUser(u); writeCachedUser(u) }
      return access_token
    } catch (err) {
      // Network error / abort — don't clear key, next mount can retry
      log(`⚠️ Mint network error — keeping key (may be page navigation)`, { error: String(err) })
      return null
    }
  }

  // Silent refresh via DPoP — replaces v1's cookie-based /oauth/refresh.
  // Uses the existing access token (may be expired — server verifies signature
  // only, not exp) + a fresh DPoP proof to mint a new access token.
  async function refreshAccessToken(): Promise<string | null> {
    if (inFlightRef.current) {
      log(`⏸️  Refresh in-flight — returning existing promise`)
      return inFlightRef.current
    }

    const currentToken = tokenRef.current
    if (!currentToken) {
      log(`💤 No access token to refresh — user must sign in explicitly`)
      return null
    }

    log(`🔄 POST /oauth/token/refresh-dpop`)
    const startMs = Date.now()

    inFlightRef.current = (async () => {
      try {
        const keyPair = await getOrCreateKeyPair()
        const url = `${issuer}/oauth/token/refresh-dpop`
        const res = await dpopFetch(url, {
          method:      'POST',
          keyPair,
          accessToken: currentToken,
          headers:     { 'Content-Type': 'application/json' },
          body:        JSON.stringify({ client_id: publishableKey }),
        })
        const took = Date.now() - startMs

        // Only 401/403 = the server explicitly said this session is dead.
        // Any other non-2xx (5xx, transient, etc.) — keep the token in
        // sessionStorage and let the next attempt retry. The stored token
        // is still valid until its exp.
        if (res.status === 401 || res.status === 403) {
          log(`❌ /oauth/token/refresh-dpop → ${res.status} — session invalid, signing out`, { tookMs: took })
          clearSession()
          return null
        }
        if (!res.ok) {
          log(`⚠️ /oauth/token/refresh-dpop → ${res.status} — transient, keeping session`, { tookMs: took })
          return null
        }

        const { access_token } = await res.json() as { access_token: string }
        const expMs = decodeJwtExp(access_token)
        log(`✅ /oauth/token/refresh-dpop → 200`, {
          tookMs:      took,
          tokenLife:   expMs ? `${Math.floor((expMs - Date.now()) / 1000)}s` : '?',
        })
        setToken(access_token)
        writeSessionToken(access_token)
        const u = userFromJwt(access_token)
        if (u) { setUser(u); writeCachedUser(u) }
        return access_token
      } catch (err) {
        // Network-level failure — most commonly a `TypeError: Failed to fetch`
        // when the browser aborts an in-flight fetch because the user navigated
        // away (F5, back button, close tab). Do NOT clear session here — the
        // token in sessionStorage is still valid, and the next page load will
        // retry the refresh. Killing the session on abort would sign the user
        // out on any rapid navigation.
        //
        // If it's a real network problem (offline, DNS fail), user will find
        // out when they try to make a real API call that gets 401.
        log(`⚠️ Refresh network error — keeping session (may be page navigation)`, { error: String(err) })
        return null
      }
    })()

    try { return await inFlightRef.current }
    finally { inFlightRef.current = null }
  }

  // Initial mount: three paths
  //   1. PKCE ?code= in URL → exchange for token → register DPoP key → replace token
  //   2. Existing sessionStorage token → use it (already loaded via useState)
  //   3. No token → user is signed-out; must sign in explicitly
  React.useEffect(() => {
    async function init() {
      log(`🚀 HeadloProviderV2 mounted`, { issuer, publishableKey: publishableKey.slice(0, 12) + '…' })
      const params = new URLSearchParams(window.location.search)
      const code = params.get('code')

      if (code) {
        log(`🔑 Found ?code= in URL — exchanging PKCE + registering DPoP key`)
        await handleCallback(code)
        const clean = new URL(window.location.href)
        clean.searchParams.delete('code')
        clean.searchParams.delete('state')
        window.history.replaceState({}, '', clean.toString())
      } else if (tokenRef.current) {
        // Fresh-token fast path — if the cached token has > REFRESH_LEAD_MS
        // left, trust it and skip the network round-trip. Only hit /refresh-dpop
        // when the token is actually near expiry.
        //
        // This dramatically reduces refresh traffic on rapid navigation:
        // every page load within the first ~50s of a 60s token stays cached.
        // Also shrinks the surface area for aborted-fetch races.
        //
        // Trade: a token that was revoked server-side (via /oauth/dpop/revoke
        // from another tab) will still be treated as valid here until it hits
        // its natural exp. Acceptable — real API calls that use this token
        // will get 401 from the server and force re-auth. UI-side "am I
        // signed in" state can lag revocation by up to REFRESH_LEAD_MS.
        const expMs = decodeJwtExp(tokenRef.current)
        if (expMs && expMs - Date.now() > REFRESH_LEAD_MS) {
          const secLeft = Math.floor((expMs - Date.now()) / 1000)
          log(`♻️  Token still fresh (${secLeft}s left) — using cached, skipping refresh`)
          // Hydrate user from the cached token so <SignedIn> renders correctly.
          // setUser is already populated from readCachedUser at mount, but the
          // token in memory drives isSignedIn = !!user — profile cache already
          // did this, no additional work needed.
        } else {
          log(`♻️  Token near/past expiry — validating with silent refresh`)
          await refreshAccessToken()
        }
      } else {
        // No session token in this tab — but the DPoP key may still be in
        // IndexedDB (shared across tabs) from a prior sign-in on this device.
        // Try to resurrect the session via /oauth/dpop/mint. If successful,
        // this tab is now signed in without requiring a fresh OAuth flow.
        //
        // This is the mechanism that makes "close tab, reopen — still signed in"
        // work. Without it, v2 sessions are per-tab only.
        log(`💤 No cached token — attempting resurrection from DPoP key`)
        await mintFromDpopKey()
        // mintFromDpopKey handles both success (setToken/setUser called)
        // and failure (returns null, state stays signed-out) internally.
      }
      setIsLoaded(true)
    }
    init()

    const channel = typeof BroadcastChannel === 'function'
      ? new BroadcastChannel(BROADCAST_CHANNEL)
      : null
    channelRef.current = channel
    if (channel) {
      channel.onmessage = (e: MessageEvent) => {
        if (e.data === 'signout') {
          log(`📡 BroadcastChannel: signout from another tab`)
          clearSession()
        }
      }
    }

    return () => { channel?.close() }
  }, [])

  async function handleCallback(code: string) {
    const verifier = localStorage.getItem(VERIFIER_KEY)
    if (!verifier) return
    localStorage.removeItem(VERIFIER_KEY)

    // Step 1: standard PKCE exchange — same as v1, no DPoP yet
    const tokenRes = await fetch(`${issuer}/oauth/token`, {
      method:      'POST',
      credentials: 'include',  // accept refresh cookie (v2 doesn't use it, but doesn't hurt)
      headers:     { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'authorization_code',
        code,
        redirect_uri:  window.location.origin + window.location.pathname,
        client_id:     publishableKey,
        code_verifier: verifier,
      }),
    })
    if (!tokenRes.ok) {
      log(`❌ PKCE token exchange failed`, { status: tokenRes.status })
      return
    }
    const { access_token: bootstrapToken } = await tokenRes.json() as { access_token: string }
    log(`✅ PKCE exchange complete — bootstrap access token issued`)

    // Step 2: generate DPoP key + register it, get back a cnf.jkt-bound token
    log(`🔐 Registering DPoP key with /oauth/dpop/register`)
    const keyPair = await getOrCreateKeyPair()
    const registerUrl = `${issuer}/oauth/dpop/register`
    const regRes = await dpopFetch(registerUrl, {
      method:      'POST',
      keyPair,
      accessToken: bootstrapToken,
      headers:     { 'Content-Type': 'application/json' },
      body:        JSON.stringify({ client_id: publishableKey }),
    })
    if (!regRes.ok) {
      log(`❌ DPoP registration failed`, { status: regRes.status })
      return
    }
    const { access_token: dpopToken } = await regRes.json() as { access_token: string }
    const expMs = decodeJwtExp(dpopToken)
    log(`✅ DPoP registered — session bound to key`, {
      tokenLife: expMs ? `${Math.floor((expMs - Date.now()) / 1000)}s` : '?',
    })

    setToken(dpopToken)
    writeSessionToken(dpopToken)
    const u = userFromJwt(dpopToken)
    if (u) {
      setUser(u)
      writeCachedUser(u)
    }
  }

  async function signIn(opts?: { forceRedirectUrl?: string }) {
    log(`🚪 signIn() — generating PKCE + redirecting`)
    const verifier  = generateCodeVerifier()
    const challenge = await generateCodeChallenge(verifier)
    localStorage.setItem(VERIFIER_KEY, verifier)

    const url = new URL(`${issuer}/oauth/authorize`, window.location.origin)
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('client_id',     publishableKey)
    const target = opts?.forceRedirectUrl ?? signInForceRedirectUrl ?? signInFallbackRedirectUrl
    const redirectUri = target
      ? window.location.origin + target
      : window.location.origin + window.location.pathname
    url.searchParams.set('redirect_uri',          redirectUri)
    url.searchParams.set('code_challenge',        challenge)
    url.searchParams.set('code_challenge_method', 'S256')
    url.searchParams.set('scope',                 'openid email profile')

    window.location.href = url.toString()
  }

  async function signOut() {
    log(`🚪 signOut() — revoking DPoP + clearing local state`)
    // Best-effort revoke — fire and forget, don't block UX
    const currentToken = tokenRef.current
    if (currentToken) {
      const keyPair = await getOrCreateKeyPair().catch(() => null)
      if (keyPair) {
        const revokeUrl = `${issuer}/oauth/dpop/revoke`
        dpopFetch(revokeUrl, {
          method:      'POST',
          keyPair,
          accessToken: currentToken,
          headers:     { 'Content-Type': 'application/json' },
          body:        JSON.stringify({ client_id: publishableKey }),
        }).catch(() => {})
      }
    }
    clearSession()
    channelRef.current?.postMessage('signout')
  }

  const getToken = React.useCallback(async (): Promise<string | null> => {
    const current = tokenRef.current
    if (!current) return null
    const expMs = decodeJwtExp(current)
    if (expMs && expMs - Date.now() < REFRESH_LEAD_MS) {
      log(`🔍 getToken() — token expiring soon, refreshing first`)
      return refreshAccessToken()
    }
    return current
  }, [])

  const value: HeadloAuthContextValue = {
    isLoaded,
    isSignedIn: !!user,
    user,
    getToken,
    signIn,
    signOut,
  }

  return (
    <HeadloAuthContext.Provider value={value}>
      {children}
    </HeadloAuthContext.Provider>
  )
}

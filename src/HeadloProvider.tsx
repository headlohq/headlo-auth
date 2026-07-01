import React from 'react'
import { generateCodeVerifier, generateCodeChallenge } from './pkce'
import type { HeadloAuthContextValue, HeadloProviderProps, HeadloUser } from './types'

const DEFAULT_ISSUER  = 'https://auth.headlo.com'
const VERIFIER_KEY    = 'headlo_pkce_verifier'
const USER_CACHE_KEY  = 'headlo_auth_user'   // last-known profile only, no token
const REFRESH_LEAD_MS = 10 * 1000  // TEMP for testing: refresh when access token has <10s left
// const REFRESH_LEAD_MS = 5 * 60 * 1000  // production: refresh 5 minutes before exp

// Clerk-style auth: refresh_token lives in an HttpOnly cookie set by the worker.
// JavaScript can't read it (XSS-immune). The access JWT lives in memory only —
// never written to localStorage. Every page load attempts a silent refresh
// via the cookie; if it succeeds, the user is signed in.
//
// One optimization: the *user profile* ({id, email, displayName}) IS written
// to localStorage. Not sensitive on its own, and it lets us paint the signed-in
// UI on the first render with no network round trip. Silent refresh still runs
// in the background; if it fails, we clear the cache and drop to signed-out.

export const HeadloAuthContext = React.createContext<HeadloAuthContextValue | null>(null)

const BROADCAST_CHANNEL = 'headlo_auth'

function decodeJwtPayload(jwt: string): { sub?: string; email?: string; name?: string; exp?: number } | null {
  try {
    const [, payload] = jwt.split('.')
    if (!payload) return null
    const json = atob(payload.replace(/-/g, '+').replace(/_/g, '/'))
    return JSON.parse(json)
  } catch {
    return null
  }
}

// Build marker — bump the version string on every real change so you can tell
// at a glance whether the SDK bundle in the browser is the latest build.
// If you don't see this line in the console, the deploy didn't ship.
const HEADLO_AUTH_VERSION = 'cache-fix-1'
console.log(`%c[headlo-auth]%c 📦 SDK build: ${HEADLO_AUTH_VERSION}`, 'color:#5dcaa5;font-weight:bold', 'color:inherit')

// Debug logging — visible in DevTools Console. Filter by "[headlo-auth]".
function log(msg: string, data?: Record<string, unknown>) {
  if (data) console.log(`%c[headlo-auth]%c ${msg}`, 'color:#5dcaa5;font-weight:bold', 'color:inherit', data)
  else      console.log(`%c[headlo-auth]%c ${msg}`, 'color:#5dcaa5;font-weight:bold', 'color:inherit')
}

function fmtSeconds(ms: number): string {
  const s = Math.floor(ms / 1000)
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
}

function decodeJwtExp(jwt: string): number | null {
  const claims = decodeJwtPayload(jwt)
  return claims && typeof claims.exp === 'number' ? claims.exp * 1000 : null
}

function userFromJwt(jwt: string): HeadloUser | null {
  const claims = decodeJwtPayload(jwt)
  if (!claims?.sub || !claims.email) return null
  return { id: claims.sub, email: claims.email, displayName: claims.name ?? null }
}

// Read last-known user profile from localStorage — runs synchronously at
// mount so the signed-in UI can paint on the first render without waiting
// for /oauth/refresh. Malformed / missing values return null.
function readCachedUser(): HeadloUser | null {
  try {
    const raw = localStorage.getItem(USER_CACHE_KEY)
    if (!raw) {
      console.log('[headlo-auth] 💾 No cached user — first paint will show Loading… until /oauth/refresh returns')
      return null
    }
    const u = JSON.parse(raw) as HeadloUser
    if (!u.id || !u.email) {
      console.log('[headlo-auth] 💾 Cached user malformed — ignoring')
      return null
    }
    console.log('[headlo-auth] 💾 Hydrated from localStorage cache — signed-in UI paints instantly', { email: u.email, id: u.id })
    return u
  } catch { return null }
}

function writeCachedUser(u: HeadloUser): void {
  try {
    localStorage.setItem(USER_CACHE_KEY, JSON.stringify(u))
    console.log('[headlo-auth] 💾 Cached user profile → next reload will paint instantly', { email: u.email, id: u.id })
  } catch {}
}

function clearCachedUser(): void {
  try {
    if (localStorage.getItem(USER_CACHE_KEY)) {
      localStorage.removeItem(USER_CACHE_KEY)
      console.log('[headlo-auth] 💾 Cleared cached user profile')
    }
  } catch {}
}

export function HeadloProvider({ publishableKey, issuer = DEFAULT_ISSUER, signInForceRedirectUrl, signInFallbackRedirectUrl, signUpForceRedirectUrl: _signUpForce, signUpFallbackRedirectUrl: _signUpFallback, children }: HeadloProviderProps) {
  // Lazy init from localStorage cache: if a returning visitor had a session
  // last time, we render "signed in" immediately. Background refresh confirms
  // the session is still valid (or clears cache + drops to signed-out).
  const [user,     setUser]     = React.useState<HeadloUser | null>(readCachedUser)
  const [isLoaded, setIsLoaded] = React.useState<boolean>(() => readCachedUser() !== null)
  const [token,    setToken]    = React.useState<string | null>(null)

  const refreshTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null)
  const tokenRef        = React.useRef<string | null>(null)
  const inFlightRef     = React.useRef<Promise<string | null> | null>(null)
  const channelRef      = React.useRef<BroadcastChannel | null>(null)
  tokenRef.current      = token

  // Lazy refresh mode: timer is disabled. Refresh only happens when
  // getToken() is called and the cached token is expired/expiring.
  // To re-enable proactive refresh, uncomment the body below.
  function scheduleRefresh(accessToken: string) {
    const expMs = decodeJwtExp(accessToken)
    if (!expMs) return
    log(`💤 Timer disabled (lazy mode) — refresh will fire on next getToken() after expiry`, {
      tokenExpAt: new Date(expMs).toLocaleTimeString(),
      timeLeft:   fmtSeconds(expMs - Date.now()),
    })

    /* PROACTIVE TIMER MODE — uncomment to re-enable
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current)
    const lifetimeMs = expMs - Date.now()
    const delay = Math.max(0, lifetimeMs - REFRESH_LEAD_MS)
    log(`📅 Scheduled refresh`, {
      tokenLifetime: fmtSeconds(lifetimeMs),
      refreshLead:   fmtSeconds(REFRESH_LEAD_MS),
      fireIn:        fmtSeconds(delay),
      fireAt:        new Date(Date.now() + delay).toLocaleTimeString(),
      tokenExpAt:    new Date(expMs).toLocaleTimeString(),
    })
    refreshTimerRef.current = setTimeout(() => {
      log(`⏰ Timer fired — token nearing expiry, refreshing now`)
      void refreshAccessToken()
    }, delay)
    */
  }

  function clearSession() {
    log(`🧹 Session cleared — user signed out (in this tab)`)
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current)
    setToken(null)
    setUser(null)
    clearCachedUser()
  }

  async function refreshAccessToken(): Promise<string | null> {
    // Concurrency guard — see prior commit for rationale.
    if (inFlightRef.current) {
      log(`⏸️  Refresh already in-flight — returning existing promise (concurrency guard)`)
      return inFlightRef.current
    }

    log(`🔄 POST /oauth/refresh — sending refresh cookie`)
    const startMs = Date.now()

    inFlightRef.current = (async () => {
      const res = await fetch(`${issuer}/oauth/refresh`, {
        method:      'POST',
        credentials: 'include',  // send headlo_refresh HttpOnly cookie
      })
      const took = Date.now() - startMs
      // 204 = no refresh cookie at all (anonymous visitor). Not an error,
      // just means there's no session to restore. Stay logged out silently.
      if (res.status === 204) {
        log(`💤 /oauth/refresh → 204 (no cookie, anonymous) — staying signed out`, { tookMs: took })
        clearSession()
        return null
      }
      if (!res.ok) {
        log(`❌ /oauth/refresh → ${res.status} — session invalid, signing out`, { tookMs: took })
        clearSession()
        return null
      }

      const { access_token } = await res.json() as { access_token: string }
      const expMs = decodeJwtExp(access_token)
      log(`✅ /oauth/refresh → 200 — got new access token`, {
        tookMs:        took,
        newTokenLife: expMs ? fmtSeconds(expMs - Date.now()) : '?',
        newExpAt:     expMs ? new Date(expMs).toLocaleTimeString() : '?',
      })
      setToken(access_token)
      scheduleRefresh(access_token)
      // Hydrate user from JWT claims — no /oauth/userinfo call needed.
      // The access token already contains sub, email, name.
      // Always re-cache in case claims changed (name update, etc).
      const u = userFromJwt(access_token)
      if (u) {
        if (!user) log(`👤 Hydrated user from JWT claims`, { email: u.email, id: u.id })
        setUser(u)
        writeCachedUser(u)
      }
      return access_token
    })()

    try {
      return await inFlightRef.current
    } finally {
      inFlightRef.current = null
    }
  }

  // On mount: PKCE callback OR silent refresh from cookie
  React.useEffect(() => {
    async function init() {
      log(`🚀 HeadloProvider mounted`, { issuer, publishableKey: publishableKey.slice(0, 12) + '...' })
      const params = new URLSearchParams(window.location.search)
      const code   = params.get('code')

      if (code) {
        log(`🔑 Found ?code= in URL — exchanging PKCE auth code for tokens`)
        await handleCallback(code)
        const clean = new URL(window.location.href)
        clean.searchParams.delete('code')
        clean.searchParams.delete('state')
        window.history.replaceState({}, '', clean.toString())
      } else {
        log(`🔍 No PKCE code — trying silent refresh (will succeed if cookie present)`)
        await refreshAccessToken()
      }
      setIsLoaded(true)
      log(`✨ HeadloProvider isLoaded=true`)
    }
    init()

    // Cross-tab sign-out via BroadcastChannel. When one tab calls signOut(),
    // all tabs of the same origin receive the message and clear their state.
    const channel = typeof BroadcastChannel === 'function'
      ? new BroadcastChannel(BROADCAST_CHANNEL)
      : null
    channelRef.current = channel
    if (channel) {
      channel.onmessage = (e: MessageEvent) => {
        if (e.data === 'signout') {
          log(`📡 BroadcastChannel: another tab signed out — clearing local session`)
          clearSession()
        }
      }
    }

    return () => {
      if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current)
      channel?.close()
    }
  }, [])

  async function handleCallback(code: string) {
    const verifier = localStorage.getItem(VERIFIER_KEY)
    if (!verifier) return
    localStorage.removeItem(VERIFIER_KEY)

    const res = await fetch(`${issuer}/oauth/token`, {
      method:      'POST',
      credentials: 'include',  // accept Set-Cookie for headlo_refresh
      headers:     { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'authorization_code',
        code,
        redirect_uri:  window.location.origin + window.location.pathname,
        client_id:     publishableKey,
        code_verifier: verifier,
      }),
    })
    if (!res.ok) return

    const { access_token } = await res.json() as { access_token: string }
    const expMs = decodeJwtExp(access_token)
    log(`✅ PKCE exchange complete — session created`, {
      tokenLife: expMs ? fmtSeconds(expMs - Date.now()) : '?',
      expAt:     expMs ? new Date(expMs).toLocaleTimeString() : '?',
    })
    setToken(access_token)
    scheduleRefresh(access_token)
    const u = userFromJwt(access_token)
    if (u) {
      log(`👤 Hydrated user from JWT`, { email: u.email, id: u.id })
      setUser(u)
      writeCachedUser(u)
    }
  }

  async function signIn(opts?: { forceRedirectUrl?: string }) {
    log(`🚪 signIn() — generating PKCE + redirecting to /oauth/authorize`)
    const verifier  = generateCodeVerifier()
    const challenge = await generateCodeChallenge(verifier)
    localStorage.setItem(VERIFIER_KEY, verifier)

    const url = new URL(`${issuer}/oauth/authorize`, window.location.origin)
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('client_id',     publishableKey)
    // Resolution order (mirrors Clerk):
    //   per-call forceRedirectUrl > signInForceRedirectUrl > signInFallbackRedirectUrl > current page
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
    log(`🚪 signOut() — POST /oauth/signout + clearing local session`)
    // Best-effort revoke + cookie clear via server
    fetch(`${issuer}/oauth/signout`, {
      method:      'POST',
      credentials: 'include',
    }).catch(() => {})

    clearSession()
    log(`📡 Broadcasting signout to other tabs`)
    channelRef.current?.postMessage('signout')
  }

  // getToken returns a guaranteed-fresh token. If the current one is expired
  // or about to expire, refresh first so callers never see an expired JWT.
  const getToken = React.useCallback(async (): Promise<string | null> => {
    const current = tokenRef.current
    if (!current) {
      log(`🔍 getToken() called — no token in memory, returning null`)
      return null
    }
    const expMs = decodeJwtExp(current)
    if (expMs && expMs - Date.now() < REFRESH_LEAD_MS) {
      log(`🔍 getToken() — token has < ${fmtSeconds(REFRESH_LEAD_MS)} left, refreshing first`, {
        timeLeft: fmtSeconds(expMs - Date.now()),
      })
      return refreshAccessToken()
    }
    log(`🔍 getToken() — returning cached token`, {
      timeLeft: expMs ? fmtSeconds(expMs - Date.now()) : '?',
    })
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

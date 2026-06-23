import React from 'react'
import { generateCodeVerifier, generateCodeChallenge } from './pkce'
import type { HeadloAuthContextValue, HeadloProviderProps, HeadloUser } from './types'

const DEFAULT_ISSUER  = 'https://auth.headlo.com'
const VERIFIER_KEY    = 'headlo_pkce_verifier'
const REFRESH_LEAD_MS = 5 * 60 * 1000  // refresh when access token has <5 min left

// Clerk-style auth: refresh_token lives in an HttpOnly cookie set by the worker.
// JavaScript can't read it (XSS-immune). The access JWT lives in memory only —
// never written to localStorage. Every page load attempts a silent refresh
// via the cookie; if it succeeds, the user is signed in.

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

function decodeJwtExp(jwt: string): number | null {
  const claims = decodeJwtPayload(jwt)
  return claims && typeof claims.exp === 'number' ? claims.exp * 1000 : null
}

function userFromJwt(jwt: string): HeadloUser | null {
  const claims = decodeJwtPayload(jwt)
  if (!claims?.sub || !claims.email) return null
  return { id: claims.sub, email: claims.email, displayName: claims.name ?? null }
}

export function HeadloProvider({ publishableKey, issuer = DEFAULT_ISSUER, signInFallbackRedirectUrl, signUpFallbackRedirectUrl, children }: HeadloProviderProps) {
  const [isLoaded, setIsLoaded] = React.useState(false)
  const [user,     setUser]     = React.useState<HeadloUser | null>(null)
  const [token,    setToken]    = React.useState<string | null>(null)

  const refreshTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null)
  const tokenRef        = React.useRef<string | null>(null)
  const inFlightRef     = React.useRef<Promise<string | null> | null>(null)
  const channelRef      = React.useRef<BroadcastChannel | null>(null)
  tokenRef.current      = token

  function scheduleRefresh(accessToken: string) {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current)
    const expMs = decodeJwtExp(accessToken)
    if (!expMs) return
    const delay = Math.max(0, expMs - Date.now() - REFRESH_LEAD_MS)
    refreshTimerRef.current = setTimeout(() => { void refreshAccessToken() }, delay)
  }

  function clearSession() {
    if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current)
    setToken(null)
    setUser(null)
  }

  async function refreshAccessToken(): Promise<string | null> {
    // Concurrency guard — see prior commit for rationale.
    if (inFlightRef.current) return inFlightRef.current

    inFlightRef.current = (async () => {
      const res = await fetch(`${issuer}/oauth/refresh`, {
        method:      'POST',
        credentials: 'include',  // send headlo_refresh HttpOnly cookie
      })
      // 204 = no refresh cookie at all (anonymous visitor). Not an error,
      // just means there's no session to restore. Stay logged out silently.
      if (res.status === 204) { clearSession(); return null }
      if (!res.ok)            { clearSession(); return null }

      const { access_token } = await res.json() as { access_token: string }
      setToken(access_token)
      scheduleRefresh(access_token)
      // Hydrate user from JWT claims — no /oauth/userinfo call needed.
      // The access token already contains sub, email, name.
      if (!user) {
        const u = userFromJwt(access_token)
        if (u) setUser(u)
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
      const params = new URLSearchParams(window.location.search)
      const code   = params.get('code')

      if (code) {
        await handleCallback(code)
        const clean = new URL(window.location.href)
        clean.searchParams.delete('code')
        clean.searchParams.delete('state')
        window.history.replaceState({}, '', clean.toString())
      } else {
        // Try silent refresh — succeeds if the HttpOnly cookie is present.
        await refreshAccessToken()
      }
      setIsLoaded(true)
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
        if (e.data === 'signout') clearSession()
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
    setToken(access_token)
    scheduleRefresh(access_token)
    const u = userFromJwt(access_token)
    if (u) setUser(u)
  }

  async function signIn() {
    const verifier  = generateCodeVerifier()
    const challenge = await generateCodeChallenge(verifier)
    localStorage.setItem(VERIFIER_KEY, verifier)

    const url = new URL(`${issuer}/oauth/authorize`, window.location.origin)
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('client_id',     publishableKey)
    const redirectUri = signInFallbackRedirectUrl
      ? window.location.origin + signInFallbackRedirectUrl
      : window.location.origin + window.location.pathname
    url.searchParams.set('redirect_uri',          redirectUri)
    url.searchParams.set('code_challenge',        challenge)
    url.searchParams.set('code_challenge_method', 'S256')
    url.searchParams.set('scope',                 'openid email profile')

    window.location.href = url.toString()
  }

  async function signOut() {
    // Best-effort revoke + cookie clear via server
    fetch(`${issuer}/oauth/signout`, {
      method:      'POST',
      credentials: 'include',
    }).catch(() => {})

    clearSession()
    channelRef.current?.postMessage('signout')
  }

  // getToken returns a guaranteed-fresh token. If the current one is expired
  // or about to expire, refresh first so callers never see an expired JWT.
  const getToken = React.useCallback(async (): Promise<string | null> => {
    const current = tokenRef.current
    if (!current) return null
    const expMs = decodeJwtExp(current)
    if (expMs && expMs - Date.now() < REFRESH_LEAD_MS) {
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

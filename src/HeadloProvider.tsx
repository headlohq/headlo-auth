import React from 'react'
import { generateCodeVerifier, generateCodeChallenge } from './pkce'
import type { HeadloAuthContextValue, HeadloProviderProps, HeadloUser } from './types'

const DEFAULT_ISSUER  = 'https://auth.headlo.com'
const TOKEN_KEY       = 'headlo_auth_token'
const VERIFIER_KEY    = 'headlo_pkce_verifier'
const CLIENT_ID_PARAM = 'headlo_client_id'

export const HeadloAuthContext = React.createContext<HeadloAuthContextValue | null>(null)

export function HeadloProvider({ publishableKey, issuer = DEFAULT_ISSUER, children }: HeadloProviderProps) {
  const [isLoaded,   setIsLoaded]   = React.useState(false)
  const [user,       setUser]       = React.useState<HeadloUser | null>(null)
  const [token,      setToken]      = React.useState<string | null>(null)

  // On mount: handle PKCE callback or restore existing token
  React.useEffect(() => {
    async function init() {
      const params = new URLSearchParams(window.location.search)
      const code   = params.get('code')

      if (code) {
        await handleCallback(code)
        // Clean code from URL without reload
        const clean = new URL(window.location.href)
        clean.searchParams.delete('code')
        clean.searchParams.delete('state')
        window.history.replaceState({}, '', clean.toString())
      } else {
        const stored = localStorage.getItem(TOKEN_KEY)
        if (stored) await hydrateFromToken(stored)
      }

      setIsLoaded(true)
    }
    init()
  }, [])

  async function handleCallback(code: string) {
    const verifier    = localStorage.getItem(VERIFIER_KEY)
    if (!verifier) return
    localStorage.removeItem(VERIFIER_KEY)

    const res = await fetch(`${issuer}/oauth2/token`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:          'authorization_code',
        code,
        redirect_uri:        window.location.origin + window.location.pathname,
        client_id:           publishableKey,
        code_verifier:       verifier,
      }),
    })
    if (!res.ok) return

    const { access_token } = await res.json() as { access_token: string }
    localStorage.setItem(TOKEN_KEY, access_token)
    await hydrateFromToken(access_token)
  }

  async function hydrateFromToken(t: string) {
    const res = await fetch(`${issuer}/oauth2/userinfo`, {
      headers: { Authorization: `Bearer ${t}` },
    })
    if (!res.ok) { localStorage.removeItem(TOKEN_KEY); return }

    const { sub, email, name } = await res.json() as { sub: string; email: string; name?: string }
    setToken(t)
    setUser({ id: sub, email, displayName: name ?? null })
  }

  async function signIn() {
    const verifier   = generateCodeVerifier()
    const challenge  = await generateCodeChallenge(verifier)
    localStorage.setItem(VERIFIER_KEY, verifier)

    const url = new URL(`${issuer}/oauth2/authorize`)
    url.searchParams.set('response_type',          'code')
    url.searchParams.set('client_id',              publishableKey)
    url.searchParams.set('redirect_uri',           window.location.origin + window.location.pathname)
    url.searchParams.set('code_challenge',         challenge)
    url.searchParams.set('code_challenge_method',  'S256')
    url.searchParams.set('scope',                  'openid email profile')

    window.location.href = url.toString()
  }

  async function signOut() {
    localStorage.removeItem(TOKEN_KEY)
    setToken(null)
    setUser(null)
  }

  const getToken = React.useCallback(async () => token, [token])

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

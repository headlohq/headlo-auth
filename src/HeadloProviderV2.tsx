import React from 'react'
import { HeadloAuthClientV2 } from './client-v2'
import { HeadloAuthContext } from './HeadloProviderV1'
import type { HeadloAuthContextValue, HeadloProviderProps } from './types'

// HeadloProviderV2 — Anchor-Bound Session (ABS) React SDK.
//
// Design locked in claude/headlo-auth-abs-phase0-spec.md.
// As of the phase 1 extraction (claude/propCode/headloAuthService.md § 2.1),
// all auth logic lives in HeadloAuthClientV2 (./client-v2.ts). This provider is a
// thin React wrapper: it news up the client, mirrors state into React
// context, and forwards signIn/signOut/getToken. Same public surface,
// same behavior as before the extraction — consumers require zero changes.
//
// The shared class means the future headlo-auth PROP service can new up its
// own instance of the same class, and (via the future CustomEvent bridge)
// both instances stay in sync when they coexist on the same page.

const DEFAULT_ISSUER = 'https://auth.headlo.com'
const HEADLO_AUTH_V2_VERSION = 'v2-abs-phase-1-extract'
console.log(`%c[headlo-auth-v2]%c 📦 SDK build: ${HEADLO_AUTH_V2_VERSION}`, 'color:#7c3aed;font-weight:bold', 'color:inherit')

export function HeadloProviderV2({
  publishableKey,
  issuer = DEFAULT_ISSUER,
  signInForceRedirectUrl,
  signInFallbackRedirectUrl,
  children,
}: HeadloProviderProps) {
  // Client instance — owned by this provider, never re-created. Held in a
  // ref rather than state because the client owns its own state; the
  // provider just mirrors it into React state via onChange.
  const clientRef = React.useRef<HeadloAuthClientV2 | null>(null)
  if (!clientRef.current) {
    clientRef.current = new HeadloAuthClientV2({
      publishableKey,
      issuer,
      signInForceRedirectUrl,
      signInFallbackRedirectUrl,
    })
  }
  const client = clientRef.current

  // Mirror client state into React state so any consumer using
  // useHeadloAuth() re-renders on sign-in/out/refresh.
  const [state, setState] = React.useState(() => client.getState())

  React.useEffect(() => {
    const unsubscribe = client.onChange(setState)
    void client.init()
    return () => {
      unsubscribe()
      client.destroy()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Bind methods once — using useCallback-like memoization via useMemo so
  // context consumers don't see new function refs every render.
  const value = React.useMemo<HeadloAuthContextValue>(() => ({
    isLoaded:   state.isLoaded,
    isSignedIn: state.isSignedIn,
    user:       state.user,
    getToken:   () => client.getToken(),
    signIn:     (opts) => client.signIn(opts),
    signOut:    () => client.signOut(),
  }), [state, client])

  return (
    <HeadloAuthContext.Provider value={value}>
      {children}
    </HeadloAuthContext.Provider>
  )
}

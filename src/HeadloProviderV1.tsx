import React from 'react'
import { HeadloAuthClientV1 } from './client-v1'
import type { HeadloAuthContextValue, HeadloProviderProps } from './types'

// HeadloProviderV1 — Clerk-style cookie-refresh React SDK.
//
// As of the phase 1v1 extraction (claude/propCode/headloAuthService.md § 2.1),
// all auth logic lives in HeadloAuthClientV1 (./client-v1.ts). This provider
// is a thin React wrapper: it news up the client, mirrors state into React
// context, and forwards signIn/signOut/getToken. Same public surface, same
// behavior as before the extraction — consumers require zero changes.
//
// Sibling to HeadloProviderV2 (DPoP-based). Both providers expose the SAME
// HeadloAuthContext, so downstream hooks/components (useAuth, useUser,
// <SignedIn>, <SignedOut>, <SignInButton>, <SignOutButton>) work identically
// under either provider.

const DEFAULT_ISSUER = 'https://auth.headlo.com'
const HEADLO_AUTH_VERSION = 'v1-extract'
console.log(`%c[headlo-auth]%c 📦 SDK build: ${HEADLO_AUTH_VERSION}`, 'color:#5dcaa5;font-weight:bold', 'color:inherit')

// Re-exported for HeadloProviderV2 (which shares the same context) and for
// hooks that read it via useContext. Same identity as before extraction so
// existing consumers pull from the same context reference.
export const HeadloAuthContext = React.createContext<HeadloAuthContextValue | null>(null)

export function HeadloProviderV1({
  publishableKey,
  issuer = DEFAULT_ISSUER,
  signInForceRedirectUrl,
  signInFallbackRedirectUrl,
  signUpForceRedirectUrl: _signUpForce,
  signUpFallbackRedirectUrl: _signUpFallback,
  children,
}: HeadloProviderProps) {
  // Client instance — owned by this provider, never re-created. Held in a
  // ref because the client owns its own state; the provider just mirrors it
  // into React state via onChange.
  const clientRef = React.useRef<HeadloAuthClientV1 | null>(null)
  if (!clientRef.current) {
    clientRef.current = new HeadloAuthClientV1({
      publishableKey,
      issuer,
      signInForceRedirectUrl,
      signInFallbackRedirectUrl,
    })
  }
  const client = clientRef.current

  // Mirror client state into React state so any consumer using
  // useHeadloAuth() re-renders on sign-in/out/refresh/cross-instance sync.
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

  // useMemo the context value so consumers don't see new function refs
  // every render — matches ref stability of the old inline useCallback.
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

export { HeadloProviderV1 }                from './HeadloProviderV1'
export { HeadloProviderV2 }                from './HeadloProviderV2'
export { HeadloAuthClientV1 }              from './client-v1'
export { HeadloAuthClientV2 }              from './client-v2'
// SSO Wave 1 B.8 close-out — expose revocation detection so merchants who
// handle protected-endpoint 401s manually can reuse the same code list the
// Provider's auto-sign-out uses.
export { REVOCATION_ERROR_CODES, isRevocationCode } from './client-v2'
export { useAuth, useUser, useHeadloAuth, useHeadloUser, useSignIn, useClerk } from './hooks'
export type { GetTokenOptions, ClerkCompatSignInResource } from './hooks'
export { SignInButton, SignOutButton, SignedIn, SignedOut, SignIn, SignUp, AuthenticateWithRedirectCallback } from './components'
export { useAuthFetch, createAuthFetch }   from './authFetch'
export { dpopFetch, getExistingKeyPair, getOrCreateKeyPair, signDpopProof, exportPublicJwk, computeJwkThumbprint } from './dpop'

// SSO Wave 2 B.2 — silent discovery via hidden iframe + profile cache helpers
export { discoverSession, readCachedProfile, writeCachedProfile, clearCachedProfile } from './discover'
export type { DiscoverSessionOpts, DiscoveredUser, DiscoverResult } from './discover'

// SSO Wave 2 B.3 — visible popup sign-in + PKCE verifier helpers
export { signInViaPopup, readStoredPkceVerifier, clearStoredPkceState, pickDefaultSignInMode, PopupBlockedError, UserClosedPopupError, PopupTimeoutError, StateMismatchError, AuthServerError, exchangeAuthCodeDpop } from './signInPopup'
export type { SignInPopupOpts, SignInPopupResult, ExchangeAuthCodeOpts, ExchangeAuthCodeResult } from './signInPopup'

// SSO Wave 3 B.4 — "Continue as X" modal (composes B.2 discovery + B.3 popup + Option A DPoP exchange)
export { ContinueAsModal } from './ContinueAsModal'
export type { ContinueAsModalProps } from './ContinueAsModal'

// SSO Wave 4 B.10 — Google One Tap (Chrome-native account chooser)
export { GoogleOneTap } from './GoogleOneTap'
export type { GoogleOneTapProps } from './GoogleOneTap'

// SSO Wave 4 B.11 — Sign in with Apple.
export { HeadloAppleSignIn } from './HeadloAppleSignIn'
export type { HeadloAppleSignInProps } from './HeadloAppleSignIn'

// SSO Wave 4 B.12 — Multi-provider auth menu + SignIn/SignUp wrappers.
export { AuthMenu, SignInButton as AuthMenuSignInButton, SignUpButton as AuthMenuSignUpButton } from './AuthMenu'
export type { AuthMenuProps, AuthButtonProps, AuthAction, AuthProvider } from './AuthMenu'

// SSO Wave 4 B.6 — Encoded publishable keys (Clerk-style one-env-var integration)
export { encodePublishableKey, decodePublishableKey, resolveIssuer } from './pk'
export type { DecodedPk, PkPrefix } from './pk'
export type { HeadloUser, HeadloAuthContextValue, HeadloProviderProps, PlatformAdapter } from './types'
export type { HeadloAuthClientV1Config, AuthStateV1, AuthStateV1Listener } from './client-v1'
export type { HeadloAuthClientV2Config, AuthStateV2, AuthStateV2Listener } from './client-v2'

// Multi-environment auth — hold N independent sessions in one renderer,
// each bound to its own auth server (e.g. local / dev / prod). See
// ./multi-env.tsx for the design and the storageKey backward-compat rules.
export {
  HeadloAuthMultiEnvRegistry,
  HeadloMultiEnvProvider,
  useAuthRegistry,
  useOptionalAuthRegistry,
  useAuthClient,
  useAuthStateForEnv,
} from './multi-env'
export type { EnvClientConfig, HeadloMultiEnvProviderProps } from './multi-env'

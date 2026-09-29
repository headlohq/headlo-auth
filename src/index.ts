export { HeadloProviderV1 }                from './HeadloProviderV1'
export { HeadloProviderV2 }                from './HeadloProviderV2'
export { HeadloAuthClientV1 }              from './client-v1'
export { HeadloAuthClientV2 }              from './client-v2'
export { useAuth, useUser, useHeadloAuth, useHeadloUser, useSignIn, useClerk } from './hooks'
export type { GetTokenOptions, ClerkCompatSignInResource } from './hooks'
export { SignInButton, SignOutButton, SignedIn, SignedOut, SignIn, SignUp, AuthenticateWithRedirectCallback } from './components'
export { useAuthFetch, createAuthFetch }   from './authFetch'
export { dpopFetch, getExistingKeyPair, getOrCreateKeyPair, signDpopProof } from './dpop'
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

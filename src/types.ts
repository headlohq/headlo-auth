export interface HeadloUser {
  id:          string
  email:       string
  displayName: string | null
}

export interface SignInOptions {
  // Override the redirect URL for this sign-in attempt. Takes precedence over
  // HeadloProvider's signInFallbackRedirectUrl. Matches Clerk's `forceRedirectUrl` prop.
  forceRedirectUrl?: string

  // Skip the IdP's silent-SSO short-circuit and force the login form to
  // render even if the auth server already has a valid `headlo_session`
  // cookie for this browser. Wire-level: appends `prompt=login` (OIDC
  // standard) to /oauth/authorize; the server's silent-SSO branch is gated
  // on `prompt !== 'login'` (see routes/oauth.ts:911-947). Default false =
  // preserves the current auto-login behavior.
  forceLogin?: boolean
}

export interface HeadloAuthContextValue {
  isLoaded:    boolean
  isSignedIn:  boolean
  user:        HeadloUser | null
  getToken:    () => Promise<string | null>
  signIn:      (opts?: SignInOptions) => Promise<void>
  signOut:     () => Promise<void>
  /**
   * The publishable key the provider was mounted with. Needed by
   * consumers that call DPoP primitives directly (e.g. a custom
   * useDpopFetch hook) since Phase 1 introduced per-pk key storage —
   * `getExistingKeyPair(pk)` must know which pk to load. Optional
   * because pre-Phase-1 provider builds don't populate it.
   */
  publishableKey?: string
}

export interface HeadloProviderProps {
  publishableKey:            string
  issuer?:                   string
  // Redirect resolution order on sign-in (matches Clerk):
  //   per-call SignInButton forceRedirectUrl  >  signInForceRedirectUrl
  //   >  signInFallbackRedirectUrl  >  current page
  signInForceRedirectUrl?:   string
  signInFallbackRedirectUrl?: string
  // Sign-up redirects — currently unused (Headlo's /oauth/authorize handles
  // sign-in and register in one screen) but reserved for future split flows.
  signUpForceRedirectUrl?:   string
  signUpFallbackRedirectUrl?: string
  // Non-web host adapter. Supplied by Electron desktop / mobile shell apps
  // to override the web-native touchpoints (window.location redirect for
  // sign-in, URL-based callback detection). Web apps omit it and get the
  // default behavior. See HeadloAuthClientV2Config.platformAdapter for the
  // full contract.
  platformAdapter?:          PlatformAdapter
  children:                  React.ReactNode
}

/**
 * Shape re-exported from client-v2 for consumers that only import from the
 * package root. Keep in sync with the source of truth at
 * headlo-auth/src/client-v2.ts::PlatformAdapter.
 */
export interface PlatformAdapter {
  openAuthUrl:         (url: string) => void | Promise<void>
  redirectUri:         string
  subscribeToCallback: (handler: (params: { code: string; state: string }) => void) => (() => void)
}

export interface HeadloUser {
  id:          string
  email:       string
  displayName: string | null
}

export interface SignInOptions {
  // Override the redirect URL for this sign-in attempt. Takes precedence over
  // HeadloProvider's signInFallbackRedirectUrl. Matches Clerk's `forceRedirectUrl` prop.
  forceRedirectUrl?: string
}

export interface HeadloAuthContextValue {
  isLoaded:    boolean
  isSignedIn:  boolean
  user:        HeadloUser | null
  getToken:    () => Promise<string | null>
  signIn:      (opts?: SignInOptions) => Promise<void>
  signOut:     () => Promise<void>
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
  children:                  React.ReactNode
}

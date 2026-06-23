export interface HeadloUser {
  id:          string
  email:       string
  displayName: string | null
}

export interface HeadloAuthContextValue {
  isLoaded:    boolean
  isSignedIn:  boolean
  user:        HeadloUser | null
  getToken:    () => Promise<string | null>
  signIn:      () => Promise<void>
  signOut:     () => Promise<void>
}

export interface HeadloProviderProps {
  publishableKey:            string
  issuer?:                   string
  signInFallbackRedirectUrl?: string
  signUpFallbackRedirectUrl?: string
  children:                  React.ReactNode
}

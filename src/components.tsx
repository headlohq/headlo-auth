import React from 'react'
import { useHeadloAuth } from './hooks'

// SignInButton supports two usage patterns (same as Clerk):
//
//   1. Text/no children — renders a default <button>:
//        <SignInButton style={...}>Sign in</SignInButton>
//
//   2. A React element as the sole child — clones it and injects onClick.
//      Lets the consumer use any wrapper element (button, anchor, custom):
//        <SignInButton><button style={...}>Custom label</button></SignInButton>
//
// forceRedirectUrl (optional) overrides HeadloProvider's signInFallbackRedirectUrl
// for this button only. Matches Clerk's per-button override pattern.
export function SignInButton({
  children,
  forceRedirectUrl,
  forceLogin,
  ...props
}: {
  children?:         React.ReactNode
  forceRedirectUrl?: string
  // Skips the IdP silent-SSO short-circuit — user always sees the login
  // form even if `headlo_session` cookie is valid. Wire-level: appends
  // `prompt=login` to /oauth/authorize.
  forceLogin?:       boolean
} & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const { signIn } = useHeadloAuth()
  const handler = () => signIn({ forceRedirectUrl, forceLogin })
  if (React.isValidElement(children)) {
    return React.cloneElement(children as React.ReactElement<{ onClick?: () => void }>, {
      onClick: handler,
    })
  }
  return (
    <button onClick={handler} {...props}>
      {children ?? 'Sign in'}
    </button>
  )
}

export function SignOutButton({ children, ...props }: { children?: React.ReactNode } & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const { signOut } = useHeadloAuth()
  if (React.isValidElement(children)) {
    return React.cloneElement(children as React.ReactElement<{ onClick?: () => void }>, {
      onClick: () => signOut(),
    })
  }
  return (
    <button onClick={() => signOut()} {...props}>
      {children ?? 'Sign out'}
    </button>
  )
}

// Renders children only when a user is signed in. Returns null while auth is
// still hydrating (matches Clerk's <SignedIn> semantics — avoids flashing
// signed-out UI to a user whose session is about to resolve).
export function SignedIn({ children }: { children: React.ReactNode }) {
  const { isLoaded, isSignedIn } = useHeadloAuth()
  if (!isLoaded || !isSignedIn) return null
  return <>{children}</>
}

// Renders children only when no user is signed in. Returns null while auth is
// still hydrating to avoid flashing signed-out UI to a soon-to-be-signed-in user.
export function SignedOut({ children }: { children: React.ReactNode }) {
  const { isLoaded, isSignedIn } = useHeadloAuth()
  if (!isLoaded || isSignedIn) return null
  return <>{children}</>
}

// ── Wave 6 Clerk-migration compat ─────────────────────────────────────────
// Clerk ships full-screen <SignIn />, <SignUp /> components that render the
// auth flow inline. Headlo Auth v2 uses a hosted screen at
// `auth.headlo.com/oauth/authorize` and redirects there instead. Consumers
// that render <SignIn /> currently just want "trigger sign-in now" — so the
// migration-time behavior is: on mount, redirect to the hosted screen.
//
// Placed under a container div (no children rendered) so any layout the
// consumer wraps around it (padding, centering) still renders; user sees
// a brief blank moment before the redirect fires.

interface RedirectingProps {
  /** Optional post-auth landing. Falls back to the provider's config. */
  forceRedirectUrl?:    string
  /** Legacy Clerk prop — same as forceRedirectUrl in v2. */
  afterSignInUrl?:      string
  afterSignUpUrl?:      string
  /** Where the sign-up variant redirects. Currently v2 uses one hosted screen for both. */
  signUpUrl?:           string
  signInUrl?:           string
}

/**
 * Migration-time replacement for Clerk's `<SignIn />`. On mount, redirects
 * to `auth.headlo.com/oauth/authorize`. Renders nothing.
 */
export function SignIn({ forceRedirectUrl, afterSignInUrl }: RedirectingProps = {}) {
  const { signIn, isLoaded, isSignedIn } = useHeadloAuth()
  const fired = React.useRef(false)
  React.useEffect(() => {
    if (!isLoaded || isSignedIn || fired.current) return
    fired.current = true
    signIn({ forceRedirectUrl: forceRedirectUrl ?? afterSignInUrl })
  }, [isLoaded, isSignedIn, signIn, forceRedirectUrl, afterSignInUrl])
  return null
}

/**
 * Migration-time replacement for Clerk's `<SignUp />`. Redirects to the same
 * hosted screen — v2 doesn't split sign-in vs sign-up (the register mode
 * lives on the same page).
 */
export function SignUp({ forceRedirectUrl, afterSignUpUrl }: RedirectingProps = {}) {
  const { signIn, isLoaded, isSignedIn } = useHeadloAuth()
  const fired = React.useRef(false)
  React.useEffect(() => {
    if (!isLoaded || isSignedIn || fired.current) return
    fired.current = true
    signIn({ forceRedirectUrl: forceRedirectUrl ?? afterSignUpUrl })
  }, [isLoaded, isSignedIn, signIn, forceRedirectUrl, afterSignUpUrl])
  return null
}

/**
 * Migration-time no-op for Clerk's `<AuthenticateWithRedirectCallback />`.
 * v2's HeadloProviderV2 already parses `?code=&state=` from the callback URL
 * in its init sequence — this component just marks the route as reachable
 * and shows nothing. Kept as a component (not a bare null) so consumers
 * that route to `/sso-callback` still get a valid React element to render.
 *
 * Post-auth navigation is handled by the provider (redirects to the URL
 * saved before sign-in). Consumers pass no props today; kept for future
 * hooks like `redirectUrl` if we ever need to override.
 */
export function AuthenticateWithRedirectCallback(_props?: { redirectUrl?: string }) {
  return null
}

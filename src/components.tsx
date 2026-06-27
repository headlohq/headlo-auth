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
  ...props
}: {
  children?:         React.ReactNode
  forceRedirectUrl?: string
} & React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const { signIn } = useHeadloAuth()
  const handler = () => signIn({ forceRedirectUrl })
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

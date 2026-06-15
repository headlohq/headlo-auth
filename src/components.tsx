import React from 'react'
import { useHeadloAuth } from './hooks'

export function SignInButton({ children, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const { signIn } = useHeadloAuth()
  return (
    <button onClick={() => signIn()} {...props}>
      {children ?? 'Sign in'}
    </button>
  )
}

export function SignOutButton({ children, ...props }: React.ButtonHTMLAttributes<HTMLButtonElement>) {
  const { signOut } = useHeadloAuth()
  return (
    <button onClick={() => signOut()} {...props}>
      {children ?? 'Sign out'}
    </button>
  )
}

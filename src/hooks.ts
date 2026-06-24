import React from 'react'
import { HeadloAuthContext } from './HeadloProvider'
import type { HeadloAuthContextValue, HeadloUser } from './types'

function useHeadloAuthContext(): HeadloAuthContextValue {
  const ctx = React.useContext(HeadloAuthContext)
  if (!ctx) throw new Error('useAuth / useHeadloAuth must be used inside <HeadloProvider>')
  return ctx
}

/**
 * useAuth — Clerk-compatible alias. Returns auth state and methods.
 * Same as Clerk's useAuth() so migration is a one-line import change.
 */
export function useAuth() {
  const { isLoaded, isSignedIn, getToken, signIn, signOut } = useHeadloAuthContext()
  return { isLoaded, isSignedIn, getToken, signIn, signOut }
}

/**
 * useUser — Clerk-compatible alias. Returns the user object (or null).
 */
export function useUser(): HeadloUser | null {
  return useHeadloAuthContext().user
}

// Legacy names — kept for backwards compatibility.
// New code should prefer useAuth() / useUser() to match Clerk's API.
export const useHeadloAuth = useAuth
export const useHeadloUser = useUser

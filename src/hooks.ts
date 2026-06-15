import React from 'react'
import { HeadloAuthContext } from './HeadloProvider'
import type { HeadloAuthContextValue, HeadloUser } from './types'

function useHeadloAuthContext(): HeadloAuthContextValue {
  const ctx = React.useContext(HeadloAuthContext)
  if (!ctx) throw new Error('useHeadloAuth must be used inside <HeadloProvider>')
  return ctx
}

export function useHeadloAuth() {
  const { isLoaded, isSignedIn, getToken, signIn, signOut } = useHeadloAuthContext()
  return { isLoaded, isSignedIn, getToken, signIn, signOut }
}

export function useHeadloUser(): HeadloUser | null {
  return useHeadloAuthContext().user
}

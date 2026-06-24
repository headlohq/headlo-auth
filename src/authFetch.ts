import React from 'react'
import { useHeadloAuth } from './hooks'

// A fetch-compatible function that automatically attaches an `Authorization: Bearer <jwt>` header.
// Token is fetched fresh on every call via the provided getToken function, so it's always valid.

type GetToken = () => Promise<string | null>

/**
 * Factory for non-React use cases (server-side, vanilla JS, tests).
 * Pass in any getToken function; returns a fetch-compatible wrapper.
 */
export function createAuthFetch(getToken: GetToken): typeof fetch {
  return async (input, init) => {
    const token = await getToken()
    const headers = new Headers(init?.headers)
    if (token) headers.set('Authorization', `Bearer ${token}`)
    return fetch(input, { ...init, headers })
  }
}

/**
 * React hook — returns a fetch-compatible function bound to the current
 * HeadloProvider's getToken. The returned function refreshes the token on
 * each call so callers never see an expired JWT.
 *
 * Usage:
 *   const authFetch = useAuthFetch()
 *   await authFetch('/my-api', { method: 'POST', body: JSON.stringify(data) })
 */
export function useAuthFetch(): typeof fetch {
  const { getToken } = useHeadloAuth()
  return React.useMemo(() => createAuthFetch(getToken), [getToken])
}

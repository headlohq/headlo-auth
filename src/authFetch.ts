import React from 'react'
import { HeadloAuthContext } from './HeadloProviderV1'
import { isRevocationCode } from './client-v2'

// A fetch-compatible function that automatically attaches an `Authorization: Bearer <jwt>` header.
// Token is fetched fresh on every call via the provided getToken function, so it's always valid.
//
// SSO Wave 1 § 7.4.2 — also auto-detects server-side revocation on 401 responses.
// When the response body carries a revocation marker (SESSION_REVOKED,
// REVOKED_BY_PASSWORD_RESET, REVOKED, LEGACY_TOKEN_REAUTH_REQUIRED,
// DPOP_KEY_REVOKED), the caller-provided `onRevocation` callback fires. The
// Provider wires its own `_handleRevocation` into that slot so the SDK's
// auto-sign-out machinery runs the same way it does for silent refresh paths.
// Merchants using `createAuthFetch` directly (non-React / server-side / tests)
// can also pass their own `onRevocation` to intercept.

type GetToken = () => Promise<string | null>

export interface AuthFetchOptions {
  /** Called before every fetch to attach `Authorization: Bearer <token>`. */
  getToken:      GetToken
  /**
   * Fires when a 401 response from the merchant's protected endpoint carries
   * one of the server-side revocation markers. Receives the error code
   * string (e.g. `"SESSION_REVOKED"`). Typically wired to the Provider's
   * `_handleRevocation` which clears local state + broadcasts to peer tabs.
   */
  onRevocation?: (code: string) => void
}

/**
 * Factory for non-React use cases (server-side, vanilla JS, tests).
 *
 * Backward-compatible overload: pass a bare `getToken` function OR the full
 * `AuthFetchOptions` object. Pre-§7.4.2 callers that just pass a function
 * keep compiling + working; the revocation-detection path simply doesn't
 * fire without an `onRevocation` callback.
 */
export function createAuthFetch(getTokenOrOpts: GetToken | AuthFetchOptions): typeof fetch {
  const opts: AuthFetchOptions = typeof getTokenOrOpts === 'function'
    ? { getToken: getTokenOrOpts }
    : getTokenOrOpts

  return async (input, init) => {
    const token = await opts.getToken()
    const headers = new Headers(init?.headers)
    if (token) headers.set('Authorization', `Bearer ${token}`)
    const res = await fetch(input, { ...init, headers })

    // SSO Wave 1 § 7.4.2 — revocation detection on 401. Clone the response
    // so the merchant can still read the body themselves (fetch bodies are
    // one-shot streams). On revocation code match, fire the callback — it's
    // responsible for the clearSession + peer-tab broadcast.
    if ((res.status === 401 || res.status === 403) && opts.onRevocation) {
      try {
        const body = await res.clone().json().catch(() => null) as { error?: string } | null
        const code = body?.error
        if (code && isRevocationCode(code)) {
          opts.onRevocation(code)
        }
      } catch { /* non-fatal — merchant still gets the original 401 response */ }
    }

    return res
  }
}

/**
 * React hook — returns a fetch-compatible function bound to the current
 * HeadloProvider's getToken + revocation handler. The returned function
 * refreshes the token on each call so callers never see an expired JWT, AND
 * auto-detects server-side revocation on 401 responses to flip local state.
 *
 * Usage:
 *   const authFetch = useAuthFetch()
 *   await authFetch('/my-api', { method: 'POST', body: JSON.stringify(data) })
 */
export function useAuthFetch(): typeof fetch {
  // Read context directly rather than via useHeadloAuth() — the public Clerk-
  // shaped hook projects a narrower surface that intentionally omits internal
  // plumbing fields like _handleRevocation. We need the raw context to wire
  // revocation detection into the fetch wrapper.
  const ctx = React.useContext(HeadloAuthContext)
  if (!ctx) throw new Error('useAuthFetch must be used inside <HeadloProvider> / <HeadloProviderV2>')
  const { getToken, _handleRevocation } = ctx
  return React.useMemo(
    () => createAuthFetch({ getToken, onRevocation: _handleRevocation }),
    [getToken, _handleRevocation],
  )
}

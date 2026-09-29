import React from 'react'
import { HeadloAuthContext } from './HeadloProviderV1'
import type { HeadloAuthContextValue, HeadloUser } from './types'

function useHeadloAuthContext(): HeadloAuthContextValue {
  const ctx = React.useContext(HeadloAuthContext)
  if (!ctx) throw new Error('useAuth / useHeadloAuth must be used inside <HeadloProvider>')
  return ctx
}

/**
 * Options accepted by getToken() for Clerk-shape compatibility.
 *
 * Neither option changes v2 behavior:
 *   - `skipCache` — v2's getToken already returns a fresh token when the
 *     cached one is close to expiry (via the internal refresh path), so
 *     skipCache=true is redundant.
 *   - `template` — v2 doesn't have JWT templates (all tokens carry the
 *     same claim set); the option is accepted so existing Clerk call
 *     sites compile without churn.
 *
 * Passing an unrecognised template on a v2 caller will silently return
 * a standard token — that's Wave 6's migration philosophy: existing calls
 * keep working, and new code uses the narrower typed shape.
 */
export interface GetTokenOptions {
  skipCache?: boolean
  template?:  string
}

/**
 * useAuth — Clerk-compatible alias. Returns auth state and methods.
 * Same as Clerk's useAuth() so migration is a one-line import change.
 *
 * getToken accepts (but ignores) Clerk's options bag so dashboard call
 * sites like `getToken({ skipCache: true })` keep type-checking during
 * the Wave 6 migration.
 */
export function useAuth() {
  const ctx = useHeadloAuthContext()
  const getToken = React.useCallback((_opts?: GetTokenOptions) => ctx.getToken(), [ctx.getToken])
  return {
    isLoaded:       ctx.isLoaded,
    isSignedIn:     ctx.isSignedIn,
    getToken,
    signIn:         ctx.signIn,
    signOut:        ctx.signOut,
    publishableKey: ctx.publishableKey,
  }
}

/**
 * useUser — Clerk-compatible alias. Returns `{ user, isLoaded, isSignedIn }`
 * matching Clerk's `useUser()` return shape so consumers destructuring
 * `const { user } = useUser()` work identically under either provider.
 *
 * For narrow "just give me the HeadloUser" consumers, `useHeadloUser` still
 * returns `HeadloUser | null` directly (used by mobile / desktop).
 */
export function useUser(): { user: HeadloUser | null; isLoaded: boolean; isSignedIn: boolean } {
  const { user, isLoaded, isSignedIn } = useHeadloAuthContext()
  return { user, isLoaded, isSignedIn }
}

/**
 * useHeadloUser — narrow shape. Returns `HeadloUser | null` directly.
 * Preserved for non-dashboard consumers (mobile, desktop, widgets) that
 * were coded against the pre-Wave-6 shape.
 */
export function useHeadloUser(): HeadloUser | null {
  return useHeadloAuthContext().user
}

// Legacy name — kept for backwards compatibility. useHeadloAuth is a plain
// alias of useAuth (same Clerk-shape return). useHeadloUser is defined
// separately above because it returns the narrow HeadloUser|null shape.
export const useHeadloAuth = useAuth

// ── Wave 6 Clerk-migration compat ─────────────────────────────────────────
// useSignIn — Clerk's version returns `{ signIn: { authenticateWithRedirect } }`
// where authenticateWithRedirect kicks off a social OAuth flow. In v2 the
// same intent is: redirect to `auth.headlo.com/oauth/authorize` (where the
// user picks Google/password). The strategy hint is accepted but not acted
// on — auth.headlo.com's hosted screen offers Google alongside password
// today, so the caller lands there and picks. `redirectUrlComplete` (Clerk's
// "post-auth landing") maps to `forceRedirectUrl` in v2.
export interface ClerkCompatSignInResource {
  authenticateWithRedirect(opts: {
    strategy?:            string
    redirectUrl?:         string
    redirectUrlComplete?: string
  }): Promise<void>
}

export function useSignIn(): { signIn: ClerkCompatSignInResource; isLoaded: boolean; setActive: () => Promise<void> } {
  const { isLoaded, signIn } = useHeadloAuthContext()
  return {
    isLoaded,
    signIn: {
      authenticateWithRedirect: (opts) =>
        signIn({ forceRedirectUrl: opts.redirectUrlComplete }),
    },
    // Clerk exposes setActive() alongside signIn for switching the active
    // session after auth. v2 has one session — no-op.
    setActive: async () => {},
  }
}

// useClerk — Clerk's escape hatch that returns the raw client. The only two
// dashboard call sites just want signOut(). Provide that, plus a placeholder
// `session` prop the Clerk types include (undefined in v2 because there's
// no equivalent shared session object). Any code reaching further into
// useClerk() will need a specific refactor.
export function useClerk(): { signOut: HeadloAuthContextValue['signOut']; session: undefined } {
  const { signOut } = useHeadloAuthContext()
  return { signOut, session: undefined }
}

import React from 'react'
import { HeadloAuthClientV2 } from './client-v2'
import { HeadloAuthContext } from './HeadloProviderV1'
import { decodePublishableKey } from './pk'
import type { HeadloAuthContextValue, HeadloProviderProps } from './types'

// HeadloProviderV2 — Anchor-Bound Session (ABS) React SDK.
//
// Design locked in claude/headlo-auth-abs-phase0-spec.md.
// As of the phase 1 extraction (claude/propCode/headloAuthService.md § 2.1),
// all auth logic lives in HeadloAuthClientV2 (./client-v2.ts). This provider is a
// thin React wrapper: it news up the client, mirrors state into React
// context, and forwards signIn/signOut/getToken. Same public surface,
// same behavior as before the extraction — consumers require zero changes.
//
// The shared class means the future headlo-auth PROP service can new up its
// own instance of the same class, and (via the future CustomEvent bridge)
// both instances stay in sync when they coexist on the same page.

const DEFAULT_ISSUER = 'https://auth.headlo.com'
const HEADLO_AUTH_V2_VERSION = 'v2-abs-phase-1-extract'
console.log(`%c[headlo-auth-v2]%c 📦 SDK build: ${HEADLO_AUTH_V2_VERSION}`, 'color:#7c3aed;font-weight:bold', 'color:inherit')

export function HeadloProviderV2({
  publishableKey,
  issuer,
  signInForceRedirectUrl,
  signInFallbackRedirectUrl,
  platformAdapter,
  autoSignOutOnRevocation,
  children,
}: HeadloProviderProps) {
  // Issuer resolution — three-tier precedence:
  //   1. Explicit `issuer` prop (back-compat; merchants on legacy raw-hex pks
  //      and anyone overriding for dev purposes).
  //   2. Wave 4 B.6 — hostname embedded in the publishable key itself. The
  //      pk encodes `{hostname}${keyId}` in base64url; the decoder returns
  //      the full `https://host` URL (http for localhost/127.*).
  //   3. DEFAULT_ISSUER constant (last-resort fallback for anyone whose pk
  //      is still raw-hex AND who didn't pass an issuer prop — prevents a
  //      cryptic "fetch to undefined" at init time).
  const resolvedIssuer = React.useMemo(() => {
    if (issuer) return issuer
    const decoded = decodePublishableKey(publishableKey)
    if (decoded.isEncoded && decoded.issuer) return decoded.issuer
    return DEFAULT_ISSUER
  }, [publishableKey, issuer])

  // Client instance — owned by this provider, never re-created. Held in a
  // ref rather than state because the client owns its own state; the
  // provider just mirrors it into React state via onChange.
  const clientRef = React.useRef<HeadloAuthClientV2 | null>(null)
  if (!clientRef.current) {
    clientRef.current = new HeadloAuthClientV2({
      publishableKey,
      issuer: resolvedIssuer,
      signInForceRedirectUrl,
      signInFallbackRedirectUrl,
      platformAdapter,
      autoSignOutOnRevocation,
    })
  }
  const client = clientRef.current

  // Mirror client state into React state so any consumer using
  // useHeadloAuth() re-renders on sign-in/out/refresh.
  const [state, setState] = React.useState(() => client.getState())

  React.useEffect(() => {
    const unsubscribe = client.onChange(setState)
    void client.init()
    return () => {
      unsubscribe()
      client.destroy()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Wave 4 A1 — publish a widget-facing shim on window so PROP widgets and
  // services embedded on the same React page can forward this user's V2 token
  // (bearer + DPoP proof) through their compiler-injected exchange call. Same
  // shape and global name as the vanilla PROP-service bundle
  // (window.__headlo_service_headlo_auth_v2), so widget bundles don't need to
  // distinguish React-provider vs bundle-loaded contexts.
  //
  // Only installs if nothing else has published the global already — an app
  // that <script>-loads the standalone service bundle keeps the bundle's
  // shim, and both share the same sessionStorage token + IndexedDB DPoP key
  // so behavior converges anyway.
  //
  // authFetch returns the wrapped { status, ok, body, headers } shape that
  // cap-expert/v3/client.ts + prop-bundle.ts consume. Not signed in →
  // gracefully falls back to a plain fetch (no bearer, no DPoP) so anon
  // exchange flows work without a signed-in user.
  React.useEffect(() => {
    const w = window as unknown as { __headlo_service_headlo_auth_v2?: unknown }
    if (w.__headlo_service_headlo_auth_v2) return
    const shim = {
      authFetch: async (args: { url: string; options?: RequestInit }) => {
        const url = args.url
        const opts = args.options ?? {}
        let res: Response
        try {
          res = state.isSignedIn ? await client.dpopFetch(url, opts) : await fetch(url, opts)
        } catch {
          res = await fetch(url, opts)
        }
        let body: unknown = null
        const text = await res.text()
        try { body = JSON.parse(text) } catch { body = text }
        const headers: Record<string, string> = {}
        res.headers.forEach((v, k) => { headers[k] = v })
        return { status: res.status, ok: res.ok, body, headers }
      },
    }
    w.__headlo_service_headlo_auth_v2 = shim
    return () => {
      if (w.__headlo_service_headlo_auth_v2 === shim) delete w.__headlo_service_headlo_auth_v2
    }
  }, [client, state.isSignedIn])

  // Bind methods once — using useCallback-like memoization via useMemo so
  // context consumers don't see new function refs every render.
  const value = React.useMemo<HeadloAuthContextValue>(() => ({
    isLoaded:          state.isLoaded,
    isSignedIn:        state.isSignedIn,
    user:              state.user,
    getToken:          () => client.getToken(),
    signIn:            (opts) => client.signIn(opts),
    signOut:           () => client.signOut(),
    publishableKey,
    // SSO Wave 1 § 7.4.2 — called by createAuthFetch on merchant-endpoint 401s
    // whose body carries a revocation marker. Mirrors the refresh-path auto-
    // sign-out shipped in § 7.1.
    _handleRevocation: (code) => client.handleRevocation(code),
  }), [state, client, publishableKey])

  return (
    <HeadloAuthContext.Provider value={value}>
      {children}
    </HeadloAuthContext.Provider>
  )
}

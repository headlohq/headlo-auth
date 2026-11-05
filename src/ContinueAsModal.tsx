// SSO Wave 3 B.4 — "Continue as X" modal.
//
// Composition of the two tiers:
//   Tier 1 (B.2 discover) → paints "Continue as {name}" instantly on return
//                           visits from localStorage cache, then revalidates
//                           via a silent iframe to /oauth/discover.
//   Tier 2 (B.3 popup)   → opens on click, exchanges the code + DPoP proof
//                           at /oauth/token (Option A), writes the cnf.jkt-
//                           bound token to sessionStorage, reloads.
//
// Shop-equivalent. This is the pitch-deck demo moment: the user lands on
// merchant.com having never signed in there before, and the modal recognizes
// them from their Headlo session on auth.headlo.com.
//
// Full plan: claude/headlo-sso-shop-equivalent.md § B.4.

import React from 'react'
import { discoverSession, readCachedProfile, writeCachedProfile, clearCachedProfile, type DiscoveredUser } from './discover'
import { signInViaPopup, readStoredPkceVerifier, clearStoredPkceState, exchangeAuthCodeDpop, PopupBlockedError, UserClosedPopupError, PopupTimeoutError, AuthServerError } from './signInPopup'
import { getOrCreateKeyPair, exportPublicJwk, computeJwkThumbprint } from './dpop'
import { resolveIssuer } from './pk'

export interface ContinueAsModalProps {
  /**
   * OIDC issuer base — e.g. `https://auth.headlo.com`.
   *
   * Optional when `publishableKey` is an encoded pk (Wave 4 B.6) — the SDK
   * derives the issuer from the pk's embedded hostname. Required for legacy
   * raw-hex pks that have no embedded issuer.
   */
  issuer?:         string
  /** pk_live_… or pk_test_… — raw-hex (legacy) or encoded (Wave 4 B.6) */
  publishableKey:  string
  /**
   * Merchant redirect_uri to register the auth code against. Defaults to the
   * current `window.location.origin`. Must be in the pk's allowed_origins
   * (or allowed_redirect_uris when exact-URL allowlist is populated).
   */
  redirectUri?:    string
  /**
   * Fires AFTER the token has been written to sessionStorage and the user
   * profile to localStorage. The modal's default success behavior is to
   * `window.location.reload()` so the enclosing HeadloProviderV2 rehydrates
   * on mount — override by returning `false` from onSuccess to suppress the
   * reload (e.g. if the parent handles state updates directly).
   */
  onSuccess?:      (user: DiscoveredUser) => void | false | Promise<void | false>
  /** Fires when the user clicks the X / backdrop. */
  onCancel?:       () => void
  /**
   * Controlled visibility. When unset, the modal is always visible once
   * discovery runs. Pass a boolean + onCancel to make it dismissable.
   */
  open?:           boolean
  /**
   * Skip the Tier 1 revalidation iframe when a cached profile is present.
   * Trades the stale-modal risk (user signed out of all devices on another
   * tab) for a faster first paint. Default false — always revalidates.
   */
  trustCacheOnly?: boolean
  /**
   * SSO Wave 5 — fallback top-level handshake when the Tier 1 discovery
   * iframe times out (Safari ITP / Firefox TCP / Chrome 3PC blocks the
   * cross-site session cookie). When true (default), the modal auto-
   * navigates to `${issuer}/oauth/discover-handshake?...` which reads the
   * session cookie in first-party context and 302s back with a signed
   * handshake token. On return the modal paints "Continue as X" as if
   * discovery had succeeded. Loop-protected: max 1 handshake per page load,
   * terminal `nosession` marker short-circuits the loop.
   *
   * Set to false to pin v1 behavior (iframe only; cached paint on timeout).
   */
  fallbackHandshake?: boolean
  /**
   * TESTING-ONLY. Skip the discovery iframe entirely and jump straight to
   * the ambiguous-failure branch (same code path as a real 4s timeout).
   * Lets the `/abs-test` harness demonstrate the Wave 5 handshake fallback
   * in a browser where third-party cookies are NOT blocked (Chrome dev
   * default), by faking the condition that would normally require Safari /
   * Incognito / DevTools request-blocking to reproduce.
   *
   * Not for production use — merchants calling the modal with this set to
   * `true` would unconditionally trigger a redirect round-trip on every
   * mount. Prefix underscored to signal "internal test flag" at call sites.
   */
  _debugForceDiscoveryFail?: boolean
}

const HANDSHAKE_PARAM        = '__headlo_discover_handshake'
const HANDSHAKE_NONCE_KEY    = 'headlo_discover_handshake_nonce'
const HANDSHAKE_ATTEMPTED_FLAG = 'headlo_discover_handshake_attempted'

/**
 * Decode a handshake token's payload WITHOUT verifying the Ed25519
 * signature. Checks nonce round-trip + exp + required fields. Returns the
 * discovered user on success, null on any failure.
 *
 * Why no signature verify client-side: the SDK stays dependency-light (no
 * jose import) and the token is UX-only — real auth happens on click via
 * popup+DPoP+PKCE. A forged token at worst paints a wrong name on the
 * modal; the user can't be signed in as the forged identity (that would
 * require passing the server-side session-cookie read on auth.headlo.com).
 */
function parseHandshakeToken(token: string): DiscoveredUser | null {
  try {
    const [, payloadB64] = token.split('.')
    if (!payloadB64) return null
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/'))) as {
      sub?: string; email?: string; name?: string | null
      azp?: string; nonce?: string; exp?: number
      handshake_type?: string
    }
    if (!payload.sub || !payload.email) return null
    if (payload.handshake_type !== 'discover') return null
    if (typeof payload.exp === 'number' && payload.exp * 1000 < Date.now()) return null

    const expectedNonce = sessionStorage.getItem(HANDSHAKE_NONCE_KEY)
    if (!expectedNonce || payload.nonce !== expectedNonce) {
      console.log('[continue-as-modal] handshake nonce mismatch — rejecting token', { gotNonce: payload.nonce, expectedPresent: !!expectedNonce })
      return null
    }
    return {
      headloUserId: payload.sub,
      email:        payload.email,
      displayName:  payload.name ?? null,
      avatarUrl:    null,
    }
  } catch (e) {
    console.log('[continue-as-modal] handshake token parse failed', e)
    return null
  }
}

type Phase =
  | { kind: 'discovering' }
  // SSO Wave 2 B.9 follow-up — `consentGranted` tri-state: true/false from a
  // live discover response; undefined when painted from cache (we don't know
  // yet, so the CTA stays short and the revalidating discover will fill it
  // in on next render). Powers the "merchant will see your email + name"
  // first-grant copy on the Continue CTA.
  | { kind: 'returning-user'; user: DiscoveredUser; cached: boolean; consentGranted?: boolean }
  | { kind: 'anonymous' }
  | { kind: 'signing-in'; variant: 'continue' | 'different' | 'anonymous' }
  | { kind: 'error'; message: string; retryable: boolean }

/**
 * `<ContinueAsModal>` — the Shop-style returning-user modal. Drop-in; no
 * provider wiring required beyond the usual HeadloProviderV2 at the root of
 * your tree (so the token the modal writes to sessionStorage is picked up
 * after the reload).
 *
 * Minimal usage:
 *
 * ```tsx
 * <ContinueAsModal
 *   issuer="https://auth.headlo.com"
 *   publishableKey={pk}
 * />
 * ```
 *
 * Controlled dismissable usage:
 *
 * ```tsx
 * const [showModal, setShowModal] = useState(true)
 * <ContinueAsModal
 *   issuer={issuer}
 *   publishableKey={pk}
 *   open={showModal}
 *   onCancel={() => setShowModal(false)}
 * />
 * ```
 */
export function ContinueAsModal(props: ContinueAsModalProps): React.ReactElement | null {
  const { publishableKey, redirectUri, open, onSuccess, onCancel, trustCacheOnly, fallbackHandshake = true, _debugForceDiscoveryFail } = props
  // Derive issuer from the pk when the prop is absent (Wave 4 B.6). Throws
  // with a helpful message if neither the prop nor the pk yields a URL —
  // caught by React's error boundary rather than silently failing with a
  // "fetch to undefined" network error.
  const issuer = React.useMemo(() => resolveIssuer(publishableKey, props.issuer), [publishableKey, props.issuer])

  const [phase, setPhase] = React.useState<Phase>(() => {
    if (typeof window === 'undefined') return { kind: 'discovering' }
    // SSO Wave 5 — if we just returned from a handshake redirect, the URL
    // carries the handshake outcome. Short-circuit the normal discover flow
    // here BEFORE painting from cache so a fresh handshake result wins over
    // whatever the stale cache held.
    const params        = new URLSearchParams(window.location.search)
    const handshakeVal  = params.get(HANDSHAKE_PARAM)
    if (handshakeVal === 'nosession') {
      // Server confirmed no session via first-party cookie read. Flip to
      // anonymous and clear the stale cache. We handle URL cleanup in the
      // mount effect so it only runs once.
      clearCachedProfile()
      return { kind: 'anonymous' }
    }
    if (handshakeVal) {
      // Signed JWT with user info — decode payload without crypto verify.
      // The token is UX-only (modal paint); real auth still happens on
      // click via popup+DPoP. nonce + exp checks give tamper-resistance
      // for the common case; forging only affects what name paints.
      const parsed = parseHandshakeToken(handshakeVal)
      if (parsed) {
        writeCachedProfile(publishableKey, parsed)
        return { kind: 'returning-user', user: parsed, cached: false }
      }
      // Bad token (nonce mismatch, expired, malformed) — fall through to
      // cache / anonymous. URL cleanup still runs below.
    }
    const cached = readCachedProfile(publishableKey)
    return cached
      ? { kind: 'returning-user', user: cached, cached: true }
      : { kind: 'discovering' }
  })

  // Run Tier 1 (B.2) silent discovery on mount — paints over the cached state
  // with fresh data when the server confirms the session, OR falls back to the
  // anonymous state when the session's gone.
  //
  // Deps intentionally omit `phase.kind` + `trustCacheOnly` so this effect
  // runs exactly once per mount. Changing phase after discovery completes
  // must NOT re-trigger discovery (that would spawn a second iframe + double
  // the server round-trip + double-log every incoming postMessage). The
  // one-shot semantics are enforced by the deps array, not by the ref —
  // the ref is a belt-and-braces guard against React StrictMode's dev-only
  // double-invoke of effects.
  const didRunRef = React.useRef(false)
  // Capture trustCacheOnly at mount time so the body's cache-only short-
  // circuit still works without requiring the dep.
  const trustCacheOnlyRef = React.useRef(trustCacheOnly)
  const fallbackHandshakeRef = React.useRef(fallbackHandshake)
  React.useEffect(() => {
    if (didRunRef.current) return
    if (open === false) return
    didRunRef.current = true

    // SSO Wave 5 — clean handshake param + its sibling sessionStorage keys
    // from a prior redirect round-trip. Done AFTER initial phase decoded
    // from them (initial useState did that) so this is pure URL hygiene.
    try {
      const u = new URL(window.location.href)
      if (u.searchParams.has(HANDSHAKE_PARAM)) {
        u.searchParams.delete(HANDSHAKE_PARAM)
        history.replaceState({}, '', u.toString())
        sessionStorage.removeItem(HANDSHAKE_NONCE_KEY)
      }
    } catch { /* non-fatal */ }

    // Snapshot current phase for the cache-only short-circuit. We read via
    // ref because `phase` is intentionally not a dep.
    const startingKind = phase.kind
    if (trustCacheOnlyRef.current && startingKind === 'returning-user') return

    // If the handshake just gave us a returning-user state, skip the iframe
    // — we already have fresh server-sourced info, no need to re-discover.
    if (startingKind === 'returning-user' && !readCachedProfile(publishableKey)) {
      // (This branch catches the handshake-success path. The cache check
      // confirms we're not just reading the cached-paint fallback.)
    }
    // Separate variable so the "already attempted handshake this page load"
    // flag is read inside the closure below.
    const attemptedHandshakeThisLoad = (() => {
      try { return sessionStorage.getItem(HANDSHAKE_ATTEMPTED_FLAG) === '1' } catch { return false }
    })()

    void (async () => {
      // TESTING-ONLY — short-circuit the iframe call with a synthetic
      // ambiguous failure. Lets the test harness demonstrate the Wave 5
      // handshake path without needing a 3PC-blocked browser.
      const result = _debugForceDiscoveryFail
        ? ({ discovered: false as const, error: 'timeout' })
        : await discoverSession({ issuer, publishableKey })
      if (_debugForceDiscoveryFail) {
        console.log('[continue-as-modal] 🧪 _debugForceDiscoveryFail — synthesizing ambiguous iframe failure')
      }
      if (result.discovered) {
        setPhase({ kind: 'returning-user', user: result.user, cached: false, consentGranted: result.consentGranted })
        return
      }

      // Discovery failed. Branch on WHY — the modal's downgrade behavior
      // depends on whether we got a definitive answer or just couldn't
      // reach the server.
      //
      // `no_session` is the only "server confirmed the session is actually
      // gone" response. Anything else (timeout, 3PC blocking the cookie,
      // iframe parse failure, network blip) is ambiguous — we can't claim
      // the user is signed out just because WE couldn't check. In the
      // ambiguous case we KEEP the cached paint; the user clicking
      // Continue will resolve truth via /oauth/token's PKCE+DPoP check
      // (which 401s if the session really is gone — handled in the error
      // UI below). This is the Shop pattern — the stale-modal window is
      // intentionally bounded by click, not by iframe reliability.
      if (result.error === 'no_session') {
        // Server confirmed no session. Clear the stale cache so we don't
        // paint it on the next visit either, and flip to anonymous.
        clearCachedProfile()
        setPhase({ kind: 'anonymous' })
        return
      }

      // Ambiguous failure (timeout, 3PC-blocked, iframe error, …). We don't
      // know whether the user is signed in — the iframe just couldn't tell
      // us. SSO Wave 5: trigger the fallback handshake (top-level nav to
      // auth.headlo.com reads the cookie in first-party context, 302s back
      // with a signed token). Loop-protected: max 1 attempt per page load.
      //
      // When _debugForceDiscoveryFail is set we intentionally bypass the
      // loop-protection flag — the whole point of the test is to observe
      // the handshake path, so previous attempts in the same tab shouldn't
      // suppress it. Production mounts never pass this flag.
      if (fallbackHandshakeRef.current && (!attemptedHandshakeThisLoad || _debugForceDiscoveryFail)) {
        try {
          const nonce = (crypto.randomUUID?.() ?? Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2))
          sessionStorage.setItem(HANDSHAKE_NONCE_KEY,     nonce)
          sessionStorage.setItem(HANDSHAKE_ATTEMPTED_FLAG, '1')
          const returnUrl = window.location.href
          const handshakeUrl = new URL(`${issuer}/oauth/discover-handshake`)
          handshakeUrl.searchParams.set('client_id',    publishableKey)
          handshakeUrl.searchParams.set('redirect_url', returnUrl)
          handshakeUrl.searchParams.set('nonce',        nonce)
          console.log('[continue-as-modal] 🌀 discovery ambiguous — top-level handshake fallback', { to: handshakeUrl.toString() })
          window.location.href = handshakeUrl.toString()
          return  // navigation in progress
        } catch (e) {
          console.log('[continue-as-modal] handshake trigger failed, falling back', e)
        }
      }

      // Handshake disabled OR already attempted this page load. If we're
      // already painting a cached user, STAY on that state (bounded stale-
      // modal window is intentional; clicking Continue resolves truth via
      // the /oauth/token exchange). Otherwise flip to anonymous.
      setPhase((prev) => prev.kind === 'returning-user' ? prev : { kind: 'anonymous' })
    })()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [issuer, publishableKey, open])

  async function runSignIn(variant: 'continue' | 'different' | 'anonymous', loginHint?: string): Promise<void> {
    setPhase({ kind: 'signing-in', variant })
    try {
      // Option A — generate/retrieve DPoP keypair, pre-bind the auth code via
      // dpop_jkt, exchange code+proof at /oauth/token for a cnf.jkt-bound token.
      const keyPair = await getOrCreateKeyPair(publishableKey)
      const jwk     = await exportPublicJwk(keyPair)
      const jkt     = await computeJwkThumbprint(jwk)

      const popupResult = await signInViaPopup({
        issuer,
        publishableKey,
        redirectUri:  redirectUri ?? window.location.origin,
        // continue  → let server decide (silent-SSO expected since we're a returning user)
        // different → force the form so the user can pick a different account
        // anonymous → let server decide; user hasn't been recognized
        prompt:       variant === 'different' ? 'login' : undefined,
        loginHint,
        dpopJkt:      jkt,
      })

      const verifier = readStoredPkceVerifier()
      if (!verifier) throw new Error('PKCE verifier missing — sessionStorage cleared mid-flow')

      const tokenRes = await exchangeAuthCodeDpop({
        issuer,
        code:           popupResult.code,
        codeVerifier:   verifier,
        redirectUri:    redirectUri ?? window.location.origin,
        publishableKey,
        dpopKeyPair:    keyPair,
      })

      // Persist in the exact slots HeadloProviderV2 reads on mount: sessionStorage
      // for the token, localStorage for the user profile. storageKey is unset for
      // single-pk consumers so the unsuffixed base keys apply.
      sessionStorage.setItem('headlo_auth_v2_token', tokenRes.access_token)

      let signedInUser: DiscoveredUser | null = null
      try {
        const [, payloadB64] = tokenRes.access_token.split('.')
        if (payloadB64) {
          const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/'))) as { sub?: string; email?: string; name?: string }
          if (payload.sub && payload.email) {
            localStorage.setItem('headlo_auth_user', JSON.stringify({ id: payload.sub, email: payload.email, displayName: payload.name ?? null }))
            signedInUser = { headloUserId: payload.sub, email: payload.email, displayName: payload.name ?? null, avatarUrl: null }
            // Also refresh the discover-cache so the next visit's cached
            // paint matches reality. Without this, signing in as a different
            // account via the popup leaves `headlo_user_cache` pointing at
            // whoever previously signed in — the modal flashes the stale
            // name for one iframe round-trip before repainting.
            writeCachedProfile(publishableKey, signedInUser)
          }
        }
      } catch { /* non-fatal */ }

      clearStoredPkceState()

      // Default onSuccess behavior = reload the page so HeadloProviderV2 picks
      // up the fresh token on mount. Return `false` from the hook to opt out.
      let shouldReload: boolean = true
      if (onSuccess && signedInUser) {
        const r = await onSuccess(signedInUser)
        if (r === false) shouldReload = false
      }
      if (shouldReload) window.location.reload()
    } catch (e) {
      clearStoredPkceState()
      let message = String(e)
      let retryable = true
      if      (e instanceof PopupBlockedError)    { message = 'Your browser blocked the sign-in popup. Enable popups for this site, or try again.' }
      else if (e instanceof UserClosedPopupError) { message = 'Sign-in was cancelled. Click Continue to try again.' }
      else if (e instanceof PopupTimeoutError)    { message = 'Sign-in timed out. Click Continue to try again.' }
      else if (e instanceof AuthServerError)      {
        message = `Could not sign you in (${e.code}). ${e.code === 'step_up_required' ? 'Verify your identity to continue.' : ''}`
        retryable = e.code !== 'login_required'
      }
      setPhase({ kind: 'error', message, retryable })
    }
  }

  if (open === false) return null

  // ── Styling — scoped inline so the component ships with zero CSS imports.
  // Headlo brand: cream background, dark text, teal (#5dcaa5) accent.
  const S = {
    backdrop: {
      position: 'fixed' as const, inset: 0, background: 'rgba(26,26,24,0.55)',
      display: 'flex' as const, alignItems: 'flex-end' as const, justifyContent: 'center' as const,
      zIndex: 9999, padding: 16,
      // bottom-sheet feel on mobile; centered card on desktop
    },
    card: {
      background: '#faf9f6', border: '1px solid #e8e5df', borderRadius: 16,
      width: '100%', maxWidth: 420, padding: '28px 24px 24px',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
      color: '#1a1a18', boxShadow: '0 8px 24px rgba(0,0,0,0.18)',
      marginBottom: 'min(10vh, 60px)',
    },
    header: {
      display: 'flex' as const, alignItems: 'center' as const, justifyContent: 'space-between' as const,
      marginBottom: 16,
    },
    logo:  { fontSize: 15, fontWeight: 800, letterSpacing: '-0.3px' as const },
    logoAccent: { color: '#5dcaa5' },
    closeBtn: {
      background: 'none', border: 'none', fontSize: 20, cursor: 'pointer' as const,
      color: '#8a8a80', padding: 4, lineHeight: 1,
    },
    avatarRow: {
      display: 'flex' as const, alignItems: 'center' as const, gap: 12,
      padding: '12px 14px', background: '#fff', border: '1px solid #e8e5df',
      borderRadius: 10, marginBottom: 14,
    },
    avatar: {
      width: 36, height: 36, borderRadius: '50%',
      background: '#5dcaa5', color: '#fff', fontSize: 15, fontWeight: 700,
      display: 'flex' as const, alignItems: 'center' as const, justifyContent: 'center' as const,
      flexShrink: 0 as const,
    },
    userMeta: { display: 'flex' as const, flexDirection: 'column' as const, minWidth: 0 },
    userName: { fontSize: 14, fontWeight: 600, overflow: 'hidden' as const, textOverflow: 'ellipsis' as const, whiteSpace: 'nowrap' as const },
    userEmail: { fontSize: 12, color: '#8a8a80', overflow: 'hidden' as const, textOverflow: 'ellipsis' as const, whiteSpace: 'nowrap' as const },
    heading: { fontSize: 18, fontWeight: 700, marginBottom: 6, lineHeight: 1.3 },
    sub: { fontSize: 13, color: '#6a6a62', marginBottom: 18, lineHeight: 1.4 },
    // SSO Wave 2 B.9 follow-up — first-grant disclosure line above the CTA.
    firstGrantNote: {
      fontSize: 12, color: '#5a5a52', marginBottom: 12, lineHeight: 1.4,
      background: '#f8f6f0', border: '1px solid #e8e5df', borderRadius: 8,
      padding: '8px 10px',
    } as React.CSSProperties,
    btnPrimary: {
      width: '100%', padding: '12px 16px', background: '#1a1a18', color: '#fff',
      border: 'none', borderRadius: 10, fontSize: 14, fontWeight: 700,
      cursor: 'pointer' as const, marginBottom: 8, fontFamily: 'inherit',
    },
    btnLink: {
      width: '100%', padding: '10px 12px', background: 'transparent', color: '#1a1a18',
      border: 'none', fontSize: 13, fontWeight: 500, cursor: 'pointer' as const,
      textDecoration: 'underline' as const, fontFamily: 'inherit',
    },
    footer: {
      fontSize: 11, color: '#8a8a80', textAlign: 'center' as const, marginTop: 16,
      paddingTop: 14, borderTop: '1px solid #e8e5df',
    },
    err: {
      background: '#fef2f2', border: '1px solid #fecaca', color: '#991b1b',
      borderRadius: 8, padding: '10px 12px', fontSize: 13, marginBottom: 12,
    },
    spinner: {
      display: 'inline-block', width: 14, height: 14, border: '2px solid rgba(255,255,255,0.3)',
      borderTopColor: '#fff', borderRadius: '50%', marginRight: 8,
      animation: 'headlo-spin 0.7s linear infinite',
    },
  }

  const initials = (name: string | null, email: string): string => {
    const base = (name ?? email).trim()
    if (!base) return '?'
    const parts = base.split(/\s+/)
    if (parts.length >= 2) return (parts[0]![0]! + parts[1]![0]!).toUpperCase()
    return base.slice(0, 2).toUpperCase()
  }

  function renderBody(): React.ReactNode {
    if (phase.kind === 'discovering') {
      return (
        <>
          <div style={S.heading}>Checking for your Headlo session…</div>
          <div style={S.sub}>One moment.</div>
        </>
      )
    }
    if (phase.kind === 'anonymous') {
      return (
        <>
          <div style={S.heading}>Sign in with Headlo</div>
          <div style={S.sub}>Use your Headlo account to continue — one identity across every merchant.</div>
          <button style={S.btnPrimary} onClick={() => void runSignIn('anonymous')}>Sign in →</button>
        </>
      )
    }
    if (phase.kind === 'returning-user') {
      const { user } = phase
      // SSO Wave 2 B.9 follow-up — first-grant disclosure. consentGranted
      // tri-state: undefined (painting from cache; stay quiet, revalidation
      // will fill in), false (never granted — show the "merchant will see
      // your email + name" line), true (returning visit — just the short CTA).
      const firstGrant = phase.consentGranted === false
      return (
        <>
          <div style={S.avatarRow}>
            {user.avatarUrl
              ? <img src={user.avatarUrl} alt="" style={{ width: 36, height: 36, borderRadius: '50%', flexShrink: 0 }} />
              : <div style={S.avatar}>{initials(user.displayName, user.email)}</div>}
            <div style={S.userMeta}>
              <div style={S.userName}>{user.displayName ?? user.email}</div>
              {user.displayName && <div style={S.userEmail}>{user.email}</div>}
            </div>
          </div>
          {firstGrant && (
            <div style={S.firstGrantNote}>
              This site will see your email{user.displayName ? ' and name' : ''}.
            </div>
          )}
          <button style={S.btnPrimary} onClick={() => void runSignIn('continue')}>
            Continue as {user.displayName ?? user.email.split('@')[0]} →
          </button>
          <button style={S.btnLink} onClick={() => void runSignIn('different', user.email)}>
            Use a different account
          </button>
        </>
      )
    }
    if (phase.kind === 'signing-in') {
      const label = phase.variant === 'different' ? 'Opening sign-in form…' : 'Signing you in…'
      return (
        <>
          <div style={S.heading}>{label}</div>
          <div style={S.sub}>Complete the sign-in in the popup window.</div>
          <button style={{ ...S.btnPrimary, opacity: 0.6, cursor: 'default' }} disabled>
            <span style={S.spinner} />
            Working…
          </button>
        </>
      )
    }
    // phase.kind === 'error'
    return (
      <>
        <div style={S.err}>{phase.message}</div>
        {phase.retryable && (
          <button style={S.btnPrimary} onClick={() => setPhase({ kind: 'discovering' })}>Try again</button>
        )}
      </>
    )
  }

  return (
    <div style={S.backdrop} onClick={(e) => { if (e.target === e.currentTarget && onCancel) onCancel() }}>
      <style>{`@keyframes headlo-spin { to { transform: rotate(360deg) } }`}</style>
      <div style={S.card} role="dialog" aria-modal="true" aria-labelledby="headlo-continue-as-heading">
        <div style={S.header}>
          <div style={S.logo}>headlo<span style={S.logoAccent}>.</span></div>
          {onCancel && (
            <button style={S.closeBtn} onClick={onCancel} aria-label="Close">×</button>
          )}
        </div>
        {renderBody()}
        <div style={S.footer}>Secured by Headlo Auth · one identity across every merchant</div>
      </div>
    </div>
  )
}

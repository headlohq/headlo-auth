// SSO Wave 4 B.11 — Sign in with Apple.
//
// Drop-in React component that renders a "Continue with Apple" button,
// pops Apple's AppleID.auth.signIn flow, and exchanges the resulting
// id_token at `${issuer}/oauth/token/apple-federated` for a Headlo
// DPoP-bound access token.
//
// Composition with the rest of the SSO surfaces:
//   - Click-triggered. Unlike Google One Tap, Apple does not offer a
//     browser-level auto-prompt — the user always taps the button.
//   - Mounts alongside <GoogleOneTap /> inside a <HeadloProviderV2>.
//     B.12's multi-provider menu will stack these two + the password form
//     in one card.
//
// Full plan: claude/headlo-sso-shop-equivalent.md § B.11.
// Server: POST /oauth/token/apple-federated  (headlo-worker/src/routes/oauth.ts)

import React from 'react'
import { getOrCreateKeyPair, exportPublicJwk, computeJwkThumbprint, signDpopProof } from './dpop'
import { writeCachedProfile } from './discover'
import { resolveIssuer } from './pk'

// Minimal typing for the AppleID.auth surface we touch. The real SDK has
// many more fields; we declare only what we use so this file compiles
// without pulling @types/apple-signin-auth.
interface AppleAuthorization {
  code:      string
  id_token:  string
  state?:    string
}
interface AppleUserPayload {
  // Apple sends this exactly once — on the user's first consent for the
  // Services ID. Returned at the TOP LEVEL of the signIn result, NOT nested
  // in the id_token. The server-side handler persists this on first INSERT.
  name?: { firstName?: string | null; lastName?: string | null }
  email?: string
}
interface AppleSignInResponse {
  authorization: AppleAuthorization
  user?:         AppleUserPayload
}
interface AppleAuthService {
  init(opts: {
    clientId:    string          // the Apple Services ID
    scope:       string          // 'name email'
    redirectURI: string          // must be registered in Apple Developer portal
    state?:      string
    nonce?:      string
    usePopup:    boolean
  }): void
  signIn(opts?: { nonce?: string; state?: string }): Promise<AppleSignInResponse>
}
declare global {
  interface Window {
    AppleID?: { auth?: AppleAuthService }
  }
}

export interface HeadloAppleSignInProps {
  /** OIDC issuer base — e.g. `https://auth.headlo.com`. Optional for encoded pks (B.6). */
  issuer?:         string
  /** pk_live_… or pk_test_… — your Headlo publishable key */
  publishableKey:  string
  /**
   * Button label. Defaults to "Continue with Apple". Pass children for a
   * custom label; both work.
   */
  children?:       React.ReactNode
  label?:          string
  /** Called after the token is written. Return `false` to suppress the default reload. */
  onSuccess?:      (info: { email: string; name: string | null; sub: string }) => void | false | Promise<void | false>
  /** Called on any failure path — invalid token, origin not allowed, user cancelled. */
  onError?:        (code: string) => void
  /** Default true — mints a DPoP-bound token in one round-trip (Option A). */
  bindDpop?:       boolean
  /** Inline style for the button; defaults to Apple's black pill. */
  style?:          React.CSSProperties
  className?:      string
}

const APPLE_SCRIPT_SRC = 'https://appleid.cdn-apple.com/appleauth/static/jsapi/appleid/1/en_US/appleid.auth.js'
let appleLoadPromise: Promise<void> | null = null

function loadAppleJs(): Promise<void> {
  if (typeof window === 'undefined') return Promise.reject(new Error('SSR_NO_WINDOW'))
  if (window.AppleID?.auth) return Promise.resolve()
  if (appleLoadPromise) return appleLoadPromise
  appleLoadPromise = new Promise<void>((resolve, reject) => {
    const existing = document.querySelector<HTMLScriptElement>(`script[src="${APPLE_SCRIPT_SRC}"]`)
    if (existing) {
      // Already loading — poll briefly for the global.
      const start = Date.now()
      const poll = () => {
        if (window.AppleID?.auth) return resolve()
        if (Date.now() - start > 5000) return reject(new Error('APPLE_LOAD_TIMEOUT'))
        setTimeout(poll, 50)
      }
      poll()
      return
    }
    const script = document.createElement('script')
    script.src = APPLE_SCRIPT_SRC
    script.async = true
    script.defer = true
    script.onload = () => {
      if (window.AppleID?.auth) resolve()
      else reject(new Error('APPLE_LOADED_BUT_NO_GLOBAL'))
    }
    script.onerror = () => reject(new Error('APPLE_SCRIPT_LOAD_FAILED'))
    document.head.appendChild(script)
  })
  return appleLoadPromise
}

interface OidcDiscovery {
  'headlo:apple_services_id'?: string | null
}
const discoveryCache = new Map<string, Promise<OidcDiscovery>>()
function fetchDiscovery(issuer: string): Promise<OidcDiscovery> {
  const cached = discoveryCache.get(issuer)
  if (cached) return cached
  const p = fetch(`${issuer}/.well-known/openid-configuration`)
    .then(r => r.json() as Promise<OidcDiscovery>)
    .catch(e => { discoveryCache.delete(issuer); throw e })
  discoveryCache.set(issuer, p)
  return p
}

/**
 * `<HeadloAppleSignIn>` — renders a "Continue with Apple" button that
 * pops Apple's auth popup and exchanges the resulting id_token for a
 * Headlo DPoP-bound access token at `/oauth/token/apple-federated`.
 *
 * ```tsx
 * <HeadloAppleSignIn issuer="https://auth.headlo.com" publishableKey={pk} />
 * ```
 *
 * Zero merchant setup — the Apple Services ID is advertised in the issuer's
 * `/.well-known/openid-configuration` and fetched automatically.
 */
export function HeadloAppleSignIn(props: HeadloAppleSignInProps): React.ReactElement {
  const { publishableKey, onSuccess, onError, bindDpop = true, style, className } = props
  const issuer = React.useMemo(() => resolveIssuer(publishableKey, props.issuer), [publishableKey, props.issuer])

  const [loading, setLoading] = React.useState(false)
  const didInitRef = React.useRef(false)

  async function handleClick() {
    if (loading) return
    setLoading(true)
    const t0 = Date.now()
    try {
      const discovery = await fetchDiscovery(issuer)
      const servicesId = discovery['headlo:apple_services_id']
      if (!servicesId) {
        console.log('[headlo-apple-signin] Apple sign-in not configured on this issuer')
        onError?.('APPLE_NOT_CONFIGURED')
        return
      }
      await loadAppleJs()
      const auth = window.AppleID!.auth!

      if (!didInitRef.current) {
        auth.init({
          clientId:    servicesId,
          scope:       'name email',
          // Apple requires a registered redirectURI even when usePopup=true;
          // the current origin + root path is the common pattern. The popup
          // posts the result back via window.opener.postMessage, so the
          // redirectURI is never actually navigated to in the happy path.
          redirectURI: `${window.location.origin}/`,
          usePopup:    true,
        })
        didInitRef.current = true
      }

      console.log('[headlo-apple-signin] 🔵 opening Apple popup')
      const result = await auth.signIn()
      console.log('[headlo-apple-signin] 🟢 Apple returned', { hasUser: !!result.user, hasName: !!result.user?.name })

      // Option A — pre-generate DPoP keypair + proof, send in one shot.
      const endpoint = `${issuer}/oauth/token/apple-federated`
      const headers: Record<string, string> = { 'Content-Type': 'application/json' }
      let dpopJkt: string | null = null
      if (bindDpop) {
        const kp = await getOrCreateKeyPair(publishableKey)
        const jwk = await exportPublicJwk(kp)
        dpopJkt   = await computeJwkThumbprint(jwk)
        headers.DPoP = await signDpopProof(kp, { url: endpoint, method: 'POST' })
      }

      const res = await fetch(endpoint, {
        method:      'POST',
        credentials: 'include',
        headers,
        body: JSON.stringify({
          id_token:   result.authorization.id_token,
          client_id:  publishableKey,
          apple_user: result.user?.name
            ? { firstName: result.user.name.firstName ?? null, lastName: result.user.name.lastName ?? null }
            : null,
          ...(dpopJkt ? { dpop_jkt: dpopJkt } : {}),
        }),
      })

      if (!res.ok) {
        const text = await res.text().catch(() => '')
        let code = 'APPLE_EXCHANGE_FAILED'
        try { code = (JSON.parse(text) as { error?: string }).error ?? code } catch { /* non-JSON */ }
        console.log('[headlo-apple-signin] ❌ exchange failed', { status: res.status, code })
        onError?.(code)
        return
      }

      const tokenRes = await res.json() as { access_token: string; token_type: 'Bearer' | 'DPoP'; expires_in: number }
      sessionStorage.setItem('headlo_auth_v2_token', tokenRes.access_token)

      // Same two-cache sync as Google One Tap so ContinueAsModal paints
      // instantly on next visit.
      let signedInInfo: { email: string; name: string | null; sub: string } | null = null
      try {
        const [, payloadB64] = tokenRes.access_token.split('.')
        if (payloadB64) {
          const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/'))) as { sub?: string; email?: string; name?: string }
          if (payload.sub && payload.email) {
            localStorage.setItem('headlo_auth_user', JSON.stringify({ id: payload.sub, email: payload.email, displayName: payload.name ?? null }))
            writeCachedProfile(publishableKey, {
              headloUserId: payload.sub,
              email:        payload.email,
              displayName:  payload.name ?? null,
              avatarUrl:    null,
            })
            signedInInfo = { sub: payload.sub, email: payload.email, name: payload.name ?? null }
          }
        }
      } catch { /* non-fatal */ }

      console.log(`[headlo-apple-signin] ✅ signed in — token_type=${tokenRes.token_type} totalMs=${Date.now() - t0}`)

      let shouldReload = true
      if (onSuccess && signedInInfo) {
        const r = await onSuccess(signedInInfo)
        if (r === false) shouldReload = false
      }
      if (shouldReload) window.location.reload()
    } catch (e) {
      // Apple's signIn promise rejects on user-cancel too. Distinguish by
      // checking the thrown shape — Apple returns { error: 'popup_closed_by_user' }.
      const errMsg = e && typeof e === 'object' && 'error' in e
        ? String((e as { error: unknown }).error)
        : String(e)
      console.log('[headlo-apple-signin] 💥 flow failed', errMsg)
      onError?.(errMsg)
    } finally {
      setLoading(false)
    }
  }

  const defaultStyle: React.CSSProperties = {
    display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: 8,
    width: '100%', padding: '11px 14px', borderRadius: 10, border: '1px solid #000',
    background: '#000', color: '#fff', fontSize: 14, fontWeight: 600, cursor: 'pointer',
    fontFamily: 'inherit', opacity: loading ? 0.7 : 1,
  }

  return (
    <button
      type="button"
      onClick={() => void handleClick()}
      disabled={loading}
      style={{ ...defaultStyle, ...style }}
      className={className}
      aria-label="Continue with Apple"
    >
      {/* Apple logo (SVG, inline so no external asset). Approved mark. */}
      <svg width="14" height="14" viewBox="0 0 384 512" fill="currentColor" aria-hidden="true">
        <path d="M318.7 268.7c-.2-36.7 16.4-64.4 50-84.8-18.8-26.9-47.2-41.7-84.7-44.6-35.5-2.8-74.3 20.7-88.5 20.7-15 0-49.4-19.7-76.4-19.7C63.3 141.2 4 184.8 4 273.5q0 39.3 14.4 81.2c12.8 36.7 59 126.7 107.2 125.2 25.2-.6 43-17.9 75.8-17.9 31.8 0 48.3 17.9 76.4 17.9 48.6-.7 90.4-82.5 102.6-119.3-65.2-30.7-61.7-90-61.7-91.9zm-56.6-164.2c27.3-32.4 24.8-61.9 24-72.5-24.1 1.4-52 16.4-67.9 34.9-17.5 19.8-27.8 44.3-25.6 71.9 26.1 2 49.9-11.4 69.5-34.3z"/>
      </svg>
      {props.children ?? props.label ?? (loading ? 'Signing in…' : 'Continue with Apple')}
    </button>
  )
}

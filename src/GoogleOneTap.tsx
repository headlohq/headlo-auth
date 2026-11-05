// SSO Wave 4 B.10 — Google One Tap.
//
// Drop-in React component that shows Chrome's Google-account-chooser bubble
// (One Tap / FedCM, depending on browser) and signs the user in to Headlo
// via a single credential exchange — no popup, no redirect, no form.
//
// Composition with the rest of the SSO surfaces:
//   - <ContinueAsModal /> recognizes returning users via Headlo's own
//     session cookie (fails on brand-new browser profiles).
//   - <GoogleOneTap /> recognizes returning users via Google's browser-
//     level state — survives private-browsing resets, 3PC blocking, new
//     installs. "Almost always recognized before they ever click."
//   - Both can be mounted together; whichever surfaces first wins.
//
// Full plan: claude/headlo-sso-shop-equivalent.md § B.10.
// Server: POST /oauth/google/one-tap  (headlo-worker/src/routes/oauth.ts)

import React from 'react'
import { getOrCreateKeyPair, exportPublicJwk, computeJwkThumbprint, signDpopProof } from './dpop'
import { writeCachedProfile } from './discover'
import { resolveIssuer } from './pk'

// Minimal typing for the google.accounts.id surface we touch. The real GIS
// SDK has many more fields; we only declare what we use so this file
// compiles without pulling @types/google.accounts.
interface GoogleCredentialResponse {
  credential:    string
  select_by?:    string
  clientId?:     string
}
interface PromptMomentNotification {
  isNotDisplayed?():          boolean
  isSkippedMoment?():         boolean
  isDismissedMoment?():       boolean
  getNotDisplayedReason?():   string   // 'browser_not_supported' | 'invalid_client' | 'missing_client_id' | 'opt_out_or_no_session' | 'secure_http_required' | 'suppressed_by_user' | 'unregistered_origin' | 'unknown_reason'
  getSkippedReason?():        string   // 'auto_cancel' | 'user_cancel' | 'tap_outside' | 'issuing_failed'
  getDismissedReason?():      string   // 'credential_returned' | 'cancel_called' | 'flow_restarted'
  getMomentType?():           string   // 'display' | 'skipped' | 'dismissed'
}
interface GoogleIdService {
  initialize(opts: {
    client_id:                string
    callback:                 (resp: GoogleCredentialResponse) => void
    auto_select?:             boolean
    cancel_on_tap_outside?:   boolean
    use_fedcm_for_prompt?:    boolean
    context?:                 'signin' | 'signup' | 'use'
    ux_mode?:                 'popup' | 'redirect'
    itp_support?:             boolean
  }): void
  prompt(callback?: (notification: PromptMomentNotification) => void): void
  cancel(): void
  disableAutoSelect(): void
}
declare global {
  interface Window {
    google?: { accounts?: { id?: GoogleIdService } }
  }
}

export interface GoogleOneTapProps {
  /**
   * OIDC issuer base — e.g. `https://auth.headlo.com`.
   *
   * Optional when `publishableKey` is an encoded pk (Wave 4 B.6) — the SDK
   * derives the issuer from the pk's embedded hostname.
   */
  issuer?:         string
  /** pk_live_… or pk_test_… — your Headlo publishable key (raw-hex or encoded) */
  publishableKey:  string
  /**
   * Fires AFTER the token has been written to sessionStorage + localStorage.
   * Return `false` to suppress the default `window.location.reload()`.
   * Omit for the default behavior (reload so HeadloProviderV2 rehydrates).
   */
  onSuccess?:      (info: { email: string; name: string | null; sub: string }) => void | false | Promise<void | false>
  /**
   * Fires on any failure path — credential verification rejected by server,
   * password-account conflict (ACCOUNT_EXISTS_UNVERIFIED), network error.
   * Default behavior on error: no reload, no state change — merchant decides
   * whether to show an error banner or fall back to the popup flow.
   */
  onError?:        (code: string) => void
  /**
   * Auto-prompt on mount vs wait for an explicit `google.accounts.id.prompt()`
   * call. Default `true` — the whole point of One Tap is the auto-prompt.
   * Set `false` when the merchant wants to render a custom button + prompt
   * programmatically (future extension).
   */
  autoPrompt?:     boolean
  /**
   * When true, request a DPoP-bound token from the server (sends dpop_jkt +
   * a DPoP proof — same Option A pattern as the popup flow). The resulting
   * token carries `cnf.jkt`, participates in `/oauth/token/refresh-dpop`,
   * and survives A.5.1 enforcement. Default `true`.
   *
   * Set `false` for a legacy Bearer token + refresh cookie flow — only
   * useful if the enclosing app is still on HeadloProvider v1.
   */
  bindDpop?:       boolean
}

const GSI_SCRIPT_SRC = 'https://accounts.google.com/gsi/client'
let gsiLoadPromise: Promise<void> | null = null

/**
 * Load Google Identity Services script exactly once per page. Subsequent
 * calls return the same promise. Resolves when `window.google.accounts.id`
 * is ready to use.
 */
function loadGsi(): Promise<void> {
  if (typeof window === 'undefined') return Promise.reject(new Error('SSR_NO_WINDOW'))
  if (window.google?.accounts?.id) return Promise.resolve()
  if (gsiLoadPromise) return gsiLoadPromise
  gsiLoadPromise = new Promise<void>((resolve, reject) => {
    const existing = document.querySelector<HTMLScriptElement>(`script[src="${GSI_SCRIPT_SRC}"]`)
    if (existing) {
      // Someone else loaded it — poll briefly for the global.
      const start = Date.now()
      const poll = () => {
        if (window.google?.accounts?.id) return resolve()
        if (Date.now() - start > 5000) return reject(new Error('GSI_LOAD_TIMEOUT'))
        setTimeout(poll, 50)
      }
      poll()
      return
    }
    const script = document.createElement('script')
    script.src = GSI_SCRIPT_SRC
    script.async = true
    script.defer = true
    script.onload = () => {
      if (window.google?.accounts?.id) resolve()
      else reject(new Error('GSI_LOADED_BUT_NO_GLOBAL'))
    }
    script.onerror = () => reject(new Error('GSI_SCRIPT_LOAD_FAILED'))
    document.head.appendChild(script)
  })
  return gsiLoadPromise
}

interface OidcDiscovery {
  'headlo:google_client_id'?:        string | null
  'headlo:google_one_tap_endpoint'?: string
}

// Discovery doc cache — per issuer, in-memory, survives the tab's lifetime.
// We only read two fields; Google client ID changes are rare and would
// require a page reload anyway (GIS can't re-initialize with a different id).
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
 * `<GoogleOneTap>` — mounts the GIS SDK, auto-prompts the account chooser,
 * exchanges the resulting credential at `${issuer}/oauth/google/one-tap`.
 * Renders nothing — the chooser UI is Chrome-native, not a React element.
 *
 * ```tsx
 * <GoogleOneTap issuer="https://auth.headlo.com" publishableKey={pk} />
 * ```
 *
 * Mount it once near the root of your app. The GIS script loads once per
 * page; mounting multiple times is wasteful but harmless.
 */
export function GoogleOneTap(props: GoogleOneTapProps): React.ReactElement | null {
  const { publishableKey, onSuccess, onError, autoPrompt = true, bindDpop = true } = props
  const issuer = React.useMemo(() => resolveIssuer(publishableKey, props.issuer), [publishableKey, props.issuer])

  // One-shot guard — the GIS SDK is a singleton on `window`, so even in
  // StrictMode's dev double-mount we only initialize + prompt once.
  const didInitRef = React.useRef(false)

  React.useEffect(() => {
    if (didInitRef.current) return
    didInitRef.current = true

    void (async () => {
      try {
        const discovery = await fetchDiscovery(issuer)
        const googleClientId = discovery['headlo:google_client_id']
        const endpoint       = discovery['headlo:google_one_tap_endpoint'] ?? `${issuer}/oauth/google/one-tap`
        if (!googleClientId) {
          console.log('[headlo-one-tap] Google sign-in not configured on this issuer — skipping')
          return
        }

        await loadGsi()
        const gsi = window.google!.accounts!.id!

        gsi.initialize({
          client_id:              googleClientId,
          callback:               (resp) => { void handleCredential(resp) },
          auto_select:            true,          // Sign in silently when user has only one Google account AND prior consent
          cancel_on_tap_outside:  false,         // Keep the bubble sticky; dismissing is cheap, re-prompting isn't
          itp_support:            true,          // Enable Safari ITP workarounds built into GIS
          use_fedcm_for_prompt:   true,          // Prefer the browser-native FedCM UI when available (Chrome 128+)
          context:                'signin',
        })

        if (autoPrompt) {
          console.log('[headlo-one-tap] 🔵 prompting Google account chooser')
          // The notification callback is Google's only way to tell us WHY
          // the prompt didn't display (cooldown, no Google session, user
          // opted out, origin not registered, …). Without it, "nothing
          // happened" looks indistinguishable from a bug — browsers like
          // Chrome rate-limit the prompt per-origin for ~24h after a prior
          // interaction, and users can't tell that from "the SDK is broken."
          gsi.prompt((n) => {
            try {
              const kind = n.getMomentType?.()
              if (n.isNotDisplayed?.()) {
                const reason = n.getNotDisplayedReason?.() ?? 'unknown'
                console.log(`[headlo-one-tap] ⚠️  prompt NOT DISPLAYED — reason=${reason}`,
                  reason === 'suppressed_by_user'   ? '(Chrome one-tap cooldown — ~24h per origin after prior interaction; use Incognito or clear browser data to test again)' :
                  reason === 'opt_out_or_no_session' ? '(user not signed into Google OR has opted out of One Tap for this origin)' :
                  reason === 'unregistered_origin'  ? '(the Google OAuth client_id does not list this origin as an authorized JS origin — fix in Google Cloud Console)' :
                  reason === 'secure_http_required' ? '(One Tap requires HTTPS; localhost is exempt but 127.0.0.1 may not be depending on Chrome version)' :
                  reason === 'browser_not_supported' ? '(this browser does not support One Tap at all)' :
                  '')
              } else if (n.isSkippedMoment?.()) {
                console.log(`[headlo-one-tap] ⚠️  prompt SKIPPED — reason=${n.getSkippedReason?.() ?? 'unknown'}`,
                  '(user dismissed the bubble; subsequent prompts on this origin will be suppressed for a cooldown period)')
              } else if (n.isDismissedMoment?.()) {
                console.log(`[headlo-one-tap] ✓ prompt DISMISSED — reason=${n.getDismissedReason?.() ?? 'unknown'}`,
                  '(usually credential_returned — the auth flow is proceeding)')
              } else {
                console.log('[headlo-one-tap] prompt moment', { kind })
              }
            } catch { /* non-fatal */ }
          })
        }
      } catch (e) {
        console.log('[headlo-one-tap] init failed', e)
        onError?.(String(e))
      }
    })()

    async function handleCredential(resp: GoogleCredentialResponse): Promise<void> {
      const t0 = Date.now()
      console.log('[headlo-one-tap] 🟢 credential received', { select_by: resp.select_by })

      try {
        const discovery = await fetchDiscovery(issuer)
        const endpoint  = discovery['headlo:google_one_tap_endpoint'] ?? `${issuer}/oauth/google/one-tap`

        // Option A path — pre-generate the DPoP keypair, pass the thumbprint,
        // send a DPoP proof on the exchange so the server mints a cnf.jkt-
        // bound token in one shot. Same pattern as popup + handshake.
        let keyPair: CryptoKeyPair | null = null
        let dpopJkt:  string      | null = null
        const headers: Record<string, string> = { 'Content-Type': 'application/json' }
        if (bindDpop) {
          keyPair = await getOrCreateKeyPair(publishableKey)
          const jwk = await exportPublicJwk(keyPair)
          dpopJkt   = await computeJwkThumbprint(jwk)
          headers.DPoP = await signDpopProof(keyPair, { url: endpoint, method: 'POST' })
        }

        const res = await fetch(endpoint, {
          method:      'POST',
          credentials: 'include',   // session cookie Set-Cookie from server
          headers,
          body: JSON.stringify({
            id_token:  resp.credential,
            client_id: publishableKey,
            ...(dpopJkt ? { dpop_jkt: dpopJkt } : {}),
          }),
        })
        if (!res.ok) {
          const text = await res.text().catch(() => '')
          let code = 'ONE_TAP_EXCHANGE_FAILED'
          try { code = (JSON.parse(text) as { error?: string }).error ?? code } catch { /* non-JSON */ }
          console.log('[headlo-one-tap] ❌ exchange failed', { status: res.status, code })
          onError?.(code)
          return
        }

        const tokenRes = await res.json() as { access_token: string; token_type: 'Bearer' | 'DPoP'; expires_in: number }
        sessionStorage.setItem('headlo_auth_v2_token', tokenRes.access_token)

        // Decode payload for the shared user cache + the discover cache so
        // ContinueAsModal paints correctly on next visit (same two-cache sync
        // we do on the popup path).
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

        console.log(`[headlo-one-tap] ✅ signed in — token_type=${tokenRes.token_type} totalMs=${Date.now() - t0}`)

        let shouldReload = true
        if (onSuccess && signedInInfo) {
          const r = await onSuccess(signedInInfo)
          if (r === false) shouldReload = false
        }
        if (shouldReload) window.location.reload()
      } catch (e) {
        console.log('[headlo-one-tap] 💥 credential handler threw', e)
        onError?.(String(e))
      }
    }
  }, [issuer, publishableKey, autoPrompt, bindDpop, onSuccess, onError])

  return null
}

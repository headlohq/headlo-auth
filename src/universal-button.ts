// SSO Wave 4 B.7 — Universal install script.
//
// Compiles via tsup.runtime.config.ts to dist/runtime/universal-button.global.js.
// Served by the worker at auth.headlo.com/button.js. Merchants paste ONE line:
//
//   <script src="https://auth.headlo.com/button.js"
//           data-pk="pk_live_YOUR_ENCODED_KEY"></script>
//
// Zero React, zero bundler, zero config beyond the pk. The pk is encoded
// (Wave 4 B.6) so the SDK derives the issuer from it — no `data-issuer`
// attribute needed.
//
// What the script does on load:
//   1. Reads data-pk + optional data-mode / data-position / data-theme from
//      its own <script> tag.
//   2. Decodes the pk → issuer URL.
//   3. Mounts Google One Tap (Chrome account chooser) — zero DOM required,
//      the UI is Chrome-native.
//   4. Renders a floating "Sign in with Headlo" button (fallback when the
//      user has no Google session OR Chrome's One Tap cooldown is active).
//   5. On successful sign-in: writes token to sessionStorage + caches to
//      localStorage + reloads so merchant-side auth libraries pick it up.
//
// Non-goals in v1:
//   - Vanilla port of the full ContinueAsModal (returning-user cached paint).
//     That requires more DOM scaffolding; defer to v2.
//   - data-mode="redirect" standalone — the button's popup fallback already
//     handles the "non-Google" case.
//   - Framework-specific wrappers (<headlo-auth-button> custom element) —
//     separate ship.
//
// Full plan: claude/headlo-sso-shop-equivalent.md § B.7.

import { decodePublishableKey } from './pk'
import { signInViaPopup, exchangeAuthCodeDpop, readStoredPkceVerifier, clearStoredPkceState, PopupBlockedError, UserClosedPopupError, PopupTimeoutError, AuthServerError } from './signInPopup'
import { getOrCreateKeyPair, exportPublicJwk, computeJwkThumbprint, signDpopProof } from './dpop'
import { writeCachedProfile, type DiscoveredUser } from './discover'

// ─── Script-tag attribute reading ────────────────────────────────────────

interface ScriptConfig {
  pk:         string
  issuer:     string
  mode:       'auto' | 'button' | 'one-tap' | 'none'
  position:   'bottom-right' | 'bottom-left' | 'top-right' | 'top-left'
  theme:      'auto' | 'light' | 'dark'
  onSuccess:  'reload' | 'none'
  /** Test-only: bypass the "already-signed-in short-circuit" so the UI mounts even when a fresh sessionStorage token exists. For the /abs-test harness; merchants should never use this. */
  forceMount: boolean
}

function readScriptConfig(): ScriptConfig | null {
  // Find the script tag that loaded this bundle. Prefer currentScript (works
  // for sync + non-async loads); fall back to a querySelector matching any
  // script whose src looks like our bundle (covers async / defer loads where
  // currentScript is null by the time the IIFE runs).
  const el = (document.currentScript as HTMLScriptElement | null)
    ?? document.querySelector<HTMLScriptElement>('script[data-pk][src*="button.js"]')
    ?? document.querySelector<HTMLScriptElement>('script[data-headlo-pk]')
  if (!el) {
    console.log('[headlo-button] ⚠️ could not locate the <script> tag — set data-pk on it OR add a plain `script[data-headlo-pk]` tag')
    return null
  }

  const pk = (el.getAttribute('data-pk') ?? el.getAttribute('data-headlo-pk') ?? '').trim()
  if (!pk) {
    console.log('[headlo-button] ⚠️ missing data-pk attribute on the <script> tag')
    return null
  }

  const decoded = decodePublishableKey(pk)
  const issuer = decoded.issuer
  if (!issuer) {
    console.log('[headlo-button] ⚠️ pk is legacy raw-hex form — explicit data-issuer required for legacy pks (or mint a new encoded pk via the dashboard)', { pk })
    return null
  }

  const mode = ((el.getAttribute('data-mode') ?? 'auto').toLowerCase())
  const position = ((el.getAttribute('data-position') ?? 'bottom-right').toLowerCase())
  const theme = ((el.getAttribute('data-theme') ?? 'auto').toLowerCase())
  const onSuccess = ((el.getAttribute('data-on-success') ?? 'reload').toLowerCase())
  const forceMount = el.getAttribute('data-force-mount') === '1'

  return {
    pk,
    issuer,
    mode:      (['auto', 'button', 'one-tap', 'none'].includes(mode) ? mode : 'auto') as ScriptConfig['mode'],
    position:  (['bottom-right', 'bottom-left', 'top-right', 'top-left'].includes(position) ? position : 'bottom-right') as ScriptConfig['position'],
    theme:     (['auto', 'light', 'dark'].includes(theme) ? theme : 'auto') as ScriptConfig['theme'],
    onSuccess: (['reload', 'none'].includes(onSuccess) ? onSuccess : 'reload') as ScriptConfig['onSuccess'],
    forceMount,
  }
}

// ─── Shared post-sign-in bookkeeping ──────────────────────────────────────
// Any sign-in path (popup OR One Tap) lands here. Writes the token where
// HeadloProviderV2 looks, updates both cache slots (user profile + discover
// cache so <ContinueAsModal> paints correctly next visit), then reloads.

interface TokenResponse { access_token: string; token_type: 'Bearer' | 'DPoP'; expires_in: number }

function persistSignedIn(pk: string, tokenRes: TokenResponse, shouldReload: boolean): DiscoveredUser | null {
  try { sessionStorage.setItem('headlo_auth_v2_token', tokenRes.access_token) } catch { /* non-fatal */ }

  let user: DiscoveredUser | null = null
  try {
    const [, payloadB64] = tokenRes.access_token.split('.')
    if (payloadB64) {
      const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/'))) as { sub?: string; email?: string; name?: string }
      if (payload.sub && payload.email) {
        localStorage.setItem('headlo_auth_user', JSON.stringify({ id: payload.sub, email: payload.email, displayName: payload.name ?? null }))
        user = { headloUserId: payload.sub, email: payload.email, displayName: payload.name ?? null, avatarUrl: null }
        writeCachedProfile(pk, user)
      }
    }
  } catch { /* non-fatal */ }

  console.log(`[headlo-button] ✅ signed in — token_type=${tokenRes.token_type}, reload=${shouldReload}`)
  if (shouldReload) {
    // Give the console log + any analytics/pixel a tick to flush before the
    // page navigates away. 100 ms is imperceptible.
    setTimeout(() => window.location.reload(), 100)
  }
  return user
}

// ─── Google One Tap (ported from GoogleOneTap.tsx, no React) ─────────────

const GSI_SCRIPT_SRC = 'https://accounts.google.com/gsi/client'
let gsiLoadPromise: Promise<void> | null = null

interface GoogleIdService {
  initialize(opts: { client_id: string; callback: (resp: { credential: string; select_by?: string }) => void; auto_select?: boolean; cancel_on_tap_outside?: boolean; use_fedcm_for_prompt?: boolean; itp_support?: boolean; context?: 'signin' | 'signup' | 'use' }): void
  prompt(callback?: (notification: { isNotDisplayed?: () => boolean; isSkippedMoment?: () => boolean; getNotDisplayedReason?: () => string; getSkippedReason?: () => string }) => void): void
  cancel(): void
  disableAutoSelect(): void
}
interface GoogleGlobal { accounts?: { id?: GoogleIdService } }

function loadGsi(): Promise<void> {
  if ((window as unknown as { google?: GoogleGlobal }).google?.accounts?.id) return Promise.resolve()
  if (gsiLoadPromise) return gsiLoadPromise
  gsiLoadPromise = new Promise<void>((resolve, reject) => {
    const existing = document.querySelector<HTMLScriptElement>(`script[src="${GSI_SCRIPT_SRC}"]`)
    if (existing) {
      const start = Date.now()
      const poll = () => {
        if ((window as unknown as { google?: GoogleGlobal }).google?.accounts?.id) return resolve()
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
      if ((window as unknown as { google?: GoogleGlobal }).google?.accounts?.id) resolve()
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
const discoveryCache = new Map<string, Promise<OidcDiscovery>>()
function fetchDiscovery(issuer: string): Promise<OidcDiscovery> {
  const cached = discoveryCache.get(issuer)
  if (cached) return cached
  const p = fetch(`${issuer}/.well-known/openid-configuration`).then(r => r.json() as Promise<OidcDiscovery>)
    .catch(e => { discoveryCache.delete(issuer); throw e })
  discoveryCache.set(issuer, p)
  return p
}

async function mountGoogleOneTap(cfg: ScriptConfig): Promise<void> {
  try {
    const discovery = await fetchDiscovery(cfg.issuer)
    const googleClientId = discovery['headlo:google_client_id']
    const endpoint = discovery['headlo:google_one_tap_endpoint'] ?? `${cfg.issuer}/oauth/google/one-tap`
    if (!googleClientId) {
      console.log('[headlo-button] Google sign-in not configured on this issuer — skipping One Tap')
      return
    }
    await loadGsi()
    const gsi = (window as unknown as { google: GoogleGlobal }).google.accounts!.id!

    gsi.initialize({
      client_id:             googleClientId,
      callback:              (resp) => { void handleGoogleCredential(resp.credential, cfg, endpoint) },
      auto_select:           true,
      cancel_on_tap_outside: false,
      itp_support:           true,
      use_fedcm_for_prompt:  true,
      context:               'signin',
    })

    console.log('[headlo-button] 🔵 prompting Google account chooser')
    gsi.prompt((n) => {
      try {
        if (n.isNotDisplayed?.()) {
          const reason = n.getNotDisplayedReason?.() ?? 'unknown'
          console.log(`[headlo-button] ⚠️ One Tap NOT DISPLAYED — reason=${reason}`,
            reason === 'suppressed_by_user'   ? '(Chrome ~24h cooldown; button fallback still available)'
            : reason === 'opt_out_or_no_session' ? '(user not signed into Google OR opted out)'
            : reason === 'unregistered_origin'   ? '(Google client_id missing this origin in Authorized JS origins)'
            : '')
        } else if (n.isSkippedMoment?.()) {
          console.log(`[headlo-button] ⚠️ One Tap SKIPPED — reason=${n.getSkippedReason?.() ?? 'unknown'}`)
        }
      } catch { /* non-fatal */ }
    })
  } catch (e) {
    console.log('[headlo-button] One Tap init failed', e)
  }
}

async function handleGoogleCredential(idToken: string, cfg: ScriptConfig, endpoint: string): Promise<void> {
  const t0 = Date.now()
  console.log('[headlo-button] 🟢 Google credential received — exchanging + binding DPoP')
  try {
    const keyPair = await getOrCreateKeyPair(cfg.pk)
    const jwk     = await exportPublicJwk(keyPair)
    const jkt     = await computeJwkThumbprint(jwk)
    const proof   = await signDpopProof(keyPair, { url: endpoint, method: 'POST' })

    const res = await fetch(endpoint, {
      method:      'POST',
      credentials: 'include',
      headers:     { 'Content-Type': 'application/json', DPoP: proof },
      body:        JSON.stringify({ id_token: idToken, client_id: cfg.pk, dpop_jkt: jkt }),
    })
    if (!res.ok) {
      const text = await res.text().catch(() => '')
      let code = 'ONE_TAP_EXCHANGE_FAILED'
      try { code = (JSON.parse(text) as { error?: string }).error ?? code } catch { /* non-JSON */ }
      console.log(`[headlo-button] ❌ One Tap exchange failed — ${code}`)
      return
    }
    const tokenRes = await res.json() as TokenResponse
    console.log(`[headlo-button] ✅ One Tap exchange ok — ${Date.now() - t0}ms`)
    persistSignedIn(cfg.pk, tokenRes, cfg.onSuccess === 'reload')
  } catch (e) {
    console.log('[headlo-button] One Tap credential handler threw', e)
  }
}

// ─── Floating "Sign in with Headlo" button ───────────────────────────────

const BUTTON_ID = '__headlo_universal_button'

function positionStyles(pos: ScriptConfig['position']): string {
  const edge = '20px'
  switch (pos) {
    case 'bottom-left':  return `bottom:${edge};left:${edge}`
    case 'top-right':    return `top:${edge};right:${edge}`
    case 'top-left':     return `top:${edge};left:${edge}`
    case 'bottom-right':
    default:             return `bottom:${edge};right:${edge}`
  }
}

function resolveTheme(theme: ScriptConfig['theme']): 'light' | 'dark' {
  if (theme === 'light' || theme === 'dark') return theme
  if (typeof window.matchMedia === 'function' && window.matchMedia('(prefers-color-scheme: dark)').matches) return 'dark'
  return 'light'
}

function renderFloatingButton(cfg: ScriptConfig): HTMLElement | null {
  if (document.getElementById(BUTTON_ID)) {
    console.log('[headlo-button] button already mounted — skipping duplicate render')
    return document.getElementById(BUTTON_ID)
  }

  const resolvedTheme = resolveTheme(cfg.theme)
  const dark = resolvedTheme === 'dark'

  const container = document.createElement('div')
  container.id = BUTTON_ID
  container.setAttribute('role', 'region')
  container.setAttribute('aria-label', 'Sign in with Headlo')
  container.style.cssText = `
    position:fixed;${positionStyles(cfg.position)};
    z-index:2147483646;
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  `.trim().replace(/\s+/g, ' ')

  const bg       = dark ? '#1a1a18' : '#faf9f6'
  const fg       = dark ? '#faf9f6' : '#1a1a18'
  const border   = dark ? '#2a2a26' : '#e8e5df'
  const accent   = '#5dcaa5'
  const shadow   = dark ? '0 4px 14px rgba(0,0,0,0.4)' : '0 2px 10px rgba(0,0,0,0.08)'

  container.innerHTML = `
    <button type="button" style="
      display:inline-flex;align-items:center;gap:10px;
      padding:11px 16px;background:${bg};color:${fg};
      border:1px solid ${border};border-radius:10px;
      font-size:14px;font-weight:600;cursor:pointer;
      box-shadow:${shadow};font-family:inherit;
      transition:transform 120ms ease, box-shadow 120ms ease;
    "
    onmouseover="this.style.transform='translateY(-1px)';this.style.boxShadow='${dark ? '0 6px 18px rgba(0,0,0,0.5)' : '0 4px 14px rgba(0,0,0,0.12)'}'"
    onmouseout="this.style.transform='';this.style.boxShadow='${shadow}'">
      <span style="width:8px;height:8px;border-radius:50%;background:${accent};flex-shrink:0;display:inline-block"></span>
      <span>Sign in with Headlo</span>
    </button>
  `

  container.querySelector('button')!.addEventListener('click', () => { void runPopupSignIn(cfg) })
  document.body.appendChild(container)
  console.log(`[headlo-button] 🟢 floating button mounted (${cfg.position}, ${resolvedTheme})`)
  return container
}

function removeFloatingButton(): void {
  const el = document.getElementById(BUTTON_ID)
  if (el?.parentNode) el.parentNode.removeChild(el)
}

async function runPopupSignIn(cfg: ScriptConfig): Promise<void> {
  const t0 = Date.now()
  try {
    const keyPair = await getOrCreateKeyPair(cfg.pk)
    const jwk     = await exportPublicJwk(keyPair)
    const jkt     = await computeJwkThumbprint(jwk)

    const result = await signInViaPopup({
      issuer:        cfg.issuer,
      publishableKey: cfg.pk,
      redirectUri:   window.location.origin,
      dpopJkt:       jkt,
    })

    const verifier = readStoredPkceVerifier()
    if (!verifier) throw new Error('PKCE verifier missing — sessionStorage cleared mid-flow')

    const tokenRes = await exchangeAuthCodeDpop({
      issuer:        cfg.issuer,
      code:          result.code,
      codeVerifier:  verifier,
      redirectUri:   window.location.origin,
      publishableKey: cfg.pk,
      dpopKeyPair:   keyPair,
    })
    clearStoredPkceState()
    console.log(`[headlo-button] ✅ popup sign-in ok — ${Date.now() - t0}ms`)
    persistSignedIn(cfg.pk, tokenRes, cfg.onSuccess === 'reload')
    removeFloatingButton()
  } catch (e) {
    clearStoredPkceState()
    let msg = String(e)
    if (e instanceof PopupBlockedError)         msg = 'Popup blocked — enable popups for this site'
    else if (e instanceof UserClosedPopupError) msg = 'Sign-in cancelled'
    else if (e instanceof PopupTimeoutError)    msg = 'Sign-in timed out'
    else if (e instanceof AuthServerError)      msg = `Server returned ${e.code}`
    console.log(`[headlo-button] ❌ popup sign-in failed — ${msg}`)
  }
}

// ─── Already-signed-in short-circuit ─────────────────────────────────────

function alreadySignedIn(): boolean {
  try {
    const token = sessionStorage.getItem('headlo_auth_v2_token')
    if (!token) return false
    const [, payloadB64] = token.split('.')
    if (!payloadB64) return false
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/'))) as { exp?: number }
    if (typeof payload.exp !== 'number') return false
    return payload.exp * 1000 > Date.now() + 10_000  // >10s of life remaining
  } catch { return false }
}

// ─── Entry — run on DOM ready ────────────────────────────────────────────

function boot(cfg: ScriptConfig): void {
  if (alreadySignedIn() && !cfg.forceMount) {
    console.log('[headlo-button] user already has a fresh token in sessionStorage — not mounting UI (set data-force-mount="1" to override for testing)')
    return
  }
  if (cfg.forceMount && alreadySignedIn()) {
    console.log('[headlo-button] 🧪 data-force-mount="1" — bypassing already-signed-in short-circuit (test harness)')
  }
  if (cfg.mode === 'none') {
    console.log('[headlo-button] data-mode="none" — not mounting UI (script loaded for side-effect only)')
    return
  }
  if (cfg.mode === 'auto' || cfg.mode === 'one-tap') void mountGoogleOneTap(cfg)
  if (cfg.mode === 'auto' || cfg.mode === 'button')  renderFloatingButton(cfg)
}

(function main(): void {
  if (typeof window === 'undefined' || typeof document === 'undefined') return
  const cfg = readScriptConfig()
  if (!cfg) return
  console.log('[headlo-button] 📦 Headlo universal install script — pk:', cfg.pk.slice(0, 24) + '…', 'issuer:', cfg.issuer, 'mode:', cfg.mode)

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => boot(cfg), { once: true })
  } else {
    boot(cfg)
  }
})()

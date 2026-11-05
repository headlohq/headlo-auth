// SSO Wave 2 B.2 — Tier 1 silent discovery.
//
// Mounts a hidden iframe pointing at auth.headlo.com/oauth/discover. Because
// the iframe's origin IS auth.headlo.com, the server-side request executes
// in a first-party context for auth.headlo.com — the session cookie is sent
// as a normal same-site cookie (we flipped the session cookie to SameSite=None
// in Wave 2 to make this possible). Bypasses third-party cookie blocking.
//
// Returns the discovery result OR null on timeout / error. Fire from anywhere
// — no user gesture required (the iframe is invisible). The downside of
// invisibility: can't fall back to a visible popup from here (popup blockers
// require a gesture). That fallback is B.3's `signInViaPopup`.
//
// Full plan: claude/headlo-sso-shop-equivalent.md § B.2.
// Server handler: headlo-worker/src/routes/oauth.ts oauthDiscoverHandler.

export interface DiscoverSessionOpts {
  /** OIDC issuer base — https://auth.headlo.com. The iframe loads <issuer>/oauth/discover. */
  issuer:          string
  /** pk_live_… or pk_test_… — must be a valid Headlo publishable key. */
  publishableKey:  string
  /**
   * Parent origin for postMessage targeting. Defaults to window.location.origin
   * which is correct for 99% of merchant integrations (the SDK is loaded on
   * the merchant's page). Only override when a merchant's SDK is embedded
   * one iframe deep (unusual).
   */
  parentOrigin?:   string
  /**
   * Hard timeout in ms. If the iframe doesn't postMessage back by then,
   * discovery is treated as failed (returns `{ discovered: false }`). Default
   * 4000ms — iframes typically postMessage back in <400ms when the server
   * responds normally; the 10x headroom catches slow networks without
   * hanging the UI indefinitely.
   */
  timeoutMs?:      number
}

export interface DiscoveredUser {
  headloUserId: string
  email:        string
  displayName:  string | null
  avatarUrl:    string | null
}

export type DiscoverResult =
  | { discovered: true;  user: DiscoveredUser; stepUpRequiredUntil: string | null; consentGranted?: boolean }
  | { discovered: false; error?: string }

/**
 * Fire a silent discovery iframe and wait for the postMessage result.
 *
 * The returned promise ALWAYS resolves — on timeout, parse failure, or any
 * server error, it resolves to `{ discovered: false, error: '<reason>' }`.
 * Callers never need try/catch; a false `discovered` field is the universal
 * "nothing to show" signal.
 */
export async function discoverSession(opts: DiscoverSessionOpts): Promise<DiscoverResult> {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    console.log('[headlo-discover] ❌ no_window — SSR / Node context')
    return { discovered: false, error: 'no_window' }
  }

  const parentOrigin = opts.parentOrigin ?? window.location.origin
  const timeoutMs    = opts.timeoutMs    ?? 4000

  const url = new URL(`${opts.issuer}/oauth/discover`)
  url.searchParams.set('client_id',     opts.publishableKey)
  url.searchParams.set('parent_origin', parentOrigin)

  const expectedOrigin = new URL(opts.issuer).origin

  console.log('[headlo-discover] 🔵 START', {
    iframeUrl:        url.toString(),
    expectedOrigin,
    parentOrigin,
    timeoutMs,
    pageOrigin:       window.location.origin,
  })

  return new Promise<DiscoverResult>((resolve) => {
    let settled = false
    let iframe: HTMLIFrameElement | null = null
    let timeoutId: ReturnType<typeof setTimeout> | null = null

    function cleanup() {
      settled = true
      window.removeEventListener('message', onMessage)
      if (timeoutId) clearTimeout(timeoutId)
      if (iframe && iframe.parentNode) iframe.parentNode.removeChild(iframe)
    }

    function onMessage(ev: MessageEvent) {
      // Only Headlo-origin messages with the right `type` are consumed.
      //
      // Intentionally silent on wrong-origin: Vite HMR, React DevTools,
      // browser extensions, and other third-party scripts postMessage to the
      // window constantly. Logging each one floods the console for zero
      // signal. The security-critical origin check still runs — just no log.
      if (ev.origin !== expectedOrigin) return
      const dataType = (ev.data as { type?: unknown } | null)?.type
      if (!ev.data || typeof ev.data !== 'object' || dataType !== 'headlo_discover_result') {
        // Right origin, wrong type — rare and worth seeing (indicates something
        // from auth.headlo.com sending unexpected shapes).
        console.log('[headlo-discover]   message IGNORED — wrong type', { origin: ev.origin, dataType })
        return
      }

      console.log('[headlo-discover] 🟢 postMessage received', ev.data)
      cleanup()
      const data = ev.data as { discovered?: boolean; user?: DiscoveredUser; stepUpRequiredUntil?: string | null; error?: string }
      if (data.discovered === true && data.user) {
        resolve({
          discovered:          true,
          user:                data.user,
          stepUpRequiredUntil: data.stepUpRequiredUntil ?? null,
        })
      } else {
        resolve({ discovered: false, error: data.error })
      }
    }

    window.addEventListener('message', onMessage)
    timeoutId = setTimeout(() => {
      if (!settled) {
        console.log('[headlo-discover] ⏱ TIMEOUT — no postMessage received in', timeoutMs, 'ms')
        cleanup()
        resolve({ discovered: false, error: 'timeout' })
      }
    }, timeoutMs)

    iframe = document.createElement('iframe')
    iframe.setAttribute('aria-hidden', 'true')
    iframe.setAttribute('tabindex',    '-1')
    iframe.setAttribute('title',       'Headlo session discovery')
    iframe.style.position = 'absolute'
    iframe.style.width    = '0'
    iframe.style.height   = '0'
    iframe.style.border   = 'none'
    iframe.style.left     = '-9999px'
    iframe.style.top      = '-9999px'
    iframe.onload  = () => console.log('[headlo-discover]   iframe loaded (navigated to issuer)')
    iframe.onerror = (e) => console.log('[headlo-discover]   iframe error', e)
    iframe.src = url.toString()
    document.body.appendChild(iframe)
    console.log('[headlo-discover]   iframe mounted (invisible, offscreen)')
  })
}

// ── Profile cache ──────────────────────────────────────────────────────────
//
// Cross-visit cache for the discovered profile. Lives in merchant-origin
// localStorage; survives page reloads; cleared on sign-out OR when a lazy-
// invalidation trigger fires (any 401 SESSION_REVOKED / login_required).
//
// Non-sensitive data only (email + displayName + avatarUrl) — no tokens, no
// session IDs. The cache exists purely for instant UX paint on return visits
// so the "Continue as X" modal appears without a 150-400ms discovery round-
// trip blocking first paint.

const CACHE_KEY        = 'headlo_user_cache'
const CACHE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000  // 7 days

interface CachedProfile {
  user:     DiscoveredUser
  cachedAt: number
  pk:       string
}

export function readCachedProfile(publishableKey: string): DiscoveredUser | null {
  if (typeof localStorage === 'undefined') return null
  try {
    const raw = localStorage.getItem(CACHE_KEY)
    if (!raw) return null
    const c = JSON.parse(raw) as CachedProfile
    // Bust when the pk changes (user switched merchants on the same origin,
    // or the merchant rotated their pk). Also bust on age — a 7-day-old cache
    // of a user who hasn't come back probably shouldn't still show the modal.
    if (c.pk !== publishableKey)                                return null
    if (Date.now() - c.cachedAt > CACHE_MAX_AGE_MS)             return null
    if (!c.user?.headloUserId || !c.user?.email)                return null
    return c.user
  } catch {
    return null
  }
}

export function writeCachedProfile(publishableKey: string, user: DiscoveredUser): void {
  if (typeof localStorage === 'undefined') return
  const c: CachedProfile = { user, pk: publishableKey, cachedAt: Date.now() }
  try { localStorage.setItem(CACHE_KEY, JSON.stringify(c)) } catch { /* quota — ignore */ }
}

export function clearCachedProfile(): void {
  if (typeof localStorage === 'undefined') return
  try { localStorage.removeItem(CACHE_KEY) } catch { /* ignore */ }
}

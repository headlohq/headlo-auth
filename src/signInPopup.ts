// SSO Wave 2 B.3 — Tier 2 visible popup sign-in.
//
// Opens auth.headlo.com/oauth/authorize?response_mode=web_message in a popup.
// The server returns an HTML page that postMessages the auth code back to
// the parent (merchant site) and closes the popup. Returns the code + state
// for the caller to exchange at /oauth/token.
//
// Companion to B.2's silent iframe discovery (discover.ts): both use the
// `response_mode=web_message` server pattern, both verify postMessage origin
// against the issuer. Differences:
//   - B.2 iframe = invisible, no user gesture required, fails fast if no session
//   - B.3 popup  = visible, requires user-click gesture, can show login UI
//
// Full plan: claude/headlo-sso-shop-equivalent.md § B.3.
// Server handler: oauthAuthorizeGetHandler branch for response_mode=web_message.

import { generateCodeVerifier, generateCodeChallenge } from './pkce'
import { signDpopProof } from './dpop'

export interface SignInPopupOpts {
  /** OIDC issuer base — https://auth.headlo.com */
  issuer:          string
  /** pk_live_… or pk_test_…; validated by server */
  publishableKey:  string
  /**
   * Where the auth code was registered to go. Must be an entry in the pk's
   * `allowed_redirect_uris` OR fall under its `allowed_origins`. The server
   * uses this to derive the postMessage targetOrigin — ONLY that origin
   * receives the code, so an attacker's popup can't exfiltrate it.
   */
  redirectUri:     string
  /**
   * OIDC prompt param. Omit for default (silent-SSO if possible, else form).
   * 'login' forces the login form even when a session exists.
   */
  prompt?:         'none' | 'login' | 'consent'
  /**
   * Pre-fill the sign-in form's email field. Pass when we KNOW the user's
   * email from a prior B.2 silent-discover response — saves them from
   * retyping. Matches Shop's observed `login_hint=…` pattern.
   */
  loginHint?:      string
  /** Popup width in px. Default 500. */
  width?:          number
  /** Popup height in px. Default 640. */
  height?:         number
  /**
   * Hard timeout in ms. If no postMessage arrives in that window, resolves
   * with TimeoutError. Default 120000 (2 min) — generous because user may
   * need to type password / complete Google round-trip / handle a captcha.
   */
  timeoutMs?:      number
  /**
   * SSO Wave 2 B.3 Option A — DPoP JWK thumbprint (RFC 9449 § 10 dpop_jkt).
   * When supplied, the auth code is pre-bound to this key server-side; the
   * subsequent POST /oauth/token exchange MUST carry a DPoP proof signed by
   * the matching key and will mint a cnf.jkt-bound ("Anchor-Bound") access
   * token in one round-trip — no follow-up /oauth/dpop/register needed.
   *
   * Omit for a legacy Bearer-only flow (code redeems to a non-cnf-bound token
   * plus a refresh cookie). Callers that want DPoP binding generate/retrieve
   * the keypair, compute the thumbprint via computeJwkThumbprint(), and pass
   * it here before opening the popup.
   */
  dpopJkt?:        string
}

export interface SignInPopupResult {
  code:  string
  state: string
}

export class PopupBlockedError    extends Error { constructor() { super('Popup blocked');            this.name = 'PopupBlockedError'    } }
export class UserClosedPopupError extends Error { constructor() { super('Popup closed by user');    this.name = 'UserClosedPopupError' } }
export class PopupTimeoutError    extends Error { constructor() { super('Popup timed out');         this.name = 'PopupTimeoutError'    } }
export class StateMismatchError   extends Error { constructor() { super('State mismatch');          this.name = 'StateMismatchError'   } }
export class AuthServerError      extends Error {
  constructor(public code: string) { super(`Auth server error: ${code}`); this.name = 'AuthServerError' }
}

const PKCE_VERIFIER_KEY = 'headlo_popup_pkce_verifier'
const STATE_KEY         = 'headlo_popup_pkce_state'

/**
 * Launch a visible popup sign-in. **MUST be called synchronously inside a
 * user-gesture click handler** — browsers block `window.open` otherwise.
 * Returns the auth code + state once the popup finishes; caller is responsible
 * for exchanging the code at /oauth/token with the stored PKCE verifier
 * (read via `readStoredPkceVerifier()`).
 *
 * Error types the caller should handle:
 *   PopupBlockedError    — browser blocked window.open; fall back to redirect
 *   UserClosedPopupError — user closed the popup before completing
 *   PopupTimeoutError    — 2min elapsed with no postMessage
 *   AuthServerError      — server returned login_required / step_up_required / etc.
 *   StateMismatchError   — treat as potential CSRF; don't retry
 */
export async function signInViaPopup(opts: SignInPopupOpts): Promise<SignInPopupResult> {
  if (typeof window === 'undefined' || typeof document === 'undefined') {
    throw new Error('signInViaPopup requires a browser environment')
  }

  // Generate PKCE pair + state BEFORE opening the popup. These are stored in
  // sessionStorage so the caller can retrieve the verifier for the subsequent
  // /oauth/token exchange, and so a state round-trip-mismatch is detectable.
  const verifier  = generateCodeVerifier()
  const challenge = await generateCodeChallenge(verifier)
  const state     = generateCodeVerifier()  // reusing — 32 random bytes base64url is fine for state too
  sessionStorage.setItem(PKCE_VERIFIER_KEY, verifier)
  sessionStorage.setItem(STATE_KEY,         state)

  const authorizeUrl = new URL(`${opts.issuer}/oauth/authorize`)
  authorizeUrl.search = new URLSearchParams({
    response_type:          'code',
    response_mode:          'web_message',       // ← tells server to postMessage, not 302
    client_id:              opts.publishableKey,
    redirect_uri:           opts.redirectUri,
    code_challenge:         challenge,
    code_challenge_method:  'S256',
    scope:                  'openid email profile',
    state,
    ...(opts.prompt     ? { prompt:     opts.prompt     } : {}),
    ...(opts.loginHint  ? { login_hint: opts.loginHint  } : {}),
    ...(opts.dpopJkt    ? { dpop_jkt:   opts.dpopJkt    } : {}),  // RFC 9449 § 10
  }).toString()

  const expectedOrigin = new URL(opts.issuer).origin
  const timeoutMs      = opts.timeoutMs ?? 120_000

  // CRITICAL: window.open MUST be synchronous inside the user-gesture click
  // handler OR browsers (notably Safari) block it. Opening to about:blank
  // first lets us return the popup handle immediately; the subsequent
  // .location.href = authorizeUrl navigates it on the next tick. Any `await`
  // before window.open breaks popup-blocker-friendliness.
  const w = opts.width  ?? 500
  const h = opts.height ?? 640
  const left = window.screenX + (window.outerWidth  - w) / 2
  const top  = window.screenY + (window.outerHeight - h) / 2
  const features = `width=${w},height=${h},left=${left},top=${top},menubar=no,toolbar=no,location=yes,status=no,resizable=yes`

  console.log('[headlo-popup] 🔵 opening popup', { authorizeUrl, expectedOrigin, w, h, timeoutMs })
  const popup = window.open('about:blank', 'headlo_signin', features)
  if (!popup) {
    console.log('[headlo-popup] ❌ popup blocked')
    sessionStorage.removeItem(PKCE_VERIFIER_KEY)
    sessionStorage.removeItem(STATE_KEY)
    throw new PopupBlockedError()
  }
  popup.location.href = authorizeUrl.toString()

  return new Promise<SignInPopupResult>((resolve, reject) => {
    let settled = false
    let closedTimer: ReturnType<typeof setInterval> | null = null
    let timeoutId:   ReturnType<typeof setTimeout>  | null = null

    function cleanup() {
      settled = true
      window.removeEventListener('message', onMessage)
      if (closedTimer) clearInterval(closedTimer)
      if (timeoutId)   clearTimeout(timeoutId)
    }

    function onMessage(ev: MessageEvent) {
      // ORIGIN CHECK — load-bearing. Reject messages from any origin except
      // the issuer we're expecting a response from. Prevents a malicious page
      // (which can also open popups) from forging a fake auth code.
      //
      // Intentionally silent on wrong-origin: Vite HMR, React DevTools,
      // browser extensions, and other third-party scripts postMessage to the
      // window for their own purposes. Logging each one floods the console
      // for zero signal. The check still runs — just no log.
      if (ev.origin !== expectedOrigin) return
      const data = ev.data as { type?: string; code?: string; state?: string; error?: string } | null
      if (!data || typeof data !== 'object' || data.type !== 'headlo_auth_result') {
        return
      }

      console.log('[headlo-popup] 🟢 postMessage received', data)
      cleanup()
      try { popup?.close() } catch { /* already closed */ }

      if (data.error) {
        reject(new AuthServerError(data.error))
        return
      }
      // STATE CHECK — verifies the postMessage corresponds to the request
      // this SDK initiated. Prevents an attacker from injecting a stolen
      // code from a different flow.
      const expectedState = sessionStorage.getItem(STATE_KEY)
      if (data.state !== expectedState) {
        reject(new StateMismatchError())
        return
      }
      if (!data.code) {
        reject(new AuthServerError('missing_code'))
        return
      }
      resolve({ code: data.code, state: data.state })
    }

    // Poll popup.closed — fires when the user clicks the window's X button
    // without completing the flow. 400ms interval balances responsiveness
    // vs CPU waste.
    closedTimer = setInterval(() => {
      if (popup?.closed && !settled) {
        console.log('[headlo-popup] ❌ popup closed by user')
        cleanup()
        reject(new UserClosedPopupError())
      }
    }, 400)

    timeoutId = setTimeout(() => {
      if (!settled) {
        console.log('[headlo-popup] ⏱ timeout — no postMessage received in', timeoutMs, 'ms')
        cleanup()
        try { popup?.close() } catch {}
        reject(new PopupTimeoutError())
      }
    }, timeoutMs)

    window.addEventListener('message', onMessage)
  })
}

/**
 * Read the PKCE verifier stored by the last signInViaPopup call. Caller
 * passes this to POST /oauth/token to complete the code exchange. Consume-
 * once semantics: this function doesn't delete the key — call clearStoredPkceState()
 * after a successful token mint.
 */
export function readStoredPkceVerifier(): string | null {
  if (typeof sessionStorage === 'undefined') return null
  return sessionStorage.getItem(PKCE_VERIFIER_KEY)
}

/** Clear the stored PKCE state. Call after successful code exchange OR on error. */
export function clearStoredPkceState(): void {
  if (typeof sessionStorage === 'undefined') return
  try {
    sessionStorage.removeItem(PKCE_VERIFIER_KEY)
    sessionStorage.removeItem(STATE_KEY)
  } catch {}
}

/**
 * Detect whether to prefer popup vs redirect. Returns 'redirect' on mobile
 * where popups are unreliable (iOS Safari especially). Callers can override
 * explicitly via the SignInButton `mode` prop.
 */
export function pickDefaultSignInMode(): 'popup' | 'redirect' {
  if (typeof navigator === 'undefined') return 'redirect'
  const isMobile = /Mobi|Android|iPhone|iPad|iPod/i.test(navigator.userAgent)
  return isMobile ? 'redirect' : 'popup'
}

export interface ExchangeAuthCodeOpts {
  /** OIDC issuer base — https://auth.headlo.com */
  issuer:         string
  /** Auth code from signInViaPopup result */
  code:           string
  /** PKCE verifier from readStoredPkceVerifier() */
  codeVerifier:   string
  /** Must match the redirect_uri the auth code was issued against */
  redirectUri:    string
  /** Publishable key sent as client_id to the authorize request */
  publishableKey: string
  /**
   * DPoP keypair matching the thumbprint supplied as `dpopJkt` to
   * signInViaPopup. When provided, the exchange sends a DPoP proof and the
   * server mints a cnf.jkt-bound access token (Option A path). Omit to run
   * the legacy Bearer flow (server sets a refresh cookie too).
   */
  dpopKeyPair?:   CryptoKeyPair
}

export interface ExchangeAuthCodeResult {
  access_token: string
  token_type:   'Bearer' | 'DPoP'
  expires_in:   number
}

/**
 * POST /oauth/token with the PKCE code+verifier. When `dpopKeyPair` is
 * supplied, attaches a DPoP proof so the server can match it against the
 * auth code's `dpop_jkt` binding (RFC 9449 § 10) and return a cnf.jkt-bound
 * token.
 *
 * Companion to signInViaPopup. Separated so the exchange can be reused by
 * non-popup flows (deep-link redirect callbacks, Wave 3 B.4 "Continue as X"
 * modal, future PROP service).
 *
 * Throws on non-2xx with the server's error code string.
 */
export async function exchangeAuthCodeDpop(opts: ExchangeAuthCodeOpts): Promise<ExchangeAuthCodeResult> {
  const url = `${opts.issuer}/oauth/token`
  const body = new URLSearchParams({
    grant_type:    'authorization_code',
    code:          opts.code,
    code_verifier: opts.codeVerifier,
    redirect_uri:  opts.redirectUri,
    client_id:     opts.publishableKey,
  })

  const headers: Record<string, string> = { 'Content-Type': 'application/x-www-form-urlencoded' }
  if (opts.dpopKeyPair) {
    headers.DPoP = await signDpopProof(opts.dpopKeyPair, { url, method: 'POST' })
  }

  const res = await fetch(url, {
    method:      'POST',
    credentials: 'include',  // allows legacy Bearer path to receive its refresh cookie
    headers,
    body,
  })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    let code = 'TOKEN_EXCHANGE_FAILED'
    try { code = (JSON.parse(text) as { error?: string }).error ?? code } catch { /* non-JSON */ }
    throw new AuthServerError(code)
  }
  return res.json() as Promise<ExchangeAuthCodeResult>
}

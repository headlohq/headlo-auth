// SSO Wave 4 B.12 — Multi-provider auth menu.
//
// Centered modal with (optional) Continue-as-X recognition row at the top,
// then provider rows (Continue with Google, Continue with Apple, Continue
// with Email). Cross-link footer swaps between sign-in and sign-up without
// unmounting. One drop-in `<AuthMenu>` + two sugar wrappers (`SignInButton`,
// `SignUpButton`) satisfy the Clerk-like developer experience the spec asks
// for in both Option A (`<AuthMenu action="…">`) and Option B (wrappers).
//
// Composition:
//   - Google row  → opens popup to /oauth/google/start, exchanges via
//                   exchangeAuthCodeDpop (same code path as the headless
//                   signInViaPopup used by B.3).
//   - Apple row   → inlined copy of HeadloAppleSignIn's click handler
//                   (AppleID.auth.signIn + POST /oauth/token/apple-federated).
//                   Degrades silently when Apple Services ID is unconfigured.
//   - Email row   → signInViaPopup (shows the Headlo form inside the popup).
//   - Continue-as → ContinueAsModal's discover + cache logic, inlined for
//                   the one row we need. Fires the same popup+exchange path
//                   on click so the sign-in happens with the RIGHT identity.
//
// Deferred for v1:
//   - Anchored dropdown (position="anchor") — centered modal only
//   - PROP custom-element <headlo-auth-button mode="menu"> — React only
//   - Password-first mode (no Email popup, inline password field) — Wave 6
//
// Spec: claude/headlo-sso-shop-equivalent.md § B.12

import React from 'react'
import { getOrCreateKeyPair, exportPublicJwk, computeJwkThumbprint, signDpopProof } from './dpop'
import { discoverSession, readCachedProfile, writeCachedProfile, type DiscoveredUser } from './discover'
import { resolveIssuer } from './pk'
import {
  signInViaPopup, exchangeAuthCodeDpop, readStoredPkceVerifier, clearStoredPkceState,
} from './signInPopup'

export type AuthAction = 'signin' | 'signup'
export type AuthProvider = 'google' | 'apple' | 'email'

export interface AuthMenuProps {
  issuer?:         string
  publishableKey:  string
  action:          AuthAction
  /** Which rows to show, in display order. Default: ['google', 'apple', 'email']. */
  providers?:      readonly AuthProvider[]
  /** Where the OAuth code redeems. Defaults to the current page's origin. */
  redirectUri?:    string
  open:            boolean
  onCancel?:       () => void
  /** Fires after sign-in success. Return `false` to suppress default reload. */
  onSuccess?:      (info: { email: string; name: string | null; sub: string }) => void | false | Promise<void | false>
  /** Fires when the cross-link swaps action in place. Lets wrapper components keep state in sync. */
  onActionChange?: (next: AuthAction) => void
  /** Optional modal title override. Default: "Sign in" / "Create your account" per action. */
  title?:          string
}

// --- Shared helpers --------------------------------------------------------

interface Discovery {
  'headlo:apple_services_id'?: string | null
  'headlo:google_client_id'?:  string | null
}
const discoveryCache = new Map<string, Promise<Discovery>>()
function fetchDiscovery(issuer: string): Promise<Discovery> {
  const cached = discoveryCache.get(issuer)
  if (cached) return cached
  const p = fetch(`${issuer}/.well-known/openid-configuration`)
    .then(r => r.json() as Promise<Discovery>)
    .catch(e => { discoveryCache.delete(issuer); throw e })
  discoveryCache.set(issuer, p)
  return p
}

function writeSessionAndCaches(
  publishableKey: string, access_token: string,
): { sub: string; email: string; name: string | null } | null {
  sessionStorage.setItem('headlo_auth_v2_token', access_token)
  try {
    const [, payloadB64] = access_token.split('.')
    if (!payloadB64) return null
    const payload = JSON.parse(atob(payloadB64.replace(/-/g, '+').replace(/_/g, '/'))) as { sub?: string; email?: string; name?: string }
    if (!payload.sub || !payload.email) return null
    localStorage.setItem('headlo_auth_user', JSON.stringify({ id: payload.sub, email: payload.email, displayName: payload.name ?? null }))
    writeCachedProfile(publishableKey, {
      headloUserId: payload.sub,
      email:        payload.email,
      displayName:  payload.name ?? null,
      avatarUrl:    null,
    })
    return { sub: payload.sub, email: payload.email, name: payload.name ?? null }
  } catch { return null }
}

// --- Provider flows --------------------------------------------------------
// Each returns the signed-in info on success, or throws on failure. All three
// end with the same sessionStorage + caches write, so onSuccess receives the
// same shape regardless of which provider the user picked.

async function runEmailFlow(
  issuer: string, publishableKey: string, redirectUri: string,
): Promise<{ sub: string; email: string; name: string | null } | null> {
  const kp     = await getOrCreateKeyPair(publishableKey)
  const jwk    = await exportPublicJwk(kp)
  const dpopJkt = await computeJwkThumbprint(jwk)
  const popupResult = await signInViaPopup({
    issuer, publishableKey, redirectUri, dpopJkt,
  })
  const verifier = readStoredPkceVerifier()
  if (!verifier) throw new Error('PKCE verifier missing after popup — storage lost?')
  const tokenRes = await exchangeAuthCodeDpop({
    issuer, publishableKey,
    code:         popupResult.code,
    codeVerifier: verifier,
    redirectUri,
    dpopKeyPair:  kp,
  })
  clearStoredPkceState()
  return writeSessionAndCaches(publishableKey, tokenRes.access_token)
}

async function runGoogleFlow(
  issuer: string, publishableKey: string, redirectUri: string,
): Promise<{ sub: string; email: string; name: string | null } | null> {
  // Open popup synchronously (click handler) to /oauth/google/start with the
  // same param set signInViaPopup builds. Server redirects to Google, user
  // consents, Google calls back to /oauth/google/callback, server posts
  // auth_code via web_message exactly like the normal popup path.
  const kp      = await getOrCreateKeyPair(publishableKey)
  const jwk     = await exportPublicJwk(kp)
  const dpopJkt = await computeJwkThumbprint(jwk)
  // Reuse signInViaPopup's full URL build + popup lifecycle by first opening
  // the normal popup (lands on the Headlo form), then... no — that defeats
  // the purpose. Instead we do it inline here, close copy of signInViaPopup
  // but pointed at /oauth/google/start.
  const result = await openProviderPopup({
    issuer, publishableKey, redirectUri,
    path: '/oauth/google/start', dpopJkt,
  })
  const verifier = readStoredPkceVerifier()
  if (!verifier) throw new Error('PKCE verifier missing after popup — storage lost?')
  const tokenRes = await exchangeAuthCodeDpop({
    issuer, publishableKey,
    code:         result.code,
    codeVerifier: verifier,
    redirectUri,
    dpopKeyPair:  kp,
  })
  clearStoredPkceState()
  return writeSessionAndCaches(publishableKey, tokenRes.access_token)
}

async function runAppleFlow(
  issuer: string, publishableKey: string,
): Promise<{ sub: string; email: string; name: string | null } | null> {
  const discovery = await fetchDiscovery(issuer)
  const servicesId = discovery['headlo:apple_services_id']
  if (!servicesId) throw new Error('APPLE_NOT_CONFIGURED')
  await loadAppleJs()
  const auth = (window as unknown as { AppleID: { auth: {
    init(opts: { clientId: string; scope: string; redirectURI: string; usePopup: boolean }): void
    signIn(opts?: { nonce?: string; state?: string }): Promise<{
      authorization: { id_token: string }
      user?: { name?: { firstName?: string | null; lastName?: string | null } }
    }>
  } } }).AppleID.auth
  if (!appleInited) {
    auth.init({ clientId: servicesId, scope: 'name email', redirectURI: `${window.location.origin}/`, usePopup: true })
    appleInited = true
  }
  const result = await auth.signIn()
  const kp     = await getOrCreateKeyPair(publishableKey)
  const jwk    = await exportPublicJwk(kp)
  const dpopJkt = await computeJwkThumbprint(jwk)
  const endpoint = `${issuer}/oauth/token/apple-federated`
  const res = await fetch(endpoint, {
    method:      'POST',
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      DPoP: await signDpopProof(kp, { url: endpoint, method: 'POST' }),
    },
    body: JSON.stringify({
      id_token:   result.authorization.id_token,
      client_id:  publishableKey,
      apple_user: result.user?.name
        ? { firstName: result.user.name.firstName ?? null, lastName: result.user.name.lastName ?? null }
        : null,
      dpop_jkt: dpopJkt,
    }),
  })
  if (!res.ok) {
    let code = 'APPLE_EXCHANGE_FAILED'
    try { code = (await res.json() as { error?: string }).error ?? code } catch { /* non-JSON */ }
    throw new Error(code)
  }
  const tokenRes = await res.json() as { access_token: string }
  return writeSessionAndCaches(publishableKey, tokenRes.access_token)
}

// --- Google popup opener (close copy of signInViaPopup, different URL) ----

const PKCE_VERIFIER_KEY = 'headlo_popup_pkce_verifier'
const STATE_KEY         = 'headlo_popup_pkce_state'

function b64UrlEncode(buf: ArrayBuffer): string {
  let s = ''
  const bytes = new Uint8Array(buf)
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function randomVerifier(): string {
  const bytes = new Uint8Array(32)
  crypto.getRandomValues(bytes)
  return b64UrlEncode(bytes.buffer)
}
async function sha256(input: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input))
  return b64UrlEncode(digest)
}

async function openProviderPopup(opts: {
  issuer: string; publishableKey: string; redirectUri: string;
  path: string; dpopJkt?: string;
}): Promise<{ code: string; state: string }> {
  const verifier  = randomVerifier()
  const challenge = await sha256(verifier)
  const state     = randomVerifier()
  sessionStorage.setItem(PKCE_VERIFIER_KEY, verifier)
  sessionStorage.setItem(STATE_KEY,         state)

  const url = new URL(`${opts.issuer}${opts.path}`)
  url.search = new URLSearchParams({
    response_type:          'code',
    response_mode:          'web_message',
    client_id:              opts.publishableKey,
    redirect_uri:           opts.redirectUri,
    code_challenge:         challenge,
    code_challenge_method:  'S256',
    scope:                  'openid email profile',
    state,
    ...(opts.dpopJkt ? { dpop_jkt: opts.dpopJkt } : {}),
  }).toString()

  const expectedOrigin = new URL(opts.issuer).origin
  const w = 500, h = 640
  const left = Math.max(0, Math.floor((window.screen.availWidth  - w) / 2))
  const top  = Math.max(0, Math.floor((window.screen.availHeight - h) / 2))
  const popup = window.open('about:blank', 'headlo_signin', `width=${w},height=${h},left=${left},top=${top}`)
  if (!popup) throw new Error('Popup blocked')
  popup.location.href = url.toString()

  return new Promise<{ code: string; state: string }>((resolve, reject) => {
    const timeoutId = setTimeout(() => {
      cleanup(); try { popup.close() } catch { /* ignore */ }
      reject(new Error('Popup timed out'))
    }, 120_000)
    const pollId = setInterval(() => {
      if (popup.closed) {
        cleanup()
        reject(new Error('Popup closed by user'))
      }
    }, 500)
    const onMessage = (ev: MessageEvent) => {
      if (ev.origin !== expectedOrigin) return
      const data = ev.data as { type?: string; code?: string; state?: string; error?: string }
      if (!data || data.type !== 'authorization_response') return
      cleanup()
      if (data.error) { reject(new Error(data.error)); return }
      if (data.state !== state) { reject(new Error('State mismatch')); return }
      if (!data.code) { reject(new Error('No code in response')); return }
      resolve({ code: data.code, state: data.state })
    }
    function cleanup() {
      clearTimeout(timeoutId); clearInterval(pollId)
      window.removeEventListener('message', onMessage)
    }
    window.addEventListener('message', onMessage)
  })
}

// --- Apple SDK loader (shared with HeadloAppleSignIn's own) ---------------

const APPLE_SCRIPT_SRC = 'https://appleid.cdn-apple.com/appleauth/static/jsapi/appleid/1/en_US/appleid.auth.js'
let appleLoadPromise: Promise<void> | null = null
let appleInited = false
function loadAppleJs(): Promise<void> {
  if (typeof window === 'undefined') return Promise.reject(new Error('SSR_NO_WINDOW'))
  if ((window as unknown as { AppleID?: { auth?: unknown } }).AppleID?.auth) return Promise.resolve()
  if (appleLoadPromise) return appleLoadPromise
  appleLoadPromise = new Promise<void>((resolve, reject) => {
    const existing = document.querySelector<HTMLScriptElement>(`script[src="${APPLE_SCRIPT_SRC}"]`)
    if (existing) {
      const start = Date.now()
      const poll = () => {
        if ((window as unknown as { AppleID?: { auth?: unknown } }).AppleID?.auth) return resolve()
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
      if ((window as unknown as { AppleID?: { auth?: unknown } }).AppleID?.auth) resolve()
      else reject(new Error('APPLE_LOADED_BUT_NO_GLOBAL'))
    }
    script.onerror = () => reject(new Error('APPLE_SCRIPT_LOAD_FAILED'))
    document.head.appendChild(script)
  })
  return appleLoadPromise
}

// --- Component -------------------------------------------------------------

type Phase =
  | { kind: 'idle' }
  | { kind: 'running'; provider: AuthProvider | 'continue-as' }
  | { kind: 'error'; message: string }

export function AuthMenu(props: AuthMenuProps): React.ReactElement | null {
  const { publishableKey, open, onCancel, onSuccess, onActionChange, title } = props
  const providers = props.providers ?? ['google', 'apple', 'email']
  const issuer = React.useMemo(() => resolveIssuer(publishableKey, props.issuer), [publishableKey, props.issuer])
  const redirectUri = props.redirectUri ?? (typeof window !== 'undefined' ? window.location.origin : '')

  const [action, setAction]   = React.useState<AuthAction>(props.action)
  React.useEffect(() => setAction(props.action), [props.action])

  const [returning, setReturning] = React.useState<DiscoveredUser | null>(null)
  const [phase, setPhase]     = React.useState<Phase>({ kind: 'idle' })
  const [appleAvailable, setAppleAvailable] = React.useState<boolean | null>(null)

  // One silent discover on open, plus a sync cache paint for instant UX.
  React.useEffect(() => {
    if (!open) return
    const cached = readCachedProfile(publishableKey)
    if (cached) setReturning(cached)
    void (async () => {
      try {
        const r = await discoverSession({ issuer, publishableKey })
        if (r.discovered) setReturning(r.user)
        else if (r.error === 'no_session') setReturning(null)
      } catch { /* ambiguous — keep cache paint */ }
    })()
    // Check whether Apple is configured so we can hide/dim the row.
    void (async () => {
      try {
        const d = await fetchDiscovery(issuer)
        setAppleAvailable(!!d['headlo:apple_services_id'])
      } catch { setAppleAvailable(null) }
    })()
  }, [open, issuer, publishableKey])

  // ESC-to-close + background scroll lock while open.
  React.useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onCancel?.() }
    window.addEventListener('keydown', onKey)
    const prevOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      window.removeEventListener('keydown', onKey)
      document.body.style.overflow = prevOverflow
    }
  }, [open, onCancel])

  async function run(provider: AuthProvider | 'continue-as'): Promise<void> {
    setPhase({ kind: 'running', provider })
    try {
      let info: { sub: string; email: string; name: string | null } | null = null
      if (provider === 'google')              info = await runGoogleFlow(issuer, publishableKey, redirectUri)
      else if (provider === 'apple')          info = await runAppleFlow(issuer, publishableKey)
      else if (provider === 'email')          info = await runEmailFlow(issuer, publishableKey, redirectUri)
      else if (provider === 'continue-as')    info = await runEmailFlow(issuer, publishableKey, redirectUri) // reuses popup — server will silent-SSO when session cookie is still valid
      let shouldReload = true
      if (info && onSuccess) {
        const r = await onSuccess(info)
        if (r === false) shouldReload = false
      }
      if (shouldReload) window.location.reload()
    } catch (e) {
      setPhase({ kind: 'error', message: String((e as Error).message ?? e) })
    }
  }

  function swapAction(): void {
    const next: AuthAction = action === 'signin' ? 'signup' : 'signin'
    setAction(next)
    onActionChange?.(next)
  }

  if (!open) return null

  const resolvedTitle = title ?? (action === 'signin' ? 'Sign in' : 'Create your account')
  const providersOrdered: AuthProvider[] = providers.filter(p => p !== 'apple' || appleAvailable !== false) as AuthProvider[]

  return (
    <div style={S.backdrop} onClick={(e) => { if (e.target === e.currentTarget) onCancel?.() }}>
      <div style={S.card} role="dialog" aria-modal="true" aria-labelledby="headlo-auth-menu-title">
        <button type="button" aria-label="Close" onClick={onCancel} style={S.closeBtn}>×</button>

        <h2 id="headlo-auth-menu-title" style={S.title}>{resolvedTitle}</h2>
        <p style={S.subtitle}>Powered by Headlo — one identity, every merchant.</p>

        {returning && (
          <>
            <button type="button" style={S.continueBtn} disabled={phase.kind === 'running'} onClick={() => void run('continue-as')}>
              <div style={S.avatarInline}>{initials(returning.displayName, returning.email)}</div>
              <div style={S.continueMeta}>
                <div style={S.continueName}>Continue as {returning.displayName ?? returning.email.split('@')[0]}</div>
                <div style={S.continueEmail}>{returning.email}</div>
              </div>
              <div style={S.chevron}>→</div>
            </button>
            <div style={S.divider}><span>or {action === 'signin' ? 'sign in' : 'sign up'} with</span></div>
          </>
        )}

        {providersOrdered.includes('google') && (
          <ProviderButton kind="google" running={phase.kind === 'running' && phase.provider === 'google'} disabled={phase.kind === 'running'} onClick={() => void run('google')} />
        )}
        {providersOrdered.includes('apple') && (
          <ProviderButton kind="apple" running={phase.kind === 'running' && phase.provider === 'apple'} disabled={phase.kind === 'running' || appleAvailable === false} onClick={() => void run('apple')} />
        )}
        {providersOrdered.includes('email') && (
          <ProviderButton kind="email" running={phase.kind === 'running' && phase.provider === 'email'} disabled={phase.kind === 'running'} onClick={() => void run('email')} action={action} />
        )}

        {phase.kind === 'error' && (
          <div style={S.err}>{phase.message}</div>
        )}

        <div style={S.footer}>
          {action === 'signin'
            ? <>Don't have an account? <button type="button" style={S.crossLink} onClick={swapAction}>Sign up</button></>
            : <>Already have an account? <button type="button" style={S.crossLink} onClick={swapAction}>Log in</button></>}
        </div>
      </div>
    </div>
  )
}

function ProviderButton(props: { kind: AuthProvider; running: boolean; disabled: boolean; onClick: () => void; action?: AuthAction }): React.ReactElement {
  const label = props.kind === 'google' ? 'Continue with Google'
              : props.kind === 'apple'  ? 'Continue with Apple'
              : props.action === 'signup' ? 'Continue with email' : 'Continue with email'
  const style: React.CSSProperties = props.kind === 'apple'
    ? { ...S.providerBtn, background: '#000', color: '#fff', borderColor: '#000' }
    : S.providerBtn
  return (
    <button type="button" style={{ ...style, opacity: props.disabled && !props.running ? 0.5 : 1 }} disabled={props.disabled} onClick={props.onClick}>
      <ProviderIcon kind={props.kind} />
      <span style={{ flex: 1, textAlign: 'center' }}>{props.running ? 'Signing in…' : label}</span>
    </button>
  )
}

function ProviderIcon(props: { kind: AuthProvider }): React.ReactElement {
  if (props.kind === 'google') return (
    <svg width="18" height="18" viewBox="0 0 48 48" aria-hidden="true">
      <path fill="#EA4335" d="M24 9.5c3.5 0 6.6 1.2 9 3.6l6.7-6.7C35.9 2.6 30.4 0 24 0 14.6 0 6.5 5.4 2.6 13.2l7.8 6c1.9-5.6 7.2-9.7 13.6-9.7z"/>
      <path fill="#4285F4" d="M46.5 24.5c0-1.6-.1-3.2-.4-4.7H24v8.9h12.7c-.6 3-2.3 5.5-4.8 7.2l7.4 5.8c4.3-4 6.8-9.8 6.8-17.2z"/>
      <path fill="#FBBC05" d="M10.4 28.8c-.5-1.4-.7-2.9-.7-4.3s.3-2.9.7-4.3l-7.8-6C.9 17.3 0 20.5 0 24s.9 6.7 2.6 9.8l7.8-5z"/>
      <path fill="#34A853" d="M24 48c6.4 0 11.9-2.1 15.9-5.7l-7.4-5.8c-2 1.4-4.7 2.3-8.5 2.3-6.4 0-11.7-4.1-13.6-9.7l-7.8 6C6.5 42.6 14.6 48 24 48z"/>
    </svg>
  )
  if (props.kind === 'apple') return (
    <svg width="14" height="14" viewBox="0 0 384 512" fill="currentColor" aria-hidden="true">
      <path d="M318.7 268.7c-.2-36.7 16.4-64.4 50-84.8-18.8-26.9-47.2-41.7-84.7-44.6-35.5-2.8-74.3 20.7-88.5 20.7-15 0-49.4-19.7-76.4-19.7C63.3 141.2 4 184.8 4 273.5q0 39.3 14.4 81.2c12.8 36.7 59 126.7 107.2 125.2 25.2-.6 43-17.9 75.8-17.9 31.8 0 48.3 17.9 76.4 17.9 48.6-.7 90.4-82.5 102.6-119.3-65.2-30.7-61.7-90-61.7-91.9zm-56.6-164.2c27.3-32.4 24.8-61.9 24-72.5-24.1 1.4-52 16.4-67.9 34.9-17.5 19.8-27.8 44.3-25.6 71.9 26.1 2 49.9-11.4 69.5-34.3z"/>
    </svg>
  )
  // email
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true">
      <rect x="3" y="5" width="18" height="14" rx="2"/>
      <path d="M3 7l9 6 9-6"/>
    </svg>
  )
}

function initials(name: string | null | undefined, email: string): string {
  const src = (name && name.trim()) || email
  const parts = src.split(/\s+/).filter(Boolean).slice(0, 2)
  return (parts.map(p => p[0] ?? '').join('').toUpperCase() || '?')
}

// --- Sugar wrappers -------------------------------------------------------

export interface AuthButtonProps {
  issuer?:        string
  publishableKey: string
  providers?:     readonly AuthProvider[]
  children?:      React.ReactNode
  /** Button style passthrough */
  style?:         React.CSSProperties
  className?:     string
}

/** `<SignInButton>` — opens the AuthMenu in sign-in mode. */
export function SignInButton(props: AuthButtonProps): React.ReactElement {
  return <AuthButton {...props} action="signin" />
}

/** `<SignUpButton>` — opens the AuthMenu in sign-up mode. */
export function SignUpButton(props: AuthButtonProps): React.ReactElement {
  return <AuthButton {...props} action="signup" />
}

function AuthButton(props: AuthButtonProps & { action: AuthAction }): React.ReactElement {
  const [open, setOpen]     = React.useState(false)
  const [action, setAction] = React.useState<AuthAction>(props.action)
  return (
    <>
      <button type="button" onClick={() => { setAction(props.action); setOpen(true) }} style={props.style ?? S.triggerBtn} className={props.className}>
        {props.children ?? (props.action === 'signin' ? 'Sign in' : 'Sign up')}
      </button>
      <AuthMenu
        {...(props.issuer ? { issuer: props.issuer } : {})}
        publishableKey={props.publishableKey}
        {...(props.providers ? { providers: props.providers } : {})}
        action={action}
        open={open}
        onCancel={() => setOpen(false)}
        onActionChange={setAction}
      />
    </>
  )
}

// --- Styles --------------------------------------------------------------

const S = {
  backdrop: { position: 'fixed' as const, inset: 0, background: 'rgba(14,14,12,0.6)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999, padding: 16 },
  card: { position: 'relative' as const, background: '#fff', borderRadius: 14, padding: '28px 24px 20px', width: 'min(100%, 400px)', boxShadow: '0 12px 36px rgba(0,0,0,0.18)', fontFamily: '-apple-system, system-ui, sans-serif', color: '#0e0e0c' },
  closeBtn: { position: 'absolute' as const, top: 8, right: 10, border: 0, background: 'transparent', fontSize: 24, lineHeight: 1, color: '#8a8a80', cursor: 'pointer', padding: 4 },
  title: { fontSize: 20, fontWeight: 700, margin: '0 0 6px', lineHeight: 1.3 },
  subtitle: { fontSize: 13, color: '#6a6a62', margin: '0 0 18px', lineHeight: 1.4 },
  continueBtn: { display: 'flex', width: '100%', alignItems: 'center', gap: 12, padding: '10px 12px', background: '#f8f6f0', border: '1px solid #e8e5df', borderRadius: 10, cursor: 'pointer', marginBottom: 14, fontFamily: 'inherit', fontSize: 14, textAlign: 'left' as const },
  avatarInline: { width: 36, height: 36, borderRadius: '50%', background: '#0f6e56', color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 13, fontWeight: 700, flexShrink: 0 },
  continueMeta: { flex: 1, minWidth: 0 },
  continueName: { fontSize: 14, fontWeight: 600, color: '#0e0e0c', overflow: 'hidden' as const, textOverflow: 'ellipsis' as const, whiteSpace: 'nowrap' as const },
  continueEmail: { fontSize: 12, color: '#6a6a62', overflow: 'hidden' as const, textOverflow: 'ellipsis' as const, whiteSpace: 'nowrap' as const },
  chevron: { color: '#8a8a80', fontSize: 16 },
  divider: { display: 'flex', alignItems: 'center', gap: 10, color: '#8a8a80', fontSize: 11, textTransform: 'uppercase' as const, letterSpacing: '0.08em', margin: '14px 0' },
  providerBtn: { display: 'flex', width: '100%', alignItems: 'center', gap: 10, padding: '11px 14px', border: '1px solid #d8d5cd', background: '#fff', color: '#0e0e0c', borderRadius: 10, cursor: 'pointer', fontFamily: 'inherit', fontSize: 14, fontWeight: 500, marginBottom: 8 },
  err: { marginTop: 10, padding: '8px 10px', background: '#fef2f2', border: '1px solid #fecaca', color: '#991b1b', borderRadius: 8, fontSize: 12 },
  footer: { fontSize: 12, color: '#6a6a62', textAlign: 'center' as const, marginTop: 18, paddingTop: 14, borderTop: '1px solid #e8e5df' },
  crossLink: { background: 'transparent', border: 0, color: '#0f6e56', fontWeight: 600, cursor: 'pointer', padding: 0, fontSize: 'inherit', fontFamily: 'inherit', textDecoration: 'underline' },
  triggerBtn: { padding: '9px 16px', background: '#0e0e0c', color: '#fff', border: 0, borderRadius: 10, cursor: 'pointer', fontSize: 14, fontWeight: 600, fontFamily: 'inherit' },
}

// Framework-agnostic core of HeadloProviderV2's auth logic. Runs in any JS
// context (React, Vue, vanilla). Extracted so both the React provider AND
// the future PROP service (headlo-auth) can share one implementation.
//
// Owns:
//   - sessionStorage access token (per-tab, survives navigation)
//   - localStorage user profile cache (cross-tab)
//   - IndexedDB DPoP key pair (extractable:false, cross-tab; managed by ./dpop)
//   - Refresh timer, in-flight refresh dedupe
//   - BroadcastChannel for cross-tab signout
//
// External surface = HeadloProviderV2's internal methods verbatim. The provider
// news up an instance and delegates. Consumers see zero behavior change.
//
// Design: claude/propCode/headloAuthService.md § 2.1.

import { generateCodeVerifier, generateCodeChallenge } from './pkce'
import { getOrCreateKeyPair, getExistingKeyPair, clearKeyPair, dpopFetch } from './dpop'
import type { HeadloUser, SignInOptions } from './types'

const VERIFIER_KEY      = 'headlo_pkce_verifier'
const USER_CACHE_KEY    = 'headlo_auth_user'          // shared with v1 provider
const SESSION_TOKEN_KEY = 'headlo_auth_v2_token'      // sessionStorage; per-tab; v2-only
const REFRESH_LEAD_MS   = 10 * 1000                   // refresh when < 10s left
const BROADCAST_CHANNEL = 'headlo_auth'               // shared with v1
const DEBUG_LOG_KEY     = 'headlo_auth_v2_debug_log'
const DEBUG_LOG_MAX     = 200

// ─── Persistent log — writes to localStorage as a ring buffer ───────────

type PersistedLog = { ts: number; msg: string; data?: Record<string, unknown> }
function persistLog(entry: PersistedLog): void {
  try {
    const raw = localStorage.getItem(DEBUG_LOG_KEY)
    const arr: PersistedLog[] = raw ? JSON.parse(raw) : []
    arr.push(entry)
    const trimmed = arr.length > DEBUG_LOG_MAX ? arr.slice(-DEBUG_LOG_MAX) : arr
    localStorage.setItem(DEBUG_LOG_KEY, JSON.stringify(trimmed))
  } catch { /* localStorage full or unavailable — silently skip */ }
}
function log(msg: string, data?: Record<string, unknown>): void {
  if (data) console.log(`%c[headlo-auth-v2]%c ${msg}`, 'color:#7c3aed;font-weight:bold', 'color:inherit', data)
  else      console.log(`%c[headlo-auth-v2]%c ${msg}`, 'color:#7c3aed;font-weight:bold', 'color:inherit')
  persistLog({ ts: Date.now(), msg, data })
}
function logExternal(msg: string, data?: Record<string, unknown>): void {
  persistLog({ ts: Date.now(), msg, data })
}

// ─── JWT / storage helpers ──────────────────────────────────────────────

function decodeJwtPayload(jwt: string): { sub?: string; email?: string; name?: string; exp?: number; azp?: string } | null {
  try {
    const [, payload] = jwt.split('.')
    if (!payload) return null
    return JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')))
  } catch { return null }
}
function decodeJwtExp(jwt: string): number | null {
  const c = decodeJwtPayload(jwt)
  return c && typeof c.exp === 'number' ? c.exp * 1000 : null
}
function userFromJwt(jwt: string): HeadloUser | null {
  const c = decodeJwtPayload(jwt)
  if (!c?.sub || !c.email) return null
  return { id: c.sub, email: c.email, displayName: c.name ?? null }
}
function readCachedUser(): HeadloUser | null {
  try {
    const raw = localStorage.getItem(USER_CACHE_KEY)
    if (!raw) return null
    const u = JSON.parse(raw) as HeadloUser
    return u.id && u.email ? u : null
  } catch { return null }
}
function writeCachedUser(u: HeadloUser): void {
  try { localStorage.setItem(USER_CACHE_KEY, JSON.stringify(u)) } catch {}
}
function clearCachedUser(): void {
  try { localStorage.removeItem(USER_CACHE_KEY) } catch {}
}
function readSessionToken(): string | null {
  try { return sessionStorage.getItem(SESSION_TOKEN_KEY) } catch { return null }
}
function writeSessionToken(token: string): void {
  try {
    sessionStorage.setItem(SESSION_TOKEN_KEY, token)
    const readback = sessionStorage.getItem(SESSION_TOKEN_KEY)
    if (readback !== token) {
      const msg = `⚠️ sessionStorage write verify FAILED — write:${token.length}b readback:${readback?.length ?? 'null'}`
      console.warn(`%c[headlo-auth-v2]%c ${msg}`, 'color:#7c3aed;font-weight:bold', 'color:inherit')
      logExternal(msg)
    } else {
      const msg = `💾 Wrote + verified sessionStorage (${token.length}b, key=${SESSION_TOKEN_KEY})`
      console.log(`%c[headlo-auth-v2]%c ${msg}`, 'color:#7c3aed;font-weight:bold', 'color:inherit')
      logExternal(msg)
    }
  } catch (e) {
    const msg = `💥 sessionStorage.setItem THREW: ${String(e)}`
    console.error(`%c[headlo-auth-v2]%c ${msg}`, 'color:#7c3aed;font-weight:bold', 'color:inherit', e)
    logExternal(msg)
  }
}
function clearSessionToken(): void {
  try {
    sessionStorage.removeItem(SESSION_TOKEN_KEY)
    const msg = `🗑️ Cleared sessionStorage token`
    console.log(`%c[headlo-auth-v2]%c ${msg}`, 'color:#7c3aed;font-weight:bold', 'color:inherit')
    logExternal(msg)
  } catch {}
}

// ─── Public API ─────────────────────────────────────────────────────────

export interface HeadloAuthClientV2Config {
  publishableKey:             string
  issuer:                     string
  signInForceRedirectUrl?:    string
  signInFallbackRedirectUrl?: string
}

export interface AuthStateV2 {
  isLoaded:   boolean
  isSignedIn: boolean
  user:       HeadloUser | null
  token:      string | null
}

export type AuthStateV2Listener = (state: AuthStateV2) => void

// Cross-instance state-sync event. Fires on `window` whenever ANY HeadloAuthClientV2
// on the page updates its state. Each instance listens for it and mirrors the
// external state locally — without re-dispatching, to prevent loops.
//
// Payload includes `sourceInstanceId` so an instance can identify (and skip)
// its own emissions. See applyExternalState / emitBridge for the flow.
const AUTH_CHANGE_EVENT = 'headlo:auth:change'

interface AuthChangeEventDetail extends AuthStateV2 {
  sourceInstanceId: string
}

export class HeadloAuthClientV2 {
  private config:      HeadloAuthClientV2Config
  private _user:       HeadloUser | null
  private _token:      string | null
  private _isLoaded:   boolean
  private inFlight:    Promise<string | null> | null = null
  private channel:     BroadcastChannel | null       = null
  private listeners:   Set<AuthStateV2Listener>        = new Set()

  // Per-instance identifier for cross-instance CustomEvent sync. Generated
  // once in the constructor; used to skip own dispatches on receive so a
  // client doesn't re-process its own events.
  private instanceId:  string
  // Bound handler so add/removeEventListener see the same reference.
  private boundExternalChange: ((e: Event) => void) | null = null

  constructor(config: HeadloAuthClientV2Config) {
    this.config = config
    this.instanceId = (typeof crypto !== 'undefined' && crypto.randomUUID)
      ? crypto.randomUUID()
      : Math.random().toString(36).slice(2) + Date.now().toString(36)
    // Hydrate synchronously from storage — matches provider's useState
    // initializers so first paint shows correct signed-in state without a
    // network round trip.
    //
    // Only paint signed-in when we have BOTH a session token (per-tab) AND
    // a cached user profile. No token = fresh tab or private window; treat
    // as signed-out even if a profile cache from another tab is present.
    // Do NOT clear the profile cache here — that would sign the user out
    // in EVERY tab.
    this._token    = readSessionToken()
    this._user     = this._token ? readCachedUser() : null
    this._isLoaded = this._token !== null && this._user !== null
  }

  // Kick off async init. Provider calls this in a useEffect; vanilla
  // consumers call after `new`. Idempotent — repeated calls are cheap.
  async init(): Promise<void> {
    log(`🚀 HeadloAuthClientV2 init`, {
      issuer:         this.config.issuer,
      publishableKey: this.config.publishableKey.slice(0, 12) + '…',
    })
    const params = new URLSearchParams(window.location.search)
    const code = params.get('code')

    if (code) {
      log(`🔑 Found ?code= in URL — exchanging PKCE + registering DPoP key`)
      await this.handleCallback(code)
      const clean = new URL(window.location.href)
      clean.searchParams.delete('code')
      clean.searchParams.delete('state')
      window.history.replaceState({}, '', clean.toString())
    } else if (this._token) {
      // Fresh-token fast path — if cached token has > REFRESH_LEAD_MS left,
      // trust it and skip the network round-trip. Dramatically reduces
      // refresh traffic on rapid navigation.
      const expMs = decodeJwtExp(this._token)
      if (expMs && expMs - Date.now() > REFRESH_LEAD_MS) {
        const secLeft = Math.floor((expMs - Date.now()) / 1000)
        log(`♻️  Token still fresh (${secLeft}s left) — using cached, skipping refresh`)
      } else {
        log(`♻️  Token near/past expiry — validating with silent refresh`)
        await this.refreshAccessToken()
      }
    } else {
      // No session token in this tab — but the DPoP key may still be in
      // IndexedDB (shared across tabs) from a prior sign-in. Try to
      // resurrect via /oauth/dpop/mint.
      log(`💤 No cached token — attempting resurrection from DPoP key`)
      await this.mintFromDpopKey()
    }
    this._isLoaded = true
    this.emit()

    // BroadcastChannel for cross-tab signout.
    this.channel = typeof BroadcastChannel === 'function'
      ? new BroadcastChannel(BROADCAST_CHANNEL)
      : null
    if (this.channel) {
      this.channel.onmessage = (e: MessageEvent) => {
        if (e.data === 'signout') {
          log(`📡 BroadcastChannel: signout from another tab`)
          this.clearSession()
        }
      }
    }

    // Cross-instance sync — listen for state changes from other
    // HeadloAuthClientV2 instances on the same page (React provider,
    // headlo-auth PROP service, third-party direct instantiation).
    // Design: claude/propCode/headloAuthService.md § 6.5.
    if (typeof window !== 'undefined') {
      this.boundExternalChange = (e: Event) => this.handleExternalChange(e as CustomEvent)
      window.addEventListener(AUTH_CHANGE_EVENT, this.boundExternalChange)
    }
  }

  // Cleanup — close BroadcastChannel + unhook the cross-instance listener.
  // Idempotent.
  destroy(): void {
    this.channel?.close()
    this.channel = null
    if (this.boundExternalChange && typeof window !== 'undefined') {
      window.removeEventListener(AUTH_CHANGE_EVENT, this.boundExternalChange)
      this.boundExternalChange = null
    }
  }

  // ─── State readers ────────────────────────────────────────────────────

  getState(): AuthStateV2 {
    return {
      isLoaded:   this._isLoaded,
      isSignedIn: !!this._user,
      user:       this._user,
      token:      this._token,
    }
  }
  getUser():     HeadloUser | null { return this._user }
  isSignedIn(): boolean            { return !!this._user }
  isLoaded():   boolean            { return this._isLoaded }

  onChange(cb: AuthStateV2Listener): () => void {
    this.listeners.add(cb)
    return () => { this.listeners.delete(cb) }
  }

  // Emit local + dispatch cross-instance CustomEvent. Called from every
  // state mutation that originated INSIDE this instance (sign-in, refresh,
  // sign-out, mint, clearSession). External-origin changes route through
  // notifyLocal() only — never dispatch, to prevent loops.
  private emit(): void {
    const s = this.getState()
    this.notifyLocal(s)
    if (typeof window !== 'undefined') {
      const detail: AuthChangeEventDetail = { ...s, sourceInstanceId: this.instanceId }
      window.dispatchEvent(new CustomEvent(AUTH_CHANGE_EVENT, { detail }))
    }
  }

  // Fire local subscribers only — no cross-instance dispatch. Used when
  // applying state that arrived FROM another instance's event (we already
  // know about it; re-dispatching would ping-pong forever).
  private notifyLocal(s: AuthStateV2): void {
    this.listeners.forEach(cb => { try { cb(s) } catch (e) { console.error('[headlo-auth-v2] listener threw:', e) } })
  }

  // Cross-instance event handler. Skip our own emissions (sourceInstanceId
  // match), otherwise apply the external state to our in-memory fields and
  // notify local subscribers. Does NOT re-dispatch — that's what breaks the
  // loop.
  private handleExternalChange(e: CustomEvent<AuthChangeEventDetail>): void {
    const detail = e.detail
    if (!detail || detail.sourceInstanceId === this.instanceId) return
    // Only mutate if state actually differs — avoid spurious re-renders.
    if (this._token === detail.token && this._user?.id === detail.user?.id && this._isLoaded === detail.isLoaded) return
    log(`🔗 Cross-instance sync — applying state from ${detail.sourceInstanceId.slice(0, 8)}…`, {
      signedIn: detail.isSignedIn,
      user:     detail.user?.email ?? null,
    })
    this._token    = detail.token
    this._user     = detail.user
    this._isLoaded = detail.isLoaded
    this.notifyLocal(this.getState())
  }

  // ─── Public methods ───────────────────────────────────────────────────

  async getToken(): Promise<string | null> {
    if (!this._token) return null
    const expMs = decodeJwtExp(this._token)
    if (expMs && expMs - Date.now() < REFRESH_LEAD_MS) {
      log(`🔍 getToken() — token expiring soon, refreshing first`)
      return this.refreshAccessToken()
    }
    return this._token
  }

  // Authenticated fetch with a fresh DPoP proof per call. Consumers hit
  // any Headlo backend endpoint that expects Authorization: Bearer + DPoP
  // (all v2-scoped MCP tools, /oauth/dpop/* endpoints, DPoP-enforced data
  // API endpoints per A.5.1) through this helper — no need to touch
  // signDpopProof / dpopFetch primitives directly.
  //
  // Retrieves the IndexedDB-stored extractable:false keypair, gets a fresh
  // access token (auto-refreshes if near expiry), signs a per-request proof
  // for (method, url), and dispatches. Throws if not signed in or if the
  // DPoP key is missing (session was signed out but token cache is stale).
  async dpopFetch(url: string, init: RequestInit = {}): Promise<Response> {
    const token = await this.getToken()
    if (!token) throw new Error('not signed in — call signIn() first')
    const keyPair = await getExistingKeyPair()
    if (!keyPair) throw new Error('no DPoP key in IndexedDB — session may have been signed out')

    const method  = ((init.method as string | undefined) ?? 'GET').toUpperCase()
    const headers = init.headers as Record<string, string> | undefined

    return dpopFetch(url, {
      method,
      keyPair,
      accessToken: token,
      headers,
      body:        init.body as BodyInit | null | undefined,
    })
  }

  async signIn(opts?: SignInOptions): Promise<void> {
    log(`🚪 signIn() — generating PKCE + redirecting`)
    const verifier  = generateCodeVerifier()
    const challenge = await generateCodeChallenge(verifier)
    localStorage.setItem(VERIFIER_KEY, verifier)

    const url = new URL(`${this.config.issuer}/oauth/authorize`, window.location.origin)
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('client_id',     this.config.publishableKey)
    const target = opts?.forceRedirectUrl
      ?? this.config.signInForceRedirectUrl
      ?? this.config.signInFallbackRedirectUrl
    const redirectUri = target
      ? window.location.origin + target
      : window.location.origin + window.location.pathname
    url.searchParams.set('redirect_uri',          redirectUri)
    url.searchParams.set('code_challenge',        challenge)
    url.searchParams.set('code_challenge_method', 'S256')
    url.searchParams.set('scope',                 'openid email profile')

    window.location.href = url.toString()
  }

  async signOut(): Promise<void> {
    log(`🚪 signOut() — revoking DPoP + clearing local state`)
    // Best-effort revoke — fire and forget, don't block UX
    const currentToken = this._token
    if (currentToken) {
      const keyPair = await getOrCreateKeyPair().catch(() => null)
      if (keyPair) {
        const revokeUrl = `${this.config.issuer}/oauth/dpop/revoke`
        dpopFetch(revokeUrl, {
          method:      'POST',
          keyPair,
          accessToken: currentToken,
          headers:     { 'Content-Type': 'application/json' },
          body:        JSON.stringify({ client_id: this.config.publishableKey }),
        }).catch(() => {})
      }
    }
    this.clearSession()
    this.channel?.postMessage('signout')
  }

  // ─── Internals — moved verbatim from HeadloProviderV2 ─────────────────

  private async handleCallback(code: string): Promise<void> {
    const verifier = localStorage.getItem(VERIFIER_KEY)
    if (!verifier) return
    localStorage.removeItem(VERIFIER_KEY)

    // Step 1: standard PKCE exchange
    const tokenRes = await fetch(`${this.config.issuer}/oauth/token`, {
      method:      'POST',
      credentials: 'include',
      headers:     { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'authorization_code',
        code,
        redirect_uri:  window.location.origin + window.location.pathname,
        client_id:     this.config.publishableKey,
        code_verifier: verifier,
      }),
    })
    if (!tokenRes.ok) {
      log(`❌ PKCE token exchange failed`, { status: tokenRes.status })
      return
    }
    const { access_token: bootstrapToken } = await tokenRes.json() as { access_token: string }
    log(`✅ PKCE exchange complete — bootstrap access token issued`)

    // Step 2: generate DPoP key + register it
    log(`🔐 Registering DPoP key with /oauth/dpop/register`)
    const keyPair = await getOrCreateKeyPair()
    const registerUrl = `${this.config.issuer}/oauth/dpop/register`
    const regRes = await dpopFetch(registerUrl, {
      method:      'POST',
      keyPair,
      accessToken: bootstrapToken,
      headers:     { 'Content-Type': 'application/json' },
      body:        JSON.stringify({ client_id: this.config.publishableKey }),
    })
    if (!regRes.ok) {
      log(`❌ DPoP registration failed`, { status: regRes.status })
      return
    }
    const { access_token: dpopToken } = await regRes.json() as { access_token: string }
    const expMs = decodeJwtExp(dpopToken)
    log(`✅ DPoP registered — session bound to key`, {
      tokenLife: expMs ? `${Math.floor((expMs - Date.now()) / 1000)}s` : '?',
    })

    this.setTokenAndUser(dpopToken)
  }

  private async refreshAccessToken(): Promise<string | null> {
    if (this.inFlight) {
      log(`⏸️  Refresh in-flight — returning existing promise`)
      return this.inFlight
    }

    const currentToken = this._token
    if (!currentToken) {
      log(`💤 No access token to refresh — user must sign in explicitly`)
      return null
    }

    log(`🔄 POST /oauth/token/refresh-dpop`)
    const startMs = Date.now()

    this.inFlight = (async () => {
      try {
        const keyPair = await getOrCreateKeyPair()
        const url = `${this.config.issuer}/oauth/token/refresh-dpop`
        const res = await dpopFetch(url, {
          method:      'POST',
          keyPair,
          accessToken: currentToken,
          headers:     { 'Content-Type': 'application/json' },
          body:        JSON.stringify({ client_id: this.config.publishableKey }),
        })
        const took = Date.now() - startMs

        // Only 401/403 = server explicitly killed this session. Any other
        // non-2xx (5xx, transient) — keep the token in sessionStorage and
        // let the next attempt retry. Stored token is still valid until exp.
        if (res.status === 401 || res.status === 403) {
          log(`❌ /oauth/token/refresh-dpop → ${res.status} — session invalid, signing out`, { tookMs: took })
          this.clearSession()
          return null
        }
        if (!res.ok) {
          log(`⚠️ /oauth/token/refresh-dpop → ${res.status} — transient, keeping session`, { tookMs: took })
          return null
        }

        const { access_token } = await res.json() as { access_token: string }
        const expMs = decodeJwtExp(access_token)
        log(`✅ /oauth/token/refresh-dpop → 200`, {
          tookMs:    took,
          tokenLife: expMs ? `${Math.floor((expMs - Date.now()) / 1000)}s` : '?',
        })
        this.setTokenAndUser(access_token)
        return access_token
      } catch (err) {
        // Network-level failure — most commonly a `TypeError: Failed to fetch`
        // when the browser aborts an in-flight fetch because the user
        // navigated away. Do NOT clear session on abort — token is still
        // valid, next page load retries.
        log(`⚠️ Refresh network error — keeping session (may be page navigation)`, { error: String(err) })
        return null
      }
    })()

    try { return await this.inFlight }
    finally { this.inFlight = null }
  }

  private async mintFromDpopKey(): Promise<string | null> {
    log(`🔮 Attempting resurrection via /oauth/dpop/mint`)
    const startMs = Date.now()

    const keyPair = await getExistingKeyPair()
    if (!keyPair) {
      log(`💤 No DPoP key in IndexedDB — nothing to resurrect`)
      return null
    }

    try {
      const url = `${this.config.issuer}/oauth/dpop/mint`
      const res = await dpopFetch(url, {
        method:  'POST',
        keyPair,
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify({ client_id: this.config.publishableKey }),
      })
      const took = Date.now() - startMs

      if (res.status === 401 || res.status === 403) {
        log(`❌ /oauth/dpop/mint → ${res.status} — key revoked, clearing local`, { tookMs: took })
        this.clearSession()
        return null
      }
      if (!res.ok) {
        log(`⚠️ /oauth/dpop/mint → ${res.status} — transient, keeping key`, { tookMs: took })
        return null
      }

      const { access_token } = await res.json() as { access_token: string }
      const expMs = decodeJwtExp(access_token)
      log(`✅ /oauth/dpop/mint → 200 — session resurrected`, {
        tookMs:    took,
        tokenLife: expMs ? `${Math.floor((expMs - Date.now()) / 1000)}s` : '?',
      })
      this.setTokenAndUser(access_token)
      return access_token
    } catch (err) {
      log(`⚠️ Mint network error — keeping key (may be page navigation)`, { error: String(err) })
      return null
    }
  }

  // Single write path for token + user cache — used by handleCallback,
  // refreshAccessToken, mintFromDpopKey. Emits state change to subscribers.
  private setTokenAndUser(token: string): void {
    this._token = token
    writeSessionToken(token)
    const u = userFromJwt(token)
    if (u) {
      this._user = u
      writeCachedUser(u)
    }
    this.emit()
  }

  private clearSession(): void {
    // Capture caller stack so unexpected clearSession invocations are
    // traceable (BroadcastChannel signout leaks, spurious refresh
    // failures, etc.). Trim to first few frames — we only need who called.
    const stack = new Error().stack?.split('\n').slice(1, 5).join(' | ') ?? '?'
    console.trace('[headlo-auth-v2] clearSession() called — stack trace')
    log(`🧹 Session cleared — caller: ${stack}`)
    this._token = null
    this._user  = null
    clearSessionToken()
    clearCachedUser()
    void clearKeyPair()
    this.emit()
  }
}

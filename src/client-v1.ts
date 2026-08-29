// Framework-agnostic core of HeadloProvider (v1)'s auth logic. Sibling to
// HeadloAuthClient (v2, in ./client.ts) — same shape, different transport.
//
// v1 uses HttpOnly refresh cookies (headlo_refresh); v2 uses DPoP keys in
// IndexedDB. Consumers pick per-page based on which auth model fits.
//
// Owns:
//   - Access token in MEMORY ONLY (never localStorage/sessionStorage)
//   - localStorage user profile cache (paints signed-in UI on first render)
//   - Refresh flow via cookie (credentials:'include')
//   - Cross-tab BroadcastChannel for signout coordination
//   - Cross-instance CustomEvent bridge (headlo:auth:change) so v1 and v2
//     clients on the same page stay in sync
//
// External surface = HeadloProvider's internal methods verbatim. The
// provider news up an instance and delegates. Consumers see zero behavior
// change.
//
// Design: claude/propCode/headloAuthService.md § 2.1 (extraction principle).

import { generateCodeVerifier, generateCodeChallenge } from './pkce'
import type { HeadloUser, SignInOptions } from './types'

const VERIFIER_KEY      = 'headlo_pkce_verifier'
const USER_CACHE_KEY    = 'headlo_auth_user'       // shared with v2
const REFRESH_LEAD_MS   = 10 * 1000                // refresh when < 10s left
const BROADCAST_CHANNEL = 'headlo_auth'            // shared with v2

// ─── Cross-instance sync event (shared with v2) ─────────────────────────

const AUTH_CHANGE_EVENT = 'headlo:auth:change'

interface AuthChangeEventDetail {
  isLoaded:         boolean
  isSignedIn:       boolean
  user:             HeadloUser | null
  token:            string | null
  sourceInstanceId: string
}

// ─── Log helpers ────────────────────────────────────────────────────────

function log(msg: string, data?: Record<string, unknown>): void {
  if (data) console.log(`%c[headlo-auth]%c ${msg}`, 'color:#5dcaa5;font-weight:bold', 'color:inherit', data)
  else      console.log(`%c[headlo-auth]%c ${msg}`, 'color:#5dcaa5;font-weight:bold', 'color:inherit')
}

function fmtSeconds(ms: number): string {
  const s = Math.floor(ms / 1000)
  if (s < 60)   return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s`
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
}

// ─── JWT / storage helpers ──────────────────────────────────────────────

function decodeJwtPayload(jwt: string): { sub?: string; email?: string; name?: string; exp?: number } | null {
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
    if (!raw) {
      console.log('[headlo-auth] 💾 No cached user — first paint will show Loading… until /oauth/refresh returns')
      return null
    }
    const u = JSON.parse(raw) as HeadloUser
    if (!u.id || !u.email) {
      console.log('[headlo-auth] 💾 Cached user malformed — ignoring')
      return null
    }
    console.log('[headlo-auth] 💾 Hydrated from localStorage cache — signed-in UI paints instantly', { email: u.email, id: u.id })
    return u
  } catch { return null }
}
function writeCachedUser(u: HeadloUser): void {
  try {
    localStorage.setItem(USER_CACHE_KEY, JSON.stringify(u))
    console.log('[headlo-auth] 💾 Cached user profile → next reload will paint instantly', { email: u.email, id: u.id })
  } catch {}
}
function clearCachedUser(): void {
  try {
    if (localStorage.getItem(USER_CACHE_KEY)) {
      localStorage.removeItem(USER_CACHE_KEY)
      console.log('[headlo-auth] 💾 Cleared cached user profile')
    }
  } catch {}
}

// ─── Public API ─────────────────────────────────────────────────────────

export interface HeadloAuthClientV1Config {
  publishableKey:             string
  issuer:                     string
  signInForceRedirectUrl?:    string
  signInFallbackRedirectUrl?: string
}

export interface AuthStateV1 {
  isLoaded:   boolean
  isSignedIn: boolean
  user:       HeadloUser | null
  token:      string | null
}

export type AuthStateV1Listener = (state: AuthStateV1) => void

export class HeadloAuthClientV1 {
  private config:    HeadloAuthClientV1Config
  private _user:     HeadloUser | null
  private _token:    string | null       = null
  private _isLoaded: boolean
  private inFlight:  Promise<string | null> | null = null
  private channel:   BroadcastChannel | null       = null
  private listeners: Set<AuthStateV1Listener>      = new Set()

  // Cross-instance sync — matches v2 client's bridge. Instance id skips
  // own dispatches to prevent loops.
  private instanceId:  string
  private boundExternalChange: ((e: Event) => void) | null = null

  constructor(config: HeadloAuthClientV1Config) {
    this.config = config
    this.instanceId = (typeof crypto !== 'undefined' && crypto.randomUUID)
      ? crypto.randomUUID()
      : Math.random().toString(36).slice(2) + Date.now().toString(36)
    // Hydrate synchronously from localStorage — matches provider's useState
    // initializers so first paint shows signed-in UI without network round trip.
    // Unlike v2, we don't require a sessionStorage token: v1 has no client-side
    // token persistence — the cookie is the source of truth and background
    // refresh confirms.
    this._user     = readCachedUser()
    this._isLoaded = this._user !== null
  }

  async init(): Promise<void> {
    log(`🚀 HeadloAuthClientV1 init`, {
      issuer:         this.config.issuer,
      publishableKey: this.config.publishableKey.slice(0, 12) + '…',
    })
    const params = new URLSearchParams(window.location.search)
    const code = params.get('code')

    if (code) {
      log(`🔑 Found ?code= in URL — exchanging PKCE auth code for tokens`)
      await this.handleCallback(code)
      const clean = new URL(window.location.href)
      clean.searchParams.delete('code')
      clean.searchParams.delete('state')
      window.history.replaceState({}, '', clean.toString())
    } else {
      log(`🔍 No PKCE code — trying silent refresh (will succeed if cookie present)`)
      await this.refreshAccessToken()
    }
    this._isLoaded = true
    log(`✨ HeadloAuthClientV1 isLoaded=true`)
    this.emit()

    // Cross-tab signout via BroadcastChannel (shared with v2 — signout in
    // either version signs out the other).
    this.channel = typeof BroadcastChannel === 'function'
      ? new BroadcastChannel(BROADCAST_CHANNEL)
      : null
    if (this.channel) {
      this.channel.onmessage = (e: MessageEvent) => {
        if (e.data === 'signout') {
          log(`📡 BroadcastChannel: another tab signed out — clearing local session`)
          this.clearSession()
        }
      }
    }

    // Cross-instance sync — listen for state changes from other clients on
    // the same page (React provider, PROP service, another version).
    if (typeof window !== 'undefined') {
      this.boundExternalChange = (e: Event) => this.handleExternalChange(e as CustomEvent)
      window.addEventListener(AUTH_CHANGE_EVENT, this.boundExternalChange)
    }
  }

  destroy(): void {
    this.channel?.close()
    this.channel = null
    if (this.boundExternalChange && typeof window !== 'undefined') {
      window.removeEventListener(AUTH_CHANGE_EVENT, this.boundExternalChange)
      this.boundExternalChange = null
    }
  }

  // ─── State readers ────────────────────────────────────────────────────

  getState(): AuthStateV1 {
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

  onChange(cb: AuthStateV1Listener): () => void {
    this.listeners.add(cb)
    return () => { this.listeners.delete(cb) }
  }

  // Emit local + dispatch cross-instance CustomEvent. Called from every
  // state mutation originating INSIDE this instance.
  private emit(): void {
    const s = this.getState()
    this.notifyLocal(s)
    if (typeof window !== 'undefined') {
      const detail: AuthChangeEventDetail = { ...s, sourceInstanceId: this.instanceId }
      window.dispatchEvent(new CustomEvent(AUTH_CHANGE_EVENT, { detail }))
    }
  }
  // Fire local subscribers only — no cross-instance dispatch. Used when
  // applying state that arrived FROM another instance's event.
  private notifyLocal(s: AuthStateV1): void {
    this.listeners.forEach(cb => { try { cb(s) } catch (e) { console.error('[headlo-auth] listener threw:', e) } })
  }
  private handleExternalChange(e: CustomEvent<AuthChangeEventDetail>): void {
    const detail = e.detail
    if (!detail || detail.sourceInstanceId === this.instanceId) return
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
    if (!this._token) {
      log(`🔍 getToken() — no token in memory, returning null`)
      return null
    }
    const expMs = decodeJwtExp(this._token)
    if (expMs && expMs - Date.now() < REFRESH_LEAD_MS) {
      log(`🔍 getToken() — token has < ${fmtSeconds(REFRESH_LEAD_MS)} left, refreshing first`, {
        timeLeft: fmtSeconds(expMs - Date.now()),
      })
      return this.refreshAccessToken()
    }
    log(`🔍 getToken() — returning cached token`, {
      timeLeft: expMs ? fmtSeconds(expMs - Date.now()) : '?',
    })
    return this._token
  }

  async signIn(opts?: SignInOptions): Promise<void> {
    log(`🚪 signIn() — generating PKCE + redirecting to /oauth/authorize`)
    const verifier  = generateCodeVerifier()
    const challenge = await generateCodeChallenge(verifier)
    localStorage.setItem(VERIFIER_KEY, verifier)

    const url = new URL(`${this.config.issuer}/oauth/authorize`, window.location.origin)
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('client_id',     this.config.publishableKey)
    // Resolution order mirrors Clerk:
    //   per-call forceRedirectUrl > signInForceRedirectUrl > signInFallbackRedirectUrl > current page
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
    log(`🚪 signOut() — POST /oauth/signout + clearing local session`)
    // Best-effort revoke + cookie clear via server
    fetch(`${this.config.issuer}/oauth/signout`, {
      method:      'POST',
      credentials: 'include',
    }).catch(() => {})
    this.clearSession()
    log(`📡 Broadcasting signout to other tabs`)
    this.channel?.postMessage('signout')
  }

  // ─── Internals — moved verbatim from HeadloProvider ────────────────

  private async refreshAccessToken(): Promise<string | null> {
    if (this.inFlight) {
      log(`⏸️  Refresh already in-flight — returning existing promise (concurrency guard)`)
      return this.inFlight
    }

    log(`🔄 POST /oauth/refresh — sending refresh cookie`)
    const startMs = Date.now()

    this.inFlight = (async () => {
      // client_id required — worker enforces refresh token's `azp` claim
      // matches the caller. Prevents a compromised sibling app (same
      // auth issuer) from silently minting tokens for this app's user.
      const res = await fetch(`${this.config.issuer}/oauth/refresh?client_id=${encodeURIComponent(this.config.publishableKey)}`, {
        method:      'POST',
        credentials: 'include',  // send headlo_refresh HttpOnly cookie
      })
      const took = Date.now() - startMs
      // 204 = no refresh cookie at all (anonymous). Not an error; stay signed out.
      if (res.status === 204) {
        log(`💤 /oauth/refresh → 204 (no cookie, anonymous) — staying signed out`, { tookMs: took })
        this.clearSession()
        return null
      }
      if (!res.ok) {
        log(`❌ /oauth/refresh → ${res.status} — session invalid, signing out`, { tookMs: took })
        this.clearSession()
        return null
      }

      const { access_token } = await res.json() as { access_token: string }
      const expMs = decodeJwtExp(access_token)
      log(`✅ /oauth/refresh → 200 — got new access token`, {
        tookMs:       took,
        newTokenLife: expMs ? fmtSeconds(expMs - Date.now()) : '?',
        newExpAt:     expMs ? new Date(expMs).toLocaleTimeString() : '?',
      })
      this.setTokenAndUser(access_token)
      return access_token
    })()

    try { return await this.inFlight }
    finally { this.inFlight = null }
  }

  private async handleCallback(code: string): Promise<void> {
    const verifier = localStorage.getItem(VERIFIER_KEY)
    if (!verifier) return
    localStorage.removeItem(VERIFIER_KEY)

    const res = await fetch(`${this.config.issuer}/oauth/token`, {
      method:      'POST',
      credentials: 'include',   // accept Set-Cookie for headlo_refresh
      headers:     { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'authorization_code',
        code,
        redirect_uri:  window.location.origin + window.location.pathname,
        client_id:     this.config.publishableKey,
        code_verifier: verifier,
      }),
    })
    if (!res.ok) return

    const { access_token } = await res.json() as { access_token: string }
    const expMs = decodeJwtExp(access_token)
    log(`✅ PKCE exchange complete — session created`, {
      tokenLife: expMs ? fmtSeconds(expMs - Date.now()) : '?',
      expAt:     expMs ? new Date(expMs).toLocaleTimeString() : '?',
    })
    this.setTokenAndUser(access_token)
  }

  // Single write path for token + user cache. Emits state change to subscribers.
  private setTokenAndUser(token: string): void {
    this._token = token
    const u = userFromJwt(token)
    if (u) {
      if (!this._user) log(`👤 Hydrated user from JWT claims`, { email: u.email, id: u.id })
      this._user = u
      writeCachedUser(u)
    }
    this.emit()
  }

  private clearSession(): void {
    log(`🧹 Session cleared — user signed out (in this tab)`)
    this._token = null
    this._user  = null
    clearCachedUser()
    this.emit()
  }
}

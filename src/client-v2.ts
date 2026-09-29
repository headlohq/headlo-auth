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
import { getOrCreateKeyPair, getExistingKeyPair, clearKeyPair, dpopFetch, exportPublicJwk, computeJwkThumbprint } from './dpop'
import type { HeadloUser, SignInOptions } from './types'

// Base key names — used as-is when a client has no storageKey (backward-
// compat default), suffixed with `:${storageKey}` when a client opts into
// multi-instance mode. Multi-instance is what enables one renderer to hold
// separate auth sessions per environment (auth.headlo.com vs
// auth-local.headlo.com), each with its own token, PKCE verifier, user
// cache and cross-tab broadcast channel.
const VERIFIER_KEY_BASE      = 'headlo_pkce_verifier'
const USER_CACHE_KEY_BASE    = 'headlo_auth_user'          // shared with v1 provider (unsuffixed only)
const SESSION_TOKEN_KEY_BASE = 'headlo_auth_v2_token'      // sessionStorage; per-tab; v2-only
const BROADCAST_CHANNEL_BASE = 'headlo_auth'               // shared with v1 (unsuffixed only)
const REFRESH_LEAD_MS        = 10 * 1000                   // refresh when < 10s left
const BOOTSTRAP_TIMEOUT_MS   = 8 * 1000                    // rescue: force isLoaded=true if init() stalls
const DEBUG_LOG_KEY          = 'headlo_auth_v2_debug_log'  // debug log is process-wide, not per-instance
const DEBUG_LOG_MAX          = 200

function suffix(base: string, storageKey: string | undefined): string {
  return storageKey ? `${base}:${storageKey}` : base
}

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

function decodeJwtPayload(jwt: string): { sub?: string; email?: string; name?: string; exp?: number; azp?: string; cnf?: { jkt?: string } } | null {
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
function decodeJwtCnfJkt(jwt: string): string | null {
  const c = decodeJwtPayload(jwt)
  return c?.cnf?.jkt ?? null
}
function userFromJwt(jwt: string): HeadloUser | null {
  const c = decodeJwtPayload(jwt)
  if (!c?.sub || !c.email) return null
  return { id: c.sub, email: c.email, displayName: c.name ?? null }
}
// All storage helpers now take an optional `storageKey` so a single tab can
// hold N independent sessions. Undefined preserves the pre-multi-env keys
// so shipped users don't lose their session on upgrade.
function readCachedUser(storageKey?: string): HeadloUser | null {
  try {
    const raw = localStorage.getItem(suffix(USER_CACHE_KEY_BASE, storageKey))
    if (!raw) return null
    const u = JSON.parse(raw) as HeadloUser
    return u.id && u.email ? u : null
  } catch { return null }
}
function writeCachedUser(u: HeadloUser, storageKey?: string): void {
  try { localStorage.setItem(suffix(USER_CACHE_KEY_BASE, storageKey), JSON.stringify(u)) } catch {}
}
function clearCachedUser(storageKey?: string): void {
  try { localStorage.removeItem(suffix(USER_CACHE_KEY_BASE, storageKey)) } catch {}
}
function readSessionToken(storageKey?: string): string | null {
  try { return sessionStorage.getItem(suffix(SESSION_TOKEN_KEY_BASE, storageKey)) } catch { return null }
}
function writeSessionToken(token: string, storageKey?: string): void {
  const key = suffix(SESSION_TOKEN_KEY_BASE, storageKey)
  try {
    sessionStorage.setItem(key, token)
    const readback = sessionStorage.getItem(key)
    if (readback !== token) {
      const msg = `⚠️ sessionStorage write verify FAILED — write:${token.length}b readback:${readback?.length ?? 'null'}`
      console.warn(`%c[headlo-auth-v2]%c ${msg}`, 'color:#7c3aed;font-weight:bold', 'color:inherit')
      logExternal(msg)
    } else {
      const msg = `💾 Wrote + verified sessionStorage (${token.length}b, key=${key})`
      console.log(`%c[headlo-auth-v2]%c ${msg}`, 'color:#7c3aed;font-weight:bold', 'color:inherit')
      logExternal(msg)
    }
  } catch (e) {
    const msg = `💥 sessionStorage.setItem THREW: ${String(e)}`
    console.error(`%c[headlo-auth-v2]%c ${msg}`, 'color:#7c3aed;font-weight:bold', 'color:inherit', e)
    logExternal(msg)
  }
}
function clearSessionToken(storageKey?: string): void {
  try {
    sessionStorage.removeItem(suffix(SESSION_TOKEN_KEY_BASE, storageKey))
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
  /**
   * Optional platform adapter. Web (default, omitted) uses `window.location`
   * to redirect the tab for sign-in and reads the auth callback from URL
   * query params on init. Non-web hosts (Electron desktop, mobile shells)
   * supply an adapter that overrides those touchpoints — the OAuth callback
   * arrives through a native channel (custom protocol handler, App Link,
   * Universal Link) rather than a browser redirect.
   *
   * See headlo-desktop/src/renderer/desktop-auth-adapter.ts for the canonical
   * Electron implementation. When omitted, behavior is 100% unchanged from
   * the pre-adapter (web-only) implementation — purely additive.
   */
  platformAdapter?:           PlatformAdapter
  /**
   * Unique storage suffix. Enables multiple client instances to coexist in
   * the SAME renderer with independent sessions (session token, PKCE
   * verifier, user cache, cross-tab broadcast channel). Typical use: one
   * client per auth-server domain when the desktop / dashboard wants to
   * sign into local + prod concurrently.
   *
   * When ABSENT (default), the client uses the original unsuffixed storage
   * keys — preserving the pre-multi-env behavior for shipped users so an
   * upgrade doesn't sign anyone out. When PRESENT, every storage key is
   * suffixed with `:${storageKey}`.
   *
   * Recommended values: the auth server's hostname (e.g. `auth.headlo.com`,
   * `auth-local.headlo.com`) so the storage suffix stays stable across
   * different publishable-key rotations within the same env.
   *
   * DPoP key pair in IndexedDB is already scoped by publishableKey in
   * ./dpop — no additional suffixing needed there.
   */
  storageKey?:                string
}

/**
 * Overrides for the web-native touchpoints in HeadloAuthClientV2. Every field
 * is required when supplying an adapter — half-implementations produce
 * inconsistent behavior (e.g. adapter overrides `openAuthUrl` but not
 * `redirectUri` → authorize URL has adapter's redirect_uri, but the token
 * exchange still uses window.location, and the server rejects the mismatch).
 */
export interface PlatformAdapter {
  /**
   * Called instead of `window.location.href = url` when signIn() needs to
   * send the user to the OAuth authorize endpoint. Desktop opens the URL in
   * the system browser via IPC → `shell.openExternal`. Mobile opens an
   * in-app browser tab (SFSafariViewController / Chrome Custom Tabs).
   */
  openAuthUrl:  (url: string) => void | Promise<void>

  /**
   * The `redirect_uri` value sent to `/oauth/authorize` and `/oauth/token`.
   * MUST match one of the client's allowed_redirect_uris on the auth server
   * exactly (Phase 2 exact-URL allowlist), or the server rejects with
   * `redirect_uri not in this client's allowed_redirect_uris`.
   *
   * Desktop example: `'headlo://oauth/callback'`
   * Mobile example:  `'https://auth.headlo.com/oauth/mobile-callback'`
   */
  redirectUri:  string

  /**
   * Subscribe to native callback events. Fires with the auth server's
   * `{ code, state }` when the OS routes the redirect back into the app.
   * Return an unsubscribe function — called on client destroy() and on
   * repeat init() calls.
   *
   * When present, `init()` will NOT read `window.location.search` for
   * `code` — the adapter is the exclusive callback source. Wire this to
   * whatever native channel the platform uses (Electron IPC event,
   * Capacitor deep-link plugin, React Native Linking listener, etc.).
   */
  subscribeToCallback: (handler: (params: { code: string; state: string }) => void) => (() => void)
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
  version:          'v1' | 'v2'
  sourceInstanceId: string
  // Multi-env scope — instances with different storageKey are DIFFERENT
  // sessions (env-local vs env-prod). Cross-instance sync only applies
  // within the same storageKey. `null` matches the pre-multi-env default
  // (no suffix), so single-provider setups still cross-sync as before.
  storageKey:       string | null
}

export class HeadloAuthClientV2 {
  private config:      HeadloAuthClientV2Config
  private _user:       HeadloUser | null
  private _token:      string | null
  private _isLoaded:   boolean
  private inFlight:    Promise<string | null> | null = null
  private channel:     BroadcastChannel | null       = null
  private listeners:   Set<AuthStateV2Listener>        = new Set()

  // Platform-adapter callback subscription. Populated in init() when config
  // has a platformAdapter; cleared in destroy(). Guarded against
  // re-subscription so repeated init() calls don't stack listeners.
  private _adapterUnsubscribe: (() => void) | null = null

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
    this._token    = readSessionToken(config.storageKey)
    this._user     = this._token ? readCachedUser(config.storageKey) : null
    this._isLoaded = this._token !== null && this._user !== null
  }

  // Kick off async init. Provider calls this in a useEffect; vanilla
  // consumers call after `new`. Idempotent — repeated calls are cheap.
  async init(): Promise<void> {
    log(`🚀 HeadloAuthClientV2 init`, {
      issuer:         this.config.issuer,
      publishableKey: this.config.publishableKey.slice(0, 12) + '…',
      platform:       this.config.platformAdapter ? 'adapter' : 'web',
    })

    // Platform-adapter mode: callback arrives via a native channel (IPC deep
    // link, Capacitor plugin, etc.). Subscribe once here; the handler fires
    // whenever the OS routes back into the app. init() DOES NOT touch
    // window.location — the renderer's URL is app-shell (e.g.
    // http://localhost:5175/index.html) and never carries OAuth params.
    if (this.config.platformAdapter) {
      // Guard against re-subscription across repeated init() calls.
      if (!this._adapterUnsubscribe) {
        this._adapterUnsubscribe = this.config.platformAdapter.subscribeToCallback(({ code }) => {
          log(`🔑 Adapter callback — exchanging PKCE + registering DPoP key`)
          void this.handleCallback(code)
        })
      }
      // Fall through to token-validity checks below (which may sign the user
      // in from an existing session without ever needing a fresh callback).
    }

    // Rescue timer: if any await in the bootstrap block below stalls
    // (network hang on /oauth/dpop/mint or /oauth/token/refresh-dpop, stuck
    // IndexedDB open, unresolvable PKCE exchange), _isLoaded never flips true
    // → both <SignedIn> and <SignedOut> render null → the page shows no auth
    // controls at all with no error signal. Force _isLoaded=true after
    // BOOTSTRAP_TIMEOUT_MS so consumers at minimum see signed-out UI and the
    // user can retry. No-op if bootstrap finished normally (guarded by
    // !_isLoaded check). The finally block clears the timer and applies the
    // same rescue if the bootstrap body threw before its own isLoaded flip.
    const stallTimer = setTimeout(() => {
      if (!this._isLoaded) {
        log(`⏱️  Bootstrap stalled >${BOOTSTRAP_TIMEOUT_MS}ms — forcing isLoaded=true so UI can render sign-in`)
        this._isLoaded = true
        this.emit()
      }
    }, BOOTSTRAP_TIMEOUT_MS)

    try {

    // Web-native path: look for ?code= in the current URL. Skipped entirely
    // when an adapter is present.
    const code = this.config.platformAdapter
      ? null
      : new URLSearchParams(window.location.search).get('code')

    if (code) {
      log(`🔑 Found ?code= in URL — exchanging PKCE + registering DPoP key`)
      await this.handleCallback(code)
      const clean = new URL(window.location.href)
      clean.searchParams.delete('code')
      clean.searchParams.delete('state')
      window.history.replaceState({}, '', clean.toString())
    } else if (this._token) {
      // Guard: a DPoP-bound token (cnf.jkt present) is useless without its
      // referenced key in IndexedDB. If the key was cleared out of band —
      // storage eviction, DevTools delete, mid-clear-reload race, cross-tab
      // signout leak — the token is dead weight and every authFetch will
      // throw "no DPoP key". Detect that state at init and clear cleanly
      // instead of letting a stale token silently survive across reloads.
      //
      // Extended 2026-09-02: also verify the stored key's thumbprint actually
      // MATCHES the token's cnf.jkt. Same-DB-different-key case surfaces as
      // DPOP_JKT_MISMATCH at server side otherwise (token signed against one
      // key, IDB has a different key from a later re-sign-in). Now caught
      // and cleared at init instead of leaking a mismatch to the server.
      const cnfJkt = decodeJwtCnfJkt(this._token)
      if (cnfJkt) {
        const keyPair = await getExistingKeyPair(this.config.publishableKey)
        if (!keyPair) {
          log(`⚠️  Cached token references missing DPoP key (jkt=${cnfJkt.slice(0, 8)}…) — clearing session`)
          this.clearSession()
          this._isLoaded = true
          this.emit()
          return
        }
        // Verify the stored key actually matches the token's binding
        try {
          const jwk = await exportPublicJwk(keyPair)
          const storedJkt = await computeJwkThumbprint(jwk)
          if (storedJkt !== cnfJkt) {
            log(`⚠️  Cached token cnf.jkt=${cnfJkt.slice(0, 8)}… doesn't match IndexedDB key jkt=${storedJkt.slice(0, 8)}… — clearing session`)
            this.clearSession()
            this._isLoaded = true
            this.emit()
            return
          }
        } catch (e) {
          log(`⚠️  Could not compute stored key thumbprint — clearing session as precaution`, { error: String(e) })
          this.clearSession()
          this._isLoaded = true
          this.emit()
          return
        }
      }

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

    } finally {
      clearTimeout(stallTimer)
      // Belt-and-suspenders: if any await above threw before its own
      // isLoaded flip, still force the flag so consumers aren't stuck on a
      // blank render forever.
      if (!this._isLoaded) {
        log(`⚠️  Bootstrap threw before isLoaded flip — forcing true so UI can render`)
        this._isLoaded = true
        this.emit()
      }
    }

    // BroadcastChannel for cross-tab signout — pk-scoped so signing out of
    // pk_A in tab 1 doesn't kill pk_B's session in tab 2 (multi-pk SSO).
    //
    // Legacy string payload ('signout') tolerated for back-compat with
    // any pre-Phase-1 tab that's still open at upgrade time — it signs
    // out ALL pks in the receiving tab (matches pre-Phase-1 behavior).
    this.channel = typeof BroadcastChannel === 'function'
      ? new BroadcastChannel(suffix(BROADCAST_CHANNEL_BASE, this.config.storageKey))
      : null
    if (this.channel) {
      this.channel.onmessage = (e: MessageEvent) => {
        // Two payload shapes: pre-Phase-1 string 'signout' (all-pks kill)
        // OR Phase-1 object { type: 'signout', pk } (this-pk-only kill).
        const data = e.data
        if (data === 'signout') {
          log(`📡 BroadcastChannel: legacy signout from another tab — clearing session`)
          this.clearSession()
        } else if (data && typeof data === 'object' && data.type === 'signout' && data.pk === this.config.publishableKey) {
          log(`📡 BroadcastChannel: signout for pk=${data.pk} from another tab`)
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
    if (this._adapterUnsubscribe) {
      this._adapterUnsubscribe()
      this._adapterUnsubscribe = null
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
      const detail: AuthChangeEventDetail = {
        version:          'v2',
        ...s,
        sourceInstanceId: this.instanceId,
        storageKey:       this.config.storageKey ?? null,
      }
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
    // Version guard — v1 clients also dispatch on this event name for
    // external listeners. Ignoring v1 state here prevents v1's null state
    // from overwriting v2's signed-in state on pages that mount both
    // providers. See "close-tab + open-in-new-tab" bug notes in client-v1.ts.
    if (detail.version !== 'v2') return
    // Multi-env scope guard — only cross-sync between instances with the
    // same storageKey. Different envs are separate sessions; without this
    // filter, signing out of prod would sign you out of dev too.
    // Null == null still matches (pre-multi-env single-provider default).
    const mine = this.config.storageKey ?? null
    if (detail.storageKey !== mine) return
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
  //
  // On 401, force-refreshes the token and retries once. Closes the narrow
  // stale-token race where getToken()'s REFRESH_LEAD_MS margin + clock skew
  // + network latency lets a squeaking-past-expiry token slip out. Retry
  // only fires when the server disagrees with our expiry view — a legitimate
  // 401 (revoked session, wrong scope) is surfaced after refresh returns the
  // same 401 or refresh itself fails.
  async dpopFetch(url: string, init: RequestInit = {}): Promise<Response> {
    const keyPair = await getExistingKeyPair(this.config.publishableKey)
    if (!keyPair) throw new Error('no DPoP key in IndexedDB — session may have been signed out')

    const method  = ((init.method as string | undefined) ?? 'GET').toUpperCase()
    const headers = init.headers as Record<string, string> | undefined
    const body    = init.body as BodyInit | null | undefined

    const dispatch = async (token: string): Promise<Response> =>
      dpopFetch(url, { method, keyPair, accessToken: token, headers, body })

    const firstToken = await this.getToken()
    if (!firstToken) throw new Error('not signed in — call signIn() first')
    const res = await dispatch(firstToken)

    // Retry-on-401: server says the token is bad. Force a refresh (bypasses
    // getToken()'s lead-time check) and retry once with the fresh token.
    // Only 401 triggers retry — 403/5xx are surfaced as-is.
    if (res.status === 401) {
      log(`🔁 dpopFetch 401 — forcing refresh + retry`, { url })
      const refreshed = await this.refreshAccessToken()
      if (refreshed && refreshed !== firstToken) {
        return dispatch(refreshed)
      }
      log(`⚠️ dpopFetch retry skipped — refresh returned ${refreshed === null ? 'null' : 'same token'}`)
    }

    return res
  }

  async signIn(opts?: SignInOptions): Promise<void> {
    log(`🚪 signIn() — generating PKCE + ${this.config.platformAdapter ? 'opening system browser' : 'redirecting'}`)
    const verifier  = generateCodeVerifier()
    const challenge = await generateCodeChallenge(verifier)
    localStorage.setItem(suffix(VERIFIER_KEY_BASE, this.config.storageKey), verifier)

    // Non-web hosts get the adapter's fixed redirect_uri; web hosts fall back
    // to the current pathname (or an explicit forceRedirectUrl override).
    const redirectUri = this.config.platformAdapter
      ? this.config.platformAdapter.redirectUri
      : (() => {
          const target = opts?.forceRedirectUrl
            ?? this.config.signInForceRedirectUrl
            ?? this.config.signInFallbackRedirectUrl
          return target
            ? window.location.origin + target
            : window.location.origin + window.location.pathname
        })()

    const authorizeBase = this.config.platformAdapter
      ? this.config.issuer
      : window.location.origin
    const url = new URL(`${this.config.issuer}/oauth/authorize`, authorizeBase)
    url.searchParams.set('response_type', 'code')
    url.searchParams.set('client_id',     this.config.publishableKey)
    url.searchParams.set('redirect_uri',          redirectUri)
    url.searchParams.set('code_challenge',        challenge)
    url.searchParams.set('code_challenge_method', 'S256')
    url.searchParams.set('scope',                 'openid email profile')

    // OIDC prompt=login → server skips silent-SSO short-circuit and renders
    // the login form even when a valid `headlo_session` cookie exists on
    // the auth origin. See routes/oauth.ts:911-947. Opt-in via
    // SignInOptions.forceLogin — default preserves existing auto-login UX.
    if (opts?.forceLogin) {
      url.searchParams.set('prompt', 'login')
    }

    // Log the full authorize URL so debug pages (persistent log viewer on
    // /abs-test) can show exactly where the user is being sent. localStorage
    // write is synchronous → lands before the navigation kicks in below.
    // Safe to log: client_id is a public pk_live_, code_challenge is a
    // public one-way hash of the verifier, no secrets in the URL.
    log(`🔗 authorize URL → ${url.toString()}`, {
      redirect_uri: redirectUri,
      client_id:    this.config.publishableKey,
    })

    if (this.config.platformAdapter) {
      // Adapter opens the URL in whatever native surface the platform uses —
      // system browser (Electron), in-app browser (mobile). Renderer stays
      // put; callback arrives via subscribeToCallback later.
      await this.config.platformAdapter.openAuthUrl(url.toString())
    } else {
      // Web-native: hard-navigate the tab.
      window.location.href = url.toString()
    }
  }

  async signOut(): Promise<void> {
    log(`🚪 signOut() — revoking DPoP + clearing local state`)
    // Best-effort revoke — fire and forget, don't block UX
    const currentToken = this._token
    if (currentToken) {
      const keyPair = await getOrCreateKeyPair(this.config.publishableKey).catch(() => null)
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
    // Broadcast the pk-scoped signout to other tabs on the same origin.
    // Object payload — old string-tolerant receivers still work; new
    // per-pk receivers ignore this if their pk doesn't match.
    this.channel?.postMessage({ type: 'signout', pk: this.config.publishableKey })
  }

  // ─── Internals — moved verbatim from HeadloProviderV2 ─────────────────

  private async handleCallback(code: string): Promise<void> {
    const verifierKey = suffix(VERIFIER_KEY_BASE, this.config.storageKey)
    const verifier = localStorage.getItem(verifierKey)
    if (!verifier) return
    localStorage.removeItem(verifierKey)

    // Step 1: standard PKCE exchange. redirect_uri MUST match what signIn()
    // sent to /oauth/authorize — the auth server compares them and rejects
    // mismatches. In web mode that's the tab's current URL; in adapter mode
    // it's the adapter's fixed redirectUri (e.g. headlo://oauth/callback).
    const redirectUri = this.config.platformAdapter
      ? this.config.platformAdapter.redirectUri
      : window.location.origin + window.location.pathname
    const tokenRes = await fetch(`${this.config.issuer}/oauth/token`, {
      method:      'POST',
      credentials: 'include',
      headers:     { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type:    'authorization_code',
        code,
        redirect_uri:  redirectUri,
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
    const keyPair = await getOrCreateKeyPair(this.config.publishableKey)
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
        const keyPair = await getOrCreateKeyPair(this.config.publishableKey)
        const url = `${this.config.issuer}/oauth/token/refresh-dpop`
        const res = await dpopFetch(url, {
          method:      'POST',
          keyPair,
          accessToken: currentToken,
          headers:     { 'Content-Type': 'application/json' },
          body:        JSON.stringify({ client_id: this.config.publishableKey }),
        })
        const took = Date.now() - startMs

        // Match the discrimination pattern used by mintFromDpopKey — only
        // DPOP_KEY_REVOKED means server explicitly killed the session and
        // we should clear local state. Other 401/403 error codes (WRONG_PK,
        // UNREGISTERED, JKT_MISMATCH) mean the session is fine but this
        // specific refresh attempt won't work — usually because the caller
        // switched pk mid-session, or the DPoP key rotated. Keep the token
        // in sessionStorage; a future refresh under the original pk will
        // succeed or the user will sign in fresh.
        if (res.status === 401 || res.status === 403) {
          const body = await res.json().catch(() => null) as { error?: string } | null
          const errCode = typeof body?.error === 'string' ? body.error : ''
          if (errCode === 'DPOP_KEY_REVOKED') {
            log(`❌ /oauth/token/refresh-dpop → ${res.status} DPOP_KEY_REVOKED — clearing local`, { tookMs: took })
            this.clearSession()
            return null
          }
          log(`⚠️ /oauth/token/refresh-dpop → ${res.status} ${errCode || 'unspecified'} — keeping session (refresh failed but token cache preserved)`, { tookMs: took })
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

    const keyPair = await getExistingKeyPair(this.config.publishableKey)
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
        // Server distinguishes three failure modes (see /oauth/dpop/mint):
        //   DPOP_KEY_REVOKED       — server explicitly killed the key.
        //                            Local state is dead weight, clear it.
        //   DPOP_KEY_WRONG_PK      — key valid, wrong pk on THIS page.
        //                            Common in dev when pages use different
        //                            pks against the same shared IDB.
        //                            Keep session; a future mint on the
        //                            correct pk will resurrect.
        //   DPOP_KEY_UNREGISTERED  — server doesn't know this key. Could
        //                            be dev reset, transient DB glitch,
        //                            or genuinely wiped. Prefer keeping
        //                            local state over aggressive signout.
        // Only REVOKED triggers clearSession — everything else preserves
        // local key + session, logs a warning, and returns null so the
        // caller sees "not signed in for now" without losing state.
        const body = await res.json().catch(() => null) as { error?: string } | null
        const errCode = typeof body?.error === 'string' ? body.error : ''
        if (errCode === 'DPOP_KEY_REVOKED') {
          log(`❌ /oauth/dpop/mint → ${res.status} DPOP_KEY_REVOKED — clearing local`, { tookMs: took })
          this.clearSession()
          return null
        }
        log(`⚠️ /oauth/dpop/mint → ${res.status} ${errCode || 'unspecified'} — keeping session`, { tookMs: took })
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
    writeSessionToken(token, this.config.storageKey)
    const u = userFromJwt(token)
    if (u) {
      this._user = u
      writeCachedUser(u, this.config.storageKey)
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
    clearSessionToken(this.config.storageKey)
    clearCachedUser(this.config.storageKey)
    // Only clear THIS pk's key — other apps on the same origin (multi-pk
    // SSO) keep their sessions intact. Pre-Phase-1 fallback: also clear
    // the legacy 'session_key' slot so a stale pre-migration key doesn't
    // linger in IDB forever on rare edge paths.
    void clearKeyPair(this.config.publishableKey)
    void clearKeyPair()   // legacy back-compat — cleanup only, harmless if already gone
    this.emit()
  }
}

// headlo-auth v1 — PROP service client_js source.
//
// Paste this file's contents into the dashboard editor at
// /dashboard/prop/services/headlo-auth (Impl App tab → v1 → Client JS).
// Save triggers bundle compile (config inlined as __HEADLO_SERVICE_CONFIG)
// + KV cache bust; subsequent /v1/prop/service/headlo-auth/v1/bundle fetches
// serve the fresh output.
//
// Wraps the framework-agnostic HeadloAuthClientV1 class (loaded lazily from
// /v1/prop/auth-runtime/v1/bundle) as PROP service actions. Sibling to
// v2/client.ts — same shape, different transport underneath (cookie refresh
// instead of DPoP). Design: claude/propCode/headloAuthService.md § 5.1.
//
// Actions exposed (matching contract at ../contract.json):
//   getToken, getUser, isSignedIn, signIn, signOut, authFetch
//
// The client is a MODULE SINGLETON — one per page, shared across every widget
// and consumer that binds to headlo-auth:v1:*. Cross-instance sync with the
// React HeadloProviderV1 (if present on the same page) is handled by the
// shared `headlo:auth:change` CustomEvent bridge inside HeadloAuthClientV1
// itself (see headlo-auth/src/client-v1.ts § handleExternalChange).

declare const __HEADLO_SERVICE_CONFIG: {
  authIssuer:        string
  publishableKey:    string
  defaultReturnUrl?: string
}

const CONFIG = __HEADLO_SERVICE_CONFIG

// Lazy-load the runtime bundle. Memoized — subsequent action calls reuse
// the same client instance. Concurrent first-time calls share the same
// in-flight load Promise (no double-init).
let _clientPromise: Promise<any> | null = null

function getClient(): Promise<any> {
  if (_clientPromise) return _clientPromise
  _clientPromise = (async () => {
    // Prefer window globals so a customer embedding this service on their own
    // page can override the compile-time app config without creating their
    // own headlo-auth app. Precedence:
    //   1. window.__headlo_api_url / window.__headlo_prop_key   (page-level)
    //   2. Baked-in __HEADLO_SERVICE_CONFIG (dashboard-set per-app defaults)
    // React consumers set the globals via main.tsx (from env vars); vanilla
    // HTML pages set them with a <script> tag before loading widgets.
    const apiUrl         = (window as any).__headlo_api_url  || CONFIG.authIssuer     || ''
    const publishableKey = (window as any).__headlo_prop_key || CONFIG.publishableKey || ''
    // If runtime already loaded (React provider on the same page, or a manual
    // <script> tag), skip the fetch — reuse the existing global.
    if (!(window as any).__headlo_auth_runtime_v1) {
      await new Promise<void>((resolve, reject) => {
        const s = document.createElement('script')
        s.src = `${apiUrl}/v1/prop/auth-runtime/v1/bundle`
        s.async = true
        s.onload  = () => resolve()
        s.onerror = () => reject(new Error('failed to load auth runtime bundle'))
        document.head.appendChild(s)
      })
    }
    const rt = (window as any).__headlo_auth_runtime_v1
    if (!rt || typeof rt.create !== 'function') {
      throw new Error('__headlo_auth_runtime_v1 missing after script load')
    }
    const client = rt.create({
      issuer:                    apiUrl,
      publishableKey:            publishableKey,
      signInFallbackRedirectUrl: CONFIG.defaultReturnUrl,
    })
    await client.init()
    return client
  })()
  return _clientPromise
}

export default {
  async getToken() {
    const c = await getClient()
    const token = await c.getToken()
    return { token, expiresAt: token ? null : null }
  },

  async getUser() {
    const c = await getClient()
    const u = c.getUser()
    if (!u) return { userId: null, email: null, displayName: null, verified: false }
    return {
      userId:      u.id,
      email:       u.email,
      displayName: u.displayName,
      // v1 tokens are only issued after verified sign-in — every user reaching
      // here has verified their email at OAuth time.
      verified:    true,
    }
  },

  async isSignedIn() {
    const c = await getClient()
    return { signedIn: c.isSignedIn() }
  },

  async signIn(args: { returnUrl?: string }) {
    const c = await getClient()
    // Normalise returnUrl: the underlying client expects a PATH (it prepends
    // window.location.origin to build redirect_uri). PROP callers naturally
    // reach for `window.location.href` and get a duplicated origin. Strip it
    // here so both shapes work.
    const raw = args?.returnUrl ?? CONFIG.defaultReturnUrl
    const returnPath = raw && /^https?:\/\//i.test(raw)
      ? new URL(raw).pathname + new URL(raw).search
      : raw
    // client.signIn triggers window.location.href internally — returns void.
    // We return { url: null } to satisfy the contract; the navigation has
    // already happened by the time the promise settles.
    await c.signIn({ forceRedirectUrl: returnPath })
    return { url: null }
  },

  async signOut() {
    const c = await getClient()
    await c.signOut()
    return { signedOut: true }
  },

  async authFetch(args: { url: string; options?: RequestInit }) {
    const c = await getClient()
    const token = await c.getToken()
    if (!token) throw new Error('not signed in')

    // v1 is Bearer-only — no DPoP proof. Cookie-based refresh sits in the
    // browser layer, transparent to caller. If the request needs the refresh
    // cookie to travel (e.g. proxied through auth issuer), pass
    // `credentials: 'include'` in `options`.
    const res = await fetch(args.url, {
      ...(args.options ?? {}),
      headers: {
        ...(args.options?.headers ?? {}),
        Authorization: `Bearer ${token}`,
      },
    })
    const ct = res.headers.get('content-type') ?? ''
    const body = ct.includes('application/json')
      ? await res.json().catch(() => null)
      : await res.text()
    const headers: Record<string, string> = {}
    res.headers.forEach((v, k) => { headers[k] = v })
    return { status: res.status, ok: res.ok, body, headers }
  },
}

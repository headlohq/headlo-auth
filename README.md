# Headlo Auth SDK

React auth SDK for [Headlo](https://www.headlo.com). Wraps a [headlo-oauth](https://www.headlo.com) issuer and exposes a **Clerk-compatible surface** — `useAuth`, `useUser`, drop-in sign-in / sign-out buttons, and an `authFetch` helper.

Two provider variants ship in the same package:

- **`HeadloProvider`** — cookie-based refresh (v1). Works best on Headlo-owned or subdomain-bridged deployments.
- **`HeadloProviderV2`** — DPoP-anchored, cookie-less (as of 0.2.0). Works on customer bare domains including iOS Safari. First hosted auth provider shipping browser-side DPoP.

Migration from Clerk is a one-line import change. See "Which provider should I use?" below.

## Install

```bash
npm install headlo-auth
```

---

## Quick start — `HeadloProvider` (v1, cookie-based)

Best default for React apps deployed on Headlo-owned subdomains or with subdomain-bridged custom domains.

```tsx
import {
  HeadloProvider,
  useAuth,
  useUser,
  SignInButton,
  SignOutButton,
} from 'headlo-auth'

function App() {
  return (
    <HeadloProvider publishableKey="pk_live_xxx">
      <Nav />
    </HeadloProvider>
  )
}

function Nav() {
  const { isLoaded, isSignedIn } = useAuth()
  const user = useUser()

  if (!isLoaded) return null         // hide UI until auth state is known
  if (!isSignedIn) return <SignInButton />

  return (
    <>
      <span>{user?.email}</span>
      <SignOutButton />
    </>
  )
}
```

## Quick start — `HeadloProviderV2` (DPoP, cookie-less)

Same API, DPoP under the hood. Recommended for React apps deployed on customer bare domains where iOS Safari support matters.

```tsx
import {
  HeadloProviderV2,    // ← the only difference from v1
  useAuth,
  useUser,
  SignInButton,
  SignOutButton,
} from 'headlo-auth'

function App() {
  return (
    <HeadloProviderV2 publishableKey="pk_live_xxx">
      <Nav />                        // ← identical to v1 example
    </HeadloProviderV2>
  )
}
```

All hooks (`useAuth`, `useUser`, `useAuthFetch`) and components (`SignInButton`, `SignOutButton`, `SignedIn`, `SignedOut`) work identically with both providers.

## Which provider should I use?

| Deployment | Recommended | Why |
|---|---|---|
| React app on your own subdomain (`app.acme.com`) | `HeadloProviderV2` | No DNS setup needed, works on iOS Safari |
| React app on Headlo-owned subdomain (`*.headlo.com`) | Either works | v1 has established production track record; v2 has stronger XSS posture |
| React app on `auth-acme.acme.com` CNAMEd to Headlo | Either works | v1 refresh cookie works first-party via subdomain |
| Chrome-only internal tool | Either works | Both work identically in Chrome |
| Vue / Svelte / vanilla HTML | Use PROP tag (see [headlo-client-react demo](https://github.com/headlohq/headlo-client-react)) | React-only for now; framework-neutral form (Phase B) coming when signaled |

**When in doubt for new projects: use `HeadloProviderV2`.** It's the future-proof default — cookie-less, works everywhere, stronger security posture.

---

## `<HeadloProvider>`

| Prop | Type | Description |
|---|---|---|
| `publishableKey` | `string` | Your Headlo publishable key (`pk_live_xxx`) — required |
| `issuer` | `string` | OAuth server base URL. Defaults to `https://auth.headlo.com` |
| `signInFallbackRedirectUrl` | `string` | Path to redirect to after sign-in. Defaults to current path. |
| `signUpFallbackRedirectUrl` | `string` | Path to redirect to after sign-up. Defaults to current path. |

### Headlo-managed (default)

```tsx
<HeadloProvider publishableKey="pk_live_xxx">
  {children}
</HeadloProvider>
```

### Self-hosted

```tsx
<HeadloProvider
  publishableKey="pk_live_xxx"
  issuer="https://auth.acme.com"
>
  {children}
</HeadloProvider>
```

---

## Hooks

### `useAuth()`

Returns auth state and methods. Matches Clerk's `useAuth` exactly.

```ts
const { isLoaded, isSignedIn, getToken, signIn, signOut } = useAuth()
```

| Key | Type | Description |
|---|---|---|
| `isLoaded` | `boolean` | Provider has finished initializing (PKCE callback handled or silent refresh attempted) |
| `isSignedIn` | `boolean` | User is authenticated |
| `getToken` | `() => Promise<string \| null>` | Returns a fresh access token. Refreshes automatically if cached one is near expiry. |
| `signIn` | `() => Promise<void>` | Starts the PKCE flow — redirects to the OAuth authorize endpoint |
| `signOut` | `() => Promise<void>` | Clears the session locally and revokes the refresh token server-side |

### `useUser()`

Returns the current user or `null`.

```ts
const user = useUser()
// { id: '...', email: '...', displayName: '...' } | null
```

### Legacy aliases

`useHeadloAuth` and `useHeadloUser` are kept as aliases for backwards compatibility. New code should prefer `useAuth` / `useUser`.

---

## Components

```tsx
<SignInButton>Sign in</SignInButton>
<SignOutButton>Sign out</SignOutButton>
```

Both accept all standard `<button>` props. Default labels are `Sign in` and `Sign out`.

---

## `useAuthFetch()` — fetch with auto-attached Bearer token

A drop-in replacement for `fetch` that automatically calls `getToken()` and adds the `Authorization` header.

```tsx
import { useAuthFetch } from 'headlo-auth'

function MyComponent() {
  const authFetch = useAuthFetch()

  async function save(data) {
    const res = await authFetch('/api/things', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data),
    })
    return res.json()
  }
  // ...
}
```

The returned function is fully fetch-compatible. Token is fetched fresh on every call — never stale.

For non-React use cases, use `createAuthFetch(getToken)` directly:

```ts
import { createAuthFetch } from 'headlo-auth'

const authFetch = createAuthFetch(async () => mySession.accessToken)
await authFetch('/api/foo')
```

---

## Auth flow — v1 (`HeadloProvider`, cookie-based)

`HeadloProvider` implements OAuth 2.0 PKCE with S256 — no client secret required.

### Sign in

1. `signIn()` generates a `code_verifier` + `code_challenge` (S256)
2. Browser navigates to `{issuer}/oauth/authorize?response_type=code&...`
3. User authenticates at the OAuth server's hosted UI
4. Server redirects back with `?code=xxx`
5. Provider exchanges code for access token via `POST {issuer}/oauth/token`
6. Server sets an `HttpOnly` refresh cookie + returns access token in JSON body
7. `isSignedIn = true`, `useUser()` returns the user

### Storage (v1)

| Token | Where | Why |
|---|---|---|
| **Access JWT** (24h) | React state (memory only) | Short-lived; never written to localStorage. Dies with the tab — XSS can't exfiltrate. |
| **Refresh JWT** (30d) | `HttpOnly` cookie `headlo_refresh` | JavaScript cannot read it. Browser sends automatically on `/oauth/refresh`. |

### Refresh (v1)

The access token is refreshed automatically via the HttpOnly refresh cookie:

- **On page load** — silent refresh restores the session if the cookie is present
- **On `getToken()`** — if the cached token is close to expiry, refresh fires first so the caller always gets a fresh token

If the refresh fails (cookie expired or revoked), the session is cleared and the user must sign in again.

### Sign out (v1)

`signOut()`:
1. Calls `POST /oauth/signout` to revoke the refresh token server-side (KV denylist)
2. Clears the cookie via `Set-Cookie: Max-Age=0`
3. Clears local React state
4. Broadcasts to other tabs via `BroadcastChannel` (cross-tab signout)

### Known limitation of v1 — Safari on customer bare domains

The refresh cookie is `SameSite=None; Secure`. Safari ITP (default since 2020), Firefox strict ETP, Brave-Aggressive, and Chrome-post-3PC-deprecation all block cross-origin cookies of this shape. On `acme.com` (a customer domain, third-party to `auth.headlo.com`), silent refresh returns 401 → session dies on every page reload.

Two fixes:

1. **Subdomain-bridged deployment** — customer CNAMEs `auth.acme.com` → Headlo. Cookie becomes first-party. Same pattern Clerk sells as "Satellite Domains," Auth0 as "Custom Domains."
2. **Use `HeadloProviderV2`** (below) — cookie-less by design, no ITP interaction.

---

## Auth flow — v2 (`HeadloProviderV2`, DPoP + cookie-less)

`HeadloProviderV2` replaces the HttpOnly refresh cookie with a **DPoP (RFC 9449) proof-of-possession** model. Same PKCE sign-in flow, different session mechanics after that.

### Sign in

1. Standard PKCE flow (identical to v1) — client gets a bootstrap access token from `/oauth/token`
2. Client generates an ECDSA P-256 key pair via `crypto.subtle.generateKey({ extractable: false })` and stores it in IndexedDB. **The private key is unextractable — even the JS that created it cannot serialize it out.**
3. Client calls `POST /oauth/dpop/register` with the bootstrap token + a DPoP proof signed by the new key
4. Server registers the public key thumbprint and issues a new access token with a `cnf.jkt` claim binding it to the DPoP key
5. Client stores this DPoP-bound access token in `sessionStorage` and discards the bootstrap token

### Storage (v2)

| Token | Where | Why |
|---|---|---|
| **Access JWT** (24h, `cnf.jkt`-bound) | `sessionStorage` (per-tab) | Persists across page reload within a tab. Attacker with stolen token cannot use it without the DPoP private key. |
| **DPoP key pair** (session-lifetime) | `IndexedDB` with `extractable: false` | Shared across tabs of the same origin. JS literally cannot serialize the private key. Effectively "HttpOnly for JavaScript." |
| **User profile** (id/email/name) | `localStorage` | For instant paint on same-tab reload. Not sensitive on its own. |

**No cookies used.** Chrome, Safari desktop, Safari iOS, Firefox, Brave all behave identically.

### Refresh (v2)

Two mechanisms depending on session state:

- **Same tab, token near expiry** — `POST /oauth/token/refresh-dpop`. Requires existing access token as `Authorization: Bearer` + fresh DPoP proof. Server validates both, issues new `cnf.jkt`-bound token.
- **New tab or browser restart** (sessionStorage empty but IndexedDB has key) — `POST /oauth/dpop/mint`. Requires only a valid DPoP proof against a registered key. Server mints a fresh access token bound to the same key. ~500ms round trip. This is the resurrection path that makes "close tab, reopen — still signed in" work.
- **Fresh-token fast path** — if the sessionStorage token has more than 10s of life left, the client skips the network call entirely and hydrates from cache. Zero server traffic on rapid same-tab navigation.

### Sign out (v2)

`signOut()`:
1. Calls `POST /oauth/dpop/revoke` to mark the DPoP key inactive server-side (`is_active = false`)
2. Deletes the DPoP key from IndexedDB
3. Clears sessionStorage access token + localStorage user profile
4. Broadcasts to other tabs via `BroadcastChannel` (they clear their state too)
5. Next `/oauth/dpop/mint` attempt from any tab returns 401 → all tabs signed out

### Why v2 exists — the load-bearing security claim

**With v1 cookies:** XSS can call `fetch(url, { credentials: 'include' })` and make authenticated requests as the user for the lifetime of the refresh cookie. XSS effectively equals full account takeover.

**With v2 DPoP + `extractable: false`:** XSS running RIGHT NOW can still make requests via `crypto.subtle.sign()` (WebCrypto is same-origin available). But XSS cannot exfiltrate the private key to another machine or persist it beyond the current page. **XSS attack window narrows from "session-lifetime" to "current-page-view."** The long-lived credential (the DPoP key) is genuinely unreachable to JavaScript.

Full architecture write-up: [`claude/headlo-auth-anchor-bound-session.md`](https://github.com/headlohq/headlo/blob/master/claude/headlo-auth-anchor-bound-session.md) in the monorepo.

---

## Migration from Clerk

Identical hook names — change one line:

```diff
-import { useAuth, useUser, SignInButton, SignOutButton } from '@clerk/clerk-react'
+import { useAuth, useUser, SignInButton, SignOutButton } from 'headlo-auth'
```

And swap the provider:

```diff
-<ClerkProvider publishableKey={key}>
+<HeadloProvider publishableKey={key}>
```

The shape of `useAuth()` and `useUser()` matches Clerk's:

| Clerk | headlo-auth | Notes |
|---|---|---|
| `<ClerkProvider>` | `<HeadloProvider>` | Same `publishableKey` prop |
| `useAuth()` | `useAuth()` | Returns `isLoaded`, `isSignedIn`, `getToken`, `signOut` |
| `useUser()` | `useUser()` | Returns `{ id, email, displayName }` |
| `<SignInButton>` | `<SignInButton>` | Same usage |
| `<SignOutButton>` | `<SignOutButton>` | Same usage |
| Clerk's `<UserButton>` | Not yet — build it yourself from `useUser` + `signOut` | Coming soon |

---

## White-label

Ship your own auth package wrapping `HeadloProvider`:

```tsx
// packages/auth/src/index.tsx  →  published as @acme/auth
import { HeadloProvider } from 'headlo-auth'

export function AcmeProvider({ children }: { children: React.ReactNode }) {
  return (
    <HeadloProvider
      publishableKey={process.env.ACME_KEY!}
      issuer="https://auth.acme.com"
    >
      {children}
    </HeadloProvider>
  )
}

export {
  useAuth,
  useUser,
  SignInButton,
  SignOutButton,
  useAuthFetch,
} from 'headlo-auth'
```

Consumers install `@acme/auth` and never see `headlo-auth` directly.

---

## Security architecture

### v1 (`HeadloProvider`, cookie-based)

- **Stateless signed refresh JWTs** — refresh token verification is pure cryptography. No database lookup per refresh.
- **KV-backed revocation** — sign-out adds the session ID to a Cloudflare KV denylist (with TTL = remaining JWT life)
- **HttpOnly cookie** — refresh token is JavaScript-immune (XSS-resistant)
- **PKCE S256** — no client secret in the browser
- **24-hour access JWT** — Auth0-compatible default; configurable via `ACCESS_TTL_SECONDS` env var on the worker
- **`azp` claim binding** — refresh tokens bound to the client that minted them; prevents cross-tenant reuse

### v2 (`HeadloProviderV2`, DPoP + cookie-less)

Everything in v1 above, plus:

- **DPoP (RFC 9449) proof-of-possession** — every request to the auth server signed with a per-session ECDSA P-256 key
- **`extractable: false` IndexedDB key** — WebCrypto primitive where JS cannot serialize the private key material; only sign with it
- **Access tokens `cnf.jkt`-bound** — RFC 7800 confirmation claim binding each token to a specific DPoP key thumbprint; XSS-stolen tokens are unusable without the corresponding private key
- **No cross-origin cookies** — works identically on Safari, Firefox strict, Brave, Chrome-with-3PC-off. Verified end-to-end on iOS Safari on customer bare domains.
- **First hosted auth provider shipping browser-side DPoP** (as of 0.2.0) — a security-posture step-up beyond what Clerk / Auth0 / Supabase / Firebase / Cognito ship in their browser SDKs

Full architecture write-ups in the monorepo:
- [`claude/headlo-auth-anchor-bound-session.md`](https://github.com/headlohq/headlo/blob/master/claude/headlo-auth-anchor-bound-session.md) — the ABS design
- [`claude/headlo-auth-abs-build-sequencing.md`](https://github.com/headlohq/headlo/blob/master/claude/headlo-auth-abs-build-sequencing.md) — ship record (Phase A completed 2026-07-26, 14/14 ship criteria met)
- [`claude/headlo-auth-refresh-architecture.md`](https://github.com/headlohq/headlo/blob/master/claude/headlo-auth-refresh-architecture.md) — architectural comparison of v1 vs v2 (piece-by-piece)

---

## License

[Elastic License 2.0](./LICENSE) — © Headlo

Source available. Free for internal use. Production self-hosting requires a commercial license. See [LICENSE](./LICENSE) for full terms.

Built by [Headlo](https://www.headlo.com).

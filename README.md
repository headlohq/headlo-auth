# Headlo Auth SDK

React auth SDK for [Headlo](https://www.headlo.com). Wraps a [headlo-oauth](https://www.headlo.com) issuer and exposes a **Clerk-compatible surface** — `useAuth`, `useUser`, drop-in sign-in / sign-out buttons, and an `authFetch` helper.

Migration from Clerk is a one-line import change.

## Install

```bash
npm install headlo-auth
```

---

## Quick start

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

## Auth flow

`HeadloProvider` implements OAuth 2.0 PKCE with S256 — no client secret required.

### Sign in

1. `signIn()` generates a `code_verifier` + `code_challenge` (S256)
2. Browser navigates to `{issuer}/oauth/authorize?response_type=code&...`
3. User authenticates at the OAuth server's hosted UI
4. Server redirects back with `?code=xxx`
5. Provider exchanges code for access token via `POST {issuer}/oauth/token`
6. Server sets an `HttpOnly` refresh cookie + returns access token in JSON body
7. `isSignedIn = true`, `useUser()` returns the user

### Storage

| Token | Where | Why |
|---|---|---|
| **Access JWT** (24h) | React state (memory only) | Short-lived; never written to localStorage. Dies with the tab — XSS can't exfiltrate. |
| **Refresh JWT** (30d) | `HttpOnly` cookie `headlo_refresh` | JavaScript cannot read it. Browser sends automatically on `/oauth/refresh`. |

### Refresh

The access token is refreshed automatically via the HttpOnly refresh cookie:

- **On page load** — silent refresh restores the session if the cookie is present
- **On `getToken()`** — if the cached token is close to expiry, refresh fires first so the caller always gets a fresh token
- (Optional) **Background timer** — proactive refresh shortly before exp; configurable in the source

If the refresh fails (cookie expired or revoked), the session is cleared and the user must sign in again.

### Sign out

`signOut()`:
1. Calls `POST /oauth/signout` to revoke the refresh token server-side (KV denylist)
2. Clears the cookie via `Set-Cookie: Max-Age=0`
3. Clears local React state
4. Broadcasts to other tabs via `BroadcastChannel` (cross-tab signout)

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

Built on a Phase 3 stateless-session model:

- **Stateless signed refresh JWTs** — refresh token verification is pure cryptography. No database lookup per refresh.
- **KV-backed revocation** — sign-out adds the session ID to a Cloudflare KV denylist (with TTL = remaining JWT life)
- **HttpOnly cookie** — refresh token is JavaScript-immune (XSS-resistant)
- **PKCE S256** — no client secret in the browser
- **24-hour access JWT** — Auth0-compatible default; configurable via `ACCESS_TTL_SECONDS` env var on the worker

See [claude/headlo-prop-oauth.md](https://github.com/headlohq/headlo/blob/main/claude/headlo-prop-oauth.md) for the full architecture write-up (cookies, JWKS, key rotation, performance at scale, etc.).

---

## License

[Elastic License 2.0](./LICENSE) — © Headlo

Source available. Free for internal use. Production self-hosting requires a commercial license. See [LICENSE](./LICENSE) for full terms.

Built by [Headlo](https://www.headlo.com).

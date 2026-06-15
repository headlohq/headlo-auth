# Headlo Auth SDK

React auth SDK for [Headlo](https://www.headlo.com). Wraps a [headlo-oauth](https://www.headlo.com) issuer and exposes a Clerk-compatible surface — `HeadloProvider`, hooks, and drop-in sign-in / sign-out buttons.

## Install

```bash
npm install headlo-auth
```

---

## Usage

```tsx
import { HeadloProvider, useHeadloAuth, useHeadloUser, SignInButton, SignOutButton } from 'headlo-auth'

function App() {
  return (
    <HeadloProvider publishableKey="pk_live_xxx">
      <YourApp />
    </HeadloProvider>
  )
}

function Nav() {
  const { isSignedIn } = useHeadloAuth()
  const user = useHeadloUser()

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

## `HeadloProvider`

| Prop | Type | Description |
|---|---|---|
| `publishableKey` | `string` | Your Headlo publishable key |
| `issuer` | `string` | OAuth server base URL. Defaults to Headlo's managed instance. |

### Option A — Headlo managed (default)

```tsx
<HeadloProvider publishableKey="pk_live_xxx">
  {children}
</HeadloProvider>
```

### Option B — self-hosted

Point `issuer` at your own headlo-oauth instance:

```tsx
<HeadloProvider publishableKey="pk_live_xxx" issuer="https://auth.acme.internal">
  {children}
</HeadloProvider>
```

---

## White-label

Ship your own auth package wrapping `HeadloProvider`:

```tsx
// packages/auth/src/index.tsx  →  published as @acme/auth
import { HeadloProvider } from 'headlo-auth'

export function AcmeProvider({ children }: { children: React.ReactNode }) {
  return (
    <HeadloProvider publishableKey={process.env.ACME_KEY!} issuer="https://auth.acme.com">
      {children}
    </HeadloProvider>
  )
}

export { useHeadloAuth as useAuth, useHeadloUser as useUser, SignInButton, SignOutButton } from 'headlo-auth'
```

Consumers install `@acme/auth` and never see `headlo-auth` directly.

---

## Hooks

### `useHeadloAuth()`

```ts
const { isLoaded, isSignedIn, getToken, signIn, signOut } = useHeadloAuth()
```

| Key | Type | Description |
|---|---|---|
| `isLoaded` | `boolean` | Provider has finished initializing (PKCE callback handled, token restored) |
| `isSignedIn` | `boolean` | User is authenticated |
| `getToken` | `() => Promise<string \| null>` | Returns the current access token |
| `signIn` | `() => Promise<void>` | Starts the PKCE flow — redirects to the issuer's authorize endpoint |
| `signOut` | `() => Promise<void>` | Clears the session |

### `useHeadloUser()`

```ts
const user = useHeadloUser()
// { id, email, displayName } | null
```

---

## Components

```tsx
<SignInButton>Sign in</SignInButton>
<SignOutButton>Sign out</SignOutButton>
```

Both accept all standard `<button>` props. Default labels are `Sign in` and `Sign out`.

---

## Auth flow

`HeadloProvider` implements PKCE S256 — no client secret required:

1. `signIn()` → generates `code_verifier` + `code_challenge` → redirects to `{issuer}/oauth2/authorize`
2. User authenticates at the issuer's login UI
3. Issuer redirects back with `?code=...`
4. Provider exchanges code for access token via `POST {issuer}/oauth2/token`
5. Provider fetches user info from `GET {issuer}/oauth2/userinfo`
6. `isSignedIn = true`, `useHeadloUser()` returns the user

Token is stored in `localStorage`. The callback URL is cleaned from the address bar after exchange.

---

## Migration from Clerk

| Clerk | headlo-auth |
|---|---|
| `<ClerkProvider>` | `<HeadloProvider>` |
| `useAuth()` | `useHeadloAuth()` |
| `useUser()` | `useHeadloUser()` |
| `<SignInButton>` | `<SignInButton>` |
| `<SignOutButton>` | `<SignOutButton>` |

---

## License

[Elastic License 2.0](./LICENSE) — © Headlo

Source available. Free for internal use. Production self-hosting requires a commercial license. See [LICENSE](./LICENSE) for full terms.

Built by [Headlo](https://www.headlo.com).

# headlo-auth PROP service

Source of truth for the `headlo-auth` PROP service registered in the dashboard at `/dashboard/prop/services/headlo-auth`. Files here are the canonical versions — they get pasted into the dashboard editor when creating or updating the service.

**Design spec:** [claude/propCode/headloAuthService.md](../../../claude/propCode/headloAuthService.md)

## Layout

```
prop-service/
└── headlo-auth/            ← Slug folder — this is the `headlo-auth` service
    ├── contract.json       ← Def contract (shared across all apps under this def)
    ├── README.md
    ├── v1/                 ← Cookie-refresh app (HttpOnly headlo_refresh)
    │   ├── config.local.json   ← Local dev config
    │   ├── config.prod.json    ← Prod config
    │   └── client.ts           ← Author-written client_js source (compiled on save)
    └── v2/                 ← DPoP-anchored app (IndexedDB key + sessionStorage token)
        ├── config.local.json
        ├── config.prod.json
        └── client.ts
```

Both apps share the same contract. They differ only in the underlying auth
model: v1 uses HttpOnly refresh cookies; v2 uses DPoP proof-of-possession.
Future vendor bridges (Clerk, Auth0, Firebase) get sibling slug folders next
to `headlo-auth/` at the `prop-service/` level — e.g. `clerk/`, `auth0/`.

## Which version to use

| Use case | Pick |
|---|---|
| Third-party embed on a customer's marketing site | **v2** — cookie-less, immune to Safari third-party cookie restrictions |
| First-party app (same origin as auth issuer) | Either; v1 is simpler, v2 is more resilient |
| Vanilla HTML page needing a signed-in identity | **v2** — no cookie/domain gotchas |
| Existing dashboard app already using `HeadloProviderV1` | v1 (matches the React provider on the page → single client instance shared via CustomEvent bridge) |

Both apps expose the same 6 actions with identical shapes — swap `v1` for `v2` in any `on-*="headlo-auth:vN:*"` action attribute to change the transport without touching consumer code.

## Workflow — creating or updating the service in the dashboard

**One-time (first-time setup):**

1. Open `/dashboard/prop/services` — click "+ New PROP service"
2. Slug: `headlo-auth`. Name: `Headlo Auth`.
3. **Contract tab** — paste [contract.json](./contract.json) as the contract JSON. Save.
4. Click **"Make public"** on the def.
5. **Impl App tab** — click "+ Add app" for each version:
   - **v1 app:** Slug `headlo-auth`, Version `v1`, Name `Headlo Auth (v1 — Cookie refresh)`. Config from [v1/config.local.json](./v1/config.local.json). Save. Make public. Paste [v1/client.ts](./v1/client.ts) into Client JS. Save.
   - **v2 app:** Slug `headlo-auth`, Version `v2`, Name `Headlo Auth (v2 — DPoP)`. Config from [v2/config.local.json](./v2/config.local.json). Save. Make public. Paste [v2/client.ts](./v2/client.ts) into Client JS. Save.

**Iterating (subsequent updates):**

- Edit the file(s) here, commit.
- Paste the updated content into the dashboard editor and save. Save triggers KV cache bust + bundle rebuild.

The dashboard is still the authoritative store (contents live in `prop_service.def` / `prop_service.app` in Postgres). Files here are for version control, code review, and easy replay across environments.

## Consumers

- **HeadloProviderV1 / HeadloProviderV2** (React) — untouched by these services. They continue to work as before.
- **Widgets** binding `on-*="headlo-auth:vN:*"` — automatic via the action-binding resolver.
- **Other PROP services** that want authenticated fetches — load `/v1/prop/service/headlo-auth/vN/bundle` and call `.authFetch({url, options})`.
- **Vanilla HTML** — add `<script src="/v1/prop/service/headlo-auth/vN/bundle">` + a widget bound to `on-*="headlo-auth:vN:*"`.

## Related runtime files

- `../../src/client-v1.ts` — `HeadloAuthClientV1` class (framework-agnostic; cookie refresh)
- `../../src/client-v2.ts` — `HeadloAuthClientV2` class (framework-agnostic; DPoP)
- `../../src/client-runtime-v1.ts` — IIFE entry that publishes `window.__headlo_auth_runtime_v1`
- `../../src/client-runtime-v2.ts` — IIFE entry that publishes `window.__headlo_auth_runtime_v2`
- `../../tsup.runtime.config.ts` — build config for the two IIFEs
- `../../dist/runtime/client-runtime-v1.global.js` — built IIFE served by `GET /v1/prop/auth-runtime/v1/bundle`
- `../../dist/runtime/client-runtime-v2.global.js` — built IIFE served by `GET /v1/prop/auth-runtime/v2/bundle`

## Related worker files

- `headlo-worker/src/routes/prop-auth-runtime.ts` — worker route that serves both IIFEs
- `headlo-worker/wrangler.jsonc` (`rules`) — text loader for the built `.global.js` files

## Verify after deploy

```bash
# Service bundles serve
curl http://127.0.0.1:8787/v1/prop/service/headlo-auth/v1/bundle
curl http://127.0.0.1:8787/v1/prop/service/headlo-auth/v2/bundle

# Runtime bundles serve
curl http://127.0.0.1:8787/v1/prop/auth-runtime/v1/bundle
curl http://127.0.0.1:8787/v1/prop/auth-runtime/v2/bundle
```

Browser sanity check on any page with `window.__headlo_api_url` set. Swap `v1` for `v2` to test the other flavor:

```js
const s = document.createElement('script')
s.src = 'http://127.0.0.1:8787/v1/prop/service/headlo-auth/v1/bundle'
s.onload = async () => {
  const svc = window.__headlo_service_headlo_auth_v1
  console.log('signedIn:', await svc.isSignedIn())
  console.log('user:',     await svc.getUser())
}
document.head.appendChild(s)
```

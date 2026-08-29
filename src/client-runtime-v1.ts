// Browser IIFE runtime — bundled separately from the React SDK. Exposes
// HeadloAuthClientV1 via a window global so any consumer that loads this
// file via a <script> tag can new-up a v1 client (cookie-refresh, no DPoP)
// without importing anything.
//
// Sibling to client-runtime-v2.ts (v2 — DPoP). Both publish separate globals
// (__headlo_auth_runtime_v1 vs __headlo_auth_runtime_v2). Pages that use
// only one version don't download the other.
//
// Consumers:
//   - headlo-auth PROP service v1 (loads /v1/prop/auth-runtime/v1/bundle in
//     its client_js on first getAuth() call)
//   - Vanilla HTML pages that want cookie-based auth without a framework
//   - Third-party integrators wiring headlo-auth into non-React JS
//
// Design: claude/propCode/headloAuthService.md § 7 (Runtime bundle).
//
// Built by tsup in IIFE format via tsup.runtime.config.ts alongside v2.
// Compiled output publishes:
//   window.__headlo_auth_runtime_v1 = {
//     create: (config) => new HeadloAuthClientV1(config)
//   }

import { HeadloAuthClientV1, type HeadloAuthClientV1Config } from './client-v1'

// The clean API we want consumers to see:
//   window.__headlo_auth_runtime_v1.create({...})
//   window.__headlo_auth_runtime_v1.HeadloAuthClientV1
const runtime = {
  create: (config: HeadloAuthClientV1Config) => new HeadloAuthClientV1(config),
  // Expose the class too — for `instanceof` checks in debug tooling.
  HeadloAuthClientV1,
}

// tsup IIFE format wraps the default export in `{__esModule:true, default:...}`
// under the configured globalName (kept private in tsup config). Side effect
// assigns the clean object to `window.__headlo_auth_runtime_v1` during
// IIFE evaluation — by the time the <script> load event fires, the flat
// global is ready.
if (typeof window !== 'undefined') {
  ;(window as unknown as Record<string, unknown>).__headlo_auth_runtime_v1 = runtime
}

export default runtime

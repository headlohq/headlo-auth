// Browser IIFE runtime — bundled separately from the React SDK. Exposes
// HeadloAuthClientV2 via a window global so any consumer that loads this
// file via a <script> tag can new-up a client without importing anything.
//
// Consumers:
//   - headlo-auth PROP service (loads /v1/prop/auth-runtime/v2/bundle in its
//     client_js on first getAuth() call — see claude/propCode/headloAuthService.md § 7)
//   - Vanilla HTML pages that want auth without a framework
//   - Third-party integrators wiring headlo-auth into non-React JS
//
// Design: claude/propCode/headloAuthService.md § 7 (Runtime bundle).
//
// Built by tsup in IIFE format via tsup.runtime.config.ts — separate from the
// main SDK build (which exports React components + must-be-external React).
// This bundle has ZERO React dependency; consumers load it in any page.
//
// Compiled output publishes:
//   window.__headlo_auth_runtime_v2 = {
//     create: (config) => new HeadloAuthClientV2(config)
//   }

import { HeadloAuthClientV2, type HeadloAuthClientV2Config } from './client-v2'

// The clean API we want consumers to see:
//   window.__headlo_auth_runtime_v2.create({...})
//   window.__headlo_auth_runtime_v2.HeadloAuthClientV2
const runtime = {
  create: (config: HeadloAuthClientV2Config) => new HeadloAuthClientV2(config),
  // Expose the class too — for `instanceof` checks in advanced integrations
  // (e.g. debug tooling that wants to inspect the singleton).
  HeadloAuthClientV2,
}

// tsup IIFE format wraps the default export in `{__esModule:true, default:...}`
// under the configured globalName. That's OK for internal tooling but the
// public consumer API should be flat. Assign to window directly during IIFE
// evaluation — side effect runs before the IIFE returns, so by the time the
// script tag load event fires, `window.__headlo_auth_runtime_v2` is the clean
// object. The tsup-wrapped global (see tsup.runtime.config.ts globalName) sits
// on a separate `_HEADLO_AUTH_INTERNAL` name for debug access.
if (typeof window !== 'undefined') {
  ;(window as unknown as Record<string, unknown>).__headlo_auth_runtime_v2 = runtime
}

export default runtime

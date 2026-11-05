import { defineConfig } from 'tsup'

// Separate build for the browser IIFE runtime — consumed via <script> tag by
// the headlo-auth PROP service + vanilla HTML pages. No React dependency;
// bundles the framework-agnostic HeadloAuthClient class only.
//
// Kept out of the main tsup config (tsup.config.ts) because:
//   - Different format (iife vs esm+cjs)
//   - Different externals (none — this bundle is self-contained)
//   - Different consumers (browser <script> vs `import from 'headlo-auth'`)
//
// Outputs:
//   dist/runtime/client-runtime-v2.global.js → window.__headlo_auth_runtime_v2
//   dist/runtime/client-runtime-v1.global.js → window.__headlo_auth_runtime_v1

export default defineConfig({
  // Two IIFE entries — one per client version. Each publishes its own
  // clean window global via side effect (see client-runtime-v1.ts /
  // client-runtime-v2.ts).
  entry: {
    'client-runtime-v1': 'src/client-runtime-v1.ts',    // v1 (cookie)
    'client-runtime-v2': 'src/client-runtime-v2.ts',    // v2 (DPoP)
    // Wave 4 B.7 — universal install script. Zero-config `<script>` tag that
    // reads data-pk from itself, derives issuer, mounts One Tap + floating
    // "Sign in with Headlo" button. Served by the worker at /button.js.
    'universal-button':  'src/universal-button.ts',
  },
  format:     ['iife'],
  // tsup wraps each entry's default export in `{__esModule, default}` under
  // this global. Kept on a private-ish name shared across both entries — the
  // real consumer-facing globals (`__headlo_auth_runtime_v1` and `_v2`) are
  // assigned via side effects inside each entry file, so this private name
  // being overwritten if both bundles load on the same page is harmless.
  globalName: '_HEADLO_AUTH_INTERNAL',
  outDir:     'dist/runtime',
  clean:      false,          // main build cleans dist/; don't clobber it
  dts:        false,           // types not needed for the IIFE consumer path
  external:   [],              // bundle EVERYTHING — no React, no import.meta
  platform:   'browser',
  minify:     true,
})

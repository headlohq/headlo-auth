import { defineConfig } from 'tsup'

export default defineConfig({
  entry:    { index: 'src/index.ts' },
  format:   ['esm', 'cjs'],
  dts:      true,
  // Only wipe THIS build's outputs, not the whole dist/. Preserves
  // dist/runtime/*.global.js from tsup.runtime.config.ts so wrangler
  // doesn't hit ENOENT during the SDK rebuild window.
  clean:    ['dist/index.*', 'dist/*.map'],
  external: ['react'],
})

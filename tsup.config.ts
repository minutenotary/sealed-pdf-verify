import { defineConfig } from 'tsup';

export default defineConfig([
  {
    // Library, ESM: dependencies stay external (they all ship ESM).
    entry: { index: 'src/index.ts' },
    format: ['esm'],
    dts: true,
    sourcemap: true,
    clean: true,
    target: 'es2022',
    platform: 'neutral',
    treeshake: true,
  },
  {
    // Library, CJS: several dependencies are ESM-only, so the CJS build is
    // self-contained (everything bundled) to keep `require()` working.
    entry: { index: 'src/index.ts' },
    format: ['cjs'],
    sourcemap: true,
    target: 'node20',
    platform: 'node',
    noExternal: [/.*/],
    treeshake: true,
  },
  {
    // Command-line tool: one self-contained ESM file (no node_modules needed
    // at runtime, which keeps the container image to dist/cli.js alone).
    entry: { cli: 'cli/index.ts' },
    format: ['esm'],
    sourcemap: true,
    target: 'node20',
    platform: 'node',
    noExternal: [/.*/],
    treeshake: true,
    banner: { js: '#!/usr/bin/env node' },
  },
]);

import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vite';
import { viteSingleFile } from 'vite-plugin-singlefile';

// One self-contained index.html: no external script, style or font requests,
// so the page works from file:// and stays usable offline once loaded.
export default defineConfig({
  root: fileURLToPath(new URL('.', import.meta.url)),
  base: './',
  plugins: [viteSingleFile()],
  build: {
    // No modulepreload polyfill: it is dead code in a single-file build and
    // its `fetch(` would contradict the page's no-network promise.
    modulePreload: { polyfill: false },
    outDir: 'dist',
    emptyOutDir: true,
    target: 'es2022',
    sourcemap: false,
    minify: true,
  },
});

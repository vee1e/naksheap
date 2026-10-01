import { defineConfig } from 'vite'
import { svelte } from '@sveltejs/vite-plugin-svelte'

export default defineConfig({
  plugins: [svelte()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    // The wasm-bindgen glue is tiny, but the .wasm itself must be served as a
    // static asset from public/pkg, so no special handling is needed here.
    target: 'es2022',
  },
  worker: {
    format: 'es',
  },
  server: {
    fs: { allow: ['..'] },
  },
})

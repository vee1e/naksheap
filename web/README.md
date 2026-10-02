# web

Single-page frontend for naksheap. The analyzer is compiled to WebAssembly and
runs in a Web Worker, so a core dump is read from the file input and analyzed in
the tab. Nothing is uploaded.

Svelte 5 + Vite, matching the other frontends in this fleet.

## Layout

    src/App.svelte        shell, file handling, worker lifecycle
    src/worker.ts         owns the wasm module, streams progress back
    src/lib/Graph.svelte  canvas force-directed graph
    src/lib/Table.svelte  filterable object table
    src/lib/Detail.svelte selected object: type, fields, evidence
    src/lib/Dropzone.svelte
    src/lib/ProgressBar.svelte
    src/lib/types.ts      mirrors the wasm crate's JSON exactly
    src/lib/sample.ts     loads public/sample.core for the demo button
    public/sample.core        the repo's own synthetic fixture, as a demo dump
    public/real-sample.core.gz  a real x86-64 core from scripts/real-src/test.cpp,
                                 gzipped (9.7 MiB -> 60 KiB)

## Build

`npm run build` rebuilds the wasm module and then the bundle, so it works from
a clean checkout with nothing but a Rust toolchain, `wasm-bindgen-cli`, and Node.

    npm install
    npm run build        # -> dist/

Prerequisites:

    rustup target add wasm32-unknown-unknown
    cargo install wasm-bindgen-cli   # must match the wasm-bindgen version in Cargo.lock

## Tests

`npm run check` runs `svelte-check` for type errors.

The wasm bindings are covered by the crate's own integration tests, which run in
a real browser rather than being asserted in isolation:

    cargo test -p naksheap-wasm --target wasm32-unknown-unknown

That needs `chromedriver` on PATH and a Chrome or Chromium install. See
`crates/naksheap-wasm/webdriver.json` for capabilities; add `--no-sandbox` there
if you are running as root in a container.

## Deployment

Static files, served by Vercel at `naksheap.lverma.com`. `vercel.json` pins the
build command and output directory.

The page has no backend dependency. `naksheap.lverma.com` is fully functional on
its own; the API at `naksheap-api.lverma.com` is only needed for dumps above
about 256 MiB, and the UI points people there when a file is too large.

## Sample dumps

Two are served as static assets and linked from the dropzone.

`sample.core` is the synthetic fixture from `fixtures/`, built by
`naksheap-testkit` with a ground-truth manifest. It is small and exercises a
pointer ring, a stack root, a freed chunk and a vtable pointer.

`real-sample.core.gz` is a genuine kernel core: `scripts/real-src/test.cpp`
compiled `-O2` and stripped in Ubuntu 24.04, crashing with SIGSEGV, captured
with the default core pattern. It is 9.7 MiB raw and 60 KiB gzipped. It
recovers 24 objects including a 1 MiB mmap allocation, two arenas (main plus a
thread arena), six tcache-freed chunks, and `Worker`/`Manager` correctly
identified as vtable objects.

Regenerate it with `scripts/real-dump-test.sh`, then:

```bash
gzip -9 -c target/real-dumps/test.crash.core > web/public/real-sample.core.gz
```

## Size ceiling

A `wasm32` guest can address 4 GiB of linear memory and the pipeline needs
several times the input size, so the analyzer refuses files over 256 MiB
(`MAX_INPUT_BYTES` in the wasm crate) with a message pointing at the service
rather than dying in an allocation failure.

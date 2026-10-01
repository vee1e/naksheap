# naksheap web deployment

This guide explains how to run naksheap as a web service. People upload a core dump, the service reconstructs the heap, and a browser gets an interactive report plus the machine-readable graph.

Privacy comes first. Core dumps contain credentials and keys. The analyzer never sends data anywhere, and the HTML report is a single self-contained file with no external scripts, fonts, or stylesheets, so opening a report makes no network request either.

There are two ways to run this. The in-browser build is the default and the safer one: it runs the analyzer as WebAssembly inside the page, so the dump never leaves the machine at all. The service described below is the alternative, for dumps too large for a browser and for CI.

## In-browser build (no upload)

`crates/naksheap-wasm` compiles the analysis pipeline to `wasm32-unknown-unknown`. The page loads the module, reads the dump from a file input, and analyzes it in a Web Worker. The bytes are never uploaded and never written to disk.

```bash
cargo build --release -p naksheap-wasm --target wasm32-unknown-unknown
wasm-bindgen --target web --out-dir web/pkg \
    target/wasm32-unknown-unknown/release/naksheap_wasm.wasm
```

The crate depends only on the five analysis libraries, not on `naksheap-cli`, so nothing pulls in `std::fs`, `std::process`, or `clap`. It uses the in-memory parse path (`parse_elf_bytes` + `MappedImage::from_bytes`) that `naksheap self-test` already exercises; `naksheap_core_parse::open`, the only entry point that needs a filesystem, is never called.

`analyze_js(bytes, on_progress)` returns the graph as JSON and calls `on_progress` with `{ stage, done, total, fraction }` as the pipeline advances. The frontend runs it in a worker so a long analysis does not freeze the tab.

### Size ceiling

A `wasm32` guest can address at most 4 GiB of linear memory, and the pipeline needs roughly 5-6x the input size to work, plus a similar multiple again to serialize the result. Measured on synthetic ground-truth fixtures, a 8.8 MiB dump peaked near 60 MiB of linear memory and produced a 20 MiB JSON payload.

That puts the practical in-browser ceiling at a few hundred MiB, far below what the native CLI or the service can take. `MAX_INPUT_BYTES` in the crate is set to 256 MiB as a guard. For larger dumps, use the service.

### Performance

`rayon` falls back to a single thread on `wasm32-unknown-unknown`, so the pointer scan runs on one core. A 32k-object dump takes about 2 seconds. Progress is reported roughly 200 times across the scan, throttled so the UI does not become the bottleneck.

### Deferred: WebAssembly threads

`wasm-bindgen-rayon` would let the scan use every core, likely a 4-8x speedup on large dumps. It is deliberately not enabled: it needs a nightly toolchain, `-C target-feature=+atomics`, `build-std`, and `SharedArrayBuffer`, which in turn requires the page to send `Cross-Origin-Opener-Policy: same-origin` and `Cross-Origin-Embedder-Policy: require-corp`. That rules out serving the frontend from a third-party CDN and complicates every embedding. Correctness and a single-threaded build that works everywhere is the better trade until the size ceiling actually bites.

## Service deployment

### What you are deploying

naksheap is a Rust command line tool. There is no web server built in. The service is a thin wrapper that accepts an uploaded dump, runs the CLI, stores the results, and serves them over HTTP.

The `deploy` directory has everything:

| File | Purpose |
|---|---|
| `Dockerfile` | Multi-stage build. Compiles the Rust binary, then a slim runtime image with Python and the server. |
| `server.py` | A small standard-library HTTP server. Accepts a dump, runs naksheap, serves the report. |
| `docker-compose.yml` | Service definition with upload limits, resource caps, and an artifact volume. |

## Build and run

```bash
cargo build --release --workspace
cd deploy
docker build -t naksheap-server .
docker compose up -d
```

## Analyze a dump

Upload with curl. The raw request body is the dump file.

```bash
curl -s -X PUT --data-binary @/path/to/core.dump \
     -H 'Content-Type: application/octet-stream' \
     http://localhost:8080/analyze?name=my-crash
```

The response is JSON with the object counts and links to the report, the graph JSON, and the Graphviz file. Open the report link in a browser.

If an analysis is already running, the service answers 503 with a Retry-After header instead of blocking. Analyses are serialized because carving is CPU and memory bound.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| NAKSHEAP_BIN | naksheap | Path to the CLI binary |
| NAKSHEAP_ARTIFACTS | /data | Where reports are stored |
| NAKSHEAP_MAX_UPLOAD_BYTES | 10737418240 | Reject larger uploads with 413 |
| NAKSHEAP_MAX_REPORTS | 1000 | Prune the oldest reports past this count |
| NAKSHEAP_MAX_DEPTH | 8 | graph --max-depth |
| NAKSHEAP_TIMEOUT | 1800 | Seconds before a stuck analysis is abandoned |
| NAKSHEAP_PORT | 8080 | Listen port |

## Production setups

Single host with systemd and nginx: run server.py as a service, put nginx in front with TLS and a client_max_body_size that matches the upload limit.

Kubernetes: deploy the same container as a Deployment with a PVC for the artifact directory. For large fleets, run one Job per upload instead. A small dispatcher creates a Job that runs naksheap on the uploaded core, then serves the artifacts from object storage. That way a malicious dump only ever takes down its own Job, and a NetworkPolicy can deny all outbound traffic from the analyzer Pods.

Crash pipeline: hook the CLI directly into your existing core collector instead of the web service.

```bash
./target/release/naksheap graph "$core" --json --html --out "reports/$(date +%s)"
```

The JSON contract is stable, so alerts can key off the edge counts or the number of confirmed references.

## Air-gapped networks

Nothing needs fixing. The report is a single file with no external references, so it works on an isolated network, from a `file://` path, or attached to an incident ticket. The in-browser build also needs no network access after the page and the `.wasm` module have loaded once.

## Operations

The server logs each analysis: the id, upload size, exit code, elapsed time, and any warning from the CLI. A truncated core prints a warning that it may be partial, which usually means the upload was cut off and should be retried.

Exit code 0 means success. Exit code 1 means a clean error, such as a file that is not a core dump. A broken pipe from piping to head also exits 0, which is the usual Unix behavior. On failure the server stores the stderr text in the report directory.

Reports are pruned past NAKSHEAP_MAX_REPORTS. Point the artifact volume at your backup policy.

## Security checklist

- The analyzer makes no outbound connections. For hard isolation, put a NetworkPolicy or proxy in front that blocks egress.
- Set NAKSHEAP_MAX_UPLOAD_BYTES and mirror it in the reverse proxy.
- Use TLS in front and do not expose the upload endpoint without auth if the dumps are sensitive.
- Run as a non-root user with a read-only filesystem.
- Keep the artifact volume private. Reports contain raw memory-derived data.
- Run scripts/real-dump-test.sh once in your target environment, because the allocator parser is tied to the glibc version of the machines you capture dumps from.

## Non-goals

- No built-in authentication, rate limiting, or multi-tenant isolation. Put those in the reverse proxy.
- No incremental upload and analyze. A large dump is processed in one job.
- No support for macOS cores, 32-bit dumps, jemalloc, or tcmalloc.

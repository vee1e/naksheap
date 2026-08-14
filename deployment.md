# naksheap web deployment

This guide explains how to run naksheap as a web service. People upload a core dump, the service reconstructs the heap, and a browser gets an interactive report plus the machine-readable graph.

Privacy comes first. Core dumps contain credentials and keys. The reference stack is self-hosted and offline. The analyzer never sends data anywhere, and the only network request in the whole system is the optional cytoscape.js download in the HTML report, made by the browser, not the server.

## What you are deploying

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

The HTML report loads cytoscape.js from a CDN. For an offline network, download the bundle once, serve it next to the reports, and change the script tag in the HTML to a local path. Everything else in the report is already embedded.

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

#!/usr/bin/env python3
"""naksheap web service.

A small standard-library HTTP wrapper around the `naksheap` CLI.

Endpoints
---------
PUT  /analyze?name=<id>   raw body is a core dump / memory image; runs
                          `naksheap graph --json --html` and returns a JSON
                          summary with links to the artifacts.
GET  /reports/            HTML index of analyses.
GET  /reports/<id>/report.html | graph.json | graph.dot
                          Static artifacts.

Environment
-----------
NAKSHEAP_BIN              path to the naksheap CLI (default: naksheap)
NAKSHEAP_ARTIFACTS        artifact dir (default: ./data)
NAKSHEAP_MAX_UPLOAD_BYTES reject larger uploads (default: 10 GiB)
NAKSHEAP_MAX_REPORTS      prune oldest past this count (default: 1000)
NAKSHEAP_MAX_DEPTH        graph --max-depth (default: 8)
NAKSHEAP_PORT             listen port (default: 8080)
NAKSHEAP_CORS_ORIGINS     comma-separated allowed browser origins, or "*"
NAKSHEAP_RETENTION_HOURS  delete artifacts older than this (default: 24)
"""
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIN = os.environ.get("NAKSHEAP_BIN", "naksheap")
ARTIFACTS = os.environ.get("NAKSHEAP_ARTIFACTS", "./data")
MAX_UPLOAD = int(os.environ.get("NAKSHEAP_MAX_UPLOAD_BYTES", str(10 * 1024**3)))
MAX_REPORTS = int(os.environ.get("NAKSHEAP_MAX_REPORTS", "1000"))
MAX_DEPTH = os.environ.get("NAKSHEAP_MAX_DEPTH", "8")
PORT = int(os.environ.get("NAKSHEAP_PORT", "8080"))
ANALYSIS_TIMEOUT = float(os.environ.get("NAKSHEAP_TIMEOUT", "1800"))
# Reports contain raw memory-derived data, so they are held only briefly by
# default. A report is a crash artefact, not a database.
RETENTION_HOURS = float(os.environ.get("NAKSHEAP_RETENTION_HOURS", "24"))
# The web UI is served from a different origin than this API, so the browser
# needs an explicit allow-list. Uploads carry the dump, so this is a
# deliberate allow-list and not a wildcard.
CORS_ORIGINS = {
    o.strip()
    for o in os.environ.get(
        "NAKSHEAP_CORS_ORIGINS", "https://naksheap.lverma.com"
    ).split(",")
    if o.strip()
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("naksheap-web")

# Only one analysis runs at a time; carving is CPU and memory bound. While one
# is running, further uploads get a 503 with Retry-After instead of blocking.
_busy = threading.Lock()


def _try_acquire_busy(timeout: float) -> bool:
    return _busy.acquire(timeout=timeout)


def _run_analysis(core_path: str, out_dir: str) -> dict:
    started = time.monotonic()
    cmd = [
        BIN, "graph", core_path,
        "--json", "--html", "--dot", "--out", out_dir, "--max-depth", MAX_DEPTH,
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=ANALYSIS_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"exit": -1, "stdout": "", "stderr": f"analysis timed out after {ANALYSIS_TIMEOUT}s"}
    return {
        "exit": proc.returncode,
        "stdout": proc.stdout[-4000:],
        "stderr": proc.stderr[-4000:],
        "elapsed": round(time.monotonic() - started, 2),
    }


def _prune():
    """Drop reports past MAX_REPORTS, and anything older than RETENTION_HOURS.

    Both bounds matter: the count bound stops unbounded disk growth, and the
    age bound stops a credential-bearing report from sitting around for weeks
    because nobody happened to upload enough dumps to trip the count.
    """
    now = time.time()
    try:
        entries = sorted(
            (p for p in os.listdir(ARTIFACTS) if os.path.isdir(os.path.join(ARTIFACTS, p))),
            key=lambda p: os.path.getmtime(os.path.join(ARTIFACTS, p)),
        )
    except OSError:
        return
    for p in entries[: max(0, len(entries) - MAX_REPORTS)]:
        shutil.rmtree(os.path.join(ARTIFACTS, p), ignore_errors=True)
        log.info("pruned report %s (count limit)", p)
    if RETENTION_HOURS > 0:
        cutoff = now - RETENTION_HOURS * 3600
        for p in entries:
            full = os.path.join(ARTIFACTS, p)
            try:
                if os.path.getmtime(full) < cutoff:
                    shutil.rmtree(full, ignore_errors=True)
                    log.info("pruned report %s (older than %sh)", p, RETENTION_HOURS)
            except OSError:
                pass


class Handler(BaseHTTPRequestHandler):
    # A core dump is a large body; the default 100 KiB is irrelevant here since
    # the body length is checked explicitly, but keep the noise down.
    protocol_version = "HTTP/1.1"

    def _cors(self):
        """Send CORS headers for an allow-listed origin.

        This only adds headers; the caller owns send_response/end_headers. A
        response built without a status line is unparseable, so the two
        concerns must not be conflated here.
        """
        origin = self.headers.get("Origin")
        # Echo the origin only when it is on the list, so a browser cannot read
        # a response from a site that is not allowed to send dumps here.
        if origin and (origin in CORS_ORIGINS or "*" in CORS_ORIGINS):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def do_OPTIONS(self):
        # Preflight. The status line has to be sent first, then the headers.
        self.send_response(204)
        self._cors()
        self.send_header("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        # The preflight itself must not advertise an age, or a cached
        # negative result can outlive a config change.
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _file(self, path, ctype="application/octet-stream"):
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            self.send_error(404, "not found")
            return
        self.send_response(200)
        self._cors()
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_PUT(self):
        if not self.path.startswith("/analyze"):
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_UPLOAD:
            self._json(413, {"ok": False, "error": "upload too large"})
            return
        rid = uuid.uuid4().hex
        out_dir = os.path.join(ARTIFACTS, rid)
        os.makedirs(out_dir, exist_ok=True)
        core_path = os.path.join(out_dir, "core")
        log.info("upload start id=%s size=%d", rid, length)
        try:
            with open(core_path, "wb") as f:
                remaining = length
                while remaining > 0:
                    chunk = self.rfile.read(min(1 << 20, remaining))
                    if not chunk:
                        break
                    f.write(chunk)
                    remaining -= len(chunk)
        except OSError:
            self._json(500, {"ok": False, "error": "write failed"})
            return

        if not _try_acquire_busy(0.5):
            log.warning("busy, rejecting id=%s with 503", rid)
            # The dump is already on disk at this point. Remove it: this
            # response never produces a report, and leaving an un-referenced
            # multi-gigabyte core in the artifact directory would be both a
            # disk leak and a copy of a credential-bearing file.
            shutil.rmtree(out_dir, ignore_errors=True)
            body = b'{"ok":false,"error":"an analysis is already running, retry shortly"}'
            self.send_response(503)
            self._cors()
            self.send_header("Retry-After", "30")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        try:
            result = _run_analysis(core_path, out_dir)
        finally:
            _busy.release()
            # The report and the graph are derived data; the raw core is not
            # needed once the analysis has run, and a core dump routinely
            # contains credentials and keys in plaintext. Drop it in every
            # case, including the failure path below.
            try:
                os.unlink(core_path)
            except OSError:
                pass

        log.info(
            "analysis done id=%s exit=%d elapsed=%ss",
            rid, result["exit"], result.get("elapsed"),
        )
        if result["exit"] != 0:
            log.warning("analysis failed id=%s stderr=%s", rid, result["stderr"])
            self._json(502, {
                "ok": False,
                "id": rid,
                "error": "analysis failed",
                "stderr": result["stderr"],
            })
            return
        graph_path = os.path.join(out_dir, "graph.json")
        summary = {"ok": True, "id": rid}
        try:
            g = json.load(open(graph_path))
            summary["stats"] = g.get("stats", {})
        except OSError:
            pass
        summary["report"] = f"/reports/{rid}/report.html"
        summary["json"] = f"/reports/{rid}/graph.json"
        summary["dot"] = f"/reports/{rid}/graph.dot"
        if result["stderr"].strip():
            summary["warning"] = result["stderr"].strip()
        _prune()
        self._json(200, summary)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/healthz", "/health"):
            # The compose healthcheck and the deploy verification both use this.
            # It must not touch the artifact directory, so it stays green even
            # when analysis is failing.
            self._json(200, {"ok": True, "binary": BIN, "artifacts": ARTIFACTS})
            return
        if path == "/reports/" or path == "/reports":
            entries = sorted(os.listdir(ARTIFACTS)) if os.path.isdir(ARTIFACTS) else []
            html = "<html><body><h1>naksheap reports</h1><ul>" + "".join(
                f'<li><a href="/reports/{e}/report.html">{e}</a></li>' for e in entries
            ) + "</ul></body></html>"
            body = html.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        m = re.match(r"^/reports/([0-9a-f]+)/([A-Za-z0-9_.-]+)$", path)
        if not m:
            self.send_error(404)
            return
        rid, name = m.groups()
        base = os.path.join(ARTIFACTS, rid)
        ctype = {
            "report.html": "text/html; charset=utf-8",
            "graph.json": "application/json",
            "graph.dot": "text/vnd.graphviz",
        }.get(name, "application/octet-stream")
        self._file(os.path.join(base, name), ctype)


def main():
    os.makedirs(ARTIFACTS, exist_ok=True)
    if shutil.which(BIN) is None:
        print(f"error: naksheap binary '{BIN}' not found on PATH", file=sys.stderr)
        sys.exit(1)
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"naksheap server listening on :{PORT} (bin={BIN}, artifacts={ARTIFACTS})")
    httpd.serve_forever()


if __name__ == "__main__":
    main()

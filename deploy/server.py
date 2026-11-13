#!/usr/bin/env python3
"""naksheap web service.

A small standard-library HTTP wrapper around the `naksheap` CLI.

Endpoints
---------
PUT  /analyze?name=<id>   raw body is a core dump / memory image; runs
                          `naksheap graph --json --html` and returns a JSON
                          summary with links to the artifacts. Requires
                          `Authorization: Bearer $NAKSHEAP_API_TOKEN`.
GET  /health, /healthz    liveness probe. Unauthenticated, so a missing token
                          does not take the container down.
GET  /reports/            HTML index of analyses. Requires the bearer token.
GET  /reports/<id>/report.html | graph.json | graph.dot
                          Static artifacts. Requires the bearer token.
                          The raw upload is never served.

Environment
-----------
NAKSHEAP_BIN              path to the naksheap CLI (default: naksheap)
NAKSHEAP_ARTIFACTS        artifact dir (default: ./data)
NAKSHEAP_UPLOAD_DIR       scratch dir for raw uploads, outside the served
                          tree (default: $TMPDIR/naksheap-uploads)
NAKSHEAP_API_TOKEN        shared secret. If unset or empty, analyze, list,
                          and download all return 401 (fail closed). The
                          process still starts and /health stays 200.
NAKSHEAP_MAX_UPLOAD_BYTES reject larger uploads (default: 10 GiB)
NAKSHEAP_MAX_REPORTS      prune oldest past this count (default: 1000)
NAKSHEAP_MAX_DEPTH        graph --max-depth (default: 8)
NAKSHEAP_PORT             listen port (default: 8080)
NAKSHEAP_CORS_ORIGINS     comma-separated allowed browser origins, or "*"
NAKSHEAP_RETENTION_HOURS  delete artifacts older than this (default: 24)
NAKSHEAP_PRUNE_INTERVAL   seconds between background prunes (default: 300)
NAKSHEAP_SOCKET_TIMEOUT   idle socket timeout in seconds (default: 300)
"""
import hmac
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIN = os.environ.get("NAKSHEAP_BIN", "naksheap")
ARTIFACTS = os.environ.get("NAKSHEAP_ARTIFACTS", "./data")
# Default to a hidden directory beside the reports, on the same disk volume,
# so a 10 GiB upload cannot OOM a tmpfs-backed /tmp (compose gives the
# container 4 GiB of RAM and mounts /tmp as tmpfs). The index and prune
# paths only consider 32-hex report ids, so `.uploads` is never served.
UPLOAD_DIR = os.environ.get(
    "NAKSHEAP_UPLOAD_DIR",
    os.path.join(ARTIFACTS, ".uploads"),
)
# Fail closed when unset: listing, download, and upload all return 401.
# Compared as UTF-8 bytes with hmac.compare_digest; never logged. Strip so a
# secret file with a trailing newline still matches.
API_TOKEN = os.environ.get("NAKSHEAP_API_TOKEN", "").strip().encode("utf-8")
MAX_UPLOAD = int(os.environ.get("NAKSHEAP_MAX_UPLOAD_BYTES", str(10 * 1024**3)))
MAX_REPORTS = int(os.environ.get("NAKSHEAP_MAX_REPORTS", "1000"))
MAX_DEPTH = os.environ.get("NAKSHEAP_MAX_DEPTH", "8")
PORT = int(os.environ.get("NAKSHEAP_PORT", "8080"))
ANALYSIS_TIMEOUT = float(os.environ.get("NAKSHEAP_TIMEOUT", "1800"))
RETENTION_HOURS = float(os.environ.get("NAKSHEAP_RETENTION_HOURS", "24"))
PRUNE_INTERVAL = float(os.environ.get("NAKSHEAP_PRUNE_INTERVAL", "300"))
SOCKET_TIMEOUT = float(os.environ.get("NAKSHEAP_SOCKET_TIMEOUT", "300"))
CORS_ORIGINS = {
    o.strip()
    for o in os.environ.get(
        "NAKSHEAP_CORS_ORIGINS", "https://naksheap.lverma.com"
    ).split(",")
    if o.strip()
}

# Only these names are served from a report directory. The raw core is never
# one of them, even if a file called "core" is somehow left on disk.
SERVED_ARTIFACTS = {
    "report.html": "text/html; charset=utf-8",
    "graph.json": "application/json",
    "graph.dot": "text/vnd.graphviz",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("naksheap-web")

# Only one analysis (and its upload) runs at a time; carving is CPU and
# memory bound. The lock is taken *before* the body is read so a second
# client cannot fill the disk while the first is still uploading.
_busy = threading.Lock()
_prune_lock = threading.Lock()


def _token_configured() -> bool:
    return bool(API_TOKEN)


def _bearer_ok(header: str | None) -> bool:
    """Constant-time comparison of the Bearer token.

    Missing, wrong-scheme, wrong-length, and wrong-value headers all take
    the compare_digest path so the failure is not distinguished by timing
    of a short-circuit on length alone more than we can help. A missing
    configured token always fails closed.
    """
    if not _token_configured():
        return False
    header = header or ""
    if header[:7].lower() == "bearer ":
        got = header[7:].strip().encode("utf-8")
    else:
        got = b""
    expected = API_TOKEN
    if len(got) != len(expected):
        # Dummy compare so a length mismatch still does a digest. The
        # result is ignored; we already know it cannot match.
        hmac.compare_digest(expected, expected)
        return False
    return hmac.compare_digest(got, expected)


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
    with _prune_lock:
        try:
            entries = sorted(
                (
                    p for p in os.listdir(ARTIFACTS)
                    if re.fullmatch(r"[0-9a-f]{32}", p)
                    and os.path.isdir(os.path.join(ARTIFACTS, p))
                ),
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
    _prune_uploads()


def _prune_uploads():
    """Delete leftover raw cores in UPLOAD_DIR.

    In-flight uploads are skipped by leaving files newer than the analysis
    plus socket timeout alone. A process crash mid-upload would otherwise
    leave a credential-bearing dump on disk forever.
    """
    cutoff = time.time() - max(ANALYSIS_TIMEOUT, SOCKET_TIMEOUT) - 60
    try:
        names = os.listdir(UPLOAD_DIR)
    except OSError:
        return
    for name in names:
        if not name.endswith(".core"):
            continue
        path = os.path.join(UPLOAD_DIR, name)
        try:
            if os.path.getmtime(path) < cutoff:
                _unlink(path)
                log.info("pruned leftover upload %s", name)
        except OSError:
            pass


def _prune_loop():
    while True:
        time.sleep(max(PRUNE_INTERVAL, 1))
        try:
            _prune()
        except Exception:
            log.exception("background prune failed")


def _unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


class Handler(BaseHTTPRequestHandler):
    # Large dumps can take minutes to arrive; this is an idle timeout between
    # reads, not a total-transfer deadline.
    timeout = SOCKET_TIMEOUT
    protocol_version = "HTTP/1.1"

    def _cors(self):
        """Send CORS headers for an allow-listed origin.

        This only adds headers; the caller owns send_response/end_headers. A
        response built without a status line is unparseable, so the two
        concerns must not be conflated here.
        """
        origin = self.headers.get("Origin")
        if origin and (origin in CORS_ORIGINS or "*" in CORS_ORIGINS):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _json(self, code, obj, close=False):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self._cors()
        if code in (401, 403):
            self.send_header("WWW-Authenticate", 'Bearer realm="naksheap"')
        if close:
            self.send_header("Connection", "close")
            self.close_connection = True
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def handle_expect_100(self):
        # Do not tell the client to stream a multi-gigabyte body if the
        # request is already going to be rejected for a missing token.
        if self.command == "PUT" and not _bearer_ok(self.headers.get("Authorization")):
            self._require_auth()
            return False
        return super().handle_expect_100()

    def _require_auth(self) -> bool:
        if _bearer_ok(self.headers.get("Authorization")):
            return True
        if not _token_configured():
            self._json(401, {
                "ok": False,
                "error": "NAKSHEAP_API_TOKEN is not configured; listing, "
                         "download, and upload are disabled",
            }, close=True)
        else:
            self._json(401, {"ok": False, "error": "unauthorized"}, close=True)
        return False

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
        if not self._require_auth():
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._json(400, {"ok": False, "error": "invalid Content-Length"}, close=True)
            return
        if length <= 0 or length > MAX_UPLOAD:
            self._json(413, {"ok": False, "error": "upload too large"}, close=True)
            return
        # Take the slot before any disk write so a second upload cannot land
        # a multi-gigabyte body while an analysis is already running.
        if not _try_acquire_busy(0.5):
            log.warning("busy, rejecting upload with 503")
            self.close_connection = True
            body = b'{"ok":false,"error":"an analysis is already running, retry shortly"}'
            self.send_response(503)
            self._cors()
            self.send_header("Retry-After", "30")
            self.send_header("Connection", "close")
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        rid = uuid.uuid4().hex
        out_dir = os.path.join(ARTIFACTS, rid)
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        tmp_fd, core_path = tempfile.mkstemp(prefix=f"{rid}-", suffix=".core", dir=UPLOAD_DIR)
        os.close(tmp_fd)
        log.info("upload start id=%s size=%d", rid, length)
        try:
            try:
                remaining = length
                with open(core_path, "wb") as f:
                    while remaining > 0:
                        chunk = self.rfile.read(min(1 << 20, remaining))
                        if not chunk:
                            break
                        f.write(chunk)
                        remaining -= len(chunk)
                if remaining > 0:
                    self._json(400, {"ok": False, "error": "upload truncated"})
                    return
            except OSError:
                self._json(500, {"ok": False, "error": "write failed"})
                return

            os.makedirs(out_dir, exist_ok=True)
            try:
                result = _run_analysis(core_path, out_dir)
            except Exception:
                result = {"exit": -1, "stdout": "", "stderr": "analysis failed to start"}
                raise
            finally:
                # Always drop the raw core, including on failure. It routinely
                # contains credentials and keys in plaintext.
                _unlink(core_path)
                leftover = os.path.join(out_dir, "core")
                _unlink(leftover)

            log.info(
                "analysis done id=%s exit=%d elapsed=%ss",
                rid, result["exit"], result.get("elapsed"),
            )
            if result["exit"] != 0:
                log.warning("analysis failed id=%s stderr=%s", rid, result["stderr"])
                try:
                    with open(os.path.join(out_dir, "stderr.txt"), "w", encoding="utf-8") as fh:
                        fh.write(result.get("stderr") or "")
                except OSError:
                    pass
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
                with open(graph_path, encoding="utf-8") as fh:
                    g = json.load(fh)
                summary["stats"] = g.get("stats", {})
            except (OSError, json.JSONDecodeError, AttributeError, TypeError):
                pass
            summary["report"] = f"/reports/{rid}/report.html"
            summary["json"] = f"/reports/{rid}/graph.json"
            summary["dot"] = f"/reports/{rid}/graph.dot"
            if result["stderr"].strip():
                summary["warning"] = result["stderr"].strip()
            _prune()
            self._json(200, summary)
        finally:
            _unlink(core_path)
            _busy.release()

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path in ("/healthz", "/health"):
            # The compose healthcheck and the deploy verification both use this.
            # It must not require a token, so a missing NAKSHEAP_API_TOKEN
            # leaves the container healthy while protected routes stay 401.
            self._json(200, {"ok": True, "binary": BIN, "auth_required": True})
            return
        if not self._require_auth():
            return
        if path == "/reports/" or path == "/reports":
            entries = sorted(os.listdir(ARTIFACTS)) if os.path.isdir(ARTIFACTS) else []
            # Only list directories that look like report ids (32 hex chars)
            # so scratch files cannot leak into the index.
            entries = [e for e in entries if re.fullmatch(r"[0-9a-f]{32}", e)]
            html = "<html><body><h1>naksheap reports</h1><ul>" + "".join(
                f'<li><a href="/reports/{e}/report.html">{e}</a></li>' for e in entries
            ) + "</ul></body></html>"
            body = html.encode()
            self.send_response(200)
            self._cors()
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
        ctype = SERVED_ARTIFACTS.get(name)
        if ctype is None:
            self.send_error(404, "not found")
            return
        self._file(os.path.join(ARTIFACTS, rid, name), ctype)


def main():
    os.makedirs(ARTIFACTS, exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    if shutil.which(BIN) is None:
        print(f"error: naksheap binary '{BIN}' not found on PATH", file=sys.stderr)
        sys.exit(1)
    _prune()
    if PRUNE_INTERVAL > 0:
        t = threading.Thread(target=_prune_loop, name="naksheap-prune", daemon=True)
        t.start()
    httpd = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    httpd.timeout = SOCKET_TIMEOUT
    if _token_configured():
        auth_state = "token configured"
    else:
        auth_state = "NAKSHEAP_API_TOKEN unset; analyze/list/download return 401"
    print(
        f"naksheap server listening on :{PORT} "
        f"(bin={BIN}, artifacts={ARTIFACTS}, {auth_state})"
    )
    httpd.serve_forever()


if __name__ == "__main__":
    main()

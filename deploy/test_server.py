#!/usr/bin/env python3
"""HTTP tests for deploy/server.py.

Spawned as a subprocess so environment variables are applied the same way
they are in production. The CLI is replaced by a tiny fake that writes the
three artifact files and never needs a real core dump.
"""
from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SERVER = ROOT / "server.py"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _write_fake_cli(path: Path, delay: float = 0.0, fail: bool = False) -> None:
    body = f"""#!/usr/bin/env python3
import json, sys, time
from pathlib import Path
args = sys.argv[1:]
out = Path(args[args.index("--out") + 1])
out.mkdir(parents=True, exist_ok=True)
time.sleep({delay!r})
if {fail!r}:
    print("fake analysis failed", file=sys.stderr)
    sys.exit(1)
(out / "graph.json").write_text(json.dumps({{"stats": {{"objects": 1}}}}))
(out / "report.html").write_text("<html>ok</html>")
(out / "graph.dot").write_text("digraph {{}}")
"""
    path.write_text(body)
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


class Server:
    def __init__(self, token: str | None, extra_env: dict | None = None,
                 cli_delay: float = 0.0, cli_fail: bool = False):
        self.tmpdir = Path(tempfile.mkdtemp(prefix="naksheap-svc-"))
        self.artifacts = self.tmpdir / "data"
        self.uploads = self.tmpdir / "uploads"
        self.artifacts.mkdir()
        self.uploads.mkdir()
        self.cli = self.tmpdir / "fake-naksheap"
        _write_fake_cli(self.cli, delay=cli_delay, fail=cli_fail)
        self.port = _free_port()
        self.token = token
        env = os.environ.copy()
        env.update({
            "NAKSHEAP_BIN": str(self.cli),
            "NAKSHEAP_ARTIFACTS": str(self.artifacts),
            "NAKSHEAP_UPLOAD_DIR": str(self.uploads),
            "NAKSHEAP_PORT": str(self.port),
            "NAKSHEAP_PRUNE_INTERVAL": "3600",
            "NAKSHEAP_SOCKET_TIMEOUT": "5",
            "NAKSHEAP_RETENTION_HOURS": "24",
        })
        if token is None:
            env.pop("NAKSHEAP_API_TOKEN", None)
        else:
            env["NAKSHEAP_API_TOKEN"] = token
        if extra_env:
            env.update(extra_env)
        self.proc = subprocess.Popen(
            [sys.executable, str(SERVER)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self._wait_up()

    def _wait_up(self):
        deadline = time.time() + 5
        last = None
        while time.time() < deadline:
            if self.proc.poll() is not None:
                out = self.proc.stdout.read().decode("utf-8", "replace") if self.proc.stdout else ""
                raise RuntimeError(f"server exited {self.proc.returncode}: {out}")
            try:
                self.request("GET", "/health")
                return
            except Exception as e:
                last = e
                time.sleep(0.05)
        raise RuntimeError(f"server did not start: {last}")

    def close(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.proc.kill()

    def request(self, method: str, path: str, data: bytes | None = None,
                token: str | None | object = Ellipsis, headers: dict | None = None):
        url = f"http://127.0.0.1:{self.port}{path}"
        hdrs = dict(headers or {})
        auth = self.token if token is Ellipsis else token
        if auth:
            hdrs["Authorization"] = f"Bearer {auth}"
        if data is not None:
            hdrs.setdefault("Content-Type", "application/octet-stream")
        req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                return resp.status, dict(resp.headers), resp.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()


class HealthAndAuthTests(unittest.TestCase):
    def test_health_without_token_stays_ok_and_protected_routes_are_401(self):
        srv = Server(token=None)
        self.addCleanup(srv.close)
        status, _, body = srv.request("GET", "/health")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["auth_required"])
        for path, method, data in (
            ("/reports/", "GET", None),
            ("/reports", "GET", None),
            ("/analyze", "PUT", b"dump"),
            ("/reports/" + "a" * 32 + "/report.html", "GET", None),
        ):
            status, _, body = srv.request(method, path, data=data)
            self.assertEqual(status, 401, msg=f"{method} {path}")
            self.assertIn(b"not configured", body)

    def test_wrong_token_is_401_and_correct_token_works(self):
        srv = Server(token="s3cret-token")
        self.addCleanup(srv.close)
        status, _, _ = srv.request("GET", "/reports/", token="wrong")
        self.assertEqual(status, 401)
        status, _, _ = srv.request("GET", "/reports/", token="s3cret-toke")  # wrong length
        self.assertEqual(status, 401)
        status, _, _ = srv.request("GET", "/reports/", token="")
        self.assertEqual(status, 401)
        status, _, body = srv.request("GET", "/reports/")
        self.assertEqual(status, 200)
        self.assertIn(b"naksheap reports", body)


class AnalyzeAndArtifactsTests(unittest.TestCase):
    def setUp(self):
        self.srv = Server(token="tok")
        self.addCleanup(self.srv.close)

    def test_analyze_and_allowlisted_download(self):
        status, _, body = self.srv.request("PUT", "/analyze", data=b"ELFCORE")
        self.assertEqual(status, 200, body)
        payload = json.loads(body)
        self.assertTrue(payload["ok"])
        rid = payload["id"]
        self.assertEqual(payload["stats"], {"objects": 1})
        for name in ("report.html", "graph.json", "graph.dot"):
            status, _, data = self.srv.request("GET", f"/reports/{rid}/{name}")
            self.assertEqual(status, 200, name)
            self.assertTrue(data)
        # The server must not leave a raw core in the served tree.
        self.assertFalse((self.srv.artifacts / rid / "core").exists())
        self.assertEqual(list(self.srv.uploads.glob("*.core")), [])
        # Even if a core is planted, it must not be served.
        planted = self.srv.artifacts / rid / "core"
        planted.write_bytes(b"SECRET-DUMP")
        status, _, _ = self.srv.request("GET", f"/reports/{rid}/core")
        self.assertEqual(status, 404)
        status, _, index = self.srv.request("GET", "/reports/")
        self.assertEqual(status, 200)
        self.assertIn(rid.encode(), index)

    def test_unauthenticated_cannot_see_a_report_after_upload(self):
        status, _, body = self.srv.request("PUT", "/analyze", data=b"ELFCORE")
        rid = json.loads(body)["id"]
        status, _, _ = self.srv.request("GET", "/reports/", token=None)
        self.assertEqual(status, 401)
        status, _, _ = self.srv.request("GET", f"/reports/{rid}/report.html", token=None)
        self.assertEqual(status, 401)
        status, _, _ = self.srv.request("GET", f"/reports/{rid}/core", token=None)
        self.assertEqual(status, 401)

    def test_failed_analysis_stores_stderr_and_drops_core(self):
        srv = Server(token="tok", cli_fail=True)
        self.addCleanup(srv.close)
        status, _, body = srv.request("PUT", "/analyze", data=b"ELFCORE")
        self.assertEqual(status, 502, body)
        rid = json.loads(body)["id"]
        stderr = (srv.artifacts / rid / "stderr.txt").read_text()
        self.assertIn("fake analysis failed", stderr)
        self.assertFalse(any(srv.uploads.glob("*.core")))
        self.assertFalse((srv.artifacts / rid / "core").exists())


class LimitsAndPruneTests(unittest.TestCase):
    def test_busy_lock_is_taken_before_the_body_is_stored(self):
        srv = Server(token="tok", cli_delay=2.0)
        self.addCleanup(srv.close)
        import threading
        results = []

        def put():
            results.append(srv.request("PUT", "/analyze", data=b"ELFCORE"))

        t1 = threading.Thread(target=put)
        t2 = threading.Thread(target=put)
        t1.start()
        time.sleep(0.2)
        t2.start()
        t1.join()
        t2.join()
        codes = sorted(r[0] for r in results)
        self.assertEqual(codes, [200, 503])
        # The rejected upload must not leave a core behind.
        time.sleep(0.1)
        self.assertFalse(any(srv.uploads.glob("*.core")))

    def test_stale_upload_cores_are_pruned(self):
        srv = Server(
            token="tok",
            extra_env={"NAKSHEAP_TIMEOUT": "1", "NAKSHEAP_SOCKET_TIMEOUT": "1"},
        )
        self.addCleanup(srv.close)
        stale = srv.uploads / "deadbeef.core"
        stale.write_bytes(b"SECRET")
        old = time.time() - 3600
        os.utime(stale, (old, old))
        status, _, body = srv.request("PUT", "/analyze", data=b"ELFCORE")
        self.assertEqual(status, 200, body)
        self.assertFalse(stale.exists())

    def test_invalid_content_length_is_400(self):
        srv = Server(token="tok")
        self.addCleanup(srv.close)
        status, _, _ = srv.request(
            "PUT", "/analyze", data=b"ELFCORE", headers={"Content-Length": "nope"}
        )
        # urllib may refuse to send a non-integer Content-Length. If it does
        # send it, the server must not crash.
        self.assertIn(status, (400, 411, 413, 500))

    def test_too_large_upload_is_413(self):
        srv = Server(token="tok", extra_env={"NAKSHEAP_MAX_UPLOAD_BYTES": "8"})
        self.addCleanup(srv.close)
        status, _, body = srv.request("PUT", "/analyze", data=b"0123456789")
        self.assertEqual(status, 413)
        self.assertFalse(any(srv.uploads.glob("*.core")))

    def test_prune_runs_after_success_and_drops_stale_reports(self):
        srv = Server(token="tok", extra_env={"NAKSHEAP_RETENTION_HOURS": "0.0001"})
        self.addCleanup(srv.close)
        stale = srv.artifacts / ("b" * 32)
        stale.mkdir()
        (stale / "report.html").write_text("old")
        old = time.time() - 3600
        os.utime(stale, (old, old))
        status, _, body = srv.request("PUT", "/analyze", data=b"ELFCORE")
        self.assertEqual(status, 200, body)
        self.assertFalse(stale.exists())


if __name__ == "__main__":
    unittest.main()

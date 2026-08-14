#!/bin/bash
# Real-world validation harness for naksheap.
#
# Captures REAL kernel-produced Linux core dumps (aarch64, Ubuntu 24.04 /
# glibc 2.39) of C++ programs with known allocations, then runs naksheap's
# full pipeline against them and checks the ground truth.
#
# Requires: docker (colima/Docker Desktop) with the ability to run privileged
# Linux containers. Tested against colima on macOS (aarch64).
#
# Usage: scripts/real-dump-test.sh [out-dir]   (default: target/real-dumps)

set -euo pipefail
OUT="$(cd "${1:-target/real-dumps}" && pwd)"
SCRIPTS_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SCRIPTS_DIR/.." && pwd)"
BIN="$REPO/target/release/naksheap"

mkdir -p "$OUT"
echo "== building release naksheap =="
(cd "$REPO" && cargo build --release -p naksheap-cli)

# Build + capture inside a privileged Ubuntu 24.04 (aarch64) container.
# The C++ sources live in this script directory as `real-*.cpp` fixtures.
cat > "$OUT/capture.sh" <<'EOF'
#!/bin/bash
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq g++ gdb >/dev/null 2>&1
cd /work
ulimit -c unlimited
echo "core" > /proc/sys/kernel/core_pattern 2>/dev/null || true
for t in test manyfree; do
  g++ -O2 -fno-omit-frame-pointer -std=c++17 -pthread -o "$t" "$t.cpp"
  strip "$t"
  # crash dump (remove any stale core first so we cannot pair the wrong one)
  rm -f core
  (./"$t" > "/out/$t.crash.log" 2>&1 || true)
  if [ ! -s core ]; then
    echo "ERROR: no core produced for $t (core_pattern/ulimit problem?)" >&2
    exit 1
  fi
  head -c 4 core | grep -q $'\x7fELF' || { echo "ERROR: core for $t is not ELF" >&2; exit 1; }
  mv -f core "/out/$t.crash.core"
  # live gcore snapshot
  setsid ./"$t" gcore > "/out/$t.live.log" 2>&1 &
  sleep 2
  PID=$(pgrep -x "$t" | head -1)
  gdb -q -batch -ex "generate-core-file /out/$t.live.core" -p "$PID" >/dev/null 2>&1 || true
  kill -9 "$PID" 2>/dev/null || true
done
echo "captured cores"
EOF
chmod +x "$OUT/capture.sh"

echo "== capturing real cores in Linux container =="
docker run --privileged --rm \
  -v "$SCRIPTS_DIR/real-src:/work" \
  -v "$OUT:/out" \
  ubuntu:24.04 bash /out/capture.sh

echo "== running naksheap against real dumps =="
for c in "$OUT"/*.crash.core "$OUT"/*.live.core; do
  [ -e "$c" ] || continue
  echo "--- $(basename "$c") ---"
  "$BIN" info "$c" | head -4
  "$BIN" heap "$c" | tail -2
  "$BIN" graph "$c" --json > "${c%.core}.graph.json"
done

echo "== ground truth comparison =="
FAILED=0
for log in "$OUT"/*.crash.log "$OUT"/*.live.log; do
  [ -e "$log" ] || continue
  graph="${log%.log}.graph.json"
  [ -e "$graph" ] || { echo "MISSING graph for $log"; FAILED=1; continue; }
  python3 - "$log" "$graph" <<'PYEOF'
import json, re, sys
log, graph = sys.argv[1], sys.argv[2]
gt = {}
for line in open(log):
    m = re.search(r"\bGT\b(.*)", line)
    if m:
        for k, v in re.findall(r"(\w+)=0x([0-9a-fA-F]+)", m.group(1)):
            gt[k] = int(v, 16)
nodes = json.load(open(graph))["nodes"]
by_addr = {n["addr"]: n for n in nodes}
missing = []
for k, addr in gt.items():
    if k == "sso":   # global in .bss, NOT heap: must be absent from the graph
        if addr in by_addr:
            print(f"  FAIL {k}=0x{addr:x} should not be in heap graph")
            sys.exit(1)
        continue
    n = by_addr.get(addr)
    if not n:
        missing.append(f"{k}=0x{addr:x}")
if missing:
    print(f"  FAIL missing nodes: {', '.join(missing)}")
    sys.exit(1)
freed = sum(1 for n in nodes if n["state"] == "freed")
if freed == 0:
    print("  FAIL no freed objects found (expected > 0 after explicit free()s)")
    sys.exit(1)
checked = [k for k in gt if k != "sso"]  # sso is a .bss global, not heap
print(f"  ok: {len(checked)} ground-truth objects found, {freed} freed detected")
PYEOF
  rc=$?
  if [ $rc -ne 0 ]; then FAILED=1; fi
done

if [ $FAILED -ne 0 ]; then
  echo "REAL-DUMP VALIDATION FAILED"
  exit 1
fi
echo "real-dump validation passed. cores + graphs in $OUT"

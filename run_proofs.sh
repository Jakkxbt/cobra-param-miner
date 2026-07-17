#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
PROOF="$ROOT/proofs"
mkdir -p "$PROOF"

VULN_PORT=18350
SAFE_PORT=18351

cleanup() {
  [[ -n "${VULN_PID:-}" ]] && kill "$VULN_PID" 2>/dev/null || true
  [[ -n "${SAFE_PID:-}" ]] && kill "$SAFE_PID" 2>/dev/null || true
}
trap cleanup EXIT

python3 "$ROOT/vuln_app.py" --port "$VULN_PORT" >/tmp/pm-vuln.log 2>&1 &
VULN_PID=$!
python3 "$ROOT/safe_app.py" --port "$SAFE_PORT" >/tmp/pm-safe.log 2>&1 &
SAFE_PID=$!

for i in $(seq 1 30); do
  curl -sf "http://127.0.0.1:${VULN_PORT}/" >/dev/null \
    && curl -sf "http://127.0.0.1:${SAFE_PORT}/" >/dev/null && break
  sleep 0.1
done

echo "========== VULN (expect HIGH name + MEDIUM debug) =========="
set +e
python3 "$ROOT/param-miner.py" "http://127.0.0.1:${VULN_PORT}/" --json \
  | tee "$PROOF/vuln.json"
set -e
python3 - <<'PY' "$PROOF/vuln.json"
import json,sys
d=json.load(open(sys.argv[1]))
find={f["param"]:f["confidence"] for f in d["findings"]}
print("findings:", find)
assert find.get("name")=="HIGH", find
assert find.get("debug")=="MEDIUM", find
# no other unexpected HIGH noise required — only these two signals matter
print("VULN PROOF: PASS")
PY

echo
echo "========== SAFE (expect zero findings) =========="
# miner exits 1 when silent — that is success for the cry-wolf trap
set +e
python3 "$ROOT/param-miner.py" "http://127.0.0.1:${SAFE_PORT}/" --json \
  | tee "$PROOF/safe.json"
set -e
python3 - <<'PY' "$PROOF/safe.json"
import json,sys
d=json.load(open(sys.argv[1]))
assert d["findings"]==[], d["findings"]
print("SAFE PROOF: PASS (silent)")
PY

echo
echo "LAB PROOFS: PASS"

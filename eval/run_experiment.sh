#!/usr/bin/env bash
# One evaluation run, end to end: mock upstream + gateway + replay, then cleanup.
#
# Every run gets fresh processes. That is deliberate: the gateway keeps the policy it was
# started with, so reusing one gateway process silently turns a `baseline` run into a copy of
# the `enforce` run. The replay additionally asserts the live policy via `--expect`.
#
# Usage (from the repository root):
#   bash eval/run_experiment.sh enforce  eval/data/synthetic.jsonl
#   bash eval/run_experiment.sh naive    eval/data/synthetic.jsonl
#   bash eval/run_experiment.sh baseline eval/data/synthetic.jsonl
#
# Optional: PYTHON=python3.12 bash eval/run_experiment.sh ...   (default: python3)
set -euo pipefail

MODE="${1:?usage: run_experiment.sh <enforce|naive|baseline> <dataset.jsonl>}"
DATASET="${2:?usage: run_experiment.sh <mode> <dataset.jsonl>}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

CONFIG="examples/mcp-guardrails/${MODE}/config.yaml"
OUT="eval/results/${MODE}.json"
GW_LOG="eval/results/${MODE}.gateway.log"
MOCK_LOG="eval/results/${MODE}.mock.log"

case "$MODE" in
  enforce | naive) EXPECT=deny ;;
  baseline) EXPECT=allow ;;
  *)
    echo "unknown mode: $MODE (expected enforce, naive or baseline)" >&2
    exit 2
    ;;
esac

[ -f "$CONFIG" ] || { echo "missing config: $CONFIG" >&2; exit 2; }
[ -f "$DATASET" ] || { echo "missing dataset: $DATASET — run eval/generate_dataset.py first" >&2; exit 2; }

# Fail early instead of probing whatever happens to be listening on the ports.
for port in 3000 9099; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "port $port is already in use — stop the running process first (gateway on 3000, mock on 9099)" >&2
    exit 1
  fi
done

mkdir -p eval/results
PY="${PYTHON:-python3}"

cleanup() {
  [ -n "${GW_PID:-}" ] && kill "$GW_PID" 2>/dev/null || true
  [ -n "${MOCK_PID:-}" ] && kill "$MOCK_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

probe() { # probe <url> <body>
  "$PY" - "$1" "$2" <<'PYEOF'
import json, sys, urllib.request
url, body = sys.argv[1], json.loads(sys.argv[2])
req = urllib.request.Request(
    url,
    data=json.dumps(body).encode(),
    headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
)
try:
    with urllib.request.urlopen(req, timeout=0.5) as resp:
        sys.exit(0 if resp.status == 200 else 1)
except Exception:
    sys.exit(1)
PYEOF
}

echo "==> starting mock upstream on 127.0.0.1:9099"
"$PY" eval/mcp_mock.py --port 9099 --quiet >"$MOCK_LOG" 2>&1 &
MOCK_PID=$!
for _ in $(seq 1 50); do
  "$PY" -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:9099/health', timeout=0.2).status == 200 else 1)" 2>/dev/null && break
  sleep 0.1
done

echo "==> building agentgateway (incremental; the binary is large)"
cargo build -p agentgateway-app
TARGET_DIR="${CARGO_TARGET_DIR:-target}"
BIN="$TARGET_DIR/debug/agentgateway"
[ -x "$BIN" ] || { echo "missing binary: $BIN" >&2; exit 1; }

echo "==> starting gateway with $CONFIG"
"$BIN" -f "$CONFIG" >"$GW_LOG" 2>&1 &
GW_PID=$!

INIT_BODY='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"ready-probe","version":"0"}}}'
ready=""
for _ in $(seq 1 240); do
  if probe "http://127.0.0.1:3000/mcp" "$INIT_BODY"; then
    ready=1
    break
  fi
  if ! kill -0 "$GW_PID" 2>/dev/null; then
    echo "gateway exited during startup; last lines of $GW_LOG:" >&2
    tail -20 "$GW_LOG" >&2 || true
    exit 1
  fi
  sleep 0.25
done
if [ -z "$ready" ]; then
  echo "gateway did not become ready; last lines of $GW_LOG:" >&2
  tail -40 "$GW_LOG" >&2 || true
  exit 1
fi

echo "==> replaying $DATASET against mode=$MODE (expect=$EXPECT)"
"$PY" eval/replay.py --dataset "$DATASET" --expect "$EXPECT" --out "$OUT"

echo
echo "results: $OUT"
echo "table:   ${OUT%.json}.md"
echo "logs:    $GW_LOG, $MOCK_LOG"

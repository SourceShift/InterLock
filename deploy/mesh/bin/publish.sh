#!/usr/bin/env bash
# Publish a fresh timestamp, snapshot and targets from commons/packs, then
# verify the result through the same verifier a subscriber uses.
set -euo pipefail
ROOT=${INTERLOCK_MESH_ROOT:-/srv/interlock-mesh}
mkdir -p "$ROOT/logs"
cd "$ROOT"
"$ROOT/venv/bin/interlock" mesh publish \
  --source commons --out site --keys keys >> "$ROOT/logs/publish.log" 2>&1
"$ROOT/venv/bin/interlock" mesh verify site >> "$ROOT/logs/publish.log" 2>&1

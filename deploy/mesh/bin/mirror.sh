#!/usr/bin/env bash
# Serve the published commons site read-only. Loopback only; Cloudflare Tunnel
# is the public listener and terminates TLS.
set -euo pipefail
ROOT=${INTERLOCK_MESH_ROOT:-/srv/interlock-mesh}
TOKEN=$(cat "$ROOT/secrets/mirror-gossip.token")
exec "$ROOT/venv/bin/interlock" mesh serve \
  --role mirror \
  --bind "${INTERLOCK_MESH_MIRROR_BIND:-127.0.0.1:7949}" \
  --dir "$ROOT/site" \
  --token "$TOKEN"

#!/usr/bin/env bash
# Consensus collector. The catalog id is the local Interlock build's catalog;
# replace it if the node runs a different detector set.
set -euo pipefail
ROOT=${INTERLOCK_MESH_ROOT:-/srv/interlock-mesh}
TOKEN=$(cat "$ROOT/secrets/consensus.token")
exec "$ROOT/venv/bin/interlock" mesh serve \
  --role consensus \
  --bind "${INTERLOCK_MESH_CONSENSUS_BIND:-127.0.0.1:7950}" \
  --state "$ROOT/state/consensus.json" \
  --known-catalog "${INTERLOCK_MESH_CATALOG:-06fc0a224e25135b}" \
  --min-orgs "${INTERLOCK_MESH_MIN_ORGS:-3}" \
  --token "$TOKEN"

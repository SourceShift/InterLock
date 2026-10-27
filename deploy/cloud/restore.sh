#!/usr/bin/env bash
# Restore a cloud control plane backup.
#
#   deploy/cloud/restore.sh --file backup.dump --dsn postgresql://... --yes
#
# Refuses to run without --yes. Restores only into an empty database: a
# restore over live data would overwrite `version_floor`, the one table that
# keeps a plane from publishing a manifest older than a host has already
# accepted. Restoring over a non-empty database is possible only with
# --reset-floor, which says explicitly that the floor may go backwards.
#
# After a restore the operator MUST raise the floor above every host's
# installed version before publishing a manifest (see the final message and
# docs/reference/cloud-runbook.md).
set -euo pipefail

DSN="${IL_CLOUD_DSN:-}"
FILE=""
YES=0
RESET_FLOOR=0

usage() {
  cat >&2 <<'EOF'
usage: restore.sh --file DUMP --dsn DSN --yes [--reset-floor]

  --file DUMP     custom-format dump written by backup.sh
  --dsn DSN       Postgres connection string (default: $IL_CLOUD_DSN)
  --yes           required; confirms the destructive restore
  --reset-floor   allow restoring over a non-empty database (lowers the
                  manifest version floor; use only when you accept that)
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --file) FILE="${2:-}"; shift 2 ;;
    --dsn) DSN="${2:-}"; shift 2 ;;
    --yes) YES=1; shift ;;
    --reset-floor) RESET_FLOOR=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 64 ;;
  esac
done

if [ "$YES" -ne 1 ]; then
  echo "restore.sh: refusing to restore without --yes" >&2
  exit 2
fi
if [ -z "$FILE" ] || [ ! -f "$FILE" ]; then
  echo "restore.sh: --file must name an existing dump" >&2
  exit 2
fi
if [ -z "$DSN" ]; then
  echo "restore.sh: set IL_CLOUD_DSN or pass --dsn" >&2
  exit 2
fi
for tool in psql pg_restore; do
  command -v "$tool" >/dev/null 2>&1 || {
    echo "restore.sh: $tool is not on PATH" >&2
    exit 2
  }
done

if [ -f "$FILE.sha256" ]; then
  if command -v sha256sum >/dev/null 2>&1; then
    ( cd "$(dirname "$FILE")" && sha256sum -c "$(basename "$FILE").sha256" )
  else
    ( cd "$(dirname "$FILE")" && shasum -a 256 -c "$(basename "$FILE").sha256" )
  fi
else
  echo "restore.sh: no .sha256 beside the dump; continuing unchecked" >&2
fi

TABLES="$(psql "$DSN" -Atc \
  "SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'")"
if [ "${TABLES:-0}" -ne 0 ]; then
  if [ "$RESET_FLOOR" -ne 1 ]; then
    cat >&2 <<'EOF'
restore.sh: the target database is not empty.

Restoring over it would overwrite `version_floor` and could let the plane
publish an older manifest than a host already accepted. Restore into an empty
database, or pass --reset-floor if you have established that no host is above
the dump's floor.
EOF
    exit 2
  fi
  echo "restore.sh: --reset-floor given; overwriting the existing schema" >&2
  pg_restore --clean --if-exists --no-owner --no-privileges \
    --dbname="$DSN" "$FILE"
else
  pg_restore --no-owner --no-privileges --dbname="$DSN" "$FILE"
fi

echo "restore: done"
cat <<'EOF'

MANDATORY post-restore step - publish nothing yet:

  1. Ask every host for its installed manifest version (the connector reports
     it, and the C5 manifest fetch refuses a lower version).
  2. Raise the floor above the highest reported version:
       interlock cloud admin version-floor --org ORG --bump-to N
  3. Confirm the next publish is at or above the floor:
       interlock cloud admin version-floor --org ORG --show
  4. Then publish the next manifest.

Skipping this is how a restore hands a host an older policy than the one it is
already enforcing.
EOF

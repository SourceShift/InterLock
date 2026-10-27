#!/usr/bin/env bash
# Back up the cloud control plane's Postgres database.
#
#   IL_CLOUD_DSN=postgresql://... deploy/cloud/backup.sh
#   deploy/cloud/backup.sh --dsn postgresql://... --out /var/backups/interlock
#
# Writes one timestamped custom-format dump plus its SHA-256 sidecar. Set
# IL_CLOUD_BACKUP_S3=s3://bucket/prefix to upload both with the AWS CLI (the
# hook is optional; a failure there is reported, not hidden).
#
# The DSN is never echoed. pg_dump still receives it on its argv, which is
# visible to the same host's process list; run backups as a dedicated account.
set -euo pipefail

DSN="${IL_CLOUD_DSN:-}"
OUT="${IL_CLOUD_BACKUP_DIR:-./backups}"
S3="${IL_CLOUD_BACKUP_S3:-}"

usage() {
  cat >&2 <<'EOF'
usage: backup.sh [--dsn DSN] [--out DIR]

  --dsn DSN   Postgres connection string (default: $IL_CLOUD_DSN)
  --out DIR   destination directory (default: $IL_CLOUD_BACKUP_DIR or ./backups)
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --dsn) DSN="${2:-}"; shift 2 ;;
    --out) OUT="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 64 ;;
  esac
done

if [ -z "$DSN" ]; then
  echo "backup.sh: set IL_CLOUD_DSN or pass --dsn" >&2
  exit 2
fi
command -v pg_dump >/dev/null 2>&1 || {
  echo "backup.sh: pg_dump is not on PATH" >&2
  exit 2
}
mkdir -p "$OUT"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
FILE="$OUT/interlock-cloud-$STAMP.dump"

pg_dump --format=custom --no-owner --no-privileges \
  --dbname="$DSN" --file="$FILE"

if command -v sha256sum >/dev/null 2>&1; then
  ( cd "$OUT" && sha256sum "$(basename "$FILE")" > "$(basename "$FILE").sha256" )
else
  ( cd "$OUT" && shasum -a 256 "$(basename "$FILE")" > "$(basename "$FILE").sha256" )
fi

echo "backup: wrote $FILE"
echo "backup: wrote $FILE.sha256"

if [ -n "$S3" ]; then
  if command -v aws >/dev/null 2>&1; then
    aws s3 cp "$FILE" "$S3/" >/dev/null
    aws s3 cp "$FILE.sha256" "$S3/" >/dev/null
    echo "backup: uploaded to $S3/"
  else
    echo "backup: IL_CLOUD_BACKUP_S3 is set but the aws CLI is missing" >&2
    exit 1
  fi
fi

# Restore safety: the dump alone does not remember the manifest version floor.
# After restoring an older dump, an operator must run
#   interlock cloud admin version-floor --show
# and bump the floor above every host's installed version before publishing.
cat <<'EOF'

Next: deploy/cloud/restore.sh restores this file into an *empty* database and
prints the mandatory version-floor step. A plane restored from an older dump
must never publish a manifest below a version a host already accepted.
EOF

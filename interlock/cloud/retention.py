"""The receipt retention job (FR-039).

Receipts live for the org's configured period: 365 days by default, and never
less than 30 or more than 2,555. Retention is deliberately conservative:

* a **dry run** counts what would go and deletes nothing;
* the head of a chain that is not ``verified`` is never deleted, because it is
  the only evidence of the chain's tail - it is reported as
  ``retention_skipped`` instead;
* the newest checkpoint per host is never pruned;
* every run is audited (actor ``system:retention``), and every skipped head is
  audited separately so an operator can see the chain that outlived its
  receipts.

Both stores implement ``retention_delete``; this module only decides the
cutoff and writes the audit record, so the same job runs in tests against
``MemoryStore`` and against Postgres from the CLI::

    python3 -m interlock.cloud.retention --dsn DSN [--dry-run] [--days N]
"""
from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Dict, List, Optional

#: FR-039 bounds. A configured value outside these is clamped, never refused:
#: an org with a typo still gets a safe retention period.
DEFAULT_RETENTION_DAYS = 365
MIN_RETENTION_DAYS = 30
MAX_RETENTION_DAYS = 2_555

SECONDS_PER_DAY = 24 * 60 * 60

#: The actor every retention audit row carries; it is not a human user.
RETENTION_ACTOR = "system:retention"


def clamp_days(value: Any,
               default: int = DEFAULT_RETENTION_DAYS) -> int:
    """Clamp a configured retention period into the FR-039 bounds."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    days = int(value)
    return max(MIN_RETENTION_DAYS, min(MAX_RETENTION_DAYS, days))


def run(store: Any, now: float, *, days: Optional[int] = None,
        dry_run: bool = False, org_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """Delete expired receipts for every org (or ``org_ids``).

    ``days`` overrides each org's configured period - the operator override.
    It is clamped exactly like a configured value. Returns totals plus one
    entry per org so the caller can report what happened where.
    """
    at = float(now)
    total_receipts = 0
    total_checkpoints = 0
    runs: List[Dict[str, Any]] = []
    wanted = set(org_ids) if org_ids is not None else None
    for org in store.list_orgs():
        if wanted is not None and org.id not in wanted:
            continue
        effective = clamp_days(
            days if days is not None else getattr(org, "retention_days", None))
        cutoff = at - effective * SECONDS_PER_DAY
        result = store.retention_delete(
            org.id, cutoff, dry_run=dry_run, now=at)
        removed_receipts = int(result.get("receipts") or 0)
        removed_checkpoints = int(result.get("checkpoints") or 0)
        total_receipts += removed_receipts
        total_checkpoints += removed_checkpoints
        skipped = list(result.get("skipped") or [])
        store.audit_append(
            org.id, "retention.ran", actor=RETENTION_ACTOR,
            detail={
                "days": effective,
                "cutoff": cutoff,
                "receipts": removed_receipts,
                "checkpoints": removed_checkpoints,
                "skipped": len(skipped),
                "dry_run": bool(dry_run),
                "at": at,
            },
        )
        for entry in skipped:
            store.audit_append(
                org.id, "retention_skipped", actor=RETENTION_ACTOR,
                detail={
                    "host_id": entry.get("host_id"),
                    "mac": entry.get("mac"),
                    "reason": "head of an unverified chain is preserved",
                    "at": at,
                },
            )
        runs.append({
            "org_id": org.id,
            "days": effective,
            "cutoff": cutoff,
            "receipts": removed_receipts,
            "checkpoints": removed_checkpoints,
            "skipped": skipped,
            "dry_run": bool(dry_run),
        })
    return {
        "receipts": total_receipts,
        "checkpoints": total_checkpoints,
        "runs": runs,
        "dry_run": bool(dry_run),
        "at": at,
    }


def main(argv: Optional[List[str]] = None) -> int:
    from .db import CloudDependencyMissing
    from .store import PostgresStore

    parser = argparse.ArgumentParser(
        prog="python -m interlock.cloud.retention",
        description="Delete receipts older than each org's retention period.",
    )
    parser.add_argument("--dsn", default=os.environ.get("IL_CLOUD_DSN"),
                        metavar="DSN", help="Postgres connection string")
    parser.add_argument("--days", type=int, default=None,
                        help="override the org period (clamped to 30..2555)")
    parser.add_argument("--dry-run", action="store_true",
                        help="report what would be deleted, delete nothing")
    args = parser.parse_args(argv)
    if not args.dsn:
        parser.error("--dsn is required (or set IL_CLOUD_DSN)")

    import time

    try:
        result = run(PostgresStore(args.dsn), time.time(),
                     days=args.days, dry_run=args.dry_run)
    except CloudDependencyMissing as exc:
        sys.stderr.write("interlock cloud retention: {}\n".format(exc))
        return 2
    except Exception as exc:
        sys.stderr.write("interlock cloud retention: {}\n".format(exc))
        return 2

    sys.stdout.write(
        "{}: {} receipts, {} checkpoints{}\n".format(
            "would delete" if args.dry_run else "deleted",
            result["receipts"], result["checkpoints"],
            " (dry run)" if args.dry_run else ""))
    for entry in result["runs"]:
        sys.stdout.write(
            "  {}: {} receipts, {} checkpoints, {} preserved heads\n".format(
                entry["org_id"], entry["receipts"], entry["checkpoints"],
                len(entry["skipped"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())


__all__ = [
    "DEFAULT_RETENTION_DAYS",
    "MAX_RETENTION_DAYS",
    "MIN_RETENTION_DAYS",
    "RETENTION_ACTOR",
    "clamp_days",
    "main",
    "run",
]

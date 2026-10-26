"""Apply the plane's SQL migrations, in order, once each.

    python3 -m interlock.cloud.migrate --dsn DSN
    python3 -m interlock.cloud.migrate --dsn DSN --check

A migration is ``NNN_name.sql`` under :data:`MIGRATIONS_DIR`. Versions are
contiguous from 1: a duplicate prefix or a gap is a packaging error, and
:func:`parse_versions` rejects it before a connection is opened. Each pending
file runs in its own transaction, together with the row that records it, so a
failed migration leaves neither half applied.

The Postgres driver is imported lazily inside :func:`run`; the pure helpers
(:func:`parse_versions`, :func:`available`) work with no driver installed.

Exit codes: 0 applied (or nothing pending), 1 ``--check`` found pending files,
2 the database is unreachable or the driver is missing.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from .db import CloudDependencyMissing, connect

#: ``sql/`` sits beside this module and ships via package-data.
MIGRATIONS_DIR = Path(__file__).with_name("sql")

_MIGRATION_NAME = re.compile(r"^(\d+)_[A-Za-z0-9._-]+\.sql$")

SCHEMA_MIGRATIONS_DDL = (
    "CREATE TABLE IF NOT EXISTS schema_migrations ("
    "version integer primary key, "
    "name text not null, "
    "applied_at timestamptz not null default now())"
)


def parse_versions(names: Iterable[str]) -> List[Tuple[int, str]]:
    """Return ``[(version, filename)]`` sorted, or raise ``ValueError``.

    Files that are not ``.sql`` are ignored so a stray README does not break
    the runner; a ``.sql`` file without a numeric prefix is rejected.
    """
    parsed: List[Tuple[int, str]] = []
    seen = set()
    for name in names:
        if not name.endswith(".sql"):
            continue
        match = _MIGRATION_NAME.match(name)
        if match is None:
            raise ValueError(
                "migration filename must be NNN_name.sql: {!r}".format(name)
            )
        version = int(match.group(1))
        if version in seen:
            raise ValueError("duplicate migration version {}".format(version))
        seen.add(version)
        parsed.append((version, name))
    parsed.sort(key=lambda item: item[0])
    found = [version for version, _name in parsed]
    expected = list(range(1, len(parsed) + 1))
    if found != expected:
        raise ValueError(
            "migration versions must be contiguous from 1; got {}".format(found)
        )
    return parsed


def available() -> List[Tuple[int, str]]:
    """The migrations on disk, in version order."""
    if not MIGRATIONS_DIR.is_dir():
        return []
    names = [
        path.name for path in MIGRATIONS_DIR.iterdir()
        if path.is_file() and path.name.endswith(".sql")
    ]
    return parse_versions(names)


def _recorded(conn) -> set:
    """Versions already in ``schema_migrations``; empty when it is absent."""
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT version FROM schema_migrations")
            return {row[0] for row in cur.fetchall()}
    except Exception:
        conn.rollback()
        return set()


def run(dsn: str) -> List[str]:
    """Apply every pending migration, returning the filenames applied."""
    conn = connect(dsn)
    applied: List[str] = []
    try:
        with conn.cursor() as cur:
            cur.execute(SCHEMA_MIGRATIONS_DDL)
        conn.commit()
        recorded = _recorded(conn)
        for version, name in available():
            if version in recorded:
                continue
            sql = (MIGRATIONS_DIR / name).read_text(encoding="utf-8")
            try:
                with conn.cursor() as cur:
                    cur.execute(sql)
                    cur.execute(
                        "INSERT INTO schema_migrations (version, name) "
                        "VALUES (%s, %s)",
                        (version, name),
                    )
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            applied.append(name)
    finally:
        conn.close()
    return applied


def pending(dsn: str) -> List[str]:
    """The migration filenames not yet recorded in the database."""
    conn = connect(dsn)
    try:
        recorded = _recorded(conn)
    finally:
        conn.close()
    return [name for version, name in available() if version not in recorded]


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m interlock.cloud.migrate",
        description="Apply the interlock cloud Postgres migrations.",
    )
    parser.add_argument("--dsn", default=os.environ.get("IL_CLOUD_DSN"),
                        metavar="DSN", help="Postgres connection string")
    parser.add_argument("--check", action="store_true",
                        help="report pending migrations and exit 1 if any")
    args = parser.parse_args(argv)
    if not args.dsn:
        parser.error("--dsn is required (or set IL_CLOUD_DSN)")

    try:
        if args.check:
            todo = pending(args.dsn)
            for name in todo:
                sys.stdout.write("pending: {}\n".format(name))
            return 1 if todo else 0
        names = run(args.dsn)
    except CloudDependencyMissing as exc:
        sys.stderr.write("interlock cloud migrate: {}\n".format(exc))
        return 2
    except Exception as exc:
        sys.stderr.write("interlock cloud migrate: {}\n".format(exc))
        return 2

    for name in names:
        sys.stdout.write("applied: {}\n".format(name))
    if not names:
        sys.stdout.write("no pending migrations\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

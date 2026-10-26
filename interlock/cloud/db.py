"""Postgres access, imported lazily so the package stays dependency-free.

``psycopg`` lives in the ``cloud`` extra. Importing this module must never
import it: the driver import happens inside :func:`connect`, so ``import
interlock.cloud.app`` and ``python -m interlock.cloud --help`` work on a bare
interpreter.
"""
from __future__ import annotations

import contextlib
from typing import Any, Iterator

INSTALL_HINT = "install the cloud extra: pip install -e '.[cloud]'"

#: Seconds to wait for a TCP/TLS connection. Without this, libpq retries every
#: resolved address indefinitely and a readiness probe can hang for minutes.
CONNECT_TIMEOUT_SECONDS = 5


class CloudDependencyMissing(RuntimeError):
    """The optional cloud extra (the Postgres driver) is not installed."""


def connect(dsn: str) -> Any:
    """Open a Postgres connection, or explain how to install the driver."""
    try:
        import psycopg
    except ImportError:
        raise CloudDependencyMissing(INSTALL_HINT) from None
    return psycopg.connect(dsn, connect_timeout=CONNECT_TIMEOUT_SECONDS)


def ping(dsn: str) -> bool:
    """True when a trivial query succeeds; False on any error, never raises."""
    try:
        conn = connect(dsn)
    except Exception:
        return False
    try:
        with conn.cursor() as cur:
            cur.execute("select 1")
        return True
    except Exception:
        return False
    finally:
        try:
            conn.close()
        except Exception:
            pass


def quote_literal(value: str) -> str:
    """Quote a value as a SQL string literal.

    ``SET LOCAL`` does not accept a bound parameter, so the org id is
    interpolated. Quotes are doubled per the SQL standard and nothing else is
    interpreted, which is the only embedding that is safe here.
    """
    return "'" + str(value).replace("'", "''") + "'"


@contextlib.contextmanager
def org_transaction(dsn: str, org_id: str) -> Iterator[Any]:
    """Open a transaction whose first statement sets ``interlock.org_id``.

    Postgres row-level security reads the setting for the duration of the
    transaction (``SET LOCAL``). It is issued first, before any tenant query,
    so a pool reuse can never inherit another org's setting.
    """
    conn = connect(dsn)
    try:
        with conn.cursor() as cur:
            cur.execute("SET LOCAL interlock.org_id = " + quote_literal(org_id))
            yield cur
        conn.commit()
    except BaseException:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        try:
            conn.close()
        except Exception:
            pass

"""Postgres access, imported lazily so the package stays dependency-free.

``psycopg`` lives in the ``cloud`` extra. Importing this module must never
import it: the driver import happens inside :func:`connect`, so ``import
interlock.cloud.app`` and ``python -m interlock.cloud --help`` work on a bare
interpreter.
"""
from __future__ import annotations

from typing import Any

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

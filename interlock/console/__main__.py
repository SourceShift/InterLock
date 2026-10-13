"""Command line: ``python -m interlock.console`` or the ``interlock-console``
script.

The loopback host check runs here, before any socket opens: refusing a bad
``--host`` after a process has already bound and started listening would mean
a brief window where the wrong thing is true. Checking first means the
process never binds at all when the host is wrong.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

import interlock

from .audit import read_key_file
from .server import ConsoleServer, LOOPBACK_HOSTS
from .session import configure

EXIT_BAD_HOST = 2
EXIT_BAD_KEY_FILE = 2

DEFAULT_PORT = 7878


def _default_static_dir() -> Path:
    return Path(interlock.__file__).resolve().parent.parent / "web" / "dist"


def _parse_args(argv: Optional[Sequence[str]]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="interlock-console",
        description="Serve the interlock console: a local web UI over this process's policy engine.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="loopback address to bind (127.0.0.1, localhost or ::1; default 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="port to bind (default {})".format(DEFAULT_PORT),
    )
    parser.add_argument(
        "--static",
        type=Path,
        default=None,
        metavar="DIR",
        help="static asset directory (default: the web/dist next to the installed package)",
    )
    parser.add_argument(
        "--receipts",
        default=None,
        metavar="PATH",
        help="read decision receipts from PATH (default: the audit routes answer 404)",
    )
    parser.add_argument(
        "--key-file",
        default=None,
        metavar="PATH",
        help="receipt MAC key: 64 hex characters or raw bytes (default: verify reports unverified)",
    )
    parser.add_argument(
        "--policy",
        default=None,
        metavar="PATH",
        help="the declarative policy the editor reads and saves (default ~/.interlock/policy.json)",
    )
    parser.add_argument(
        "--reviews-db",
        default=None,
        metavar="PATH",
        help="the review queue (default ~/.interlock/reviews.db)",
    )
    parser.add_argument(
        "--four-eyes",
        action="store_true",
        help="refuse an approval by the account that filed the review",
    )
    parser.add_argument(
        "--sidecar",
        default=None,
        metavar="PATH",
        help="the guard daemon's socket to probe (default: its usual path, if present)",
    )
    parser.add_argument(
        "--sidecar-admin",
        default=None,
        metavar="HOST:PORT",
        help="the guard daemon's loopback admin address, for its stats and config",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = _parse_args(argv)

    if args.host not in LOOPBACK_HOSTS:
        sys.stderr.write(
            "interlock-console: --host must be a loopback address "
            "(127.0.0.1, localhost or ::1), got {!r}\n".format(args.host)
        )
        return EXIT_BAD_HOST

    key = None
    if args.key_file is not None:
        try:
            key = read_key_file(args.key_file)
        except ValueError as exc:
            sys.stderr.write("interlock-console: {}\n".format(exc))
            return EXIT_BAD_KEY_FILE

    static_dir = args.static if args.static is not None else _default_static_dir()
    server = ConsoleServer(
        (args.host, args.port),
        static_dir,
        receipts_path=args.receipts,
        receipts_key=key,
    )
    gate = configure(
        server,
        policy_path=args.policy,
        reviews_db=args.reviews_db,
        four_eyes=args.four_eyes,
        sidecar=args.sidecar,
        sidecar_admin=args.sidecar_admin,
        key_file=args.key_file,
    )
    host = "[::1]" if args.host == "::1" else args.host
    base = "http://{}:{}".format(host, server.server_port)
    # The unlock link goes to this terminal and nowhere else (see session.py).
    sys.stderr.write("interlock console on {} (read-only)\n".format(base))
    sys.stderr.write("unlock writes: {}/#/unlock/{}\n".format(base, gate.code))
    sys.stderr.flush()
    try:
        server.serve_forever()
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

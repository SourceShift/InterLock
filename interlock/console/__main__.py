"""Command line: ``python -m interlock.console`` or the ``interlock-console``
script.

The loopback host check runs here, before any socket opens: refusing a bad
``--host`` after a process has already bound and started listening would mean
a brief window where the wrong thing is true. Checking first means the
process never binds at all when the host is wrong.
"""
from __future__ import annotations

import argparse
import re
import signal
import sys
from pathlib import Path
from typing import Optional, Sequence

import interlock

from interlock.sidecar.__main__ import _read_key
from ..sidecar.rules import RulesError
from .server import ConsoleServer, LOOPBACK_HOSTS
from .session import configure

EXIT_BAD_HOST = 2
EXIT_BAD_KEY_FILE = 2
EXIT_PORT_IN_USE = 1

DEFAULT_PORT = 7878


class _Stop(SystemExit):
    """Raised by the SIGINT/SIGTERM handler to unwind out of
    ``serve_forever()`` without the deadlock calling ``server.shutdown()``
    from inside its own thread would cause (F17)."""


def _install_signal_handlers() -> None:
    # Installed unconditionally, overriding whatever disposition this
    # process inherited (SIGINT ignored, for one, when started in the
    # background), so SIGINT and SIGTERM stop the server either way.
    def _stop(_signum: int, _frame: object) -> None:
        raise _Stop(0)

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)


def _url_host(host: str) -> str:
    return "[{}]".format(host) if ":" in host else host


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
        "--receipts-head",
        default=None,
        metavar="MAC",
        help="the mac the receipt log is expected to end at; with it, a rolled-back or "
             "truncated log verifies broken (default: no anchor)",
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
    parser.add_argument(
        "--mesh-dir",
        default=None,
        metavar="DIR",
        help="the mesh state to show (default: $INTERLOCK_MESH_DIR or ~/.interlock/mesh)",
    )
    parser.add_argument(
        "--transcripts",
        default=None,
        metavar="DIR",
        help="Claude Code transcripts, for real calls in the playground, backtests and the "
             "detector sweep (default ~/.claude/projects); only ever read",
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

    receipts_head = None
    if args.receipts_head is not None:
        # The chain's macs are lowercase hexdigests; fold case rather than
        # reject an anchor copied from a tool that uppercased it, so a valid
        # anchor never reports a false rollback.
        if re.fullmatch(r"[0-9a-fA-F]{64}", args.receipts_head) is None:
            sys.stderr.write(
                "interlock-console: --receipts-head must be 64 hex characters, "
                "got {!r}\n".format(args.receipts_head)
            )
            return EXIT_BAD_KEY_FILE
        receipts_head = args.receipts_head.lower()

    key = None
    if args.key_file is not None:
        try:
            key = _read_key(args.key_file)
        except RulesError as exc:
            sys.stderr.write("interlock-console: {}\n".format(exc))
            return EXIT_BAD_KEY_FILE

    static_dir = args.static if args.static is not None else _default_static_dir()
    try:
        server = ConsoleServer(
            (args.host, args.port),
            static_dir,
            receipts_path=args.receipts,
            receipts_key=key,
            receipts_head=receipts_head,
        )
    except OSError:
        sys.stderr.write(
            "interlock-console: port {} is already in use\n".format(args.port)
        )
        return EXIT_PORT_IN_USE

    sys.stdout.write(
        "interlock console listening on http://{}:{}\n".format(
            _url_host(args.host), server.server_port
        )
    )
    sys.stdout.flush()
    gate = configure(
        server,
        policy_path=args.policy,
        reviews_db=args.reviews_db,
        four_eyes=args.four_eyes,
        sidecar=args.sidecar,
        sidecar_admin=args.sidecar_admin,
        key_file=args.key_file,
        transcripts=args.transcripts,
        mesh_dir=args.mesh_dir,
    )
    # The unlock link goes to this terminal and nowhere else (see session.py).
    sys.stderr.write("unlock writes: http://{}:{}/#/unlock/{}\n".format(
        _url_host(args.host), server.server_port, gate.code))
    sys.stderr.flush()

    _install_signal_handlers()
    try:
        server.serve_forever()
    except _Stop:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Command line: ``interlock-sidecar --rules module:engine``.

Starts the guard daemon that another-language agent talks to. It refuses to
start on an empty rule set, refuses to start over a socket another daemon is
already serving, and refuses to start if it cannot restrict the socket to its
owner - every refusal is the same instinct: a guard that is not actually
guarding must not look like it is.
"""
from __future__ import annotations

import argparse
import os
import signal
import sys
from typing import Optional

from .client import probe
from .rules import RulesError, load_rules
from .server import SidecarServer

EXIT_BAD_RULES = 2
EXIT_ALREADY_RUNNING = 3
EXIT_UNSAFE_SOCKET = 4


def default_socket_path() -> str:
    """Where the daemon listens by default.

    ``$XDG_RUNTIME_DIR`` first (per-user, already 0700, cleared on logout), then
    ``~/.interlock``. Never a shared path like ``/tmp``: the socket carries tool
    arguments in cleartext, so its directory is part of the boundary.
    """
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    base = os.path.join(runtime, "interlock") if runtime else os.path.join(
        os.path.expanduser("~"), ".interlock"
    )
    return os.path.join(base, "guard.sock")


def _read_key(path: str) -> bytes:
    """Read a receipt signing key: 64 hex characters, or raw bytes.

    Trailing newlines are stripped before that test, because the difference
    between a key and the same key with a newline is a different key.
    """
    with open(path, "rb") as fh:
        raw = fh.read().rstrip(b"\r\n")
    if len(raw) == 64:
        try:
            return bytes.fromhex(raw.decode("ascii"))
        except ValueError:
            pass
    if not raw:
        raise RulesError("key file {} is empty".format(path))
    return raw


def _disable_core_dumps() -> None:
    """A crash must not write a core file holding the arguments in memory."""
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except Exception:
        pass


def _prepare_socket(path: str) -> None:
    """Create the socket's directory at 0700 and clear a dead socket file.

    A socket file left by a crash would make ``bind`` fail. It is removed only
    after proving nothing is listening on it - a live daemon's socket is never
    unlinked.
    """
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, mode=0o700, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError as exc:
        raise RulesError(
            "cannot restrict {} to 0700: {}".format(directory, exc)
        )
    if os.path.exists(path):
        if probe(path):
            sys.stderr.write(
                "interlock-sidecar: a daemon is already serving {}\n".format(path)
            )
            raise SystemExit(EXIT_ALREADY_RUNNING)
        os.unlink(path)


def _build_sink(receipts: Optional[str], key_file: Optional[str]):
    if receipts is None:
        return None
    from ..sink import FileSink

    if key_file is None:
        return FileSink(receipts)
    return FileSink(receipts, key=_read_key(key_file))


def _parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="interlock-sidecar",
        description="Serve one interlock policy engine to agents in other languages.",
    )
    parser.add_argument(
        "--rules",
        required=True,
        metavar="MODULE:ATTR",
        help="dotted module path and attribute holding a PolicyEngine or a list of rules",
    )
    parser.add_argument(
        "--socket",
        default=None,
        help="unix socket to listen on (default: $XDG_RUNTIME_DIR/interlock/guard.sock)",
    )
    parser.add_argument(
        "--receipts",
        default=None,
        metavar="PATH",
        help="append decision receipts to PATH (default: no receipts are written)",
    )
    parser.add_argument(
        "--key-file",
        default=None,
        metavar="PATH",
        help="receipt MAC key: 64 hex characters or raw bytes (default: per-process secret)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate the rules and exit without serving",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    args = _parse_args(argv)

    try:
        engine = load_rules(args.rules)
    except RulesError as exc:
        sys.stderr.write("interlock-sidecar: {}\n".format(exc))
        return EXIT_BAD_RULES

    if args.check:
        sys.stderr.write(
            "interlock-sidecar: {} rules loaded from {}\n".format(
                len(engine), args.rules
            )
        )
        return 0

    path = args.socket or default_socket_path()
    try:
        _prepare_socket(path)
        sink = _build_sink(args.receipts, args.key_file)
    except RulesError as exc:
        sys.stderr.write("interlock-sidecar: {}\n".format(exc))
        return EXIT_BAD_RULES

    _disable_core_dumps()

    try:
        server = SidecarServer(path, engine, sink=sink)
    except OSError as exc:
        sys.stderr.write(
            "interlock-sidecar: cannot listen on {}: {}\n".format(path, exc)
        )
        return EXIT_UNSAFE_SOCKET

    # Diagnostics go to stderr so the socket is the only thing on stdout.
    sys.stderr.write(
        "interlock-sidecar: listening on {}\n"
        "  rules:    {} ({} rules)\n"
        "  receipts: {}\n".format(
            path,
            args.rules,
            len(engine),
            args.receipts
            if args.receipts
            else "off - decisions will not be recorded",
        )
    )
    if args.receipts and args.key_file is None:
        sys.stderr.write(
            "  WARNING:  receipts are signed with a per-process secret, so the "
            "chain is verifiable only by this process. Use --key-file for a "
            "durable key.\n"
        )

    def _stop(signum, frame):  # pragma: no cover - delivered by the OS
        raise KeyboardInterrupt

    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(signum, _stop)
        except (ValueError, OSError):  # not the main thread / unsupported
            pass

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        try:
            os.unlink(path)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

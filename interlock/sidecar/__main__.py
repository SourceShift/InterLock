"""Command line: ``interlock-sidecar --rules module:engine``.

Starts the guard daemon that another-language agent talks to. It refuses to
start on an empty rule set, refuses to start over a socket another daemon is
already serving, and refuses to start if it cannot restrict the socket to its
owner - every refusal is the same instinct: a guard that is not actually
guarding must not look like it is.
"""
from __future__ import annotations

import argparse
import getpass
import os
import signal
import stat
import sys
from typing import Optional

from .client import probe
from .rules import RulesError, load_rules
from .server import SidecarServer

EXIT_BAD_RULES = 2
EXIT_ALREADY_RUNNING = 3
EXIT_UNSAFE_SOCKET = 4


class UnsafeSocketDir(RulesError):
    """The socket's directory is one the daemon must not use or modify.

    A subclass of :class:`RulesError` so the CLI maps it to the same exit code
    (2) every other refusal to start with an unsafe configuration uses.
    """


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
    between a key and the same key with a newline is a different key. A key
    file that is missing or unreadable is a configuration error, reported as a
    one-line refusal rather than a traceback.
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read().rstrip(b"\r\n")
    except OSError as exc:
        raise RulesError(
            "cannot read key file {}: {}".format(path, exc.strerror or exc)
        )
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


def _private_dir_hint() -> str:
    try:
        user = getpass.getuser()
    except Exception:
        user = str(os.getuid())
    return "/tmp/{}-interlock/guard.sock".format(user)


def _secure_socket_dir(directory: str) -> None:
    """Make sure the socket's directory is private to this user.

    - A missing directory is created at 0700.
    - A shared directory (world-writable or sticky-bit, like ``/tmp``) is never
      modified: the daemon refuses it. Changing its mode would fail for a normal
      user and, run as root, would lock every other user out of it.
    - A directory owned by another user is refused.
    - A directory this user owns that is not shared is tightened to 0700.
    """
    try:
        os.makedirs(directory, mode=0o700)
    except FileExistsError:
        pass
    except OSError as exc:
        raise UnsafeSocketDir(
            "cannot create socket directory {}: {}".format(
                directory, exc.strerror or exc
            )
        )
    try:
        info = os.stat(directory)
    except OSError as exc:
        raise UnsafeSocketDir(
            "cannot inspect socket directory {}: {}".format(
                directory, exc.strerror or exc
            )
        )
    if not stat.S_ISDIR(info.st_mode):
        raise UnsafeSocketDir("socket directory {} is not a directory".format(directory))
    mode = stat.S_IMODE(info.st_mode)
    if mode & 0o002 or mode & stat.S_ISVTX:
        raise UnsafeSocketDir(
            "socket directory {} is shared (world-writable or sticky), so the "
            "daemon will not use or modify it; put the socket in a private "
            "directory instead, e.g. --socket {}".format(directory, _private_dir_hint())
        )
    if info.st_uid != os.getuid():
        raise UnsafeSocketDir(
            "socket directory {} is owned by uid {}, not the current user "
            "(uid {})".format(directory, info.st_uid, os.getuid())
        )
    if mode & 0o077:
        try:
            os.chmod(directory, 0o700)
        except OSError as exc:
            raise UnsafeSocketDir(
                "cannot restrict {} to 0700: {}".format(directory, exc.strerror or exc)
            )


def _prepare_socket(path: str) -> None:
    """Secure the socket's directory and clear a dead socket file.

    A socket file left by a crash would make ``bind`` fail. It is removed only
    after proving nothing is listening on it - a live daemon's socket is never
    unlinked.
    """
    _secure_socket_dir(os.path.dirname(path) or ".")
    if os.path.exists(path):
        if probe(path):
            sys.stderr.write(
                "interlock-sidecar: a daemon is already serving {}\n".format(path)
            )
            raise SystemExit(EXIT_ALREADY_RUNNING)
        os.unlink(path)


def _build_sink(receipts: Optional[str], key_file: Optional[str]):
    # The key is read whenever it is given, so a mistyped --key-file is caught
    # at startup even before --receipts is added.
    key = _read_key(key_file) if key_file is not None else None
    if receipts is None:
        return None
    from ..sink import FileSink

    try:
        if key is None:
            return FileSink(receipts)
        return FileSink(receipts, key=key)
    except (OSError, ValueError) as exc:
        # A receipts file that can't be read, or whose last line isn't a
        # receipt, is a configuration problem: refuse to start, with one line.
        raise RulesError("cannot use receipts file {}: {}".format(receipts, exc))


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
        sink = _build_sink(args.receipts, args.key_file)
        _prepare_socket(path)
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

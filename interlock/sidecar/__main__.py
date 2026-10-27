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
import json
import os
import secrets
import signal
import stat
import sys
import tempfile
from typing import Any, Optional

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


def _engine_size(engine: Any) -> int:
    """A rule count for a ``PolicyEngine`` or a ``ScopedEngine``.

    The banner and the admin endpoint both want "how many rules is this daemon
    serving". A ``PolicyEngine`` answers with ``len``; a ``ScopedEngine`` has
    neither ``__len__`` nor ``policy_ids`` (it resolves per scope), so its size
    is the number of templates it can bind.
    """
    policy_ids = getattr(engine, "policy_ids", None)
    if policy_ids is not None:
        try:
            return len(policy_ids)
        except TypeError:
            pass
    try:
        return len(engine)
    except TypeError:
        pass
    # A CompiledPolicy has no ``__len__``: its size is the document floor plus
    # the templates its scope registry can bind.
    base = getattr(engine, "base", None)
    scoped = getattr(engine, "engine", None)
    if base is not None or scoped is not None:
        size = 0
        if base is not None:
            try:
                size += len(base)
            except TypeError:
                pass
        registry = getattr(scoped, "registry", None)
        templates = getattr(registry, "templates", None)
        if isinstance(templates, dict):
            size += len(templates)
        if size:
            return size
    registry = getattr(engine, "registry", None)
    templates = getattr(registry, "templates", None)
    if isinstance(templates, dict):
        return len(templates)
    return 0


def _effective_rule_count(engine: Any) -> int:
    """Rules that can decide an event, not just templates that could bind.

    A ``CompiledPolicy`` answers with the documents floor plus every bound
    scope's compiled rules. Everything else falls back to ``_engine_size``,
    which is the right banner count for a plain or scoped rules module.
    """
    counter = getattr(engine, "rule_count", None)
    if callable(counter):
        try:
            return int(counter())
        except Exception:  # noqa: BLE001 - a diagnostic helper, never fatal
            pass
    return _engine_size(engine)


def _scope_key(key_file: Optional[str]) -> bytes:
    """The key a scope document is signed and verified with.

    ``--key-file`` when given, else a random per-process secret - the same
    default receipts use, and the same consequence: a document signed with a
    per-process key is verifiable only by this run and prints a warning.
    """
    if key_file is not None:
        return _read_key(key_file)
    return secrets.token_bytes(32)


def _write_scope_document(path: str, envelope: dict) -> None:
    """Atomically write a signed scope document (mode 0600)."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".scope-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(envelope, fh)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _load_scope(args: Any) -> "tuple":
    """Build ``(scoped_engine, key, envelope)`` for ``--scope-document``.

    An existing ``PATH`` must hold a signed document that verifies under the
    key; a missing one is *published* from the rules module's declared scope
    document, signed the same way - mirroring ``--fallback-policy``. Either way
    the document is compiled against the module's ``templates``, and any
    shortfall (unreadable/unverified document, an unknown template, a module
    that declares no scopes) is a :class:`RulesError`: a guard told to serve a
    scope set it cannot build must refuse to start, not start scoping nothing.
    """
    from ..wire import WireError, scope_envelope, verify_scope_envelope
    from .rules import build_scoped_engine, load_rules_module, scope_document_of

    module = load_rules_module(args.rules)
    key = _scope_key(args.key_file)
    path = args.scope_document
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                envelope = json.load(fh)
        except (OSError, ValueError) as exc:
            raise RulesError("cannot read scope document {}: {}".format(path, exc))
        try:
            policy = verify_scope_envelope(envelope, key)
        except WireError as exc:
            raise RulesError("scope document {}: {}".format(path, exc))
        document = json.loads(policy)
    else:
        document = scope_document_of(module)
        envelope = scope_envelope(document, key)
        try:
            _write_scope_document(path, envelope)
        except OSError as exc:
            raise RulesError(
                "cannot publish scope document {}: {}".format(path, exc.strerror or exc)
            )
    engine = build_scoped_engine(document, getattr(module, "templates", None) or {})
    return engine, key, envelope


def _publish_fallback(
    policy_file: Optional[str],
    key_file: Optional[str],
    socket_path: str,
    *,
    engine: Any = None,
) -> None:
    """Validate, sign and write the offline fallback policy next to the socket.

    In artifact mode the file also carries the artifact's sha256 and epoch
    under their own MAC, so a client that pinned an artifact can refuse a
    fallback published for a different one.
    """
    if not policy_file:
        return
    if not key_file:
        raise RulesError("--fallback-policy needs --key-file to sign it")
    from ..policy.declarative import PolicyError, read_policy_file
    from .fallback import FallbackError, fallback_path, write_fallback
    artifact_sha256 = None
    epoch = None
    if engine is not None and getattr(engine, "artifact_bytes", None) is not None:
        sha = getattr(engine, "sha256", None)
        artifact_sha256 = sha if isinstance(sha, str) and sha else None
        epoch = getattr(engine, "epoch", None)
        if not isinstance(epoch, str):
            epoch = None
    try:
        doc, _ = read_policy_file(policy_file)
        write_fallback(
            fallback_path(socket_path), doc, _read_key(key_file),
            artifact_sha256=artifact_sha256, epoch=epoch,
        )
    except (PolicyError, FallbackError, OSError) as exc:
        raise RulesError("fallback policy {}: {}".format(policy_file, exc))


def _parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="interlock-sidecar",
        description="Serve one interlock policy engine to agents in other languages.",
    )
    parser.add_argument(
        "--rules",
        required=False,
        metavar="MODULE:ATTR",
        help="dotted module path and attribute holding a PolicyEngine or a list of rules "
             "(exactly one of --rules or --artifact is required)",
    )
    parser.add_argument(
        "--artifact",
        default=None,
        metavar="PATH",
        help="serve a manifest-delivered policy artifact, or a directory containing "
             "active.json; mutually exclusive with --rules and --scope-document. The "
             "artifact's scope bindings are served as their own engine and every "
             "receipt/response carries its sha256 and epoch",
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
        "--admin",
        default=None,
        metavar="HOST:PORT",
        help="serve /healthz /stats /metrics /config on this loopback address "
             "(see interlock.sidecar.admin)",
    )
    parser.add_argument(
        "--fallback-policy",
        default=None,
        metavar="FILE",
        help="publish this offline declarative policy, signed with --key-file, for "
             "clients running with unreachable='degraded' (see interlock.sidecar.fallback)",
    )
    parser.add_argument(
        "--scope-document",
        default=None,
        metavar="PATH",
        help="serve a scoped engine from this signed scope document. An existing "
             "PATH is read and verified (signed with --key-file); a missing PATH is "
             "published there from the rules module's scope_document, like "
             "--fallback-policy. The module must export the `templates` the "
             "document binds (see interlock.sidecar.rules.build_scoped_engine)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate the rules and exit without serving",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    args = _parse_args(argv)

    if args.artifact and args.rules:
        sys.stderr.write(
            "interlock-sidecar: choose one policy source: --rules or --artifact\n")
        return EXIT_BAD_RULES
    if not args.artifact and not args.rules:
        sys.stderr.write(
            "interlock-sidecar: one policy source is required: --rules or --artifact\n")
        return EXIT_BAD_RULES
    if args.artifact and args.scope_document:
        sys.stderr.write(
            "interlock-sidecar: --scope-document cannot be combined with "
            "--artifact; the artifact carries its scope bindings\n")
        return EXIT_BAD_RULES

    try:
        if args.artifact:
            from ..policy.artifact import load_artifact
            from ..policy.killswitch import apply_kill_marker
            try:
                engine = apply_kill_marker(
                    load_artifact(args.artifact), args.artifact)
            except Exception as exc:  # noqa: BLE001 - refusal to start
                raise RulesError(
                    "artifact {}: {}".format(args.artifact, exc)) from None
            if _effective_rule_count(engine) == 0:
                # An empty rule set allows everything. An artifact that signs,
                # verifies and decides nothing is the one failure a guard must
                # not present as a working guard.
                raise RulesError(
                    "artifact {} has no effective rules; refusing to serve a "
                    "policy that would allow every call".format(args.artifact))
        else:
            engine = load_rules(args.rules)
    except RulesError as exc:
        sys.stderr.write("interlock-sidecar: {}\n".format(exc))
        return EXIT_BAD_RULES

    if args.check:
        source = args.artifact or args.rules
        sha = getattr(engine, "sha256", None)
        sys.stderr.write(
            "interlock-sidecar: {} rule(s) loaded from {}{}\n".format(
                _engine_size(engine), source,
                " (artifact sha256 {})".format(sha) if sha else "",
            )
        )
        return 0

    scope_key = None
    scope_document = None
    if args.scope_document:
        try:
            engine, scope_key, scope_document = _load_scope(args)
        except RulesError as exc:
            sys.stderr.write("interlock-sidecar: {}\n".format(exc))
            return EXIT_BAD_RULES
    elif args.artifact and args.key_file:
        # Artifact mode still verifies a client's signed scope overlay when a
        # key is available; without one, overlays are refused as unsigned.
        try:
            scope_key = _read_key(args.key_file)
        except RulesError as exc:
            sys.stderr.write("interlock-sidecar: {}\n".format(exc))
            return EXIT_BAD_RULES

    path = args.socket or default_socket_path()
    try:
        sink = _build_sink(args.receipts, args.key_file)
        _prepare_socket(path)
        _publish_fallback(args.fallback_policy, args.key_file, path, engine=engine)
    except RulesError as exc:
        sys.stderr.write("interlock-sidecar: {}\n".format(exc))
        return EXIT_BAD_RULES

    _disable_core_dumps()

    try:
        server = SidecarServer(
            path, engine, sink=sink,
            scope_key=scope_key, scope_document=scope_document,
        )
    except OSError as exc:
        sys.stderr.write(
            "interlock-sidecar: cannot listen on {}: {}\n".format(path, exc)
        )
        return EXIT_UNSAFE_SOCKET

    # Diagnostics go to stderr so the socket is the only thing on stdout.
    sys.stderr.write(
        "interlock-sidecar: listening on {}\n"
        "  rules:    {} ({} rules)\n"
        "  scopes:   {}\n"
        "  receipts: {}\n".format(
            path,
            args.artifact or args.rules,
            _engine_size(engine),
            args.scope_document
            if args.scope_document
            else "off - one rule set for every principal",
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
    if args.scope_document and args.key_file is None:
        sys.stderr.write(
            "  WARNING:  the scope document is signed with a per-process secret, so "
            "it is verifiable only by this process. Use --key-file for a durable key.\n"
        )

    def _stop(signum, frame):  # pragma: no cover - delivered by the OS
        raise KeyboardInterrupt

    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(signum, _stop)
        except (ValueError, OSError):  # not the main thread / unsupported
            pass

    admin = None
    if args.admin:
        from .admin import start as start_admin
        try:
            admin = start_admin(args.admin, lambda: {
                "rules": _engine_size(engine),
                "epoch": getattr(engine, "epoch", None),
                "socket": path,
                "receipts": bool(args.receipts),
                "fallback_policy": bool(args.fallback_policy),
                "scope_document": bool(args.scope_document),
            })
        except (ValueError, OSError) as exc:
            sys.stderr.write("interlock-sidecar: admin endpoint: {}\n".format(exc))
            server.server_close()
            return EXIT_BAD_RULES
        sys.stderr.write("  admin:    http://{}\n".format(args.admin))

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if admin is not None:
            admin.shutdown()
        server.server_close()
        try:
            os.unlink(path)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

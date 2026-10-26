"""Enroll this host with an interlock cloud plane, and run the connector.

  interlock cloud enroll --url https://cloud.example --token TOKEN
  interlock cloud run --once
  interlock cloud status --json
  interlock cloud leave --yes
  IL_CLOUD_ADMIN_COOKIE=... IL_CLOUD_ADMIN_CSRF=... \
      interlock cloud keys rotate --host host_...

The connector is outbound-only: it polls the plane for reviews, grants and
policy manifests, and the plane cannot dial this host. ``policy`` remains a
stub until C5; it prints a notice and exits 3.

Exit codes: 0 done, 1 failure, 2 missing or unsafe configuration, 3 not
implemented yet, 64 the command line was wrong. The agent key is never asked
for on the command line and is printed only by an explicit rotate that hands
it back once.
"""
from __future__ import annotations

import json
import sys
from typing import Any, Dict, Optional

#: The connector actions; each parses and dispatches below.
ACTIONS = ("enroll", "run", "status", "leave", "policy", "keys")

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_NOT_CONFIGURED = 2
#: Printed by the one remaining stub; tests assert this exact shape.
STUB_EXIT = 3
EXIT_USAGE = 64


def add_arguments(parser) -> None:
    sub = parser.add_subparsers(dest="cloud_command", metavar="ACTION")

    enroll = sub.add_parser("enroll", help="register this host with a plane")
    enroll.add_argument("--url", metavar="URL", help="plane base URL")
    enroll.add_argument("--token", metavar="TOKEN",
                        help="single-use enrollment token")
    enroll.add_argument("--name", metavar="NAME", help="host name to register")
    enroll.add_argument("--home", metavar="DIR",
                        help="connector home (default: $IL_CLOUD_HOME)")

    run = sub.add_parser("run", help="run the connector")
    run.add_argument("--once", action="store_true", help="poll once and exit")
    run.add_argument("--url", metavar="URL", help="plane base URL override")
    run.add_argument("--home", metavar="DIR",
                     help="connector home (default: $IL_CLOUD_HOME)")
    run.add_argument("--verbose", action="store_true",
                     help="print one line per cycle")

    status = sub.add_parser("status", help="report connector and plane state")
    status.add_argument("--json", action="store_true", help="print JSON")
    status.add_argument("--home", metavar="DIR",
                        help="connector home (default: $IL_CLOUD_HOME)")

    leave = sub.add_parser("leave", help="forget this host's enrollment")
    leave.add_argument("--yes", action="store_true",
                       help="confirm without a terminal prompt")
    leave.add_argument("--home", metavar="DIR",
                       help="connector home (default: $IL_CLOUD_HOME)")

    policy = sub.add_parser("policy", help="show or refresh the applied policy")
    policy.add_argument("--policy", metavar="FILE", help="policy file to apply")

    keys = sub.add_parser("keys", help="rotate or revoke this host's agent keys")
    keys.add_argument("keys_command", nargs="?", choices=("rotate", "revoke"),
                      metavar="rotate|revoke")
    keys.add_argument("--host", metavar="HOST", help="host id")
    keys.add_argument("--key", metavar="KEY", help="agent key id (revoke)")
    keys.add_argument("--url", metavar="URL", help="plane base URL")
    # The admin session cookie and CSRF token are read from the environment,
    # never argv: argv is visible in ps and shell history.
    keys.add_argument("--json", action="store_true", help="print JSON")
    keys.add_argument("--home", metavar="DIR",
                      help="connector home (default: $IL_CLOUD_HOME)")

    # An unknown action is a command-line error (64), not argparse's default 2.
    def _usage_error(message: str) -> None:
        parser.print_usage(sys.stderr)
        sys.stderr.write("interlock cloud: {}\n".format(message))
        raise SystemExit(EXIT_USAGE)

    parser.error = _usage_error


# -- helpers ------------------------------------------------------------

def _home(args):
    from interlock.cloud.connector.config import CloudHome

    return CloudHome(getattr(args, "home", None))


def _connector(home, url: Optional[str] = None, *, queue: bool = False):
    from interlock.cloud.connector.runner import Connector
    from interlock.cloud.connector.transport import UrllibTransport

    config = home.document
    base_url = url or str(config.get("url") or "")
    review_queue = None
    if queue:
        review_queue = _local_queue()
    return Connector(home, UrllibTransport(base_url), queue=review_queue)


def _local_queue():
    """The local review queue, when this machine already has one."""
    try:
        import os

        from interlock.reviews import ReviewQueue, default_path

        path = default_path()
        if not os.path.exists(path):
            return None
        return ReviewQueue(path)
    except Exception:
        return None


def _fail(message: str) -> int:
    sys.stderr.write("interlock cloud: {}\n".format(message))
    return EXIT_FAILURE


def _print(value: Any) -> None:
    from interlock.cloud.connector.config import redact

    sys.stdout.write(json.dumps(redact(value), indent=2, sort_keys=True) + "\n")


# -- actions ------------------------------------------------------------

def _enroll(args) -> int:
    url = getattr(args, "url", None)
    token = getattr(args, "token", None)
    if not url or not token:
        sys.stderr.write(
            "interlock cloud enroll: --url and --token are required\n")
        return EXIT_USAGE
    from interlock.cloud.connector.runner import Connector
    from interlock.cloud.connector.transport import UrllibTransport

    home = _home(args)
    connector = Connector(home, UrllibTransport(url))
    result = connector.enroll(url, token, getattr(args, "name", None))
    if not result.get("ok"):
        return _fail(str(result.get("error") or "enrollment failed"))
    sys.stdout.write(
        "enrolled host {}\nagent key id {}\n".format(
            result.get("host_id"), result.get("agent_key_id"))
    )
    return EXIT_OK


def _run(args) -> int:
    home = _home(args)
    if not home.exists():
        sys.stderr.write(
            "interlock cloud: no connector config at {}; run "
            "`interlock cloud enroll` first\n".format(home.config_path))
        return EXIT_NOT_CONFIGURED
    try:
        home.load()
        connector = _connector(home, getattr(args, "url", None), queue=True)
    except PermissionError as exc:
        return _fail(str(exc))
    except (ValueError, OSError) as exc:
        return _fail(str(exc))

    if getattr(args, "once", False):
        result = connector.run_once()
        if result.get("ok"):
            sys.stdout.write(
                "sync ok: {} review(s), {} batch(es) uploaded\n".format(
                    result.get("reviews", 0), result.get("uploaded", 0)))
            return EXIT_OK
        sys.stderr.write("interlock cloud run: {}\n".format(
            result.get("error") or "sync failed"))
        return EXIT_FAILURE
    return EXIT_OK if connector.run_forever() == 0 else EXIT_FAILURE


def _status(args) -> int:
    home = _home(args)
    if not home.exists():
        sys.stderr.write(
            "interlock cloud: no connector config at {}; run "
            "`interlock cloud enroll` first\n".format(home.config_path))
        return EXIT_NOT_CONFIGURED
    try:
        home.load()
        status = _connector(home).status()
    except PermissionError as exc:
        return _fail(str(exc))
    except (ValueError, OSError) as exc:
        return _fail(str(exc))
    if getattr(args, "json", False):
        _print(status)
        return EXIT_OK
    sys.stdout.write("connected: {}\n".format("yes" if status["connected"] else "no"))
    sys.stdout.write("host:      {}\n".format(status.get("host_id") or "-"))
    sys.stdout.write("org:       {}\n".format(status.get("org_id") or "-"))
    sys.stdout.write("plane:     {}\n".format(status.get("url") or "-"))
    sys.stdout.write("last sync: {}\n".format(status.get("last_sync") or "never"))
    sys.stdout.write("spool:     {} batch(es), {} bytes, {} dropped\n".format(
        status["spool_batches"], status["spool_bytes"],
        status["dropped_batches"]))
    sys.stdout.write("cursor:    {}\n".format(status["cursor"]))
    if status.get("revoked"):
        sys.stdout.write("revoked:   yes\n")
    if status.get("last_error"):
        sys.stdout.write("last error: {}\n".format(status["last_error"]))
    return EXIT_OK


def _leave(args) -> int:
    home = _home(args)
    if not home.exists():
        sys.stderr.write(
            "interlock cloud: no connector config at {}\n".format(home.config_path))
        return EXIT_NOT_CONFIGURED
    if not getattr(args, "yes", False):
        if not sys.stdin.isatty():
            sys.stderr.write(
                "interlock cloud leave: refusing to delete {} without a "
                "terminal; pass --yes to confirm\n".format(home.config_path))
            return EXIT_FAILURE
        answer = input("Remove this host's enrollment from {}? [y/N] ".format(
            home.config_path))
        if answer.strip().lower() not in ("y", "yes"):
            return EXIT_FAILURE
    from interlock.cloud.connector.runner import Connector
    from interlock.cloud.connector.transport import UrllibTransport

    connector = Connector(home, UrllibTransport(""))
    result = connector.leave(confirmed=True)
    if not result.get("removed"):
        return _fail("the connector config was already gone")
    sys.stdout.write("removed {} and {}\n".format(
        result["config"], result["seed"]))
    sys.stdout.write("left in place: {} (spool) and {} (state)\n".format(
        result["spool"], result["state"]))
    return EXIT_OK


def _admin_request(url: str, path: str, *, cookie: str, csrf: str,
                   body: Optional[Dict[str, Any]] = None):
    """POST an admin request through the connector's vetted transport.

    That transport enforces https (loopback may use http), follows no
    redirects and caps the response, so the admin session cookie cannot be
    downgraded or replayed to another origin.
    """
    from interlock.cloud.connector.config import CloudHome
    from interlock.cloud.connector.transport import UrllibTransport

    CloudHome._validate_url(url)
    payload = None if body is None else json.dumps(body).encode("utf-8")
    transport = UrllibTransport(url)
    status, _headers, data = transport.request(
        "POST", path, payload, timeout=30,
        headers={
            "cookie": cookie,
            "x-csrf-token": csrf,
            "content-type": "application/json",
            "accept": "application/json",
        },
    )
    try:
        return status, json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return status, {"error": {"code": "request_failed"}}


def _keys(args) -> int:
    action = getattr(args, "keys_command", None)
    if action not in ("rotate", "revoke"):
        sys.stderr.write(
            "interlock cloud keys: choose rotate or revoke\n")
        return EXIT_USAGE
    import os

    cookie = os.environ.get("IL_CLOUD_ADMIN_COOKIE")
    csrf = os.environ.get("IL_CLOUD_ADMIN_CSRF")
    if not cookie or not csrf:
        sys.stderr.write(
            "interlock cloud keys: admin key changes need the web UI session. "
            "Sign in, copy the __Host-il_session and il_csrf cookies, then set "
            "IL_CLOUD_ADMIN_COOKIE and IL_CLOUD_ADMIN_CSRF (never on the "
            "command line). No password is accepted.\n")
        return EXIT_FAILURE
    url = getattr(args, "url", None)
    if not url:
        try:
            url = str(_home(args).document.get("url") or "")
        except Exception:
            url = ""
    if not url:
        sys.stderr.write(
            "interlock cloud keys: --url is required when no connector config "
            "is present\n")
        return EXIT_USAGE
    host = getattr(args, "host", None)
    key = getattr(args, "key", None)
    from interlock.cloud.connector.config import HomeError
    from interlock.cloud.connector.transport import TransportError

    try:
        if action == "rotate":
            if not host:
                sys.stderr.write(
                    "interlock cloud keys rotate: --host is required\n")
                return EXIT_USAGE
            status, payload = _admin_request(url, "/v1/keys", cookie=cookie,
                                             csrf=csrf,
                                             body={"host_id": host})
        else:
            if not key:
                sys.stderr.write(
                    "interlock cloud keys revoke: --key is required\n")
                return EXIT_USAGE
            status, payload = _admin_request(
                url, "/v1/keys/{}/revoke".format(key), cookie=cookie,
                csrf=csrf)
    except (HomeError, TransportError) as exc:
        return _fail(str(exc))
    if not 200 <= status < 300:
        error = (payload or {}).get("error") or {}
        return _fail(str(error.get("code") or "request failed"))
    _print(payload)
    return EXIT_OK


def run(args) -> int:
    action = getattr(args, "cloud_command", None)
    if action not in ACTIONS:
        sys.stderr.write(
            "interlock cloud: choose an action: {}\n".format(", ".join(ACTIONS))
        )
        return EXIT_USAGE
    if action == "policy":
        sys.stderr.write("interlock cloud policy: not implemented yet\n")
        return STUB_EXIT
    handler = {
        "enroll": _enroll,
        "run": _run,
        "status": _status,
        "leave": _leave,
        "keys": _keys,
    }[action]
    return int(handler(args))


__all__ = ["ACTIONS", "EXIT_NOT_CONFIGURED", "EXIT_USAGE", "STUB_EXIT",
           "add_arguments", "run"]

"""Enroll this host with an interlock cloud plane, and run the connector.

  interlock cloud enroll --url https://cloud.example --token TOKEN
  interlock cloud run --once
  interlock cloud status --json

The connector is outbound-only: it polls the plane for reviews, grants and
policy manifests, and the plane cannot dial this host. Every action is a stub
in this release - it prints a notice and exits 3; the transport follows in its
own milestone.

Exit codes: 0 ok, 3 the action is not implemented yet, 64 the command line was
wrong (no action, or one that does not exist).
"""
from __future__ import annotations

import sys

#: The connector actions; each parses today and is implemented in a later epic.
ACTIONS = ("enroll", "run", "status", "leave", "policy", "keys")

#: Printed by every stub; tests assert this exact shape.
STUB_EXIT = 3
EXIT_USAGE = 64


def add_arguments(parser) -> None:
    sub = parser.add_subparsers(dest="cloud_command", metavar="ACTION")

    enroll = sub.add_parser("enroll", help="register this host with a plane")
    enroll.add_argument("--url", metavar="URL", help="plane base URL")
    enroll.add_argument("--token", metavar="TOKEN", help="single-use enrollment token")

    run = sub.add_parser("run", help="run the connector")
    run.add_argument("--once", action="store_true", help="poll once and exit")
    run.add_argument("--url", metavar="URL", help="plane base URL")

    status = sub.add_parser("status", help="report connector and plane state")
    status.add_argument("--json", action="store_true", help="print JSON")

    leave = sub.add_parser("leave", help="forget this host's enrollment")
    leave.add_argument("--url", metavar="URL", help="plane base URL")

    policy = sub.add_parser("policy", help="show or refresh the applied policy")
    policy.add_argument("--policy", metavar="FILE", help="policy file to apply")

    keys = sub.add_parser("keys", help="list or rotate this host's agent keys")
    keys.add_argument("--json", action="store_true", help="print JSON")

    # An unknown action is a command-line error (64), not argparse's default 2.
    def _usage_error(message: str) -> None:
        parser.print_usage(sys.stderr)
        sys.stderr.write("interlock cloud: {}\n".format(message))
        raise SystemExit(EXIT_USAGE)

    parser.error = _usage_error


def run(args) -> int:
    action = getattr(args, "cloud_command", None)
    if action not in ACTIONS:
        sys.stderr.write(
            "interlock cloud: choose an action: {}\n".format(", ".join(ACTIONS))
        )
        return EXIT_USAGE
    sys.stderr.write("interlock cloud {}: not implemented yet\n".format(action))
    return STUB_EXIT

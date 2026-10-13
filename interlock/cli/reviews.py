"""Decide pending reviews, and serve their status to agents.

  interlock reviews list                   # pending first; --status, --all
  interlock reviews show r-1a2b3c4d
  interlock reviews approve r-1a2b3c4d     # --as NAME (default: your login)
  interlock reviews reject r-1a2b3c4d --reason "use the staging table"
  interlock reviews revoke r-1a2b3c4d
  interlock reviews wait r-1a2b3c4d --timeout 120
  interlock reviews mcp                    # read-only MCP server (stdio)

A review is filed when a call escalates and is settled through the queue (see
interlock.reviews). After an approval the agent retries the identical call,
which runs once. Run approve/reject/revoke yourself, outside the agent: the
coding-agent policy refuses them from inside one.

For the agent, add the MCP server to its config, e.g. for Claude Code:
  {"mcpServers": {"interlock-reviews": {"command": "interlock", "args": ["reviews", "mcp"]}}}

Exit codes: 0 done, 1 the review can't be changed (wrong state, self-approval,
unknown id), 64 bad arguments.
"""
from __future__ import annotations

import datetime
import json
import sys


def add_arguments(parser) -> None:
    parser.add_argument("--db", metavar="FILE", help="review queue (default ~/.interlock/reviews.db)")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    sub = parser.add_subparsers(dest="reviews_command", metavar="ACTION")
    ls = sub.add_parser("list", help="list reviews")
    ls.add_argument("--status", choices=("pending", "approved", "rejected", "revoked",
                                         "expired", "executed"))
    ls.add_argument("--limit", type=int, default=50)
    for name, text in (("show", "show one review"), ("approve", "approve a review"),
                       ("reject", "reject a review"), ("revoke", "revoke a review"),
                       ("wait", "wait for a decision")):
        p = sub.add_parser(name, help=text)
        p.add_argument("id")
        if name in ("approve", "reject", "revoke"):
            p.add_argument("--as", dest="who", metavar="NAME", help="who is deciding")
        if name == "reject":
            p.add_argument("--reason", default="", help="told to the agent")
        if name == "wait":
            p.add_argument("--timeout", type=float, default=60.0)
    sub.add_parser("mcp", help="serve review status to an agent over MCP (stdio)")


def _when(ts) -> str:
    if not ts:
        return "-"
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _print(review, as_json: bool) -> None:
    if as_json:
        print(json.dumps(review.to_dict(), indent=2))
        return
    print("{}  {}  {}".format(review.id, review.status.upper(), review.action))
    print("  reason    {}".format(review.reason))
    print("  rule      {}   agent {}   filed by {}".format(review.policy_id, review.principal,
                                                          review.requester))
    print("  filed     {}   decide by {}".format(_when(review.created), _when(review.pending_until)))
    if review.approvers:
        print("  approvals {} of {}: {}".format(len(review.approvers), review.min_approvals,
                                               ", ".join(review.approvers)))
    if review.approval_until:
        print("  use by    {}".format(_when(review.approval_until)))
    if review.rejection_reason:
        print("  rejected  {}".format(review.rejection_reason))
    if review.preview:
        print("  call      {}".format(review.preview[:500]))


def run(args) -> int:
    from ..reviews import ReviewError, ReviewQueue

    command = args.reviews_command
    if command is None:
        sys.stderr.write("interlock reviews: choose an action: list, show, approve, reject, "
                         "revoke, wait, mcp\n")
        return 64
    queue = ReviewQueue(args.db)
    if command == "mcp":
        serve_mcp(queue)
        return 0
    try:
        if command == "list":
            reviews = queue.list(args.status, args.limit)
            if args.json:
                print(json.dumps([r.to_dict() for r in reviews], indent=2))
            elif not reviews:
                print("no reviews")
            for r in [] if args.json else reviews:
                print("{}  {:<9} {:<20} {:<24} {}".format(
                    r.id, r.status, _when(r.created), r.action[:24], (r.reason or "")[:60]))
            return 0
        if command == "show":
            review = queue.get(args.id)
        elif command == "approve":
            review = queue.approve(args.id, args.who)
        elif command == "reject":
            review = queue.reject(args.id, args.reason, args.who)
        elif command == "revoke":
            review = queue.revoke(args.id, args.who)
        else:
            review = queue.wait(args.id, args.timeout)
    except ReviewError as exc:
        sys.stderr.write("interlock reviews: {}\n".format(exc))
        return 1
    _print(review, args.json)
    return 0


NEXT_INSTRUCTIONS = {
    "wait": "A human has not decided yet. Do not retry the call; wait, then ask again with "
            "review_status or review_wait.",
    "retry_identical_call": "Approved. Retry exactly the same call now (same tool, same "
                            "arguments); it will run once.",
    "stop": "Do not retry this call. Tell the user what was refused and why.",
}


def _status(review) -> dict:
    data = review.to_dict()
    data.pop("preview", None)
    data["instruction"] = NEXT_INSTRUCTIONS[review.next]
    return data


def serve_mcp(queue) -> None:
    from .. import __version__
    from ..mcp_server import StdioServer, Tool
    from ..reviews import STATUSES

    def status(arguments):
        return _status(queue.get(str(arguments["id"])))

    def listing(arguments):
        limit = max(1, min(int(arguments.get("limit", 20)), 100))
        return {"reviews": [_status(r) for r in queue.list(arguments.get("status"), limit)]}

    def wait(arguments):
        timeout = max(0.0, min(float(arguments.get("timeout_seconds", 60)), 300.0))
        return _status(queue.wait(str(arguments["id"]), timeout))

    id_schema = {"type": "string", "description": "the review id, e.g. r-1a2b3c4d"}
    StdioServer("interlock-reviews", __version__, [
        Tool("review_status", "Where a pending interlock review stands, and what to do next.",
             {"type": "object", "properties": {"id": id_schema}, "required": ["id"]}, status),
        Tool("review_list", "Recent interlock reviews (read-only).",
             {"type": "object", "properties": {
                 "status": {"type": "string", "enum": list(STATUSES)},
                 "limit": {"type": "integer", "minimum": 1, "maximum": 100}}}, listing),
        Tool("review_wait", "Wait up to timeout_seconds (max 300) for a review to be decided.",
             {"type": "object", "properties": {"id": id_schema,
                                                "timeout_seconds": {"type": "number", "maximum": 300}},
              "required": ["id"]}, wait),
    ], instructions="When interlock refuses a call with a review id, use these tools to see "
                    "whether a human approved it. They never approve anything.").serve()

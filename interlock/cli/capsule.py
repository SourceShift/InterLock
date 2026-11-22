"""Package a receipt log, its policy and its anchor into one sealed file, or
check such a file.

  interlock capsule create audit.jsonl --key-file audit.key --out evidence.zip
  interlock capsule create audit.jsonl --key-file audit.key --out evidence.zip \\
      --policy policy.json --anchor audit.anchor
  interlock capsule verify evidence.zip --key-file audit.key
  interlock capsule verify evidence.zip --key-file audit.key --json

`create` verifies the chain first, then seals the log, the optional policy and
the optional anchor behind a signed manifest: each member's sha256, the receipt
count and head, the key id and a redaction attestation. `verify` checks the
manifest seal, every member digest and the receipt chain (against the head the
manifest names, so a removed tail is caught), then prints the adequacy answers
and names each question the record cannot answer.

A capsule proves integrity to a holder of the log's key; it does not prove who
holds it. A capsule without an anchor cannot show its tail was not cut, and
`verify` says so instead of implying coverage.

Exit codes: 0 the capsule was built or verifies, 2 it was refused or failed,
3 a file could not be read, 64 bad arguments.
"""
from __future__ import annotations

import json
import sys
import time


def add_arguments(parser) -> None:
    mode = parser.add_subparsers(dest="mode", metavar="MODE")
    mode.required = True

    create = mode.add_parser("create", help="seal a log (and optionally its policy and anchor)")
    create.add_argument("file", help="a receipt log written by FileSink")
    create.add_argument("--key-file", required=True, metavar="FILE",
                        help="the MAC key that signed the log")
    create.add_argument("--out", required=True, metavar="FILE",
                        help="the bundle to write (.zip)")
    create.add_argument("--policy", metavar="FILE",
                        help="the policy file that decided, to include as evidence")
    create.add_argument("--anchor", metavar="FILE",
                        help="the anchor recorded outside the log, to prove the tail")
    create.add_argument("--json", action="store_true", help="machine-readable output")

    verify = mode.add_parser("verify", help="check a capsule and report its adequacy")
    verify.add_argument("bundle", help="a capsule written by `interlock capsule create`")
    verify.add_argument("--key-file", required=True, metavar="FILE",
                        help="the key the capsule was sealed with")
    verify.add_argument("--json", action="store_true", help="machine-readable output")


def _read_key(path: str):
    """The MAC key at *path*, or None after saying why it could not be read."""
    from ..sidecar.__main__ import _read_key as read
    from ..sidecar.rules import RulesError

    try:
        return read(path)
    except (OSError, RulesError) as exc:
        sys.stderr.write("interlock capsule: {}\n".format(exc))
        return None


def _when(ts) -> str:
    if not isinstance(ts, (int, float)):
        return "an unknown time"
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(float(ts)))


def run(args) -> int:
    from ..capsule import CapsuleError, create_capsule, verify_capsule

    key = _read_key(args.key_file)
    if key is None:
        return 3
    if getattr(args, "mode", None) == "create":
        try:
            manifest = create_capsule(args.file, key=key, out_path=args.out,
                                      policy_path=args.policy, anchor_path=args.anchor)
        except CapsuleError as exc:
            sys.stderr.write("interlock capsule: {}\n".format(exc))
            return 2
        if args.json:
            print(json.dumps({"status": "sealed", "out": args.out, "manifest": manifest}))
            return 0
        receipts = manifest["receipts"]
        print("sealed {} receipt(s) into {}".format(receipts["count"], args.out))
        print("  head {}".format(receipts["head"][:16] + "..." if receipts["head"] else "none"))
        if "policy" in manifest:
            print("  policy {} (sha256 {})".format(
                args.policy, manifest["members"]["policy.json"][:16] + "..."))
        anchor = manifest.get("anchor")
        if isinstance(anchor, dict):
            print("  anchor at receipt {}".format(anchor.get("count")))
        redactions = manifest.get("redactions") or {}
        print("  redactions: {} value(s) in {} receipt(s)".format(
            redactions.get("total", 0), redactions.get("receipts", 0)))
        return 0

    try:
        report = verify_capsule(args.bundle, key=key)
    except CapsuleError as exc:
        sys.stderr.write("interlock capsule: {}\n".format(exc))
        return 2
    if args.json:
        print(json.dumps(report))
    else:
        if report["ok"]:
            print("intact: {} receipt(s) sealed {}, verified under key {}".format(
                report["count"], _when(report.get("created")), report.get("key_id")))
        else:
            print("failed: {} problem(s)".format(len(report["problems"])))
            for problem in report["problems"]:
                print("  {}".format(problem))
        print("adequacy:")
        for entry in report["adequacy"]:
            mark = "ok" if entry["answered"] else "UNANSWERED"
            print("  {:<10} {} - {}".format(mark, entry["question"], entry["detail"]))
    return 0 if report["ok"] else 2

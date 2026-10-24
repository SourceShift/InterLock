"""Subscribe to the interlock mesh, or publish a commons for it.

For a node (the deployment running an agent):

  interlock mesh init --root root.json --mirror https://commons.example.org [--ring stable]
  interlock mesh sync                       # fetch and verify; the cache only changes if all of it verifies
  interlock mesh status [--json]            # subscriptions, freshness, what shadow rules would have done
  interlock mesh resolve mesh:coding-agent@stable   # print the pack as this node would install it

Then in your policy file:  {"version": 1, "extends": "mesh:coding-agent@stable", "rules": [...]}

For a maintainer (the people who run a commons):

  interlock mesh keys init --out keys/      # one Ed25519 key per role; raise counts/thresholds for a real root
  interlock mesh publish --source commons/ --out site/ --keys keys/
  interlock mesh verify site/               # walk the site exactly as a subscriber would

A node never auto-enforces a new community rule: every rule it has not seen
before spends a monitor window in shadow mode, and a rule's status and the
node's ring cap how strong its verdict may be. See docs/guides/mesh.md.

Exit codes: 0 ok, 1 the mesh is stale or a shadow summary shows findings
(status), 2 verification or publishing failed, 3 a file could not be read,
64 the command line was wrong.
"""
from __future__ import annotations

import json
import sys
import time


def add_arguments(parser) -> None:
    sub = parser.add_subparsers(dest="mesh_command", metavar="ACTION")

    init = sub.add_parser("init", help="pin a root and configure mirrors on this node")
    init.add_argument("--root", required=True, metavar="FILE", help="the root metadata to pin")
    init.add_argument("--mirror", action="append", default=[], metavar="URL",
                      help="a mirror (https://... or file:///...); repeatable, first wins")
    init.add_argument("--ring", default="stable", choices=["canary", "early", "stable"])
    init.add_argument("--monitor-days", type=float, default=None, metavar="DAYS",
                      help="monitor window for rules new to this node (default 7)")
    init.add_argument("--dir", default=None, metavar="DIR", help="mesh state directory")

    sync = sub.add_parser("sync", help="fetch and verify the commons into the local cache")
    sync.add_argument("--dir", default=None, metavar="DIR")
    sync.add_argument("--json", action="store_true")

    status = sub.add_parser("status", help="subscriptions, freshness and shadow findings")
    status.add_argument("--dir", default=None, metavar="DIR")
    status.add_argument("--json", action="store_true")

    resolve = sub.add_parser("resolve", help="print a pack as this node would install it")
    resolve.add_argument("spec", help="e.g. mesh:coding-agent@stable")
    resolve.add_argument("--dir", default=None, metavar="DIR")

    keys = sub.add_parser("keys", help="create signing keys for a commons")
    keys_sub = keys.add_subparsers(dest="keys_command", metavar="ACTION")
    keys_init = keys_sub.add_parser("init", help="create one key file per role")
    keys_init.add_argument("--out", required=True, metavar="DIR")
    keys_init.add_argument("--root-keys", type=int, default=1, metavar="N")
    keys_init.add_argument("--root-threshold", type=int, default=1, metavar="N")

    publish = sub.add_parser("publish", help="build and sign a static site from a commons")
    publish.add_argument("--source", required=True, metavar="DIR", help="the commons checkout (has packs/)")
    publish.add_argument("--out", required=True, metavar="DIR", help="the site to write")
    publish.add_argument("--keys", required=True, metavar="DIR")
    publish.add_argument("--timestamp-days", type=float, default=1.0, metavar="DAYS",
                         help="how long the timestamp stays valid (the kill switch)")
    publish.add_argument("--no-validate", action="store_true",
                         help="skip compiling each pack first (not recommended)")
    publish.add_argument("--json", action="store_true")

    verify = sub.add_parser("verify", help="walk a published site as a subscriber would")
    verify.add_argument("site", metavar="DIR")
    verify.add_argument("--root", default=None, metavar="FILE", help="pin this root instead of the site's")
    verify.add_argument("--json", action="store_true")


def run(args) -> int:
    command = args.mesh_command
    if command == "init":
        return _init(args)
    if command == "sync":
        return _sync(args)
    if command == "status":
        return _status(args)
    if command == "resolve":
        return _resolve(args)
    if command == "keys":
        return _keys(args)
    if command == "publish":
        return _publish(args)
    if command == "verify":
        return _verify(args)
    sys.stderr.write("interlock mesh: choose an action: init, sync, status, resolve, keys, publish, verify\n")
    return 64


def _init(args) -> int:
    from ..mesh.subscriber import Subscriber, SubscriberError

    if not args.mirror:
        sys.stderr.write("interlock mesh init: at least one --mirror is required\n")
        return 64
    try:
        with open(args.root, "rb") as fh:
            root_raw = fh.read(1024 * 1024)
    except OSError as exc:
        sys.stderr.write("interlock mesh init: cannot read {}: {}\n".format(args.root, exc))
        return 3
    node = Subscriber(args.dir)
    try:
        config = node.init(root_raw, args.mirror, ring=args.ring, monitor_days=args.monitor_days)
    except SubscriberError as exc:
        sys.stderr.write("interlock mesh init: {}\n".format(exc))
        return 2
    print("pinned root, ring {}, {} mirror(s), monitor window {:g} day(s) -> {}".format(
        config.ring, len(config.mirrors), config.monitor_days, node.dir))
    print("next: interlock mesh sync")
    return 0


def _sync(args) -> int:
    from ..mesh.subscriber import Subscriber, SubscriberError

    node = Subscriber(args.dir)
    try:
        result = node.sync()
    except SubscriberError as exc:
        sys.stderr.write("interlock mesh sync: {}\n".format(exc))
        return 2
    if args.json:
        sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
        return 0
    print("verified: root v{}, timestamp v{} (expires {}), snapshot v{}, targets v{}".format(
        result["root_version"], result["timestamp_version"], result["timestamp_expires"],
        result["snapshot_version"], result["targets_version"]))
    for path in result["fetched"]:
        print("  fetched {}".format(path))
    for path in result["kept"]:
        print("  up to date {}".format(path))
    return 0


def _status(args) -> int:
    from ..mesh.subscriber import Subscriber

    node = Subscriber(args.dir)
    status = node.status()
    if args.json:
        sys.stdout.write(json.dumps(status, indent=2, sort_keys=True, default=str) + "\n")
    else:
        if not status["configured"]:
            print("mesh: not configured ({})".format(status["dir"]))
            print("run: interlock mesh init --root ROOT --mirror URL")
            return 1
        print("mesh: {} (ring {}, monitor window {:g} day(s))".format(
            status["dir"], status["ring"], status["monitor_days"]))
        print("  mirrors: {}".format(", ".join(status["mirrors"]) or "none"))
        last = status.get("last_sync")
        print("  last sync: {}".format(_ago(time.time() - last) + " ago" if last else "never"))
        if status.get("last_error"):
            print("  last error: {}".format(status["last_error"]))
        if status.get("cache_error"):
            print("  cache: {}".format(status["cache_error"]))
        if "timestamp_expires" in status:
            print("  timestamp expires: {}{}".format(
                status["timestamp_expires"], "  (EXPIRED: the commons stopped signing, or sync is failing)"
                if status.get("timestamp_expired") else ""))
        for path, info in sorted(status.get("packs", {}).items()):
            print("  pack {}: {} rule(s) {}".format(path, info.get("rule_count"), info.get("statuses")))
        for spec, sub in sorted(status.get("subscriptions", {}).items()):
            nxt = status.get("next_transition", {}).get(spec)
            print("  subscribed {}{}".format(spec, "" if not nxt else
                                           ", next shadow rule enforces in {}".format(_ago(nxt - time.time()))))
        shadow = status.get("shadow", {})
        if shadow.get("total"):
            print("  shadow findings: {} (what monitor-window rules would have decided)".format(shadow["total"]))
            for rule, verdicts in sorted(shadow["by_rule"].items()):
                print("    {}: {}".format(rule, ", ".join("{} {}".format(v, n) for v, n in sorted(verdicts.items()))))
    stale = bool(status.get("timestamp_expired")) or bool(status.get("last_error"))
    return 1 if stale or status.get("shadow", {}).get("total") else 0


def _resolve(args) -> int:
    from ..mesh.subscriber import Subscriber, SubscriberError, parse_spec

    node = Subscriber(args.dir)
    try:
        config = node.config()
        pack, ring = parse_spec(args.spec, default_ring=config.ring)
        doc, path, details = node.resolve(pack, ring)
    except SubscriberError as exc:
        sys.stderr.write("interlock mesh resolve: {}\n".format(exc))
        return 2
    sys.stdout.write(json.dumps({"document": doc, "cache_path": path, **details}, indent=2, sort_keys=True) + "\n")
    return 0


def _keys(args) -> int:
    from ..mesh.repository import PublishError, init_keys

    if args.keys_command != "init":
        sys.stderr.write("interlock mesh keys: choose an action: init\n")
        return 64
    try:
        keys = init_keys(args.out, counts={"root": args.root_keys}, thresholds={"root": args.root_threshold})
    except PublishError as exc:
        sys.stderr.write("interlock mesh keys: {}\n".format(exc))
        return 2
    for role, role_keys in keys.items():
        for key in role_keys:
            print("{:<10} {}".format(role, key.keyid))
    print("keys written to {} (mode 0600). Keep root keys offline; keep retired root keys under retired/.".format(args.out))
    return 0


def _publish(args) -> int:
    from ..mesh.repository import PublishError, publish

    try:
        result = publish(args.source, args.out, args.keys,
                         expiry={"timestamp": int(args.timestamp_days * 86400)},
                         validate=not args.no_validate)
    except (PublishError, OSError, ValueError) as exc:
        sys.stderr.write("interlock mesh publish: {}\n".format(exc))
        return 2
    if args.json:
        sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
        return 0
    print("published {} -> root v{}{}, targets v{}, snapshot v{}, timestamp v{} (expires {})".format(
        result["site"], result["root_version"], " (new)" if result["root_changed"] else "",
        result["targets_version"], result["snapshot_version"], result["timestamp_version"],
        result["expires"]["timestamp"]))
    for path, info in result["packs"].items():
        print("  {}  {} rule(s) {}  sha256 {}".format(path, info["rule_count"], info["statuses"], info["sha256"][:16]))
    return 0


def _verify(args) -> int:
    from ..mesh.metadata import MetadataError
    from ..mesh.repository import verify_site

    try:
        result = verify_site(args.site, root_path=args.root)
    except (MetadataError, OSError, ValueError) as exc:
        sys.stderr.write("interlock mesh verify: REFUSED: {}\n".format(exc))
        return 2
    if args.json:
        sys.stdout.write(json.dumps(result, indent=2, sort_keys=True) + "\n")
    else:
        print("verified {}: root v{}, timestamp v{} (expires {}), {} target(s)".format(
            args.site, result["root_version"], result["timestamp_version"],
            result["timestamp_expires"], len(result["targets"])))
        for path in result["targets"]:
            print("  {}".format(path))
    return 0


def _ago(seconds: float) -> str:
    seconds = max(0.0, seconds)
    if seconds < 90:
        return "{:.0f}s".format(seconds)
    if seconds < 5400:
        return "{:.0f}m".format(seconds / 60)
    if seconds < 172800:
        return "{:.1f}h".format(seconds / 3600)
    return "{:.1f}d".format(seconds / 86400)

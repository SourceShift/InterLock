"""Subscribe to the interlock mesh, or publish a commons for it.

For a node (the deployment running an agent):

  interlock mesh init --root root.json --mirror https://commons.example.org [--ring stable]
  interlock mesh sync                       # fetch and verify; the cache only changes if all of it verifies
  interlock mesh status [--json]            # subscriptions, freshness, what shadow rules would have done
  interlock mesh resolve mesh:coding-agent@stable   # print the pack as this node would install it
  interlock mesh grant block --pack coding-agent --status stable   # let this pack's stable blocks block
  interlock mesh grant block --rule no-curl-pipe-sh                # or one rule (add --pack to keep it to one pack)
  interlock mesh grant --list               # the grants in force; `grant revoke ...` takes one back

Then in your policy file:  {"version": 1, "extends": "mesh:coding-agent@stable", "rules": [...]}

Reporting is off until the operator enables it, one layer at a time, and an
enable never reaches back before its own date:

  interlock mesh report init                # this node's reporting key
  interlock mesh report build --receipts ~/.interlock/receipts.jsonl --out report.json   # local only
  interlock mesh report enable [--digests] [--fingerprints] [--sample RULE --i-warrant-samples]   # the one consent point
  interlock mesh report status              # what may leave, since when, and a preview
  interlock mesh report submit report.json --consensus URL --aggregator URL --aggregator URL

INTERLOCK_MESH_NO_REPORT=1 refuses every upload, whatever is enabled. A node
that shares redacted samples gives the data warranty (CONTRIBUTING.md): the
samples were lawfully obtained and hold no personal data and no third party's
confidential data. Without it, a report carries no samples.

For a maintainer (the people who run a commons):

  interlock mesh keys init --out keys/      # one Ed25519 key per role; raise counts/thresholds for a real root
  interlock mesh publish --source commons/ --out site/ --keys keys/   # needs no root key while the root is current
  interlock mesh verify site/               # walk the site exactly as a subscriber would
  interlock mesh consensus forget --state consensus.json --sample DIGEST   # erase a sample (GOVERNANCE.md)

A new root is signed in a ceremony, each root keyholder on their own machine
(docs/guides/mesh-root-ceremony.md):

  interlock mesh root draft --site site/ --keys keys/ --out root-2.json   # root keys from keys/root-keys.json
  interlock mesh root sign root-2.json --key root.json                    # writes root-2.json.sig.<keyid>
  interlock mesh root sign root-2.json --external-signer ./token-sign     # stdin: the bytes, stdout: hex signature
  interlock mesh root assemble root-2.json --sig root-2.json.sig.* --site site/

A node never auto-enforces a new community rule: every rule it has not seen
before spends a monitor window in shadow mode, and a rule's status and the
node's ring cap how strong its verdict may be. No community rule blocks until
the operator grants it: without a grant a block is capped to an escalate, and
on a node with no approver installed that escalation is only recorded as a
shadow finding. See docs/guides/mesh.md.

Exit codes: 0 ok, 1 the mesh is stale or a shadow summary shows findings
(status), 2 verification or publishing failed, a grant could not be changed,
or a report was not sent, 3 a file could not be read, 64 the command line was
wrong.
"""
from __future__ import annotations

import argparse
import json
import sys
import time

#: `report build --out FILE` keeps the count vector in FILE + this, on the node.
COUNTS_SUFFIX = ".counts.json"


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

    grant = sub.add_parser("grant", help="let a mesh rule's block take effect on this node")
    grant.add_argument("--list", action="store_true", help="print the grants in force")
    grant.add_argument("--dir", default=None, metavar="DIR", help="mesh state directory")
    grant_sub = grant.add_subparsers(dest="grant_command", metavar="ACTION")
    for name, text in (("block", "grant block to a pack's rules at and above a status, or to one rule"),
                       ("revoke", "take back a grant given with the same arguments")):
        child = grant_sub.add_parser(name, help=text)
        child.add_argument("--pack", default=None, metavar="PACK",
                           help="the pack as subscribed (mesh:PACK), not its document name")
        child.add_argument("--status", default=None, choices=["experimental", "test", "stable"],
                           help="with --pack: this status and above (default stable)")
        child.add_argument("--rule", default=None, metavar="ID", help="one rule id (with --pack: in that pack only)")
        # SUPPRESS: the child's default would otherwise overwrite `grant --dir DIR`.
        child.add_argument("--dir", default=argparse.SUPPRESS, metavar="DIR", help="mesh state directory")

    keys = sub.add_parser("keys", help="create signing keys for a commons")
    keys_sub = keys.add_subparsers(dest="keys_command", metavar="ACTION")
    keys_init = keys_sub.add_parser("init", help="create one key file per role")
    keys_init.add_argument("--out", required=True, metavar="DIR")
    keys_init.add_argument("--root-keys", type=int, default=1, metavar="N")
    keys_init.add_argument("--root-threshold", type=int, default=1, metavar="N")

    root = sub.add_parser("root", help="draft, sign and assemble a new root with offline keys (a ceremony)")
    root_sub = root.add_subparsers(dest="root_command", metavar="ACTION")
    root_draft = root_sub.add_parser("draft", help="write the unsigned next root for the keyholders to review and sign")
    root_draft.add_argument("--site", required=True, metavar="DIR", help="the published site; its root is the one replaced")
    root_draft.add_argument("--keys", required=True, metavar="DIR",
                            help="the online keys, roles.json and root-keys.json (no root key needed)")
    root_draft.add_argument("--expires-days", type=float, default=None, metavar="N",
                            help="how long the new root stays valid (default 197)")
    root_draft.add_argument("--out", required=True, metavar="FILE", help="the draft to write; never overwritten")
    root_sign = root_sub.add_parser("sign", help="add one keyholder's detached signature, on their own machine")
    root_sign.add_argument("file", metavar="FILE", help="the draft")
    root_signer = root_sign.add_mutually_exclusive_group(required=True)
    root_signer.add_argument("--key", metavar="KEYFILE", help="a root key file")
    root_signer.add_argument("--external-signer", metavar="CMD",
                             help="a program that reads the bytes to sign on stdin and prints the hex signature")
    root_assemble = root_sub.add_parser("assemble", help="check both thresholds and write the new root into the site")
    root_assemble.add_argument("file", metavar="FILE", help="the draft")
    root_assemble.add_argument("--sig", required=True, nargs="+", action="extend", metavar="FILE",
                               help="the signature files `root sign` wrote")
    root_assemble.add_argument("--site", required=True, metavar="DIR")

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

    report = sub.add_parser("report", help="build, inspect and submit what your guard stopped")
    report_sub = report.add_subparsers(dest="report_command", metavar="ACTION")
    report_init = report_sub.add_parser("init", help="create this node's reporting key")
    report_init.add_argument("--dir", default=None, metavar="DIR")
    report_build = report_sub.add_parser("build", help="project a receipt log into a signed report (local only)")
    report_build.add_argument("--receipts", required=True, metavar="FILE", help="a receipt log written by FileSink")
    report_build.add_argument("--since", default="24h", metavar="DURATION", help="window: 30m, 24h, 7d (default 24h)")
    report_build.add_argument("--out", default=None, metavar="FILE",
                              help="write the signed envelope here, and the counts (local only) to FILE.counts.json")
    report_build.add_argument("--false-positive", action="append", default=[], metavar="RULE_ID",
                              help="say this rule is wrong here (a negative sighting); repeatable")
    report_build.add_argument("--no-digests", action="store_true", help="leave argument digests out of the report")
    report_build.add_argument("--credential", default=None, metavar="FILE",
                              help="a membership certificate for this node's reporting key")
    report_build.add_argument("--dir", default=None, metavar="DIR")
    report_build.add_argument("--json", action="store_true", help="print the envelope instead of a summary")
    report_enable = report_sub.add_parser(
        "enable", help="choose what this node may upload: counts and sightings, plus each flag's layer")
    report_enable.add_argument("--digests", action="store_true",
                               help="also upload the argument digests of what the guard blocked or escalated")
    report_enable.add_argument("--fingerprints", action="store_true",
                               help="also record, and upload, noised fingerprints of what the guard stopped")
    report_enable.add_argument("--alpha", type=float, default=None, metavar="A",
                               help="with --fingerprints: privacy budget per fingerprint; smaller is more private "
                                    "(default 1.5)")
    report_enable.add_argument("--sample", action="append", default=[], metavar="RULE_ID",
                               help="also record, and upload, redacted samples for this rule, for the forge; "
                                    "repeatable (needs --i-warrant-samples)")
    report_enable.add_argument("--i-warrant-samples", action="store_true",
                               help="with --sample: you warrant that every sample is lawfully obtained, contains "
                                    "no personal data, and contains no third party's confidential data")
    report_enable.add_argument("--off", action="store_true", help="turn every layer off, recording included")
    report_enable.add_argument("--dir", default=None, metavar="DIR")
    report_status = report_sub.add_parser("status", help="what this node may upload, since when, and a preview")
    report_status.add_argument("--receipts", default=None, metavar="FILE",
                               help="preview from this log (default ~/.interlock/receipts.jsonl)")
    report_status.add_argument("--dir", default=None, metavar="DIR")
    report_status.add_argument("--json", action="store_true")
    report_submit = report_sub.add_parser("submit", help="send a built report to the collectors")
    report_submit.add_argument("file", metavar="FILE", help="an envelope written by `report build --out`")
    report_submit.add_argument("--consensus", required=True, metavar="URL", help="the consensus service")
    report_submit.add_argument("--aggregator", action="append", default=[], metavar="URL",
                               help="an aggregator; give at least two or counts are not shared")
    report_submit.add_argument("--token", default=None, metavar="TOKEN", help="bearer token the collectors require")
    report_submit.add_argument("--dir", default=None, metavar="DIR", help="the mesh state whose consent applies")

    serve = sub.add_parser("serve", help="run a collector role, a DAP aggregator, or mirror this node's cache")
    serve.add_argument("--role", required=True,
                       choices=["consensus", "aggregator", "mirror", "dap-leader", "dap-helper"])
    serve.add_argument("--bind", default="127.0.0.1:7949", metavar="HOST:PORT")
    serve.add_argument("--state", default=None, metavar="FILE", help="persist state here")
    serve.add_argument("--token", default=None, metavar="TOKEN", help="require this bearer token on every POST")
    serve.add_argument("--task", default=None, metavar="FILE",
                       help="dap roles: the task.json written by `mesh dap task`")
    serve.add_argument("--keys", default=None, metavar="FILE",
                       help="dap roles: this role's key file (leader.json or helper.json)")
    serve.add_argument("--peer-token", default=None, metavar="TOKEN",
                       help="dap roles: bearer token between leader and helper (default: from the key files)")
    serve.add_argument("--collector-token", default=None, metavar="TOKEN",
                       help="dap-leader: bearer token the collector must present (default: from leader.json)")
    serve.add_argument("--known-catalog", action="append", default=[], metavar="ID",
                       help="consensus: accept reports from this detector catalog id; repeatable")
    serve.add_argument("--min-orgs", type=int, default=None, metavar="N")
    serve.add_argument("--dir", default=None, metavar="DIR",
                       help="mirror: the directory to serve (default: this node's mesh cache)")
    serve.add_argument("--require-credential", action="store_true",
                       help="consensus: refuse reports without a membership certificate")
    serve.add_argument("--issuer", action="append", default=[], metavar="HEX_PUBLIC",
                       help="consensus: a credential issuer's public key; repeatable")
    serve.add_argument("--min-batch", type=int, default=None, metavar="N",
                       help="aggregator: release totals over at least N reconciled reports (default 3, at least 2)")

    dap = sub.add_parser(
        "dap", help="report counts with validity proofs over DAP/Prio3, and run the aggregator roles")
    dap_sub = dap.add_subparsers(dest="dap_command", metavar="ACTION")
    dap_task = dap_sub.add_parser(
        "task", help="create a DAP task: task.json plus one key file per role")
    dap_task.add_argument("--out", required=True, metavar="DIR",
                          help="write task.json, leader.json, helper.json, collector.json here")
    dap_task.add_argument("--leader-url", required=True, metavar="URL",
                          help="the leader's public endpoint, e.g. https://leader.example")
    dap_task.add_argument("--helper-url", required=True, metavar="URL")
    dap_task.add_argument("--bucket", action="append", default=[], metavar="PATTERN",
                          help="an ordered bucket: policy|verdict|tool_class|phase[|hour]; '*' sums "
                               "the batch's hours; every count must match exactly one pattern; repeatable")
    dap_task.add_argument("--batch-hours", type=int, default=24, metavar="N",
                          help="one batch is N hours; this is the task's time_precision (default 24)")
    dap_task.add_argument("--min-batch", type=int, default=10, metavar="N",
                          help="refuse to release a batch with fewer reports (default 10)")
    dap_task.add_argument("--max-measurement", type=int, default=65535, metavar="N",
                          help="each bucket's sum must stay at or under this (default 65535)")
    dap_task.add_argument("--chunk-length", type=int, default=None, metavar="N",
                          help="VDAF proof chunk length (default: isqrt(length * bits))")
    dap_task.add_argument("--json", action="store_true")
    dap_submit = dap_sub.add_parser(
        "submit", help="shard one batch of counts into a Prio3 report and upload it")
    dap_submit.add_argument("--report", required=True, metavar="FILE",
                            help="an envelope written by `mesh report build --out`")
    dap_submit.add_argument("--task", required=True, metavar="FILE")
    dap_submit.add_argument("--token", default=None, metavar="TOKEN",
                            help="bearer token the leader requires for uploads")
    dap_submit.add_argument("--dir", default=None, metavar="DIR",
                            help="the mesh state whose consent applies, as `report submit` uses")
    dap_submit.add_argument("--json", action="store_true")
    dap_collect = dap_sub.add_parser(
        "collect", help="open one batch with the collector key")
    dap_collect.add_argument("--task", required=True, metavar="FILE")
    dap_collect.add_argument("--keys", required=True, metavar="FILE",
                             help="the collector key file written by `mesh dap task`")
    dap_collect.add_argument("--start", required=True, type=int, metavar="N",
                             help="the batch index (a DAP Time: POSIX seconds / time_precision)")
    dap_collect.add_argument("--token", default=None, metavar="TOKEN",
                             help="bearer token the leader requires (default: from the key file)")
    dap_collect.add_argument("--out", default=None, metavar="FILE")
    dap_collect.add_argument("--json", action="store_true")

    log_cmd = sub.add_parser("log", help="verify a commons' transparency log against its published documents")
    log_cmd.add_argument("site", metavar="DIR_OR_URL", help="a published site directory or mirror URL")
    log_cmd.add_argument("--root", default=None, metavar="FILE", help="pin this root (default: the site's 1.root.json)")
    log_cmd.add_argument("--json", action="store_true")

    gossip = sub.add_parser("gossip", help="compare transparency-log checkpoints with a peer")
    gossip.add_argument("--peer", required=True, action="append", metavar="URL", help="a peer mirror; repeatable")
    gossip.add_argument("--dir", default=None, metavar="DIR")
    gossip.add_argument("--token", default=None, metavar="TOKEN")

    credential = sub.add_parser("credential", help="issue or check membership certificates (issuer side)")
    cred_sub = credential.add_subparsers(dest="credential_command", metavar="ACTION")
    cred_init = cred_sub.add_parser("init", help="create an issuer key and ledger")
    cred_init.add_argument("--out", required=True, metavar="DIR")
    cred_issue = cred_sub.add_parser("issue", help="sign one certificate for a member's pseudonymous key")
    cred_issue.add_argument("--issuer", required=True, metavar="DIR", help="the directory `credential init` wrote")
    cred_issue.add_argument("--member", required=True, metavar="NAME", help="who is admitted (kept in the private ledger only)")
    cred_issue.add_argument("--pseudonym", required=True, metavar="HEX_PUBLIC", help="the member's reporting public key")
    cred_issue.add_argument("--scope", default="early", metavar="SCOPE")
    cred_issue.add_argument("--epoch", type=int, default=None, metavar="N", help="default: the current week")
    cred_issue.add_argument("--out", default=None, metavar="FILE")
    cred_revoke = cred_sub.add_parser("revoke", help="add a certificate id to the issuer's revocation list")
    cred_revoke.add_argument("--issuer", required=True, metavar="DIR")
    cred_revoke.add_argument("id", metavar="CERT_ID")
    cred_verify = cred_sub.add_parser("verify", help="check a certificate against an issuer public key")
    cred_verify.add_argument("file", metavar="FILE")
    cred_verify.add_argument("--issuer-public", required=True, metavar="HEX_PUBLIC")

    harness = sub.add_parser("harness", help="measure a policy's false-positive rate and cost on a benign corpus")
    harness.add_argument("--policy", required=True, metavar="FILE", help="a policy or pack document")
    harness.add_argument("--benign", required=True, metavar="FILE", help="JSONL of benign events: {action, args}")
    harness.add_argument("--samples", default=None, metavar="FILE", help="JSONL of attack events, for recall")
    harness.add_argument("--max-fp-rate", type=float, default=0.001, metavar="RATE")
    harness.add_argument("--max-p95-us", type=int, default=5000, metavar="US")
    harness.add_argument("--min-recall", type=float, default=0.8, metavar="RATE")
    harness.add_argument("--json", action="store_true")

    forge_cmd = sub.add_parser("forge", help="draft gated, reviewable proposals from a consensus state")
    forge_cmd.add_argument("--state", required=True, metavar="FILE", help="a consensus state file")
    forge_cmd.add_argument("--benign", required=True, metavar="FILE", help="JSONL of benign events")
    forge_cmd.add_argument("--out", required=True, metavar="DIR", help="proposals are written under here")
    forge_cmd.add_argument("--samples", default=None, metavar="FILE", help="JSONL of attack events, for recall")
    forge_cmd.add_argument("--max-fp-rate", type=float, default=0.001, metavar="RATE")
    forge_cmd.add_argument("--min-recall", type=float, default=0.8, metavar="RATE")

    consensus = sub.add_parser("consensus", help="work with a consensus state file offline")
    consensus_sub = consensus.add_subparsers(dest="consensus_command", metavar="ACTION")
    consensus_export = consensus_sub.add_parser("export", help="write the active indicators as a pack, or the stats")
    consensus_export.add_argument("--state", required=True, metavar="FILE")
    consensus_export.add_argument("--out", default=None, metavar="FILE", help="write the pack here (default: stdout)")
    consensus_export.add_argument("--stats", action="store_true", help="export the public statistics instead")
    consensus_export.add_argument("--aggregator", action="append", default=[], metavar="URL",
                                  help="with --stats: an aggregator whose combined totals give per-rule fire "
                                       "counts; give at least two")
    consensus_export.add_argument("--token", default=None, metavar="TOKEN", help="bearer token the aggregators require")
    consensus_forget = consensus_sub.add_parser(
        "forget", help="erase a sample from a consensus state file (stop the service first)")
    consensus_forget.add_argument("--state", required=True, metavar="FILE")
    consensus_forget.add_argument("--sample", required=True, metavar="DIGEST",
                                  help="the sample's digest as the state holds it: the first 16 hex characters "
                                       "of the SHA-256 of its text")


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
    if command == "grant":
        return _grant(args)
    if command == "keys":
        return _keys(args)
    if command == "root":
        return _root(args)
    if command == "publish":
        return _publish(args)
    if command == "verify":
        return _verify(args)
    if command == "report":
        return _report(args)
    if command == "dap":
        return _dap(args)
    if command == "serve":
        return _serve(args)
    if command == "consensus":
        return _consensus(args)
    if command == "harness":
        return _harness(args)
    if command == "forge":
        return _forge(args)
    if command == "log":
        return _log(args)
    if command == "gossip":
        return _gossip(args)
    if command == "credential":
        return _credential(args)
    sys.stderr.write("interlock mesh: choose an action: init, sync, status, resolve, grant, keys, root, publish, "
                     "verify, report, dap, serve, consensus, harness, forge, log, gossip, credential\n")
    return 64


def _log(args) -> int:
    import os

    from ..mesh.metadata import MetadataError
    from ..mesh.repository import verify_site

    site = args.site
    if os.path.isdir(site):
        source = site
    else:
        source = site  # a URL: verify_site fetches through the same Fetcher as a subscriber
    try:
        result = verify_site(source, root_path=args.root)
    except (MetadataError, OSError, ValueError) as exc:
        sys.stderr.write("interlock mesh log: REFUSED: {}\n".format(exc))
        return 2
    if args.json:
        sys.stdout.write(json.dumps(result, indent=2, sort_keys=True, default=str) + "\n")
        return 0
    if not result.get("log"):
        print("{}: verified, but this commons publishes no transparency log".format(site))
        return 1
    log = result["log"]
    print("{}: log verified: {} entries, root {}..., origin {}; every published document is logged".format(
        site, log["size"], log["root"][:16], log["origin"]))
    return 0


def _gossip(args) -> int:
    from ..mesh.subscriber import Subscriber, SubscriberError

    node = Subscriber(args.dir)
    worst = 0
    for peer in args.peer:
        try:
            result = node.gossip(peer, token=args.token)
        except SubscriberError as exc:
            sys.stderr.write("interlock mesh gossip: {}\n".format(exc))
            worst = max(worst, 2)
            continue
        theirs = result.get("theirs")
        if result.get("conflict"):
            print("{}: SPLIT VIEW: {}".format(peer, result["conflict"]))
            worst = max(worst, 1)
        elif theirs is None:
            print("{}: peer has no checkpoint yet (ours: size {})".format(peer, result["ours"]["size"]))
        else:
            print("{}: consistent (ours size {}, theirs size {})".format(peer, result["ours"]["size"], theirs["size"]))
    return worst


def _credential(args) -> int:
    import os

    from ..mesh.credential import CredentialError, Issuer, Revocations, issuer_map, verify_certificate

    command = args.credential_command
    if command == "init":
        os.makedirs(args.out, exist_ok=True)
        os.chmod(args.out, 0o700)
        issuer = Issuer.load_or_create(os.path.join(args.out, "issuer.json"), os.path.join(args.out, "ledger.json"))
        print("issuer {} (public {})".format(issuer.keyid, issuer.public.hex()))
        print("give the public key to the collectors (--issuer); keep {} offline".format(args.out))
        return 0
    if command == "issue":
        issuer = Issuer.load_or_create(os.path.join(args.issuer, "issuer.json"), os.path.join(args.issuer, "ledger.json"))
        try:
            cert = issuer.issue(args.member, bytes.fromhex(args.pseudonym), epoch=args.epoch, scope=args.scope)
        except (CredentialError, ValueError) as exc:
            sys.stderr.write("interlock mesh credential: {}\n".format(exc))
            return 2
        text = json.dumps(cert, indent=1, sort_keys=True)
        if args.out:
            with open(args.out, "w", encoding="utf-8") as fh:
                fh.write(text + "\n")
            print("certificate {} for epoch {} written to {}".format(cert["id"], cert["certificate"]["epoch"], args.out))
        else:
            sys.stdout.write(text + "\n")
        return 0
    if command == "revoke":
        path = os.path.join(args.issuer, "revoked.json")
        revoked = Revocations()
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                revoked = Revocations.from_dict(json.load(fh))
        revoked.revoke(args.id)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(revoked.to_dict(), fh, indent=1)
        print("revoked {}; publish {} to the collectors".format(args.id, path))
        return 0
    if command == "verify":
        try:
            with open(args.file, "r", encoding="utf-8") as fh:
                cert = json.load(fh)
            body = verify_certificate(cert, issuer_map([args.issuer_public]))
        except (OSError, ValueError, CredentialError) as exc:
            sys.stderr.write("interlock mesh credential: REFUSED: {}\n".format(exc))
            return 2
        print("valid: pseudonym {}... epoch {} scope {}".format(body["pseudonym"][:16], body["epoch"], body["scope"]))
        return 0
    sys.stderr.write("interlock mesh credential: choose an action: init, issue, revoke, verify\n")
    return 64


def _harness(args) -> int:
    from ..mesh.harness import gate, load_corpus, measure, recall

    try:
        with open(args.policy, "r", encoding="utf-8") as fh:
            policy = json.load(fh)
        benign = load_corpus(args.benign)
        samples = load_corpus(args.samples) if args.samples else []
    except (OSError, ValueError) as exc:
        sys.stderr.write("interlock mesh harness: {}\n".format(exc))
        return 3
    measured = measure(policy, benign, source=args.policy)
    recalled = recall(policy, samples, source=args.policy) if samples else None
    ok, reasons = gate(measured, max_fp_rate=args.max_fp_rate, max_p95_us=args.max_p95_us,
                       recalled=recalled, min_recall=args.min_recall if recalled else 0.0)
    if args.json:
        sys.stdout.write(json.dumps({"passed": ok, "reasons": reasons, "measured": measured, "recall": recalled},
                                    indent=2, sort_keys=True) + "\n")
    else:
        print("{}: {} benign event(s), {} false positive(s) ({:.4%}), p50 {} us, p95 {} us".format(
            args.policy, measured["evaluated"], measured["false_positives"], measured["fp_rate"],
            measured["latency_us"]["p50"], measured["latency_us"]["p95"]))
        for rule, info in measured["per_rule"].items():
            print("  {}: {} hit(s) on benign traffic ({:.4%})".format(rule, info["hits"], info["rate"]))
        if recalled:
            print("  recall: {} of {} sample(s) caught ({:.1%})".format(recalled["caught"], recalled["samples"],
                                                                        recalled["recall"]))
        print("gate: {}".format("PASS" if ok else "FAIL: " + "; ".join(reasons)))
    return 0 if ok else 1


def _forge(args) -> int:
    from ..mesh.consensus import ConsensusEngine
    from ..mesh.forge import forge
    from ..mesh.harness import load_corpus

    try:
        engine = ConsensusEngine.load(args.state)
        benign = load_corpus(args.benign)
        samples = load_corpus(args.samples) if args.samples else []
    except (OSError, ValueError) as exc:
        sys.stderr.write("interlock mesh forge: {}\n".format(exc))
        return 3
    proposals = forge(engine, benign=benign, out_dir=args.out, attack_samples=samples,
                      max_fp_rate=args.max_fp_rate, min_recall=args.min_recall)
    if not proposals:
        print("nothing to propose: no active indicators, campaigns, or multi-organisation samples")
        return 0
    for p in proposals:
        print("{} [{}] {}: {}".format("PASS" if p.passed else "FAIL", p.evidence["source"], p.id,
                                      p.pack.get("description", "")[:80]))
        for reason in p.reasons:
            print("    {}".format(reason))
    print("proposals written under {}; a human reviews and opens the pull request".format(args.out))
    return 0


def _report(args) -> int:
    from ..mesh import default_mesh_dir
    from ..mesh.report import ReportError, ReporterKey

    import os
    mesh_dir = getattr(args, "dir", None) or default_mesh_dir()
    key_path = os.path.join(mesh_dir, "reporter.key")
    if args.report_command == "init":
        os.makedirs(mesh_dir, exist_ok=True)
        try:
            key = ReporterKey.load_or_create(key_path)
        except ReportError as exc:
            sys.stderr.write("interlock mesh report: {}\n".format(exc))
            return 2
        print("reporter {} (key at {}; this id is the only identity the mesh sees)".format(key.keyid, key_path))
        return 0
    if args.report_command == "build":
        return _report_build(args, key_path)
    if args.report_command == "submit":
        return _report_submit(args, mesh_dir)
    if args.report_command == "enable":
        return _report_enable(args, mesh_dir)
    if args.report_command == "status":
        return _report_status(args, mesh_dir)
    sys.stderr.write("interlock mesh report: choose an action: init, build, enable, status, submit\n")
    return 64


def _report_enable(args, mesh_dir: str) -> int:
    from ..mesh.fingerprint import DEFAULT_ALPHA
    from ..mesh.report import BASE_LAYERS, new_attestation
    from ..mesh.subscriber import Subscriber, SubscriberError

    if args.off and (args.digests or args.fingerprints or args.sample or args.i_warrant_samples
                     or args.alpha is not None):
        sys.stderr.write("interlock mesh report: --off turns every layer off and takes no other flag\n")
        return 64
    if args.sample and not args.i_warrant_samples:
        sys.stderr.write("interlock mesh report: --sample needs --i-warrant-samples: you warrant that every sample "
                         "is lawfully obtained, contains no personal data, and contains no third party's "
                         "confidential data (CONTRIBUTING.md)\n")
        return 64
    if args.alpha is not None and not args.fingerprints:
        sys.stderr.write("interlock mesh report: --alpha is the fingerprint budget; give it with --fingerprints\n")
        return 64
    alpha = DEFAULT_ALPHA if args.alpha is None else args.alpha
    if alpha <= 0:
        sys.stderr.write("interlock mesh report: --alpha must be positive\n")
        return 64
    layers = [] if args.off else list(BASE_LAYERS) + [
        layer for layer, on in (("digests", args.digests), ("fingerprints", args.fingerprints),
                                ("samples", bool(args.sample))) if on]
    # The consent lives in state.json and needs no commons: a node may report
    # without subscribing. A watched policy reloads on it, which is how the
    # recorder in the agent's process starts or stops.
    try:
        consent = Subscriber(mesh_dir).set_report_consent(
            layers, alpha=alpha, sample_rules=args.sample,
            attestation=new_attestation() if args.sample else None)
    except (SubscriberError, OSError) as exc:
        sys.stderr.write("interlock mesh report: {}\n".format(exc))
        return 2
    print(report_summary(consent))
    if consent["enabled_at"] is None:
        print("nothing leaves this node, and the recorder records nothing for it")
    else:
        from ..mesh._util import iso
        print("nothing observed before {} is ever uploaded; `report build` shows a report, `report submit` "
              "sends it".format(iso(consent["enabled_at"])))
        if "samples" in consent["layers"]:
            print("you warranted those samples: lawfully obtained, no personal data, no third party's "
                  "confidential data; they are CC0-1.0 once shared (LICENSE-DATA)")
        if "fingerprints" in consent["layers"] or "samples" in consent["layers"]:
            print("a watched policy starts the recorder at its next check; otherwise at the next policy load")
    return 0


def report_summary(consent) -> str:
    """The line ``mesh status``, ``mesh report status`` and ``doctor`` print
    for the node's reporting consent."""
    from ..mesh._util import iso

    if not consent or consent.get("enabled_at") is None:
        return "mesh reporting: off"
    parts = []
    for layer in consent["layers"]:
        if layer == "fingerprints":
            parts.append("fingerprints (alpha {:g})".format(consent["alpha"]))
        elif layer == "samples":
            parts.append("samples ({})".format(", ".join(consent["sample_rules"])))
        else:
            parts.append(layer)
    return "mesh reporting: on since {}: layers {}".format(iso(consent["enabled_at"]), ", ".join(parts))


def _enable_command(consent, layer=None, rule=None) -> str:
    """The ``report enable`` that keeps what ``consent`` enables and adds
    ``layer`` (or the sample ``rule``): each enable replaces the last."""
    from ..mesh.fingerprint import DEFAULT_ALPHA

    layers = set(consent.get("layers") or ()) | ({layer} if layer else set())
    rules = sorted(set(consent.get("sample_rules") or ()) | ({rule} if rule else set()))
    words = ["interlock mesh report enable"]
    if "digests" in layers:
        words.append("--digests")
    if "fingerprints" in layers:
        words.append("--fingerprints")
        if consent.get("alpha", DEFAULT_ALPHA) != DEFAULT_ALPHA:
            words.append("--alpha {:g}".format(consent["alpha"]))
    if "samples" in layers:
        words.extend("--sample " + r for r in rules or ["RULE"])
        words.append("--i-warrant-samples")
    return " ".join(words)


def _projection(receipts, mesh_dir: str, since: float, now: float, consent, *, include_digests: bool = True,
                sightings=(), catalog: str = "", reporter: str = ""):
    """The report body and count vector ``build`` makes from ``receipts``, and
    how many recorded samples it left out for want of the data warranty.

    While reporting is off this is the full local preview, so the operator sees
    what enabling would let leave. Once on, the window opens no earlier than the
    enable, and only the enabled layers (and sample rules) are in it. Samples
    go in only under the warranty the consent holds (decision R4), so with
    reporting off the preview carries none."""
    import os

    from ..mesh.fingerprint import read_records
    from ..mesh.report import build_counts, build_report

    enabled_at = consent["enabled_at"]
    layers = None if enabled_at is None else consent["layers"]
    if enabled_at is not None:
        since = max(since, enabled_at)
    fingerprints = read_records(os.path.join(mesh_dir, "fingerprints.jsonl"), since, now, 500)
    samples = read_records(os.path.join(mesh_dir, "samples.jsonl"), since, now, 20)
    if enabled_at is not None:
        samples = [s for s in samples if s.get("policy_id") in consent["sample_rules"]]
    attestation = consent.get("attestation")
    unwarranted = 0 if attestation else len(samples)
    if unwarranted:
        samples = []
    body = build_report(receipts, since=since, until=now, catalog_id=catalog, reporter_id=reporter,
                        include_digests=include_digests, sightings=sightings, fingerprints=fingerprints,
                        samples=samples, enabled_since=enabled_at, enabled_layers=layers, attestation=attestation)
    counts = build_counts(receipts, since, now, enabled_since=enabled_at, enabled_layers=layers)
    return body, counts, unwarranted


#: The preview reads at most this much of a receipt log.
PREVIEW_MAX_BYTES = 32 * 1024 * 1024


def _report_preview(mesh_dir: str, consent, receipts_path=None, hours: float = 24.0) -> dict:
    """What a ``report build --since 24h`` would hold now, as numbers. Never raises."""
    import os

    from ..report import read_receipts

    if receipts_path is None:
        from ..adapters.config import receipts_paths
        receipts_path = receipts_paths()[0]
    out = {"receipts": receipts_path, "hours": hours}
    try:
        if not os.path.exists(receipts_path):
            return dict(out, error="no receipt log at {}".format(receipts_path))
        if os.path.getsize(receipts_path) > PREVIEW_MAX_BYTES:
            return dict(out, error="{} is too large to preview; run: interlock mesh report build".format(
                receipts_path))
        receipts, _bad = read_receipts(receipts_path)
        now = time.time()
        body, counts, _unwarranted = _projection(receipts, mesh_dir, now - hours * 3600, now, consent)
    except Exception as exc:  # a preview must never break `status` or `doctor`
        return dict(out, error="{}: {}".format(type(exc).__name__, exc))
    return dict(out, decisions=sum(counts.values()), count_rows=len(counts), digests=len(body["digests"]),
                fingerprints=len(body["fingerprints"]), samples=len(body["samples"]),
                sightings=len(body["sightings"]))


def preview_line(consent, preview) -> str:
    """One line: the report this node would send now, or why there is none."""
    if preview.get("error"):
        return "report preview: {}".format(preview["error"])
    what = "{} count row(s), {} digest(s), {} fingerprint(s), {} sample(s)".format(
        preview["count_rows"], preview["digests"], preview["fingerprints"], preview["samples"])
    if consent.get("enabled_at") is None:
        return "report preview, last {:g}h: {}; reporting is off, so none of it is sent".format(preview["hours"], what)
    return "report preview, last {:g}h since the enable: {}".format(preview["hours"], what)


def _report_status(args, mesh_dir: str) -> int:
    from ..mesh import reporting_killed
    from ..mesh.subscriber import Subscriber

    consent = Subscriber(mesh_dir).report_consent()
    preview = _report_preview(mesh_dir, consent, args.receipts)
    if args.json:
        sys.stdout.write(json.dumps({"report": consent, "preview": preview, "kill_switch": reporting_killed()},
                                    indent=2, sort_keys=True) + "\n")
        return 0
    print(report_summary(consent))
    print("  {}".format(preview_line(consent, preview)))
    if reporting_killed():
        print("  INTERLOCK_MESH_NO_REPORT is set: every upload is refused")
    if consent["enabled_at"] is None:
        print("  to enable: interlock mesh report enable [--digests] [--fingerprints] "
              "[--sample RULE --i-warrant-samples]")
    return 0


def _report_build(args, key_path: str) -> int:
    import os

    from ..mesh._util import atomic_write
    from ..mesh.catalog import catalog_id
    from ..mesh.report import ReportError, ReporterKey, sign_report
    from ..mesh.subscriber import Subscriber
    from ..report import parse_since, read_receipts

    if not os.path.exists(key_path):
        sys.stderr.write("interlock mesh report: no reporting key; run: interlock mesh report init\n")
        return 2
    try:
        since_seconds = parse_since(args.since)
    except ValueError as exc:
        sys.stderr.write("interlock mesh report: {}\n".format(exc))
        return 64
    try:
        receipts, bad = read_receipts(args.receipts)
    except OSError as exc:
        sys.stderr.write("interlock mesh report: cannot read {}: {}\n".format(args.receipts, exc))
        return 3
    now = time.time()
    since = now - (since_seconds or 0) if since_seconds else 0.0
    mesh_dir = os.path.dirname(key_path)
    consent = Subscriber(mesh_dir).report_consent()
    credential = None
    if args.credential:
        try:
            with open(args.credential, "r", encoding="utf-8") as fh:
                credential = json.load(fh)
        except (OSError, ValueError) as exc:
            sys.stderr.write("interlock mesh report: cannot read credential {}: {}\n".format(args.credential, exc))
            return 3
    try:
        key = ReporterKey.load_or_create(key_path)
        body, counts, unwarranted = _projection(
            receipts, mesh_dir, since, now, consent, include_digests=not args.no_digests,
            sightings=[{"policy_id": r, "kind": "false_positive"} for r in args.false_positive],
            catalog=catalog_id(), reporter=key.keyid)
        envelope = sign_report(body, key, credential=credential)
    except ReportError as exc:
        sys.stderr.write("interlock mesh report: {}\n".format(exc))
        return 2
    if unwarranted:
        sys.stderr.write("interlock mesh report: {} sample(s) left out: no data warranty on record "
                         "(interlock mesh report enable --sample RULE --i-warrant-samples)\n".format(unwarranted))
    # The count vector never goes into the envelope. It stays beside it, readable
    # by this user only, until `submit` sends it as secret shares.
    text = json.dumps(envelope, sort_keys=True, indent=1)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        atomic_write(args.out + COUNTS_SUFFIX, (json.dumps(
            {"version": 1, "reporter": body["reporter"], "period": body["period"], "counts": counts},
            sort_keys=True, indent=1) + "\n").encode("utf-8"), mode=0o600)
    if args.json:
        sys.stdout.write(text + "\n")
    else:
        print("report by {}: {} decision(s) in {} count row(s), {} digest(s), {} fingerprint(s), {} sample(s), "
              "{} sighting(s); catalog {}".format(
                  key.keyid[:12], sum(counts.values()), len(counts), len(body["digests"]), len(body["fingerprints"]),
                  len(body["samples"]), len(body["sightings"]), body["catalog"]))
        if bad:
            print("  {} unreadable line(s) in the log were skipped".format(len(bad)))
        print("  carries: rule ids, tool classes, hour buckets, argument digests, sightings. Never counts, "
              "arguments, principals or sessions.")
        if consent["enabled_at"] is None:
            print("  reporting is off, so this is a local preview: `submit` refuses it until you run "
                  "`interlock mesh report enable`")
        else:
            print("  {}; nothing from before the enable is in it".format(report_summary(consent)))
        if args.out:
            print("  written to {}; the counts stay in {} and leave only as secret shares to two or more "
                  "aggregators".format(args.out, args.out + COUNTS_SUFFIX))
    return 0


def _read_counts(path: str, body) -> dict:
    """The count vector `build` wrote beside the envelope, checked to belong to it."""
    from ..mesh._util import read_bounded

    doc = json.loads(read_bounded(path, 16 * 1024 * 1024).decode("utf-8"))
    if not isinstance(doc, dict) or doc.get("reporter") != body["reporter"] or doc.get("period") != body["period"]:
        raise ValueError("not the counts of this report (another reporter or period)")
    counts = doc.get("counts")
    if not isinstance(counts, dict) or not all(
            isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool) and v >= 0 for k, v in counts.items()):
        raise ValueError("malformed count vector")
    return counts


def _consent_refusal(body, consent, *, share_counts: bool):
    """Why ``submit`` must not send this report under the node's consent, or None."""
    from ..mesh._util import iso

    enabled_at = consent["enabled_at"]
    if enabled_at is None:
        return ("reporting is off on this node, and nothing leaves it until you run `interlock mesh report "
                "enable` (`interlock mesh report status` previews what would be sent)")
    since = body["period"].get("since")
    if not isinstance(since, (int, float)) or isinstance(since, bool) or since < enabled_at:
        return ("this report covers time before reporting was enabled ({}); rebuild it with "
                "`interlock mesh report build`".format(iso(enabled_at)))
    for layer in ("digests", "sightings", "fingerprints", "samples"):
        if body.get(layer) and layer not in consent["layers"]:
            return "{} are not enabled: run `{}`".format(layer, _enable_command(consent, layer))
    for sample in body.get("samples") or []:
        if sample["policy_id"] not in consent["sample_rules"]:
            return "samples for {} are not enabled: run `{}`".format(
                sample["policy_id"], _enable_command(consent, "samples", sample["policy_id"]))
    if share_counts and "counts" not in consent["layers"]:
        return "counts are not enabled: run `{}`".format(_enable_command(consent, "counts"))
    return None


def _report_submit(args, mesh_dir: str) -> int:
    from ..mesh import NO_REPORT_ENV, reporting_killed
    from ..mesh.aggregate import encode_counts
    from ..mesh.report import ReportError, submit, verify_report
    from ..mesh.subscriber import Subscriber

    if reporting_killed():
        sys.stderr.write("interlock mesh report: not sent: {} is set, which refuses every upload from this "
                         "node whatever is enabled; unset it to submit\n".format(NO_REPORT_ENV))
        return 2
    try:
        with open(args.file, "r", encoding="utf-8") as fh:
            envelope = json.load(fh)
        body = verify_report(envelope)  # refuses an envelope whose report carries counts
    except (OSError, ValueError, ReportError) as exc:
        sys.stderr.write("interlock mesh report: {} is not a valid report: {}\n".format(args.file, exc))
        return 3
    # Consent is checked here, before any connection, for every layer the
    # envelope carries and for the counts it would share.
    refusal = _consent_refusal(body, Subscriber(mesh_dir).report_consent(), share_counts=len(args.aggregator) >= 2)
    if refusal:
        sys.stderr.write("interlock mesh report: not sent: {}\n".format(refusal))
        return 2
    shares = None
    counts_path = args.file + COUNTS_SUFFIX
    if len(args.aggregator) >= 2:
        try:
            shares = encode_counts(_read_counts(counts_path, body), len(args.aggregator))
        except (OSError, ValueError) as exc:
            sys.stderr.write("interlock mesh report: cannot share counts from {}: {}\n".format(counts_path, exc))
            return 3
    # Only the signed envelope's own fields go to consensus; the counts never do.
    outgoing = {k: envelope[k] for k in ("report", "public", "signature", "credential") if k in envelope}
    try:
        reply = submit(args.consensus.rstrip("/") + "/v1/reports", outgoing, token=args.token)
    except (OSError, ReportError) as exc:
        sys.stderr.write("interlock mesh report: consensus {}: {}\n".format(args.consensus, exc))
        return 2
    print("consensus: {}".format("accepted" if reply.get("accepted") else "refused: {}".format(reply.get("reason"))))
    if shares is None:
        print("counts not shared: they leave this node only as secret shares to at least two aggregators "
              "(give --aggregator twice); {} aggregator(s) given".format(len(args.aggregator)))
        return 0 if reply.get("accepted") else 2
    report_id = "{}:{}".format(body["reporter"], int(body["period"]["until"]))
    for url, share in zip(args.aggregator, shares):
        try:
            answer = submit(url.rstrip("/") + "/v1/shares", {"report_id": report_id, "shares": share}, token=args.token)
        except (OSError, ReportError) as exc:
            sys.stderr.write("interlock mesh report: aggregator {}: {}\n".format(url, exc))
            return 2
        print("aggregator {}: {}".format(url, "accepted" if answer.get("accepted") else answer))
    return 0 if reply.get("accepted") else 2


def _dap(args) -> int:
    from ..mesh import default_mesh_dir
    from ..mesh.dap import client, collector
    from ..mesh.dap.task import TaskError, create_task, load_role_keys, load_task
    from ..mesh.report import ReportError, verify_report
    from ..mesh.subscriber import Subscriber

    action = args.dap_command
    if action == "task":
        try:
            task, _, _, _ = create_task(
                leader=args.leader_url, helper=args.helper_url, buckets=args.bucket,
                batch_hours=args.batch_hours, min_batch_size=args.min_batch,
                max_measurement=args.max_measurement, chunk_length=args.chunk_length,
                out_dir=args.out)
        except (TaskError, OSError) as exc:
            sys.stderr.write("interlock mesh dap task: {}\n".format(exc))
            return 3
        if args.json:
            print(json.dumps(task.to_json(), indent=1, sort_keys=True))
            return 0
        print("task {} ({} buckets, {}h batches)".format(
            task.task_id_hex, task.length, task.hours_per_batch))
        print("wrote task.json, leader.json, helper.json, collector.json under {}".format(args.out))
        print("leader  {}".format(task.leader))
        print("helper  {}".format(task.helper))
        print("Keep leader.json, helper.json and collector.json secret (mode 0600): they hold the "
              "HPKE secrets, the VDAF verify key and the bearer tokens.")
        return 0

    if action == "submit":
        from ..mesh import NO_REPORT_ENV, reporting_killed

        if reporting_killed():
            sys.stderr.write("interlock mesh dap: not sent: {} is set, which refuses every upload from "
                             "this node whatever is enabled; unset it to submit\n".format(NO_REPORT_ENV))
            return 2
        try:
            task = load_task(args.task)
            with open(args.report, "r", encoding="utf-8") as fh:
                envelope = json.load(fh)
            body = verify_report(envelope)
            counts = _read_counts(args.report + COUNTS_SUFFIX, body)
        except (OSError, ValueError, ReportError, TaskError) as exc:
            sys.stderr.write("interlock mesh dap: {} is not usable: {}\n".format(args.report, exc))
            return 3
        refusal = _consent_refusal(body, Subscriber(args.dir or default_mesh_dir()).report_consent(),
                                   share_counts=True)
        if refusal:
            sys.stderr.write("interlock mesh dap: not sent: {}\n".format(refusal))
            return 2
        try:
            batch_index = task.batch_for_counts(counts)
            plan, result = client.submit_counts(task, counts, token=args.token,
                                                batch_index=batch_index)
        except (client.ClientError, TaskError, ReportError, OSError) as exc:
            sys.stderr.write("interlock mesh dap: not sent: {}\n".format(exc))
            return 2
        if args.json:
            print(json.dumps({
                "report_id": plan.report.report_id.hex(),
                "batch": plan.batch_index,
                "measurement": list(plan.measurement),
                "accepted": bool(result.accepted),
                "errors": [{"report_id": e.report_id.hex(),
                            "error": m_name(e.error)} for e in result.errors],
            }, indent=1, sort_keys=True))
            return 0 if result.accepted else 2
        if result.accepted:
            print("report {}: accepted by the leader for batch {}".format(
                plan.report.report_id.hex(), plan.batch_index))
            return 0
        for error in result.errors:
            print("report {}: refused: {}".format(error.report_id.hex(), m_name(error.error)),
                  file=sys.stderr)
        return 2

    if action == "collect":
        try:
            task = load_task(args.task)
            keys = load_role_keys(args.keys, task)
            result = collector.collect(task, keys, args.start, token=args.token)
        except (OSError, ValueError, TaskError, collector.CollectorError) as exc:
            sys.stderr.write("interlock mesh dap collect: {}\n".format(exc))
            return 2
        document = result.to_json()
        if args.out:
            from ..mesh._util import atomic_write

            try:
                atomic_write(args.out, (json.dumps(document, indent=1, sort_keys=True) + "\n")
                             .encode("utf-8"), 0o600)
            except OSError as exc:
                sys.stderr.write("interlock mesh dap collect: cannot write {}: {}\n".format(args.out, exc))
                return 3
        if args.json:
            print(json.dumps(document, indent=1, sort_keys=True))
            return 0
        print("batch {}, {} report(s) (DAP interval start={} duration={})".format(
            args.start, result.report_count, result.interval.start, result.interval.duration))
        for label, value in sorted(result.counts.items()):
            print("  {:>8}  {}".format(value, label))
        if not result.counts:
            print("  (no non-zero buckets)")
        return 0

    sys.stderr.write("interlock mesh dap: choose an action: task, submit, collect\n")
    return 64


def m_name(error) -> str:
    """A ReportError's wire name, for messages."""
    return getattr(error, "name", str(error))


def _serve_dap(args) -> int:
    from ..mesh.dap.server import make_dap_server
    from ..mesh.dap.task import TaskError, load_role_keys, load_task

    if not args.task or not args.keys:
        sys.stderr.write("interlock mesh serve: --role {} needs --task and --keys\n".format(args.role))
        return 64
    role = "leader" if args.role == "dap-leader" else "helper"
    try:
        task = load_task(args.task)
        keys = load_role_keys(args.keys, task)
        if keys.role != role:
            raise TaskError("{} holds {!r} keys, but --role {} needs {!r} keys".format(
                args.keys, keys.role, args.role, role))
        state_path = args.state or (args.keys + ".state")
        server = make_dap_server(args.bind, role=role, task=task, keys=keys,
                                 state_path=state_path, peer_token=args.peer_token,
                                 collector_token=args.collector_token)
    except (OSError, TaskError, ValueError) as exc:
        sys.stderr.write("interlock mesh serve: {}\n".format(exc))
        return 2
    print("interlock mesh {} listening on {} (task {}, state: {})".format(
        args.role, server.url, task.task_id_hex, state_path), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def _serve(args) -> int:
    from ..mesh import default_mesh_dir
    from ..mesh.server import make_server

    from ..mesh.aggregate import MIN_BATCH_FLOOR

    if args.role in ("dap-leader", "dap-helper"):
        return _serve_dap(args)

    config = {}
    if args.min_orgs:
        config["min_orgs"] = args.min_orgs
    if args.min_batch is not None:
        if args.role != "aggregator" or args.min_batch < MIN_BATCH_FLOOR:
            sys.stderr.write("interlock mesh serve: --min-batch is for --role aggregator and at least {}\n".format(
                MIN_BATCH_FLOOR))
            return 64
        config["min_batch"] = args.min_batch
    if args.require_credential:
        config["require_credential"] = True
        config["issuers"] = list(args.issuer)
    directory = args.dir or default_mesh_dir()
    try:
        server = make_server(args.role, args.bind, state_path=args.state, token=args.token,
                             known_catalogs=tuple(args.known_catalog), config=config or None,
                             directory=directory if args.role == "mirror" else None)
    except (OSError, ValueError) as exc:
        sys.stderr.write("interlock mesh serve: {}\n".format(exc))
        return 2
    # flush=True: a supervisor or script reading this line through a pipe must
    # see the bound address before the server blocks in serve_forever.
    print("interlock mesh {} listening on {}{}".format(args.role, server.url,
                                                        " (state: {})".format(args.state) if args.state else
                                                        " (serving {})".format(directory) if args.role == "mirror" else ""),
          flush=True)
    if args.role == "consensus" and not args.known_catalog:
        print("warning: no --known-catalog given; every report will be refused (unknown catalog)", flush=True)
    if args.role == "mirror":
        print("peers add this URL as a mirror; they verify everything from their own pinned root", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def _consensus(args) -> int:
    from ..mesh.consensus import ConsensusEngine

    if args.consensus_command == "forget":
        return _consensus_forget(args)
    if args.consensus_command != "export":
        sys.stderr.write("interlock mesh consensus: choose an action: export, forget\n")
        return 64
    if args.aggregator and (not args.stats or len(args.aggregator) < 2):
        sys.stderr.write("interlock mesh consensus: --aggregator goes with --stats, given at least twice\n")
        return 64
    try:
        engine = ConsensusEngine.load(args.state)
    except (OSError, ValueError) as exc:
        sys.stderr.write("interlock mesh consensus: cannot load {}: {}\n".format(args.state, exc))
        return 3
    payload = engine.export_stats() if args.stats else engine.export_indicators()
    if args.aggregator:
        try:
            fire = _aggregator_fire_totals(args.aggregator, args.token)
        except (OSError, ValueError) as exc:
            sys.stderr.write("interlock mesh consensus: no fire counts: {}\n".format(exc))
            return 2
        for policy_id, rule in payload["rules"].items():
            rule["verdicts"] = dict(sorted(fire["rules"].pop(policy_id, {}).items()))
        for policy_id, verdicts in sorted(fire["rules"].items()):  # fired, but no digest or sighting reached consensus
            payload["rules"][policy_id] = {"orgs": 0, "verdicts": dict(sorted(verdicts.items())), "demoted": False,
                                           "false_positive_orgs": 0, "last": None}
        payload["fire_counts"] = {"aggregators": list(args.aggregator), "reports": fire["reports"],
                                  "min_batch": fire["min_batch"]}
        payload["note"] = ("rules[*].verdicts are the aggregators' combined totals over fire_counts.reports "
                           "reconciled reports; consensus never saw a count")
    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print("wrote {}".format(args.out))
    else:
        sys.stdout.write(text + "\n")
    return 0


def _consensus_forget(args) -> int:
    """Erasure (GOVERNANCE.md): drop a sample from the state and save it the engine's own way."""
    import re

    from ..mesh.consensus import ConsensusEngine

    digest = args.sample.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{16}", digest):
        sys.stderr.write("interlock mesh consensus: --sample takes the sample's 16-hex digest, not {!r}\n".format(
            args.sample))
        return 64
    try:
        engine = ConsensusEngine.load(args.state)
    except (OSError, ValueError) as exc:
        sys.stderr.write("interlock mesh consensus: cannot load {}: {}\n".format(args.state, exc))
        return 3
    removed = engine.forget_sample(digest)
    if not removed:
        sys.stderr.write("interlock mesh consensus: no sample {} in {}\n".format(digest, args.state))
        return 2
    try:
        engine.save(args.state)
    except OSError as exc:
        sys.stderr.write("interlock mesh consensus: cannot write {}: {}\n".format(args.state, exc))
        return 3
    print("forgot sample {} ({} cop{}) in {}".format(digest, removed, "y" if removed == 1 else "ies", args.state))
    print("also remove it from the commons' packs/*.tests.json and any proposal that carries it (GOVERNANCE.md)")
    return 0


def _aggregator_fire_totals(urls, token) -> dict:
    """GET each aggregator's manifest, POST /v1/totals for the reconciled ids,
    and combine the replies (:func:`interlock.mesh.aggregate.fire_totals`)."""
    import urllib.error
    import urllib.request

    from ..mesh.aggregate import fire_totals, reconcile
    from ..mesh.report import submit

    manifests = []
    for url in urls:
        request = urllib.request.Request(url.rstrip("/") + "/v1/manifest", headers={"User-Agent": "interlock-mesh"})
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310
            manifest = json.loads(response.read(16 * 1024 * 1024).decode("utf-8"))
        if not isinstance(manifest, dict) or not isinstance(manifest.get("ids"), list):
            raise ValueError("{}: not an aggregator manifest".format(url))
        manifests.append(manifest)
    ids = reconcile(*[[i for i in m["ids"] if isinstance(i, str)] for m in manifests])
    replies = []
    for url in urls:
        try:
            replies.append(submit(url.rstrip("/") + "/v1/totals", {"ids": ids}, token=token))
        except urllib.error.HTTPError as exc:
            try:
                reason = json.loads(exc.read(64 * 1024).decode("utf-8")).get("reason") or exc
            except (ValueError, AttributeError):
                reason = exc
            raise OSError("{}: {}".format(url, reason))
    return fire_totals(manifests, replies)


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
    from ..mesh import reporting_killed
    from ..mesh.subscriber import Subscriber

    node = Subscriber(args.dir)
    status = node.status()
    status["report_preview"] = _report_preview(node.dir, status["report"])
    reporting = [report_summary(status["report"]), preview_line(status["report"], status["report_preview"])]
    if reporting_killed():
        reporting.append("INTERLOCK_MESH_NO_REPORT is set: every upload is refused")
    if args.json:
        sys.stdout.write(json.dumps(status, indent=2, sort_keys=True, default=str) + "\n")
    else:
        if not status["configured"]:
            print("mesh: not configured ({})".format(status["dir"]))
            print("run: interlock mesh init --root ROOT --mirror URL")
            for line in reporting:  # reporting needs no commons
                print("  {}".format(line))
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
        for line in _grant_lines(status.get("grants", {})):
            print("  grant: {}".format(line))
        if status.get("capped"):
            print("  {}".format(capped_summary(status["capped"])))
        for line in reporting:
            print("  {}".format(line))
        shadow = status.get("shadow", {})
        if shadow.get("total"):
            print("  shadow findings: {} (what monitor-window rules, and capped rules with no approver, "
                  "would have decided)".format(shadow["total"]))
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


def capped_summary(count: int) -> str:
    """The line ``status`` and ``doctor`` print for rules capped at escalate."""
    return "{} mesh rule{} capped at escalate; no approver installed: shadow only".format(
        count, "" if count == 1 else "s")


def _grant_lines(grants) -> list:
    lines = []
    for entry in grants.get("block", []):
        if "rule" in entry:
            lines.append("block rule {}{}".format(entry["rule"], " in pack {}".format(entry["pack"])
                                                  if "pack" in entry else " in any pack"))
        else:
            lines.append("block pack {}, status {} and above".format(entry["pack"], entry["status"]))
    return lines


def _grant(args) -> int:
    from ..mesh.subscriber import Subscriber, SubscriberError

    command = getattr(args, "grant_command", None)
    if command is None and not args.list:
        sys.stderr.write("interlock mesh grant: choose an action: block, revoke, or --list\n")
        return 64
    if command is not None and args.list:
        sys.stderr.write("interlock mesh grant: --list takes no action\n")
        return 64
    node = Subscriber(args.dir)
    try:
        config = node.config()
    except SubscriberError as exc:
        sys.stderr.write("interlock mesh grant: {}\n".format(exc))
        return 2
    if args.list:
        lines = _grant_lines(config.grants)
        for line in lines:
            print(line)
        if not lines:
            print("no grants: every mesh block is capped at escalate")
        return 0
    if args.rule:
        if args.status:
            sys.stderr.write("interlock mesh grant: --status goes with --pack, not --rule\n")
            return 64
        entry = {"rule": args.rule}
        if args.pack:
            entry["pack"] = args.pack
    elif args.pack:
        entry = {"pack": args.pack, "status": args.status or "stable"}
    else:
        sys.stderr.write("interlock mesh grant: give --pack PACK [--status S] or --rule ID\n")
        return 64
    (line,) = _grant_lines({"block": [entry]})
    if command == "block":
        if not config.grant(entry):
            print("already granted: {}".format(line))
            return 0
        config.save(node.config_path)
        print("granted: {}".format(line))
        print("a watched policy picks it up at its next check; otherwise at the next policy load")
        return 0
    if not config.revoke(entry):
        sys.stderr.write("interlock mesh grant: no such grant: {}\n".format(line))
        return 2
    config.save(node.config_path)
    print("revoked: {}".format(line))
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
    print("keys written to {} (mode 0600). After the first publish, move the root key files offline: publish "
          "needs them only for a new root, and `interlock mesh root draft|sign|assemble` signs one without "
          "them.".format(args.out))
    return 0


def _root(args) -> int:
    from ..mesh.metadata import MetadataError
    from ..mesh.repository import PublishError, assemble_root, draft_root, sign_root

    command = args.root_command
    if command not in ("draft", "sign", "assemble"):
        sys.stderr.write("interlock mesh root: choose an action: draft, sign, assemble\n")
        return 64
    try:
        if command == "draft":
            return _root_draft(args, draft_root)
        if command == "sign":
            result = sign_root(args.file, key_path=args.key, external_signer=args.external_signer)
            print("signed root v{} (sha256 {}) with key {}, a key of the {} root -> {}".format(
                result["version"], result["sha256"], result["keyid"], " and the ".join(result["counts_toward"]),
                result["path"]))
            print("send that file to whoever assembles the root; it holds nothing secret")
            return 0
        result = assemble_root(args.file, args.sig, args.site)
    except (PublishError, MetadataError, ValueError) as exc:
        sys.stderr.write("interlock mesh root {}: {}\n".format(command, exc))
        return 2
    except OSError as exc:
        sys.stderr.write("interlock mesh root {}: {}\n".format(command, exc))
        return 3
    print("assembled root v{} (sha256 {}, expires {}) from {} signature(s) -> {}{}".format(
        result["root_version"], result["sha256"], result["expires"], len(result["signatures"]), result["path"],
        "; added to the transparency log" if result["logged"] else ""))
    print("next: interlock mesh publish, so the timestamp, snapshot and targets are signed under it")
    return 0


def _root_draft(args, draft_root) -> int:
    from ..mesh import metadata

    doc = draft_root(args.site, args.keys, args.out, expires_days=args.expires_days)
    signed = doc["signed"]
    print("drafted root v{} (expires {}) -> {}".format(signed["version"], signed["expires"], args.out))
    for role, spec in sorted(signed["roles"].items()):
        print("  {:<10} {} of {}".format(role, spec["threshold"], len(spec["keyids"])))
        for keyid in spec["keyids"]:
            meta = signed["keys"][keyid]
            since = meta.get(metadata.TERM_START_FIELD)
            print("    {}  {} {}".format(keyid, meta.get(metadata.KEYOWNER_FIELD, ""),
                                         "(since {})".format(since) if since else "").rstrip())
    previous = doc.get("previous_root")
    if previous:
        print("  root v{} must approve it too: {} of {}".format(previous["version"], previous["threshold"],
                                                              ", ".join(k[:16] for k in sorted(previous["keys"]))))
    print("sha256 of the bytes each keyholder signs: {}".format(
        metadata.sha256_hex(metadata.signed_bytes(signed))))
    print("next, on each keyholder's machine: interlock mesh root sign {} --key KEYFILE".format(args.out))
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
    for warning in result["warnings"]:
        sys.stderr.write("interlock mesh publish: warning: {}\n".format(warning))
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

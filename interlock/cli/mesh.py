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

    report = sub.add_parser("report", help="build, inspect and submit what your guard stopped")
    report_sub = report.add_subparsers(dest="report_command", metavar="ACTION")
    report_init = report_sub.add_parser("init", help="create this node's reporting key")
    report_init.add_argument("--dir", default=None, metavar="DIR")
    report_build = report_sub.add_parser("build", help="project a receipt log into a signed report")
    report_build.add_argument("--receipts", required=True, metavar="FILE", help="a receipt log written by FileSink")
    report_build.add_argument("--since", default="24h", metavar="DURATION", help="window: 30m, 24h, 7d (default 24h)")
    report_build.add_argument("--out", default=None, metavar="FILE", help="write the signed envelope here")
    report_build.add_argument("--false-positive", action="append", default=[], metavar="RULE_ID",
                              help="say this rule is wrong here (a negative sighting); repeatable")
    report_build.add_argument("--no-digests", action="store_true", help="counts only, no argument digests")
    report_build.add_argument("--credential", default=None, metavar="FILE",
                              help="a membership certificate for this node's reporting key")
    report_build.add_argument("--dir", default=None, metavar="DIR")
    report_build.add_argument("--json", action="store_true", help="print the envelope instead of a summary")
    report_enable = report_sub.add_parser("enable", help="record fingerprints (and opt-in samples) of what the guard stops")
    report_enable.add_argument("--alpha", type=float, default=1.5, metavar="A",
                               help="privacy budget per fingerprint; smaller is more private (default 1.5)")
    report_enable.add_argument("--sample", action="append", default=[], metavar="RULE_ID",
                               help="also keep redacted samples for this rule, for the forge; repeatable")
    report_enable.add_argument("--off", action="store_true", help="stop recording")
    report_enable.add_argument("--dir", default=None, metavar="DIR")
    report_submit = report_sub.add_parser("submit", help="send a built report to the collectors")
    report_submit.add_argument("file", metavar="FILE", help="an envelope written by `report build --out`")
    report_submit.add_argument("--consensus", required=True, metavar="URL", help="the consensus service")
    report_submit.add_argument("--aggregator", action="append", default=[], metavar="URL",
                               help="an aggregator; give at least two or counts are not shared")
    report_submit.add_argument("--token", default=None, metavar="TOKEN", help="bearer token the collectors require")

    serve = sub.add_parser("serve", help="run a collector role, or mirror this node's verified cache to peers")
    serve.add_argument("--role", required=True, choices=["consensus", "aggregator", "mirror"])
    serve.add_argument("--bind", default="127.0.0.1:7949", metavar="HOST:PORT")
    serve.add_argument("--state", default=None, metavar="FILE", help="persist state here")
    serve.add_argument("--token", default=None, metavar="TOKEN", help="require this bearer token on every POST")
    serve.add_argument("--known-catalog", action="append", default=[], metavar="ID",
                       help="consensus: accept reports from this detector catalog id; repeatable")
    serve.add_argument("--min-orgs", type=int, default=None, metavar="N")
    serve.add_argument("--dir", default=None, metavar="DIR",
                       help="mirror: the directory to serve (default: this node's mesh cache)")
    serve.add_argument("--require-credential", action="store_true",
                       help="consensus: refuse reports without a membership certificate")
    serve.add_argument("--issuer", action="append", default=[], metavar="HEX_PUBLIC",
                       help="consensus: a credential issuer's public key; repeatable")

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
    if command == "report":
        return _report(args)
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
    sys.stderr.write("interlock mesh: choose an action: init, sync, status, resolve, keys, publish, verify, "
                     "report, serve, consensus, harness, forge, log, gossip, credential\n")
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
    mesh_dir = getattr(args, "dir", None) or default_mesh_dir()  # `submit` has no --dir
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
        return _report_submit(args)
    if args.report_command == "enable":
        return _report_enable(args)
    sys.stderr.write("interlock mesh report: choose an action: init, enable, build, submit\n")
    return 64


def _report_enable(args) -> int:
    from ..mesh.subscriber import Subscriber, SubscriberError, install_recorder

    node = Subscriber(args.dir)
    try:
        config = node.config()
    except SubscriberError as exc:
        sys.stderr.write("interlock mesh report: {}\n".format(exc))
        return 2
    if args.alpha <= 0:
        sys.stderr.write("interlock mesh report: --alpha must be positive\n")
        return 64
    config.recorder = {"enabled": not args.off, "alpha": float(args.alpha), "sample_rules": sorted(set(args.sample))}
    config.save(node.config_path)
    install_recorder(node.dir)
    if args.off:
        print("recording off")
    else:
        print("recording fingerprints of blocked and escalated calls (alpha {:g}){}".format(
            args.alpha, "; redacted samples for: " + ", ".join(config.recorder["sample_rules"])
            if config.recorder["sample_rules"] else ""))
        print("they are included by the next `interlock mesh report build`; nothing leaves until `submit`")
    return 0


def _report_build(args, key_path: str) -> int:
    import os

    from ..mesh.catalog import catalog_id
    from ..mesh.report import ReportError, ReporterKey, build_report, sign_report
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
    from ..mesh.fingerprint import read_records
    mesh_dir = os.path.dirname(key_path)
    fingerprints = read_records(os.path.join(mesh_dir, "fingerprints.jsonl"), since, now, 500)
    samples = read_records(os.path.join(mesh_dir, "samples.jsonl"), since, now, 20)
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
        body = build_report(receipts, since=since, until=now, catalog_id=catalog_id(), reporter_id=key.keyid,
                            include_digests=not args.no_digests,
                            sightings=[{"policy_id": r, "kind": "false_positive"} for r in args.false_positive],
                            fingerprints=fingerprints, samples=samples)
        envelope = sign_report(body, key, credential=credential)
    except ReportError as exc:
        sys.stderr.write("interlock mesh report: {}\n".format(exc))
        return 2
    text = json.dumps(envelope, sort_keys=True, indent=1)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    if args.json:
        sys.stdout.write(text + "\n")
    else:
        total = sum(c["n"] for c in body["counts"])
        print("report by {}: {} decision(s) in {} count row(s), {} digest(s), {} fingerprint(s), {} sample(s), "
              "{} sighting(s); catalog {}".format(
                  key.keyid[:12], total, len(body["counts"]), len(body["digests"]), len(body["fingerprints"]),
                  len(body["samples"]), len(body["sightings"]), body["catalog"]))
        if bad:
            print("  {} unreadable line(s) in the log were skipped".format(len(bad)))
        print("  carries: rule ids, verdicts, tool classes, hour buckets, argument digests. Never arguments, "
              "principals or sessions.")
        if args.out:
            print("  written to {}".format(args.out))
    return 0


def _report_submit(args) -> int:
    from ..mesh.aggregate import count_key, encode_counts
    from ..mesh.report import ReportError, submit, verify_report

    try:
        with open(args.file, "r", encoding="utf-8") as fh:
            envelope = json.load(fh)
        body = verify_report(envelope)
    except (OSError, ValueError, ReportError) as exc:
        sys.stderr.write("interlock mesh report: {} is not a valid report: {}\n".format(args.file, exc))
        return 3
    try:
        reply = submit(args.consensus.rstrip("/") + "/v1/reports", envelope, token=args.token)
    except OSError as exc:
        sys.stderr.write("interlock mesh report: consensus {}: {}\n".format(args.consensus, exc))
        return 2
    print("consensus: {}".format("accepted" if reply.get("accepted") else "refused: {}".format(reply.get("reason"))))
    if len(args.aggregator) < 2:
        if args.aggregator:
            print("counts not shared: one aggregator alone would see them; give at least two")
        return 0 if reply.get("accepted") else 2
    counts = {count_key(c["policy_id"], c["verdict"], c["tool_class"], c["phase"], c["bucket"]): c["n"]
              for c in body["counts"]}
    report_id = "{}:{}".format(body["reporter"], int(body["period"]["until"]))
    shares = encode_counts(counts, len(args.aggregator))
    for url, share in zip(args.aggregator, shares):
        try:
            answer = submit(url.rstrip("/") + "/v1/shares", {"report_id": report_id, "shares": share}, token=args.token)
        except OSError as exc:
            sys.stderr.write("interlock mesh report: aggregator {}: {}\n".format(url, exc))
            return 2
        print("aggregator {}: {}".format(url, "accepted" if answer.get("accepted") else answer))
    return 0 if reply.get("accepted") else 2


def _serve(args) -> int:
    from ..mesh import default_mesh_dir
    from ..mesh.server import make_server

    config = {}
    if args.min_orgs:
        config["min_orgs"] = args.min_orgs
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

    if args.consensus_command != "export":
        sys.stderr.write("interlock mesh consensus: choose an action: export\n")
        return 64
    try:
        engine = ConsensusEngine.load(args.state)
    except (OSError, ValueError) as exc:
        sys.stderr.write("interlock mesh consensus: cannot load {}: {}\n".format(args.state, exc))
        return 3
    payload = engine.export_stats() if args.stats else engine.export_indicators()
    text = json.dumps(payload, indent=2, sort_keys=True)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
        print("wrote {}".format(args.out))
    else:
        sys.stdout.write(text + "\n")
    return 0


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

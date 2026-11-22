"""Decide one coding-agent tool call (run by the agent, not by you).

The agent passes its hook payload on stdin; the verdict goes back on stdout and
the exit code, in that agent's own protocol. `interlock install-hook` writes
the command line; you do not normally run this by hand, except to test:

  echo '{"hook_event_name":"PreToolUse","tool_name":"Bash",
         "tool_input":{"command":"git push --force origin main"},
         "session_id":"s","cwd":"/tmp"}' | interlock hook --agent claude-code

Any error - unreadable input, a policy that will not load, a crash - denies the
call (fail closed) unless --on-error allow, which lets the call through and
says so loudly.
"""
from __future__ import annotations

import json
import os
import sys


def add_arguments(parser) -> None:
    from ..adapters import ADAPTERS
    parser.add_argument("--agent", required=True, choices=sorted(ADAPTERS))
    parser.add_argument("--policy", metavar="FILE",
                        help="policy file (default ~/.interlock/policy.json, else the "
                             "built-in coding-agent pack)")
    parser.add_argument("--artifact", metavar="PATH",
                        help="a manifest-delivered policy artifact, or a directory "
                             "containing active.json; mutually exclusive with --policy")
    parser.add_argument("--rules", metavar="MODULE:ATTR", help="a Python policy module instead")
    parser.add_argument("--sidecar", metavar="PATH", help="ask this sidecar instead")
    parser.add_argument("--receipts", metavar="FILE",
                        help="receipt log (default ~/.interlock/receipts.jsonl when its key exists)")
    parser.add_argument("--key-file", metavar="FILE", help="receipt MAC key")
    parser.add_argument("--no-receipts", action="store_true", help="write no receipts")
    parser.add_argument("--no-overlay", action="store_true", help="ignore project overlays")
    parser.add_argument("--monitor", action="store_true",
                        help="record what would happen, never block")
    parser.add_argument("--on-error", choices=("deny", "allow"), default="deny",
                        help="what an internal error does (default deny)")
    parser.add_argument("--reviews", choices=("fallback", "always", "off"), default="fallback",
                        help="settle escalations through the review queue: when the agent "
                             "can't ask (default), always, or never")
    parser.add_argument("--review-db", metavar="FILE",
                        help="review queue (default ~/.interlock/reviews.db)")
    parser.add_argument("--patch-gate", choices=("off", "block", "monitor"),
                        default=None,
                        help="also refuse a git commit/push/merge whose diff has not "
                             "passed `interlock patch gate` (default $INTERLOCK_PATCH_GATE, "
                             "else off)")
    parser.add_argument("--patch-gates-dir", metavar="DIR",
                        help="where patch-gate records live (default "
                             "~/.interlock/patch-gates, or $INTERLOCK_PATCH_GATES_DIR)")
    parser.add_argument("--patch-key", metavar="FILE",
                        help="patch-gate record key (default ~/.interlock/patch-gates.key, "
                             "or $INTERLOCK_PATCH_KEY)")
    parser.add_argument("--flow-state", metavar="FILE", default=None,
                        help="remember poisoned tool results in this SQLite file across "
                             "processes (fragment digests only), so a later call that "
                             "copies their text carries the taint label (default "
                             "$INTERLOCK_FLOW_STATE, else process-local)")


def run(args) -> int:
    from ..adapters import get_adapter
    from ..adapters.base import MAX_PAYLOAD, run_hook

    adapter = get_adapter(args.agent)
    fail_open = args.on_error == "allow"
    flow_state = getattr(args, "flow_state", None) or os.environ.get("INTERLOCK_FLOW_STATE")
    if flow_state is not None:
        from .._sqlite import check_state_path
        try:
            flow_state = check_state_path(flow_state)
        except ValueError as exc:
            sys.stderr.write("interlock hook: {}\n".format(exc))
            return 64
    call = None
    if getattr(args, "artifact", None) and (
            getattr(args, "policy", None) or getattr(args, "rules", None)):
        # The command line itself is wrong: a local policy source and a
        # distributed artifact are two different authorities. --sidecar is
        # allowed: the artifact is the primary and the daemon is the second,
        # out-of-process tier.
        sys.stderr.write(
            "interlock hook: --artifact cannot be combined with --policy "
            "or --rules\n")
        return 64
    try:
        # A distributed artifact is loaded once, before any event is read. A
        # corrupt or unmaterialisable artifact takes the fail-closed deny path
        # below; it never falls back to a local policy.
        artifact_engine = None
        if getattr(args, "artifact", None):
            from ..policy.artifact import load_artifact
            from ..policy.killswitch import apply_kill_marker
            loaded = load_artifact(args.artifact)
            if loaded.rule_count() == 0:
                # An empty rule set allows every call. A hook that would allow
                # everything is not a working guard, so this is a configuration
                # error: refuse it whatever --on-error says, before any event
                # is read. The sidecar daemon refuses the same artifact.
                sys.stderr.write(
                    "interlock hook: artifact {} has no effective rules; "
                    "refusing to run a policy that would allow every call\n"
                    .format(args.artifact))
                return 64
            # The marker the connector writes beside the artifact is a
            # decision, not an error: it denies whatever --on-error says.
            artifact_engine = apply_kill_marker(loaded, args.artifact)
        raw = sys.stdin.buffer.read(MAX_PAYLOAD + 1)
        if len(raw) > MAX_PAYLOAD:
            raise ValueError("hook input larger than {} bytes".format(MAX_PAYLOAD))
        payload = json.loads(raw.decode("utf-8") or "{}")
        if not isinstance(payload, dict):
            raise ValueError("hook input is not a JSON object")
        call = adapter.parse(payload)
        cwd = call.cwd if isinstance(call.cwd, str) else None
        engine = _patch_gate(_engine(args, cwd, artifact_engine), args)
        _install_sink(args)
        if flow_state:
            _install_flow_state(flow_state)
        queue = None
        if args.reviews != "off":
            from ..notify import from_env
            from ..reviews import ReviewQueue
            # INTERLOCK_REVIEW_WEBHOOK, when set: one outbound ping per filed
            # review. A malformed setting warns and notifies nothing; it never
            # changes the decision.
            queue = ReviewQueue(args.review_db, on_file=from_env())
        stdout, stderr, code = run_hook(adapter, payload, engine,
                                        enforcement="monitor" if args.monitor else "blocking",
                                        reviews=queue, review_mode=args.reviews)
    except Exception as exc:  # fail closed (or loudly open), never crash the agent
        stdout, stderr, code = adapter.render_error(
            call, "{}: {}".format(type(exc).__name__, exc)[:300], fail_open=fail_open)
    if stdout:
        sys.stdout.write(stdout + "\n")
    if stderr:
        sys.stderr.write(stderr)
    sys.stdout.flush()
    return code


def _install_flow_state(path: str) -> None:
    """Give the process flow tracker a durable memory of poisoned fragments.

    The tracker's own memory dies with the process, and a hook host starts one
    per tool call - so the one label the next call cannot recompute, taint from
    an injected result, is written here by digest and read back by the next
    invocation. Only the taint label is persisted: every other origin is
    recomputed from the call itself.
    """
    from ..flow import FlowTracker, set_tracker
    from ..flow_ledger import durable
    set_tracker(FlowTracker(taint=durable(path)))


def _engine(args, cwd, artifact_engine=None):
    if artifact_engine is not None:
        sidecar = getattr(args, "sidecar", None)
        if not sidecar:
            return artifact_engine
        # Artifact + sidecar: the artifact is the local primary for every
        # class, and high-risk classes are additionally asked of the daemon
        # under the artifact's failure policy. The kill check stays outermost
        # inside TieredEvaluator, before any socket call.
        from ..policy.tiers import DEFAULT_DEADLINE, TieredEvaluator, TierEngine
        from ..sidecar.client import RemoteEngine

        # Pin the daemon to the artifact this hook is running. A second tier
        # that decides under a different artifact is not a second opinion on
        # this policy: a daemon reporting another sha (or none) is refused, so
        # the class falls to its failure policy rather than to an unknown rule
        # set. The deadline is passed as the daemon's own socket timeout too,
        # so a hung daemon does not depend on the join to bound the call.
        secondary = RemoteEngine(
            sidecar,
            timeout=DEFAULT_DEADLINE,
            artifact_sha256=getattr(artifact_engine, "sha256", None) or None,
            artifact_epoch=getattr(artifact_engine, "epoch", None) or None,
        )
        return TierEngine(TieredEvaluator(artifact_engine, secondary=secondary))
    from ..adapters.config import load_engine
    return load_engine(policy=args.policy, rules=args.rules, sidecar=args.sidecar,
                       cwd=cwd, overlay=not args.no_overlay)


def _patch_gate(engine, args):
    """Wrap the engine when the patch gate is on; otherwise hand it back.

    Wrapping here rather than inside a policy rule keeps the gate where it
    belongs: the adapter layer, judging a *diff*, not a call. The verdict still
    flows through the normal path, so receipts, monitor mode, the review queue
    and the sidecar tier all see it unchanged.
    """
    mode = getattr(args, "patch_gate", None) or os.environ.get(
        "INTERLOCK_PATCH_GATE", "off").strip().lower()
    if mode in ("", "off", "0", "false", "no"):
        return engine
    if mode not in ("block", "monitor"):
        raise ValueError(
            "INTERLOCK_PATCH_GATE must be off, block or monitor (got {!r})".format(mode))
    from ..patch_gate import PatchGateEvaluator
    # The simple tier takes the defaults (a key and a directory under $HOME);
    # the shared tier points both at storage the agent cannot write. Same
    # evaluator either way, and a path that is missing is a missing record -
    # which blocks, it never falls through to the cheap default.
    return PatchGateEvaluator(
        engine,
        gates_dir=getattr(args, "patch_gates_dir", None)
        or os.environ.get("INTERLOCK_PATCH_GATES_DIR") or None,
        key_path=getattr(args, "patch_key", None)
        or os.environ.get("INTERLOCK_PATCH_KEY") or None,
        mode=mode,
    )


def _install_sink(args) -> None:
    from ..adapters.config import receipts_paths
    from ..receipt import set_sink
    from ..sink import FileSink

    if args.no_receipts:
        set_sink(None)
        return
    default_log, default_key = receipts_paths()
    log = args.receipts or default_log
    key_file = args.key_file or default_key
    if not os.path.exists(key_file):
        if args.receipts:
            raise ValueError("--receipts needs a --key-file that exists")
        set_sink(None)  # not installed yet: no key, no receipts
        return
    from ..sidecar.__main__ import _read_key
    set_sink(FileSink(log, key=_read_key(key_file), shared=True))

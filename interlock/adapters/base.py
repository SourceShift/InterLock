"""The shared core of the coding-agent hook adapters.

Every supported agent (Claude Code, Codex, Cursor) runs a command for each tool
call, passes the call as JSON on stdin, and reads a verdict back from stdout
and the exit code. Each adapter does three things:

1. **parse** the agent's payload into a :class:`HookCall`: the normalized tool
   name, its arguments (relative paths made absolute against the session's
   working directory, so a ``..`` cannot walk around a prefix rule), and the
   events the policy judges. A multi-file patch becomes one event per target
   file, so one protected file refuses the whole patch.
2. say what the agent can **express**: whether it can ask the human, apply a
   rewritten input, or replace a tool's output.
3. **render** the outcome in the agent's own protocol.

:func:`run_hook` sits between them. When a policy verdict is one the agent
cannot express, it is degraded *toward safety* - a rewrite that cannot be
applied, or an ask that cannot be shown, becomes a deny - and the receipt
records both: ``policy_verdict`` is what the policy said, ``verdict`` what was
enforced. An ESCALATE the agent *can* show goes to the agent's own approval
prompt - a human outside the agent's process decides - and is recorded with
``approval="delegated:<agent>"``; the PostToolUse receipt with the same
``call_id`` then shows whether the tool ran.

Hooks are cooperative, not a boundary: a call the agent makes outside its
hooked tools is not seen. Run the agent itself under a sandbox for
containment.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field, replace
from typing import Any, Callable, Dict, List, Optional, Tuple

from ..enforce import Decision, Verdict
from ..event import SensorEvent, result_payload, strip_trust_labels
from ..policy.engine import epoch_of
from ..receipt import emit_receipt

#: Argument names that hold file paths, normalized to absolute paths.
PATH_ARGS = ("file_path", "notebook_path", "path")

#: Longest hook payload read from stdin.
MAX_PAYLOAD = 16 * 1024 * 1024

#: ``(stdout, stderr, exit code)`` - what the hook process emits.
Rendered = Tuple[str, str, int]

PATCH_PREFIXES = ("*** Add File: ", "*** Delete File: ", "*** Update File: ", "*** Move to: ")


@dataclass
class HookCall:
    """One hook invocation, normalized."""

    agent: str
    kind: str  # pre | post | failure | lifecycle | ignore
    event_name: str
    tool_name: str = ""
    tool_input: Dict[str, Any] = field(default_factory=dict)
    events: List[SensorEvent] = field(default_factory=list)
    session_id: Optional[str] = None
    cwd: Optional[str] = None
    call_id: Optional[str] = None
    result: Any = None
    error: Optional[str] = None
    can_ask: bool = True
    can_rewrite: bool = False
    can_rewrite_result: bool = False
    can_block_result: bool = False
    native: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HookOutcome:
    """What the hook enforces, and why."""

    verdict: Verdict
    reason: str = ""
    policy_id: Optional[str] = None
    policy_verdict: Optional[Verdict] = None
    modified_args: Optional[Dict[str, Any]] = None
    modified_result: Any = None
    observed: bool = False

    @property
    def message(self) -> str:
        label = " [{}]".format(self.policy_id) if self.policy_id else ""
        return "interlock: {}{}".format(self.reason or "policy decision", label)


class Adapter:
    """Base class: one subclass per agent."""

    name = ""
    #: Human name for messages.
    title = ""

    def parse(self, payload: Dict[str, Any]) -> HookCall:
        raise NotImplementedError

    def render(self, call: HookCall, outcome: HookOutcome) -> Rendered:
        raise NotImplementedError

    def result_view(self, call: HookCall) -> Tuple[Dict[str, Any], Callable[[Any], Any]]:
        """The result as rules should judge it - what the agent's model will
        read - and how to turn a rewrite of that view back into the shape the
        agent expects. Default: the tool's response as returned, unchanged."""
        return result_payload(call.result), _same

    def render_lifecycle(self, call: HookCall, summary: str) -> Rendered:
        return "", "", 0

    def render_error(self, call: Optional[HookCall], message: str, *, fail_open: bool) -> Rendered:
        raise NotImplementedError

    # Installation --------------------------------------------------------
    def settings_path(self) -> str:
        raise NotImplementedError

    def install(self, command: str, settings: Optional[str] = None) -> Tuple[str, str]:
        """Write the hook entries; return (path, new file text)."""
        raise NotImplementedError

    def uninstall(self, settings: Optional[str] = None) -> Tuple[str, Optional[str]]:
        raise NotImplementedError

    def installed_command(self, settings: Optional[str] = None) -> Optional[str]:
        """The interlock hook command registered in the settings, if any."""
        raise NotImplementedError


# --- normalization --------------------------------------------------------------


def normalize_args(args: Dict[str, Any], cwd: Optional[str]) -> Dict[str, Any]:
    """Make path arguments absolute and normal; leave everything else alone."""
    out = dict(args)
    for key in PATH_ARGS:
        value = out.get(key)
        if isinstance(value, str) and value:
            out[key] = normalize_path(value, cwd)
    return out


def normalize_path(path: str, cwd: Optional[str]) -> str:
    """The path the tool will really open, for rules to judge.

    ``expanduser`` and a relative path joined to ``cwd`` are what the tool
    itself does; ``os.path.realpath`` then resolves every symlink in the
    existing prefix (leaving a not-yet-existing tail in place), so a symlinked
    path cannot hide a protected target. ``_disk_case`` respells the existing
    components as the volume does. The executed call is untouched - this is
    only the event view.
    """
    expanded = os.path.expanduser(path)
    if not os.path.isabs(expanded):
        expanded = os.path.join(cwd or os.getcwd(), expanded)
    return _disk_case(os.path.realpath(expanded))


def _disk_case(path: str) -> str:
    """``path`` with each existing component spelled as it is on disk.

    On a case-insensitive volume (macOS, Windows) ``~/.SSH/id_rsa`` opens
    ``~/.ssh/id_rsa``; a rule that names ``~/.ssh/`` must see that spelling.
    A component is respelled only when the volume itself resolves the
    variant to an existing entry; on a case-sensitive volume nothing changes.
    """
    parts = path.split(os.sep)
    out = parts[0] or os.sep
    for i, part in enumerate(parts[1:], start=1):
        if not part:
            continue
        candidate = os.path.join(out, part)
        if not os.path.lexists(candidate):
            return os.path.join(out, *parts[i:])  # the rest doesn't exist yet
        try:
            names = os.listdir(out)
        except OSError:
            return os.path.join(out, *parts[i:])
        if part not in names:
            folded = [n for n in names if n.lower() == part.lower()]
            if len(folded) == 1:
                part = folded[0]
        out = os.path.join(out, part)
    return out


def patch_targets(patch: str, cwd: Optional[str]) -> List[str]:
    """Files an ``apply_patch`` body touches, from its ``*** ... File:`` lines.

    A header may arrive indented (a payload wrapped in a code block, a leading
    space): the structural ``***`` marker is what identifies it, so leading
    whitespace is ignored outside a hunk. Inside a hunk a ``+``, ``-`` or
    leading space is content, and a ``***`` line that starts on a hunk marker
    is not read as a header unless it begins at column zero.
    """
    targets: List[str] = []
    in_hunk = False
    for line in patch.splitlines():
        if line.startswith("@@"):
            in_hunk = True
            continue
        if in_hunk and line[:1] in ("+", "-", " "):
            if not line.startswith(PATCH_PREFIXES):
                continue
        stripped = line.lstrip()
        for prefix in PATCH_PREFIXES:
            if stripped.startswith(prefix):
                target = stripped[len(prefix):].strip()
                if target:
                    path = normalize_path(target, cwd)
                    if path not in targets:
                        targets.append(path)
                in_hunk = False
                break
    return targets


def derive_call_id(tool_use_id: Any, session_id: Any, tool_name: str,
                   tool_input: Dict[str, Any]) -> str:
    """The agent's tool-use id, or a stable hash of session + tool + input so a
    call's pre and post hooks share an id even when the agent sends none."""
    if isinstance(tool_use_id, str) and tool_use_id:
        return tool_use_id
    canonical = json.dumps(tool_input, sort_keys=True, separators=(",", ":"), default=str)
    seed = "{}|{}|{}".format(session_id or "", tool_name, canonical)
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16]


def call_events(agent: str, tool_name: str, args: Dict[str, Any], *,
                session_id: Optional[str], call_id: str,
                cwd: Optional[str]) -> List[SensorEvent]:
    """The call-phase events for one tool call (one per patch target).

    ``args`` came from the agent's hook payload, i.e. from the model, so the
    reserved trust labels are stripped before any event is built. An adapter
    that knows a trust fact sets it on :attr:`SensorEvent.labels` instead.
    """
    args = strip_trust_labels(args)
    # Glob carries its path in ``pattern`` (its ``path`` is only a base
    # directory). Rules that compare a path prefix must see the resolved
    # search pattern, not the raw ``~``/relative spelling.
    if tool_name == "Glob" and isinstance(args.get("pattern"), str) and args["pattern"]:
        args = dict(args)
        # ``pattern`` is resolved against the search root (``path``), which is
        # itself optional and may be ``~``/relative. Resolving against ``cwd``
        # alone let ``{path: ~, pattern: .interlock/*}`` read the protected
        # directory while looking like a project-relative glob.
        root = args.get("path")
        root = normalize_path(root, cwd) if isinstance(root, str) and root else cwd
        args["pattern"] = normalize_path(args["pattern"], root)
    common = dict(principal=agent, span_id=session_id, call_id=call_id, cwd=cwd)
    if tool_name == "apply_patch" and isinstance(args.get("command"), str):
        targets = patch_targets(args["command"], cwd)
        if targets:
            return [SensorEvent(action=tool_name,
                                args={"command": args["command"], "file_path": t}, **common)
                    for t in targets]
    return [SensorEvent(action=tool_name, args=normalize_args(args, cwd), **common)]


def result_event(call: HookCall) -> SensorEvent:
    return SensorEvent(action=call.tool_name, args=strip_trust_labels(result_payload(call.result)),
                       principal=call.agent, span_id=call.session_id,
                       call_id=call.call_id, phase="result", cwd=call.cwd)


# --- the decision path ----------------------------------------------------------


def combine(decisions: List[Decision]) -> Decision:
    """One decision for several events of one call: the first BLOCK, else the
    first ESCALATE, else the only MODIFY, else ALLOW. Rewrites of several
    events (a multi-file patch) cannot be applied to one call, so they block."""
    for d in decisions:
        if d.verdict == Verdict.BLOCK or d.verdict not in tuple(Verdict):
            return d
    for d in decisions:
        if d.verdict == Verdict.ESCALATE:
            return d
    rewrites = [d for d in decisions if d.verdict == Verdict.MODIFY]
    if len(rewrites) == 1 and len(decisions) == 1:
        return rewrites[0]
    if rewrites:
        return Decision.block("a rewrite of one target cannot be applied to a multi-file "
                              "patch: " + rewrites[0].reason, rewrites[0].policy_id,
                              attributed_to=rewrites[0].attributed_to)
    return Decision.allow()


def _same(value: Any) -> Any:
    return value


def _policy_artifact(engine: Any) -> Optional[str]:
    """The artifact sha256 when ``engine`` is a manifest-delivered policy.

    A local engine (``PolicyEngine``/``ScopedEngine``) has no artifact bytes,
    so the receipt field stays absent and local-only chains are unchanged.
    """
    if getattr(engine, "artifact_bytes", None) is None:
        return None
    sha = getattr(engine, "sha256", None)
    return sha if isinstance(sha, str) and sha else None


def run_hook(adapter: Adapter, payload: Dict[str, Any], engine: Any, *,
             enforcement: str = "blocking", reviews: Any = None,
             review_mode: str = "fallback") -> Rendered:
    """Decide one hook invocation and render the agent's reply.

    ``reviews`` is a :class:`interlock.reviews.ReviewQueue`. With
    ``review_mode="fallback"`` (default) it settles escalations the agent
    can't ask about itself (Codex, Cursor file reads): the call is refused with
    a pending review id, and the identical retry runs once a human approves.
    ``"always"`` routes every escalation through the queue, ``"off"`` never.
    """
    call = adapter.parse(payload)
    if call.kind == "ignore":
        return adapter.render(call, HookOutcome(Verdict.ALLOW))
    if call.kind == "lifecycle":
        size = len(engine) if hasattr(engine, "__len__") else None
        epoch = epoch_of(engine)
        summary = "policy active{}{}".format(
            " ({} rules)".format(size) if size is not None else "",
            ", epoch {}".format(epoch) if epoch else "")
        return adapter.render_lifecycle(call, summary)
    if call.kind == "failure":
        _record_failure(call, engine)
        return _decide_failure(adapter, call, engine, enforcement)
    if call.kind == "post":
        return _decide_result(adapter, call, engine, enforcement)
    return _decide_call(adapter, call, engine, enforcement, reviews, review_mode)


def _decide_call(adapter: Adapter, call: HookCall, engine: Any, enforcement: str,
                 reviews: Any = None, review_mode: str = "fallback") -> Rendered:
    started = time.perf_counter()
    decisions = [engine.evaluate(event) for event in call.events]
    elapsed = int((time.perf_counter() - started) * 1_000_000)
    decision = combine(decisions)
    # The primary event is what the receipt digests and what an approver is
    # asked about, so it carries the arguments the call will run with - the
    # tool input plus any rewrite the decision carries.
    effective = dict(call.tool_input)
    if decision.modified_args:
        effective.update(decision.modified_args)
    # The receipt and any approver see the arguments as the call will run
    # them, but a reserved trust key still names no fact here.
    effective = strip_trust_labels(effective)
    primary = SensorEvent(action=call.tool_name, args=effective,
                          principal=call.agent, span_id=call.session_id,
                          call_id=call.call_id, cwd=call.cwd)
    epoch = epoch_of(engine, primary)
    artifact = _policy_artifact(engine)
    policy = decision.verdict if decision.verdict in tuple(Verdict) else Verdict.BLOCK

    if policy == Verdict.ALLOW:
        emit_receipt(primary, decision, policy_epoch=epoch, elapsed_us=elapsed,
                     policy_artifact=artifact)
        return adapter.render(call, HookOutcome(Verdict.ALLOW))
    if enforcement == "monitor":
        emit_receipt(primary, decision, observed=True, policy_epoch=epoch, elapsed_us=elapsed,
                     policy_artifact=artifact)
        return adapter.render(call, HookOutcome(Verdict.ALLOW, decision.reason,
                                                decision.policy_id, policy, observed=True))

    outcome = HookOutcome(policy, decision.reason, decision.policy_id, policy,
                          modified_args=decision.modified_args)
    approval = None
    use_queue = reviews is not None and (review_mode == "always" or (
        review_mode == "fallback" and not call.can_ask))
    if policy == Verdict.ESCALATE and use_queue:
        from ..approval import make_request
        from ..reviews import binding_hash, pending_message

        request = make_request(primary, decision, epoch, effective_args=effective)
        review = reviews.lookup_or_file(
            binding_hash(request, bind_epoch=bool(getattr(engine, "epoch_is_stable", False))),
            request)
        if review.status == "approved" and reviews.claim(review.id):
            # A remote approval is stamped with the grant that released it;
            # a local approval keeps today's review-note shape. The lookup is
            # best-effort: an older queue without cloud_grants still runs.
            grant_id = None
            try:
                getter = getattr(reviews, "grant_for", None)
                if callable(getter):
                    grant_id = getter(review.id)
            except Exception:
                grant_id = None
            note = ("cloud:" + grant_id) if grant_id \
                else "approved:review " + review.id
            if decision.modified_args:
                # The human saw and approved the rewritten call. Run that
                # rewrite - never the pre-rewrite arguments - or refuse.
                if not call.can_rewrite:
                    reason = (
                        "{} - the approval covers a rewritten call, and {}'s hooks cannot "
                        "apply a rewrite, so it is refused".format(decision.reason, adapter.title))
                    emit_receipt(primary, Decision(Verdict.BLOCK, reason, decision.policy_id,
                                                   attributed_to=decision.attributed_to),
                                 policy_epoch=epoch, elapsed_us=elapsed,
                                 policy_verdict="ESCALATE", approval=note,
                                 policy_artifact=artifact)
                    return adapter.render(call, HookOutcome(
                        Verdict.BLOCK, reason, decision.policy_id, Verdict.ESCALATE))
                emit_receipt(primary, Decision(Verdict.MODIFY, decision.reason,
                                               decision.policy_id, decision.modified_args,
                                               attributed_to=decision.attributed_to),
                             policy_epoch=epoch, elapsed_us=elapsed,
                             policy_verdict="ESCALATE", approval=note,
                             policy_artifact=artifact)
                return adapter.render(call, HookOutcome(
                    Verdict.MODIFY, decision.reason, decision.policy_id, Verdict.ESCALATE,
                    modified_args=decision.modified_args))
            emit_receipt(primary, Decision(Verdict.ALLOW, decision.reason, decision.policy_id,
                                           attributed_to=decision.attributed_to),
                         policy_epoch=epoch, elapsed_us=elapsed, policy_verdict="ESCALATE",
                         approval=note, policy_artifact=artifact)
            return adapter.render(call, HookOutcome(Verdict.ALLOW))
        outcome = replace(outcome, verdict=Verdict.BLOCK, reason="{} - {}".format(
            decision.reason, pending_message(review)))
        approval = ("pending:" if review.status == "pending" else "declined:") + review.id
    elif policy == Verdict.ESCALATE:
        if call.can_ask:
            approval = "delegated:" + adapter.name
        else:
            outcome = replace(outcome, verdict=Verdict.BLOCK, reason=(
                "{} - this needs a human decision, and {}'s hooks cannot ask for "
                "one here, so it is refused; run it yourself or adjust the policy".format(
                    decision.reason, adapter.title)))
    elif policy == Verdict.MODIFY:
        if not call.can_rewrite or not decision.modified_args:
            outcome = replace(outcome, verdict=Verdict.BLOCK, reason=(
                "{} - interlock would rewrite this call, and {}'s hooks cannot apply a "
                "rewrite, so it is refused".format(decision.reason, adapter.title)))
    elif policy != Verdict.BLOCK:
        outcome = replace(outcome, verdict=Verdict.BLOCK,
                          reason="unhandled verdict, denied fail-closed")
    enforced = Decision(outcome.verdict, outcome.reason, decision.policy_id,
                        decision.modified_args if outcome.verdict == Verdict.MODIFY else None,
                        attributed_to=decision.attributed_to)
    emit_receipt(primary, enforced, policy_epoch=epoch, elapsed_us=elapsed,
                 policy_verdict=policy.name if outcome.verdict != policy else None,
                 approval=approval, policy_artifact=artifact)
    return adapter.render(call, outcome)


def _decide_result(adapter: Adapter, call: HookCall, engine: Any, enforcement: str) -> Rendered:
    view, rebuild = adapter.result_view(call)
    # A result payload is model-influenced: the server's text can carry a
    # reserved key, which is data, never a trust fact.
    view = strip_trust_labels(view)
    event = SensorEvent(action=call.tool_name, args=view, principal=call.agent,
                        span_id=call.session_id, call_id=call.call_id, phase="result",
                        cwd=call.cwd)
    started = time.perf_counter()
    decision = engine.evaluate(event)
    elapsed = int((time.perf_counter() - started) * 1_000_000)
    epoch = epoch_of(engine, event)
    artifact = _policy_artifact(engine)
    policy = decision.verdict if decision.verdict in tuple(Verdict) else Verdict.BLOCK
    if policy == Verdict.ALLOW:
        emit_receipt(event, decision, policy_epoch=epoch, elapsed_us=elapsed,
                     policy_artifact=artifact)
        return adapter.render(call, HookOutcome(Verdict.ALLOW))
    able = {Verdict.BLOCK: call.can_block_result, Verdict.ESCALATE: call.can_block_result,
            Verdict.MODIFY: call.can_rewrite_result}.get(policy, call.can_block_result)
    if enforcement == "monitor" or not able:
        # The output already reached (or will reach) the agent: say what policy
        # wanted, and record that it was observed, not enforced.
        emit_receipt(event, decision, observed=True, policy_epoch=epoch, elapsed_us=elapsed,
                     policy_artifact=artifact)
        return adapter.render(call, HookOutcome(Verdict.ALLOW, decision.reason,
                                                decision.policy_id, policy, observed=True))
    verdict = Verdict.BLOCK if policy == Verdict.ESCALATE else policy
    outcome = HookOutcome(verdict, decision.reason, decision.policy_id, policy,
                          modified_result=rebuild(decision.modified_result)
                          if verdict == Verdict.MODIFY else decision.modified_result)
    emit_receipt(event, replace(decision, verdict=verdict), policy_epoch=epoch,
                 elapsed_us=elapsed,
                 policy_verdict=policy.name if verdict != policy else None,
                 policy_artifact=artifact)
    return adapter.render(call, outcome)


_DENIED_SIGNS = ("operation not permitted", "permission denied", "eperm", "eacces")


def _decide_failure(adapter: Adapter, call: HookCall, engine: Any,
                    enforcement: str) -> Rendered:
    """Judge a failed call's error text as model-visible output.

    A tool failure is shown to the agent as text, so it is the same indirect
    injection channel as a successful result. The outcome receipt is already
    written; this only withholds that text when a result-phase rule blocks it.
    """
    if not call.error:
        return "", "", 0
    event = SensorEvent(action=call.tool_name,
                        args={"error": call.error},
                        principal=call.agent, span_id=call.session_id,
                        call_id=call.call_id, phase="result", cwd=call.cwd)
    started = time.perf_counter()
    decision = engine.evaluate(event)
    elapsed = int((time.perf_counter() - started) * 1_000_000)
    epoch = epoch_of(engine, event)
    artifact = _policy_artifact(engine)
    policy = decision.verdict if decision.verdict in tuple(Verdict) else Verdict.BLOCK
    able = {Verdict.BLOCK: call.can_block_result,
            Verdict.ESCALATE: call.can_block_result,
            Verdict.MODIFY: call.can_rewrite_result}.get(policy, call.can_block_result)
    if policy == Verdict.ALLOW or enforcement == "monitor" or not able:
        if policy != Verdict.ALLOW:
            emit_receipt(event, decision, observed=True, policy_epoch=epoch,
                         elapsed_us=elapsed, policy_artifact=artifact)
        return "", "", 0
    verdict = Verdict.BLOCK if policy == Verdict.ESCALATE else policy
    emit_receipt(event, replace(decision, verdict=verdict), policy_epoch=epoch,
                 elapsed_us=elapsed,
                 policy_verdict=policy.name if verdict != policy else None,
                 policy_artifact=artifact)
    # ``_render_post`` is the result-withholding shape; the call is presented
    # as a post event so the adapter renders the withhold it already knows. A
    # MODIFY here rewrites the error the model would read: the rule saw
    # ``{"error": text}``, so the replacement is that text, not the wrapper
    # dict (which the adapter would otherwise render as its repr).
    replacement = decision.modified_result
    if isinstance(replacement, dict):
        text = replacement.get("error")
        replacement = text if isinstance(text, str) else replacement
    return adapter.render(replace(call, kind="post"),
                          HookOutcome(verdict, decision.reason, decision.policy_id,
                                      policy, modified_result=replacement))


def _record_failure(call: HookCall, engine: Any) -> None:
    text = (call.error or "").lower()
    enforcer = "os" if any(sign in text for sign in _DENIED_SIGNS) else "tool"
    event = SensorEvent(action=call.tool_name, args=strip_trust_labels(call.tool_input),
                        principal=call.agent, span_id=call.session_id, call_id=call.call_id)
    emit_receipt(event, Decision(Verdict.ALLOW, "tool failed"), policy_epoch=epoch_of(engine, event),
                 outcome="failed", enforcer=enforcer, phase="outcome",
                 policy_artifact=_policy_artifact(engine))


# --- settings files -------------------------------------------------------------


def read_json(path: str) -> Dict[str, Any]:
    """A settings file as a dict; a missing file is empty, a malformed one raises."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError:
        return {}
    if not text.strip():
        return {}
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("{} is not a JSON object".format(path))
    return data


def write_json(path: str, data: Dict[str, Any]) -> str:
    """Write a settings file atomically, keeping its mode; return the text."""
    import tempfile

    text = json.dumps(data, indent=2) + "\n"
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    mode = None
    try:
        mode = os.stat(path).st_mode & 0o777
    except OSError:
        pass
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".interlock-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return text


#: Substring that marks a hook command as interlock's own.
COMMAND_MARKER = "interlock hook --agent"


def is_ours(command: Any) -> bool:
    return isinstance(command, str) and COMMAND_MARKER in command


def merge_command_hooks(hooks: Dict[str, Any], events: Dict[str, Optional[str]],
                        command: str, timeout: Optional[int] = None,
                        with_type: bool = True) -> Dict[str, Any]:
    """Add (or replace) interlock's entry under each event, keeping others.

    ``events`` maps an event name to its matcher (None: no matcher key).
    """
    out = dict(hooks)
    for event, matcher in events.items():
        entries = [e for e in out.get(event, []) if isinstance(e, dict)]
        kept = []
        for entry in entries:
            inner = [h for h in entry.get("hooks", []) if not (isinstance(h, dict) and is_ours(h.get("command")))]
            if is_ours(entry.get("command")):
                continue
            if "hooks" in entry and not inner:
                continue
            if "hooks" in entry:
                entry = dict(entry, hooks=inner)
            kept.append(entry)
        hook: Dict[str, Any] = {"command": command}
        if with_type:
            hook = {"type": "command", "command": command}
        if timeout is not None:
            hook["timeout"] = timeout
        entry: Dict[str, Any] = {"hooks": [hook]}
        if matcher is not None:
            entry = {"matcher": matcher, "hooks": [hook]}
        kept.append(entry)
        out[event] = kept
    return out


def remove_command_hooks(hooks: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            out[event] = entries
            continue
        kept = []
        for entry in entries:
            if not isinstance(entry, dict):
                kept.append(entry)
                continue
            if is_ours(entry.get("command")):
                continue
            if "hooks" in entry:
                inner = [h for h in entry["hooks"] if not (isinstance(h, dict) and is_ours(h.get("command")))]
                if not inner:
                    continue
                entry = dict(entry, hooks=inner)
            kept.append(entry)
        if kept:
            out[event] = kept
    return out


def find_command(hooks: Any) -> Optional[str]:
    if not isinstance(hooks, dict):
        return None
    for entries in hooks.values():
        for entry in entries if isinstance(entries, list) else []:
            if not isinstance(entry, dict):
                continue
            if is_ours(entry.get("command")):
                return entry["command"]
            for hook in entry.get("hooks", []) if isinstance(entry.get("hooks"), list) else []:
                if isinstance(hook, dict) and is_ours(hook.get("command")):
                    return hook["command"]
    return None

"""The two-tier evaluator (C6): local primary, out-of-process high-risk tier.

The verdict path is local by default. Every event is classified into an
action class; the irreversible classes are also sent to the out-of-process
sidecar with a short deadline, and the artifact's per-class failure policy
decides what happens when that second opinion cannot be had.

The design rules, all fail-closed:

* **One local engine is still the source of truth.** The primary decides every
  event the sidecar is not asked about, and decides again (never a synthetic
  allow) when a class policy is ``open``.
* **The deadline applies to delegated classes only.** The primary is local and
  fast; time-boxing it would turn a slow local rule into a policy change.
* **A missed deadline or an unreachable secondary follows the class policy.**
  ``closed`` blocks with ``policy_id="fail_closed"``; ``open`` falls back to
  the primary and records a ``coverage_gap``. An unknown class is
  ``irreversible`` and therefore closed.
* **The kill switch is checked before classification and before any socket.**
  A killed policy must not consult the secondary, and its decision must be the
  one on the receipt.
* **Coverage gaps are counted and warned once per class per process.** A hook
  runs per tool call; logging every occurrence would bury the agent's output.

The tier result carries the class, which tier answered, and whether the answer
was a coverage gap, so a caller can stamp a receipt without re-classifying.
``TierEngine`` adapts the result back to the ``evaluate(event) -> Decision``
shape the hook runner expects, delegating artifact identity attributes to the
primary so receipts keep naming the artifact that decided.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, replace
from typing import Any, Dict, Iterable, Mapping, Optional

from ..enforce import Decision, Verdict
from ..actions import canonical_action
from .artifact import FAILURE_POLICY_DEFAULTS

_log = logging.getLogger("interlock")

#: Every action class a failure policy must cover. ``irreversible`` is derived
#: here rather than stored in the artifact: C5's signed format carries the
#: other eight, and adding a ninth key would change every artifact's epoch.
CLASSES = (
    "read_only",
    "local",
    "granted_llm",
    "shell",
    "egress",
    "delete",
    "email",
    "payment",
    "irreversible",
)

#: Classes whose decision is additionally asked of the out-of-process tier.
#: Everything else is decided locally, with no socket and no deadline.
DELEGATED = frozenset({"shell", "egress", "delete", "email", "payment"})

#: Default per-class deadline for the out-of-process tier, in seconds. Small
#: enough that delegation can never dominate the verdict path; a daemon that
#: cannot answer in two milliseconds is treated as unavailable.
DEFAULT_DEADLINE = 0.002

FAILURE_POLICY_VALUES = ("open", "closed")

#: Canonical action spelling -> class. ``canonical_action`` folds case and the
#: ``.``/``/``/``:`` separators, so one entry covers every adapter's spelling
#: (``WebFetch`` and ``http.fetch`` both land on ``webfetch``/``http_fetch``).
#: An action absent from every set is ``irreversible``: silence is not a
#: permission, and a class we cannot name is one we cannot fail open for.
DEFAULT_CLASSES: Dict[str, frozenset] = {
    "read_only": frozenset({
        "read_file", "fs_read_file", "fs_readlink", "fs_readdir", "fs_access",
        "fs_open", "fs_create_read_stream", "fs_stat", "list_dir", "list_files",
        "glob", "grep", "search_files", "read", "view", "cat", "head", "tail",
        "ls", "stat", "read_text_file",
    }),
    "local": frozenset({
        "write_file", "fs_write_file", "fs_append_file", "fs_copy_file",
        "fs_cp", "fs_mkdir", "fs_rename", "fs_chmod", "fs_chown", "fs_link",
        "fs_symlink", "fs_truncate", "fs_utimes", "edit_file", "notebook_edit",
        "write_text_file", "apply_patch", "local_tool",
        # The coding-agent vocabulary: Claude's Edit/Write/MultiEdit and
        # Codex's write/edit tools all mutate a local file, and TodoWrite only
        # writes the agent's own task list.
        "edit", "write", "multi_edit", "todo_write",
    }),
    "granted_llm": frozenset({
        "llm_call", "model_call", "completion", "chat_completion", "inference",
        "anthropic_messages", "openai_chat",
        # LLM-mediated, granted tools: a search and a sub-agent both act under
        # the operator's grant rather than being a raw shell/egress primitive.
        "web_search", "task",
    }),
    "shell": frozenset({
        "bash", "run_shell", "shell", "sh", "exec", "spawn", "terminal",
        "child_process_exec", "child_process_exec_file", "child_process_spawn",
        "execute_shell", "run_command",
    }),
    "egress": frozenset({
        "http_post", "http_get", "http_fetch", "http_request", "net_fetch",
        "fetch", "webfetch", "web_fetch", "httpserver", "download", "upload",
        "request", "browser_fetch", "curl",
    }),
    "delete": frozenset({
        "delete_file", "remove_file", "fs_rm", "fs_unlink", "fs_rmdir",
        "unlink", "rm", "rmdir", "delete",
    }),
    "email": frozenset({
        "send_email", "email_send", "send_mail", "gmail_send", "mail", "smtp_send",
    }),
    "payment": frozenset({
        "payment", "charge", "purchase", "pay", "transfer", "refund",
        "create_payment", "stripe_charge",
    }),
}


def _canonical_classes(classes: Optional[Mapping[str, Iterable[str]]]) -> Dict[str, frozenset]:
    if classes is None:
        return {name: frozenset(names) for name, names in DEFAULT_CLASSES.items()}
    if not isinstance(classes, Mapping):
        raise ValueError("action_classes must be a map of class -> action names")
    result: Dict[str, frozenset] = {}
    for name, names in classes.items():
        if name not in CLASSES:
            raise ValueError("unknown action class {!r}".format(name))
        try:
            items = (names,) if isinstance(names, str) else iter(names)
        except TypeError:
            raise ValueError(
                "action class {!r} must be an iterable of action names".format(name)
            ) from None
        result[name] = frozenset(
            value for value in (canonical_action(item) for item in items) if value
        )
    return result


def action_class(action: Any, action_classes: Optional[Mapping[str, Iterable[str]]] = None) -> str:
    """The class of one action name; unknown names are ``irreversible``."""
    canonical = canonical_action(action)
    classes = _canonical_classes(action_classes) if action_classes is not None else DEFAULT_CLASSES
    for name in CLASSES:
        if name == "irreversible":
            continue
        if canonical in classes.get(name, ()):
            return name
    return "irreversible"


def _default_failure_policy(primary: Any) -> dict:
    """The artifact's eight classes plus a synthesized closed ``irreversible``.

    A C5 artifact cannot carry ``irreversible`` (it would change the signed
    format and every epoch), so the tier derives it: an unknown action is the
    one case where failing open would be an unmeasured permission.
    """
    source = getattr(primary, "failure_policy", None)
    normal = dict(FAILURE_POLICY_DEFAULTS)
    if isinstance(source, Mapping):
        for key in FAILURE_POLICY_DEFAULTS:
            value = source.get(key)
            if value in FAILURE_POLICY_VALUES:
                normal[key] = value
    normal["irreversible"] = "closed"
    return normal


def validate_failure_policy(policy: Any) -> dict:
    """Return a complete failure policy or raise ``ValueError``.

    Every class, including ``irreversible``, must be present: a caller that
    hands us a partial map has not decided what an unknown action does, and
    defaulting it would be a silent safety decision.
    """
    if not isinstance(policy, Mapping):
        raise ValueError("failure_policy must be a mapping")
    unknown = sorted(str(key) for key in policy if key not in CLASSES)
    if unknown:
        raise ValueError("unknown failure-policy class: {}".format(unknown[0]))
    missing = [key for key in CLASSES if key not in policy]
    if missing:
        raise ValueError("missing failure-policy class: {}".format(missing[0]))
    normal = {}
    for key in CLASSES:
        value = policy[key]
        if value not in FAILURE_POLICY_VALUES:
            raise ValueError(
                "failure policy for {} must be one of {}".format(
                    key, ", ".join(FAILURE_POLICY_VALUES)
                )
            )
        normal[key] = value
    return normal


@dataclass(frozen=True)
class TierResult:
    """One tiered decision and how it was reached."""

    decision: Decision
    class_: str
    tier: str
    coverage_gap: bool = False


#: Classes warned about already, process-local. The hook is short-lived, so a
#: module-level set is enough to keep one warning per class per process.
_WARNED_CLASSES: set = set()


def reset_warning_state() -> None:
    """Forget which coverage-gap warnings were emitted (tests, long processes)."""
    _WARNED_CLASSES.clear()


class TieredEvaluator:
    """Classify each event and optionally ask a second, out-of-process engine.

    ``primary`` is the local engine (a ``CompiledPolicy`` or a wrapper that
    still exposes ``evaluate``). ``secondary`` is duck-typed; when it has
    ``supports_timeout = True`` its ``evaluate`` receives ``timeout=deadline``.
    The call runs on a worker thread that is joined with the deadline, so a
    secondary that ignores the timeout keyword cannot make the verdict path
    unbounded - the call is abandoned and the class policy applies.

    ``failure_policy`` defaults to the primary's artifact policy (plus a closed
    ``irreversible``). Passing one explicitly requires every class. A delegated
    class with no secondary is a secondary failure, not a silent allow: its
    class policy (closed by default) decides.
    """

    def __init__(
        self,
        primary: Any,
        *,
        secondary: Any = None,
        action_classes: Optional[Mapping[str, Iterable[str]]] = None,
        deadline: float = DEFAULT_DEADLINE,
        failure_policy: Optional[Mapping[str, str]] = None,
        clock: Any = time.monotonic,
    ) -> None:
        self.primary = primary
        self.secondary = secondary
        self.classes = _canonical_classes(action_classes)
        self.deadline = float(deadline)
        self.clock = clock
        self.failure_policy = (
            validate_failure_policy(failure_policy)
            if failure_policy is not None
            else _default_failure_policy(primary)
        )
        self.coverage_gaps: Dict[str, int] = {}
        self.last: Optional[TierResult] = None

    def __getattr__(self, name: str) -> Any:
        # Only reached for attributes this object does not define. Artifact
        # identity (``artifact_bytes``, ``sha256``, ``epoch``, ``epoch_for``)
        # must survive the wrapper so receipts keep naming the artifact.
        if name in ("primary", "secondary"):
            raise AttributeError(name)
        return getattr(self.primary, name)

    def classify(self, event: Any) -> str:
        return action_class(getattr(event, "action", ""), self.classes)

    def evaluate(self, event: Any) -> TierResult:
        class_ = self.classify(event)
        result = self._evaluate(event, class_)
        self.last = result
        return result

    def _evaluate(self, event: Any, class_: str) -> TierResult:
        # Kill is outermost: a killed policy must not reach classification's
        # consequences (a socket call) and must not be decided by the secondary.
        if isinstance(getattr(self.primary, "kill", None), Mapping):
            decision = self.primary.evaluate(event)
            return TierResult(decision, class_, "kill_switch", False)

        if class_ not in DELEGATED:
            return TierResult(self.primary.evaluate(event), class_, "primary", False)
        if self.secondary is None:
            # A delegated class with no second opinion is exactly the case the
            # failure policy exists for. Failing open here would turn "no
            # daemon configured" into permission for shell/egress/delete.
            return self._unavailable(
                event, class_, RuntimeError("no secondary evaluator"))

        started = self.clock()
        decision, error = self._call_with_deadline(event)
        elapsed = self.clock() - started
        if error is not None:
            return self._unavailable(event, class_, error)
        if elapsed > self.deadline:
            return self._unavailable(
                event, class_, TimeoutError(
                    "secondary took {:.3f} ms, deadline {:.3f} ms".format(
                        elapsed * 1000.0, self.deadline * 1000.0
                    )
                ),
            )
        return TierResult(decision, class_, "secondary", False)

    def _call_with_deadline(self, event: Any) -> tuple:
        """``(decision, error)``; a call still running at the deadline is lost.

        A socket client's own timeout is the first line of defence, but a
        secondary is duck-typed and may ignore the keyword. Joining a worker
        thread with the deadline bounds the verdict path regardless, so a hung
        daemon cannot stretch the call.
        """
        box: Dict[str, Any] = {}

        def work() -> None:
            try:
                box["decision"] = self._call_secondary(event)
            except BaseException as exc:  # noqa: BLE001 - reported, never raised
                box["error"] = exc

        worker = threading.Thread(
            target=work, name="interlock-secondary", daemon=True)
        worker.start()
        # An injected clock means elapsed time is simulated: the fake worker
        # returns immediately and the clock check decides. With the live clock
        # the join itself is the hard bound.
        grace = 0.0 if self.clock is time.monotonic else 1.0
        worker.join(self.deadline + grace)
        if worker.is_alive():
            return None, TimeoutError(
                "secondary did not return within {:.3f} ms".format(
                    self.deadline * 1000.0))
        if "error" in box:
            return None, box["error"]
        decision = box.get("decision")
        if not isinstance(decision, Decision):
            return None, ValueError(
                "secondary returned {!r}, not a Decision".format(decision))
        return decision, None

    def _call_secondary(self, event: Any) -> Decision:
        if getattr(self.secondary, "supports_timeout", False):
            return self.secondary.evaluate(event, timeout=self.deadline)
        return self.secondary.evaluate(event)

    def _unavailable(self, event: Any, class_: str, exc: BaseException) -> TierResult:
        policy = self.failure_policy.get(class_, "closed")
        if policy == "open":
            decision = self.primary.evaluate(event)
            decision = self._note_gap(class_, decision, str(exc))
            return TierResult(decision, class_, "primary", True)
        _log.warning(
            "interlock: %s evaluation failed closed (%s: %s); policy_id=fail_closed",
            class_, type(exc).__name__, exc,
        )
        decision = Decision.block("sidecar_unavailable", policy_id="fail_closed")
        return TierResult(decision, class_, "fail_closed", False)

    def _note_gap(self, class_: str, decision: Decision, why: str) -> Decision:
        self.coverage_gaps[class_] = self.coverage_gaps.get(class_, 0) + 1
        if class_ not in _WARNED_CLASSES:
            _WARNED_CLASSES.add(class_)
            _log.warning(
                "interlock: coverage_gap: %s is not covered by a secondary "
                "evaluator (%s); the primary decided this call", class_, why,
            )
        if decision.verdict is Verdict.ALLOW:
            return replace(
                decision,
                policy_id=decision.policy_id or "coverage_gap",
                reason=decision.reason or "coverage_gap: {}".format(class_),
            )
        return decision


class TierEngine:
    """``evaluate(event) -> Decision`` for the hook, keeping the tier metadata.

    ``run_hook`` was written against an engine, not a tier result. This adapter
    returns the decision and exposes the last ``TierResult`` on ``last``;
    attribute access delegates to the evaluator (and through it to the
    primary), so the receipt's artifact sha256/epoch are unchanged.
    """

    def __init__(self, evaluator: TieredEvaluator) -> None:
        self.evaluator = evaluator
        self.last: Optional[TierResult] = None

    def evaluate(self, event: Any) -> Decision:
        result = self.evaluator.evaluate(event)
        self.last = result
        return result.decision

    def __getattr__(self, name: str) -> Any:
        if name in ("evaluator", "last"):
            raise AttributeError(name)
        return getattr(self.evaluator, name)


__all__ = [
    "CLASSES",
    "DEFAULT_CLASSES",
    "DELEGATED",
    "FAILURE_POLICY_VALUES",
    "TierEngine",
    "TierResult",
    "TieredEvaluator",
    "action_class",
    "reset_warning_state",
    "validate_failure_policy",
]

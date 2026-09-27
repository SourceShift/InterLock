"""The language-neutral conformance corpus.

What the corpus is, exactly: one fixed rule set (``fixtures.CONFORMANCE_ENGINE``),
a list of events, and the decision each event must produce. It is *not* a second
policy implementation - the Node.js side never evaluates anything. Its use is to
let a client written in another language be checked against these facts: encode
these events, honour these verdicts, refuse these negatives. "Same policy, same
decision" becomes executable instead of asserted.

The corpus is stored as JSON so it can be read by a runtime that is not Python,
and it is generated from this module so that the Python side and the file cannot
drift apart. A test asserts ``load_corpus(path) == build()``.

Expectations name the verdict rather than its integer, because a file a human
reads should say ``BLOCK``; the encoding the wire actually uses (0/1/2) is
checked in ``tests/test_wire.py``.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from .fixtures import CONFORMANCE_SPEC

CORPUS_VERSION = 1


def _event(
    action: str,
    args: Dict[str, Any],
    *,
    phase: str = "call",
    principal: Any = None,
    parent_principal: Any = None,
) -> Dict[str, Any]:
    event: Dict[str, Any] = {"action": action, "args": args, "phase": phase}
    if principal is not None:
        event["principal"] = principal
    if parent_principal is not None:
        event["parent_principal"] = parent_principal
    return event


def _expect(
    verdict: str,
    *,
    reason: str = "",
    policy_id: Any = None,
    attributed_to: Any = None,
    modified_args: Any = None,
    modified_result: Any = None,
    error: Any = None,
    note: str = "",
) -> Dict[str, Any]:
    if error is not None:
        return {"error": error, "note": note}
    return {
        "verdict": verdict,
        "reason": reason,
        "policy_id": policy_id,
        "attributed_to": attributed_to,
        "modified_args": modified_args,
        "modified_result": modified_result,
        "note": note,
    }


# A byte string is not JSON, so an expectation that carries one carries its hex
# and the reader turns it back into bytes. Everything else is plain JSON.
def _bytes_expectation(payload: bytes) -> Dict[str, str]:
    return {"kind": "bytes", "hex": payload.hex()}


def cases() -> List[Dict[str, Any]]:
    """Every event the daemon must answer, with the decision it must give."""
    return [
        {
            "name": "allow-with-no-opinion",
            "note": "No rule speaks for this action, so the engine's default holds.",
            "event": _event("ping", {}),
            "expect": _expect("ALLOW"),
        },
        {
            "name": "block-names-the-triggering-argument",
            "note": (
                "attributed_to is the argument NAME ('path'). The value "
                "(/etc/passwd) must not appear in any field of the decision, "
                "which is why this case also asserts the absence of the value."
            ),
            "event": _event("read_file", {"path": "/etc/passwd"}),
            "expect": _expect(
                "BLOCK",
                reason="etc is off limits",
                policy_id="p.no-etc",
                attributed_to="path",
            ),
        },
        {
            "name": "block-with-no-attribution",
            "note": "deny_tool denies a whole action; there is no argument to name.",
            "event": _event("rm_rf", {}),
            "expect": _expect("BLOCK", reason="tool not permitted"),
        },
        {
            "name": "modify-rewrites-the-request",
            "note": "modified_args rewrites the outgoing call.",
            "event": _event("write_file", {"path": "/etc/hosts"}),
            "expect": _expect(
                "MODIFY",
                reason="path quarantined",
                policy_id="p.quarantine",
                attributed_to="path",
                modified_args={"path": "/tmp/quarantine"},
            ),
        },
        {
            "name": "modify-replaces-a-non-dict-result",
            "note": (
                "A non-dict result rides the event under the 'result' key "
                "(interceptors.mcp wraps it that way), so the rule can name "
                "'result' as what it reacted to."
            ),
            "event": _event(
                "fetch_url", {"result": "token secret"}, phase="result"
            ),
            "expect": _expect(
                "MODIFY",
                reason="secret in result",
                policy_id="p.result-redact",
                attributed_to="result",
                modified_result="redacted",
            ),
        },
        {
            "name": "modify-replaces-a-dict-result",
            "note": (
                "A dict result is carried as itself, not wrapped - the two "
                "shapes must not be conflated across the wire."
            ),
            "event": _event(
                "read_dict", {"title": "a", "secret": "s"}, phase="result"
            ),
            "expect": _expect(
                "MODIFY",
                reason="secret stripped",
                policy_id="p.result-strip",
                attributed_to="secret",
                modified_result={"title": "a"},
            ),
        },
        {
            "name": "bytes-survive-the-round-trip",
            "note": (
                "JSON has no bytes. A binary result replaced by a rule must "
                "arrive as the same bytes, not as a string or a lossy repr."
            ),
            "event": _event("read_binary", {"result": "ignored"}, phase="result"),
            "expect": _expect(
                "MODIFY",
                reason="binary replaced",
                policy_id="p.result-binary",
                modified_result=_bytes_expectation(b"\x00\x01\xff"),
            ),
        },
        {
            "name": "a-set-is-normalised-to-a-sorted-list",
            "note": (
                "JSON has no set either, and unlike bytes a set is represented "
                "rather than escaped: sorted, so the same set always serialises "
                "the same way."
            ),
            "event": _event("read_set", {"result": "ignored"}, phase="result"),
            "expect": _expect(
                "MODIFY",
                reason="set normalised",
                policy_id="p.result-set",
                modified_result=[1, 2, 3],
            ),
        },
        {
            "name": "a-null-replacement-means-no-replacement",
            "note": (
                "A rule returning modified_result=None has asked for no "
                "replacement, which is how the in-process path reads it too "
                "(interceptors.mcp applies a MODIFY result only when it is not "
                "None). The wire invents no semantics Python lacks."
            ),
            "event": _event("read_null", {"result": "ignored"}, phase="result"),
            "expect": _expect(
                "MODIFY",
                reason="no replacement",
                policy_id="p.result-null",
                modified_result=None,
            ),
        },
        {
            "name": "an-untransmittable-rewrite-is-refused",
            "note": (
                "A rule rewrote the result to a value with no JSON form. The "
                "daemon cannot say what it decided, so it says so: an error "
                "frame, which the client must treat as a block. Silently "
                "dropping the rewrite would return the unredacted payload."
            ),
            "event": _event("read_opaque", {"result": "ignored"}, phase="result"),
            "expect": _expect("BLOCK", error="unrepresentable"),
        },
        {
            "name": "call-side-rules-do-not-judge-results",
            "note": (
                "The same action name at phase='result' must not trip the "
                "call-side rules that deny read_file. Two rules on one action "
                "name make the phase partition observable from outside."
            ),
            "event": _event("read_file", {"path": "/tmp/notes"}, phase="result"),
            "expect": _expect("ALLOW"),
        },
        {
            "name": "principal-crosses-the-wire",
            "note": "A rule reads event.principal; a wire that drops it changes the verdict.",
            "event": _event("ping", {}, principal="untrusted-agent"),
            "expect": _expect(
                "BLOCK",
                reason="untrusted principal",
                policy_id="p.untrusted-principal",
            ),
        },
        {
            "name": "parent-principal-crosses-the-wire",
            "note": (
                "parent_principal is the delegation field - the one a "
                "spawned-principal rule consults and the one easiest to forget "
                "in a hand-written protocol."
            ),
            "event": _event("ping", {}, parent_principal="root-agent"),
            "expect": _expect(
                "BLOCK",
                reason="spawned by root-agent",
                policy_id="p.root-agent-parent",
            ),
        },
    ]


def _dumps(frame: Dict[str, Any]) -> str:
    return json.dumps(frame, sort_keys=True, separators=(",", ":"))


def negatives() -> List[Dict[str, Any]]:
    """Frames that must be refused, each with the error code they must produce.

    Every one of these is fail-closed at the client. The misspelled-key entries
    are the ones that matter most: a permissive parser would drop the arguments
    and let the engine find no opinion, turning a client typo into an allow.
    """
    return [
        {
            "name": "unknown-protocol-version",
            "note": "A version the daemon does not speak is refused, not guessed at.",
            "kind": "frame",
            "line": _dumps({"v": 2, "id": "n-version", "event": {"action": "ping", "args": {}}}),
            "error": "bad_version",
        },
        {
            "name": "misspelled-args-key-is-refused-not-ignored",
            "note": (
                "'arg' is not 'args'. Dropping it silently would show the engine "
                "an event with no arguments - and an engine with no opinion allows."
            ),
            "kind": "frame",
            "line": _dumps({"v": 1, "id": "n-typo", "event": {"action": "ping", "arg": {}}}),
            "error": "bad_request",
        },
        {
            "name": "missing-args-is-refused",
            "note": "Absent arguments are refused rather than defaulted to an empty object.",
            "kind": "frame",
            "line": _dumps({"v": 1, "id": "n-noargs", "event": {"action": "ping"}}),
            "error": "bad_request",
        },
        {
            "name": "args-must-be-an-object",
            "note": "A list where an object belongs is a client bug worth surfacing.",
            "kind": "frame",
            "line": _dumps({"v": 1, "id": "n-args-type", "event": {"action": "ping", "args": []}}),
            "error": "bad_request",
        },
        {
            "name": "phase-is-case-sensitive",
            "note": "'Result' is not 'result'; accepting it would silently run a result rule as call-side.",
            "kind": "frame",
            "line": _dumps(
                {"v": 1, "id": "n-phase", "event": {"action": "ping", "args": {}, "phase": "Result"}}
            ),
            "error": "bad_request",
        },
        {
            "name": "unknown-event-key-is-refused",
            "note": "An unrecognised key is a typo the far end cannot see; refusing makes it visible.",
            "kind": "frame",
            "line": _dumps(
                {"v": 1, "id": "n-extra", "event": {"action": "ping", "args": {}, "extra": 1}}
            ),
            "error": "bad_request",
        },
        {
            "name": "missing-id-is-refused",
            "note": "Without an id a response cannot be matched to its request.",
            "kind": "frame",
            "line": _dumps({"v": 1, "id": "", "event": {"action": "ping", "args": {}}}),
            "error": "bad_request",
        },
        {
            "name": "malformed-json-is-refused",
            "note": "Not JSON at all.",
            "kind": "frame",
            "line": '{"v":1,"id":"n-json","event":',
            "error": "bad_request",
        },
        {
            "name": "oversized-frame-is-refused",
            "note": (
                "The size check runs before parsing, so a frame over the limit "
                "is refused without being parsed. The reader cannot report "
                "unrepresentable types in the decisions it is asked about. "
                "The connection is then closed."
            ),
            "kind": "oversized",
            "error": "too_large",
        },
    ]


def build() -> Dict[str, Any]:
    """The whole corpus, ready to serialise."""
    return {
        "corpus_version": CORPUS_VERSION,
        "rules": CONFORMANCE_SPEC,
        "cases": cases(),
        "negatives": negatives(),
    }


def write_corpus(path: str) -> None:
    """Write the corpus, canonically, with a trailing newline."""
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(json.dumps(build(), indent=2, sort_keys=True))
        fh.write("\n")


def load_corpus(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def materialise_modified_result(value: Any) -> Any:
    """Turn a stored expectation back into the value a caller would receive.

    The only non-JSON shape an expectation can hold is bytes, which is stored as
    hex. A case that carries no replacement is ``None``.
    """
    if isinstance(value, dict) and value.get("kind") == "bytes":
        return bytes.fromhex(value["hex"])
    return value

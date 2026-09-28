"""One fixed rule set, covering every part of a decision a wire has to carry.

:data:`CONFORMANCE_ENGINE` exists so that "same policy, same decision" is
something a test can execute rather than something a docstring asserts. Every
rule below is here because it exercises one field or one phase rule of the
engine that could be dropped in transit without any verdict changing:

- a verdict with no detail at all (``deny_tool``)
- ``attributed_to`` - the *name* of the offending argument, never its value
- ``modified_args`` on the call side
- ``modified_result`` on the result side, in the awkward shapes: bytes, a set,
  ``None``, and something with no JSON form at all
- ``principal`` and ``parent_principal``, which a rule can consult and a wire
  can silently drop
- a call-side rule and a result-side rule on the *same* action name, so the
  phase partition is observable from outside the process
"""
from __future__ import annotations

from ..enforce import Decision
from ..event import SensorEvent
from ..policy.engine import PolicyEngine, deny_tool


class Opaque:
    """A value with no JSON form. A rule that returns one is not a protocol
    error to be guessed at - see the corpus's ``unrepresentable`` case."""


def _no_etc(event: SensorEvent):
    if event.action == "read_file" and "etc/passwd" in str(event.args.get("path", "")):
        return Decision.block("etc is off limits", "p.no-etc", attributed_to="path")
    return None


def _quarantine_write(event: SensorEvent):
    if event.action == "write_file" and str(event.args.get("path", "")).startswith("/etc/"):
        return Decision.modify(
            {"path": "/tmp/quarantine"},
            "path quarantined",
            "p.quarantine",
            attributed_to="path",
        )
    return None


def _deny_untrusted_principal(event: SensorEvent):
    if event.principal == "untrusted-agent":
        return Decision.block("untrusted principal", "p.untrusted-principal")
    return None


def _deny_root_agent_child(event: SensorEvent):
    if event.parent_principal == "root-agent":
        return Decision.block("spawned by root-agent", "p.root-agent-parent")
    return None


def _call_side_read_file(event: SensorEvent):
    if event.action == "read_file":
        return Decision.block("read_file on the call side is denied", "p.call-side")
    return None


def _redact_fetch_result(_event: SensorEvent):
    return Decision.modify_result(
        "redacted", "secret in result", "p.result-redact", attributed_to="result"
    )


def _strip_secret_key(event: SensorEvent):
    if "secret" in event.args:
        return Decision.modify_result(
            {"title": event.args.get("title")},
            "secret stripped",
            "p.result-strip",
            attributed_to="secret",
        )
    return None


def _binary_result(_event: SensorEvent):
    return Decision.modify_result(b"\x00\x01\xff", "binary replaced", "p.result-binary")


def _set_result(_event: SensorEvent):
    return Decision.modify_result({3, 1, 2}, "set normalised", "p.result-set")


def _null_result(_event: SensorEvent):
    return Decision.modify_result(None, "no replacement", "p.result-null")


def _opaque_result(_event: SensorEvent):
    return Decision.modify_result(Opaque(), "untransmittable", "p.result-opaque")


def _result_rule_for(rule, action):
    """Tag a rule result-side and bind it to one action name.

    ``phase`` is the attribute :meth:`PolicyEngine.evaluate` reads to partition
    call-side from result-side rules; setting it is what makes a rule see only
    result events. Binding the action here keeps each result rule from speaking
    for the others' actions.
    """

    def wrapper(event: SensorEvent):
        return rule(event) if event.action == action else None

    wrapper.phase = "result"  # type: ignore[attr-defined]
    return wrapper


CONFORMANCE_ENGINE = PolicyEngine(
    rules=[
        deny_tool("rm_rf"),
        _no_etc,
        _quarantine_write,
        _deny_untrusted_principal,
        _deny_root_agent_child,
        _call_side_read_file,
        _result_rule_for(_redact_fetch_result, "fetch_url"),
        _result_rule_for(_strip_secret_key, "read_dict"),
        _result_rule_for(_binary_result, "read_binary"),
        _result_rule_for(_set_result, "read_set"),
        _result_rule_for(_null_result, "read_null"),
        _result_rule_for(_opaque_result, "read_opaque"),
    ]
)

# The spec a daemon is started with, and the string the corpus records. Both
# sides of the language boundary name the same rule set with this.
CONFORMANCE_SPEC = "interlock.testing.fixtures:CONFORMANCE_ENGINE"


# --- Effect rules: the native fs / exec / http actions of the JS interceptors ---
#
# R13 stage 3 guards Node's native effects and speaks the same wire, so the same
# daemon decides them - which means the JS tests need a policy that actually has
# an opinion about ``fs.readFile``, ``child_process.exec`` and ``http.fetch``.
# These rules are marker-based (a path or a command containing a fixed token) so
# a test can point them at its own temp files without the rule knowing the path.
#
# Every rule here is **call-phase**. The native interceptors decide before the
# effect and do not inspect a return value: a Node native can hand back a `Stats`
# or a `Dirent`, which has no wire form, so a result-phase rule on `fs.stat`
# would fail-closed a legitimate call. Result-phase belongs on the MCP and
# model-SDK tool paths, where the return value is a tool payload - see
# ``_redact_fetch_result`` / ``_strip_secret_key`` above.


def _fs_refuse(event: SensorEvent):
    if event.action == "fs.readFile" and "blockme" in str(event.args.get("path", "")):
        return Decision.block(
            "this path is off limits", "p.fs-block", attributed_to="path"
        )
    return None


def _fs_redirect(event: SensorEvent):
    if event.action == "fs.readFile" and "redirectme" in str(event.args.get("path", "")):
        return Decision.modify(
            {"path": str(event.args["path"]).replace("redirectme", "target")},
            "path redirected",
            "p.fs-redirect",
            attributed_to="path",
        )
    return None


def _exec_refuse(event: SensorEvent):
    if event.action == "child_process.exec" and "rm -rf" in str(
        event.args.get("command", "")
    ):
        return Decision.block(
            "destructive command", "p.exec-block", attributed_to="command"
        )
    return None


def _exec_rewrite(event: SensorEvent):
    if event.action == "child_process.exec" and "echo a" in str(
        event.args.get("command", "")
    ):
        return Decision.modify(
            {"command": str(event.args["command"]).replace("echo a", "echo b")},
            "command rewritten",
            "p.exec-rewrite",
            attributed_to="command",
        )
    return None


def _fetch_refuse(event: SensorEvent):
    if event.action == "http.fetch" and "blockme" in str(event.args.get("url", "")):
        return Decision.block("egress blocked", "p.fetch-block", attributed_to="url")
    return None


def _fetch_redirect(event: SensorEvent):
    if event.action == "http.fetch" and "redirectme" in str(event.args.get("url", "")):
        return Decision.modify(
            {"url": str(event.args["url"]).replace("redirectme", "target")},
            "egress redirected",
            "p.fetch-redirect",
            attributed_to="url",
        )
    return None


EFFECT_ENGINE = PolicyEngine(
    rules=[
        _fs_refuse,
        _fs_redirect,
        _exec_refuse,
        _exec_rewrite,
        _fetch_refuse,
        _fetch_redirect,
    ]
)

EFFECT_SPEC = "interlock.testing.fixtures:EFFECT_ENGINE"

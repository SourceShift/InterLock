"""`interlock scope suggest` and interlock.scope_suggest.

The fixture is one receipt log a coding agent actually produces: ``acme`` runs
``ls`` twice and ``pwd`` once; its delegate ``acme/agent1`` runs ``ls`` once;
one call was refused and one names no principal. The derived document must name
exactly what was allowed, per scope, with the counts behind it.
"""
import json

import pytest

from interlock.cli import main
from interlock.enforce import Verdict
from interlock.event import SensorEvent
from interlock.policy.capability import (
    POLICY_ID,
    TEMPLATE_ID,
    action_envelope,
    templates,
)
from interlock.policy.scopes import PyScopeTree
from interlock.receipt import Receipt
from interlock.scope_suggest import (
    UNSCOPED,
    count_receipts,
    merge,
    read_document,
    render,
    suggest,
    suggested_document,
)
from interlock.sidecar.rules import build_scoped_engine
from interlock.sink import FileSink
from interlock.wire import scope_envelope, verify_scope_envelope

KEY = b"s" * 32


def _log(tmp_path, events, *, since_ts=1.0, name="receipts.jsonl"):
    """Write one receipt per (action, verdict, principal) triple."""
    sink = FileSink(str(tmp_path / name), key=KEY)
    for index, (action, verdict, principal) in enumerate(events):
        sink.write(Receipt(ts=since_ts + index, action=action, verdict=verdict,
                           reason="observed", policy_id="monitor",
                           principal=principal, args_digest="0" * 64))
    return str(tmp_path / name)


def _fixture(tmp_path):
    return _log(tmp_path, [
        ("ls", "ALLOW", "acme"),
        ("ls", "ALLOW", "acme"),
        ("pwd", "ALLOW", "acme"),
        ("ls", "ALLOW", "acme/agent1"),
        ("rm", "BLOCK", "acme/agent1"),
        ("ls", "ALLOW", None),
    ])


# --- derivation -------------------------------------------------------------

def test_receipts_cluster_by_principal_scope_and_verdict(tmp_path):
    envelope = count_receipts(_read(_fixture(tmp_path)))

    assert envelope.counts == {
        ("acme",): {"ls": 2, "pwd": 1},
        ("acme", "agent1"): {"ls": 1},
    }
    assert envelope.excluded == {"BLOCK": 1, UNSCOPED: 1}
    assert envelope.total == 4
    assert envelope.scopes == [("acme",), ("acme", "agent1")]


def _read(path):
    from interlock.report import read_receipts

    receipts, _bad = read_receipts(path)
    return receipts


def test_the_document_cites_a_count_behind_every_action(tmp_path):
    _doc, envelope, _problems = suggest(_fixture(tmp_path))
    document = suggested_document(envelope)

    entry = document["bindings"]["acme"][0]
    assert entry["template"] == TEMPLATE_ID
    assert entry["params"]["allow"] == ["ls", "pwd"]
    assert entry["observed"] == {"ls": 2, "pwd": 1}
    assert document["allow_unscoped"] is False


def test_the_document_is_deterministic(tmp_path):
    log = _fixture(tmp_path)
    first, _envelope, _p = suggest(log)
    second, _envelope2, _p2 = suggest(log)

    assert render(first) == render(second)
    assert render(first).endswith("\n")


def test_min_count_drops_rare_actions(tmp_path):
    _doc, envelope, _problems = suggest(_fixture(tmp_path), min_count=2)
    document = suggested_document(envelope, min_count=2)

    assert document["bindings"]["acme"][0]["params"]["allow"] == ["ls"]
    # acme/agent1 has nothing at 2+, so it is not bound at all.
    assert "acme/agent1" not in document["bindings"]


def test_nothing_observed_is_refused_not_emitted(tmp_path):
    log = _log(tmp_path, [("rm", "BLOCK", "acme")])
    document, envelope, problems = suggest(log)

    assert document is None and problems == []
    assert envelope.empty
    with pytest.raises(ValueError):
        suggested_document(envelope)


def test_since_window_keeps_only_recent_receipts(tmp_path):
    log = _log(tmp_path, [("ls", "ALLOW", "acme"), ("pwd", "ALLOW", "acme")])
    _doc, envelope, _p = suggest(log, since_seconds=1.5, now=2.0)

    # Receipts sit at ts 1.0 and 2.0; the cutoff is 0.5 only for the first run.
    assert envelope.counts == {("acme",): {"ls": 1, "pwd": 1}}
    _doc, narrow, _p = suggest(log, since_seconds=1.0, now=3.0)
    assert narrow.counts == {("acme",): {"pwd": 1}}


# --- the template the document binds ---------------------------------------

def _engine(document):
    return build_scoped_engine(document, templates)


def test_the_derived_document_enforces_what_it_observed(tmp_path):
    document, _envelope, _problems = suggest(_fixture(tmp_path))
    engine = _engine(document)

    allowed = engine.evaluate(SensorEvent(action="ls", principal="acme"))
    assert allowed.verdict == Verdict.ALLOW
    unseen = engine.evaluate(SensorEvent(action="curl", principal="acme"))
    assert unseen.verdict == Verdict.ESCALATE
    assert unseen.policy_id == POLICY_ID
    assert unseen.remediation


def test_a_leaf_binding_describes_its_own_scope_only(tmp_path):
    document, _envelope, _problems = suggest(_fixture(tmp_path))
    engine = _engine(document)

    # acme/agent1 was observed running only `ls`; its own binding overrides the
    # parent's envelope, so `pwd` - which acme may run - escalates for it.
    assert engine.evaluate(
        SensorEvent(action="ls", principal="acme/agent1")).verdict == Verdict.ALLOW
    assert engine.evaluate(
        SensorEvent(action="pwd", principal="acme/agent1")).verdict == Verdict.ESCALATE
    assert engine.evaluate(
        SensorEvent(action="pwd", principal="acme")).verdict == Verdict.ALLOW


def test_an_unobserved_principal_is_refused(tmp_path):
    document, _envelope, _problems = suggest(_fixture(tmp_path))
    engine = _engine(document)

    decision = engine.evaluate(SensorEvent(action="ls", principal="beta/agent9"))
    assert decision.verdict == Verdict.BLOCK
    assert decision.policy_id == "scoped_engine.unbound"


def test_the_envelope_rule_matches_canonical_spellings():
    rule = action_envelope(allow=["http_post"])
    assert rule(SensorEvent(action="http.post")) is None
    assert rule(SensorEvent(action="http_get")).verdict == Verdict.ESCALATE


def test_the_envelope_rule_can_block_instead_of_escalate():
    rule = action_envelope(allow=["ls"], on_unseen="block")
    decision = rule(SensorEvent(action="rm"))
    assert decision.verdict == Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_an_empty_envelope_permits_nothing():
    rule = action_envelope(allow=[])
    assert rule(SensorEvent(action="ls")).verdict == Verdict.ESCALATE


def test_an_unknown_on_unseen_mode_is_refused():
    with pytest.raises(ValueError):
        action_envelope(allow=["ls"], on_unseen="allow")


# --- never widen without asking -------------------------------------------

def _existing(tmp_path, document):
    path = tmp_path / "existing.json"
    path.write_text(render(document))
    return read_document(str(path))


def test_merge_keeps_a_scope_the_window_never_saw(tmp_path):
    existing = _existing(tmp_path, {
        "version": 1,
        "default_scope": [],
        "allow_unscoped": False,
        "bindings": {
            "beta": [{"template": TEMPLATE_ID, "params": {"allow": ["grep"]}}],
        },
    })
    document, _envelope, _problems = suggest(_fixture(tmp_path), existing=existing)

    assert document["bindings"]["beta"][0]["params"]["allow"] == ["grep"]
    assert document["bindings"]["acme"][0]["params"]["allow"] == ["ls", "pwd"]


def test_merge_folds_counts_into_an_existing_binding(tmp_path):
    existing = _existing(tmp_path, {
        "version": 1,
        "bindings": {
            "acme": [{"template": TEMPLATE_ID, "params": {"allow": ["ls", "pwd"]}}],
        },
    })
    document, _envelope, problems = suggest(_fixture(tmp_path), existing=existing)

    assert problems == []
    entry = document["bindings"]["acme"][0]
    assert entry["params"]["allow"] == ["ls", "pwd"]
    assert entry["observed"] == {"ls": 2, "pwd": 1}


def test_merge_refuses_to_widen_an_existing_scope(tmp_path):
    existing = _existing(tmp_path, {
        "version": 1,
        "bindings": {
            "acme": [{"template": TEMPLATE_ID, "params": {"allow": ["ls"]}}],
        },
    })
    document, _envelope, problems = suggest(_fixture(tmp_path), existing=existing)

    assert document is None
    assert any("pwd" in problem for problem in problems)
    assert any("'acme'" in problem for problem in problems)


def test_merge_accepts_a_widening_when_told_to(tmp_path):
    existing = _existing(tmp_path, {
        "version": 1,
        "bindings": {
            "acme": [{"template": TEMPLATE_ID, "params": {"allow": ["ls"]}}],
        },
    })
    document, _envelope, problems = suggest(
        _fixture(tmp_path), existing=existing, allow_widen=True)

    assert problems and document is not None
    assert document["bindings"]["acme"][0]["params"]["allow"] == ["ls", "pwd"]


def test_a_binding_without_an_allow_list_permits_nothing(tmp_path):
    document = {
        "version": 1,
        "bindings": {"acme": [{"template": TEMPLATE_ID, "params": {}}]},
    }
    merged, problems = merge(suggested_document(
        count_receipts(_read(_fixture(tmp_path)))), document)

    assert merged is None
    assert problems


def test_merge_of_two_identical_documents_is_stable(tmp_path):
    document, _envelope, _problems = suggest(_fixture(tmp_path))
    merged, problems = merge(document, document)

    assert problems == []
    assert render(merged) == render(document)


# --- reading documents ------------------------------------------------------

def test_a_signed_envelope_is_read_as_its_document(tmp_path):
    document, _envelope, _problems = suggest(_fixture(tmp_path))
    path = tmp_path / "signed.json"
    path.write_text(json.dumps(scope_envelope(document, KEY)))

    assert read_document(str(path))["bindings"] == document["bindings"]


def test_a_foreign_version_is_not_a_scope_document(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"version": 9, "bindings": {}}))
    with pytest.raises(ValueError):
        read_document(str(path))


# --- the command line -------------------------------------------------------

def test_cli_writes_a_deterministic_document(tmp_path):
    log = _fixture(tmp_path)
    first, second = tmp_path / "a.json", tmp_path / "b.json"

    assert main(["scope", "suggest", "--from-receipts", log, "--out", str(first)]) == 0
    assert main(["scope", "suggest", "--from-receipts", log, "--out", str(second)]) == 0

    assert first.read_bytes() == second.read_bytes()
    document = json.loads(first.read_text())
    assert document["bindings"]["acme"][0]["observed"] == {"ls": 2, "pwd": 1}


def test_cli_prints_the_evidence_and_a_review_note(tmp_path, capsys):
    log = _fixture(tmp_path)
    assert main(["scope", "suggest", "--from-receipts", log,
                 "--out", str(tmp_path / "s.json")]) == 0

    out = capsys.readouterr().out
    assert "4 allowed receipt(s)" in out
    assert "ls=2" in out and "pwd=1" in out
    assert "review it before serving it" in out


def test_cli_signs_the_document_when_given_a_key(tmp_path):
    log = _fixture(tmp_path)
    key_file = tmp_path / "audit.key"
    key_file.write_bytes(KEY)
    out = tmp_path / "scope.json"

    assert main(["scope", "suggest", "--from-receipts", log, "--out", str(out),
                 "--key-file", str(key_file)]) == 0

    envelope = json.loads(out.read_text())
    document = json.loads(verify_scope_envelope(envelope, KEY))
    assert document["bindings"]["acme"][0]["params"]["allow"] == ["ls", "pwd"]


def test_cli_refuses_a_widening_and_writes_nothing(tmp_path, capsys):
    log = _fixture(tmp_path)
    existing = tmp_path / "existing.json"
    existing.write_text(render({
        "version": 1,
        "bindings": {"acme": [{"template": TEMPLATE_ID, "params": {"allow": ["ls"]}}]},
    }))
    out = tmp_path / "scope.json"

    assert main(["scope", "suggest", "--from-receipts", log, "--out", str(out),
                 "--existing", str(existing)]) == 2
    assert not out.exists()
    assert "would widen" in capsys.readouterr().err


def test_cli_allows_the_widening_when_told_to(tmp_path):
    log = _fixture(tmp_path)
    existing = tmp_path / "existing.json"
    existing.write_text(render({
        "version": 1,
        "bindings": {"acme": [{"template": TEMPLATE_ID, "params": {"allow": ["ls"]}}]},
    }))
    out = tmp_path / "scope.json"

    assert main(["scope", "suggest", "--from-receipts", log, "--out", str(out),
                 "--existing", str(existing), "--allow-widen"]) == 0
    document = json.loads(out.read_text())
    assert document["bindings"]["acme"][0]["params"]["allow"] == ["ls", "pwd"]


def test_cli_reports_an_unreadable_log(tmp_path, capsys):
    assert main(["scope", "suggest", "--from-receipts", str(tmp_path / "missing.jsonl"),
                 "--out", str(tmp_path / "scope.json")]) == 3
    assert "cannot read" in capsys.readouterr().err


def test_cli_reports_a_log_with_nothing_scoped(tmp_path, capsys):
    log = _log(tmp_path, [("ls", "ALLOW", None)])
    assert main(["scope", "suggest", "--from-receipts", log,
                 "--out", str(tmp_path / "scope.json")]) == 3
    err = capsys.readouterr().err
    assert "no scoped ALLOW receipt" in err and "unscoped" in err


def test_cli_rejects_a_bad_min_count(tmp_path, capsys):
    assert main(["scope", "suggest", "--from-receipts", str(tmp_path / "x.jsonl"),
                 "--out", str(tmp_path / "s.json"), "--min-count", "0"]) == 64
    assert "1 or more" in capsys.readouterr().err


def test_cli_rejects_a_bad_window(tmp_path, capsys):
    assert main(["scope", "suggest", "--from-receipts", str(tmp_path / "x.jsonl"),
                 "--out", str(tmp_path / "s.json"), "--since", "30 days"]) == 64
    assert "30m, 24h or 7d" in capsys.readouterr().err


def test_the_template_uses_override_not_union():
    """A union param would let a leaf inherit its ancestor's actions."""
    template = templates[TEMPLATE_ID]
    assert template.union_params == frozenset()


def test_the_tree_is_the_pure_python_reference():
    """The derived document compiles on the reference backend too."""
    tree = PyScopeTree()
    tree.bind(("acme",), [])
    assert tree.bindings_at(("acme",)) == ()

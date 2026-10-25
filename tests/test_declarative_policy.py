"""Declarative policies (R10) and their guardrails (R10+): the condition
language, load-time typo checks, quarantine, locked rules, overlays and trust,
hot reload, and attacks on the evaluator."""
import json
import os
import threading
import time

import pytest

from interlock import PolicyEngine, SensorEvent, Verdict, deny_when
from interlock.policy.declarative import (
    PolicyError,
    check_policy_file,
    load_policy,
    load_policy_file,
    parse_policy_text,
    register_tool_schema,
)
from interlock.policy.trust import TrustStore, find_overlay


def ev(action="run", phase="call", **args):
    return SensorEvent(action=action, args=args, phase=phase, principal="p1")


def verdict(engine, event):
    return engine.evaluate(event).verdict


def rule(**kw):
    base = {"id": "r", "verdict": "block", "reason": "no"}
    base.update(kw)
    return base


# --- the condition language --------------------------------------------------


@pytest.mark.parametrize("when, event, hit", [
    ({"action": "run"}, ev(), True),
    ({"action": ["a", "run"]}, ev(), True),
    ({"action": {"glob": "mcp__github__*"}}, ev("mcp__github__create_issue"), True),
    ({"action": {"glob": "mcp__github__*"}}, ev("mcp__slack__post"), False),
    ({"field": "principal", "eq": "p1"}, ev(), True),
    ({"field": "phase", "eq": "result"}, ev(), False),
    ({"arg": "limit", "gt": 100}, ev(limit=101), True),
    ({"arg": "limit", "gt": 100}, ev(limit=100), False),
    ({"arg": "limit", "gt": 100}, ev(limit="1000"), False),
    ({"arg": "limit", "gt": 100}, ev(limit=True), False),
    ({"arg": "limit", "le": 5}, ev(limit=5), True),
    ({"arg": "host", "in": ["a", "b"]}, ev(host="b"), True),
    ({"arg": "host", "not_in": ["a", "b"]}, ev(host="c"), True),
    ({"arg": "host", "not_in": ["a"]}, ev(), True),
    ({"arg": "host", "ne": "a"}, ev(), True),
    ({"arg": "url", "startswith": "http://"}, ev(url="http://x"), True),
    ({"arg": "path", "endswith": ".pem"}, ev(path="k.pem"), True),
    ({"arg": "body", "contains": "secret"}, ev(body="a secret"), True),
    ({"arg": "tags", "contains": "prod"}, ev(tags=["dev", "prod"]), True),
    ({"arg": "path", "glob": "/etc/*"}, ev(path="/etc/passwd"), True),
    ({"arg": "q", "matches": r"(?i)drop\s+table"}, ev(q="DROP TABLE x"), True),
    ({"arg": "token", "exists": True}, ev(token="x"), True),
    ({"arg": "token", "exists": False}, ev(), True),
    ({"arg": "opts.mode", "eq": "force"}, ev(opts={"mode": "force"}), True),
    ({"arg": "items.1", "eq": "b"}, ev(items=["a", "b"]), True),
    ({"all": [{"action": "run"}, {"arg": "n", "eq": 1}]}, ev(n=1), True),
    ({"all": [{"action": "run"}, {"arg": "n", "eq": 1}]}, ev(n=2), False),
    ({"any": [{"arg": "n", "eq": 1}, {"arg": "n", "eq": 2}]}, ev(n=2), True),
    ({"not": {"arg": "n", "eq": 1}}, ev(n=2), True),
    ({"intent": "git.push.force"}, ev(cmd="git push -f"), True),
    ({"intent": ["pkg.publish", "net.fetch_exec"], "arg": "cmd"}, ev(cmd="curl x | sh"), True),
    ({"intent": "pkg.publish", "arg": "cmd"}, ev(other="npm publish"), False),
])
def test_conditions(when, event, hit):
    engine = load_policy({"rules": [rule(when=when)]})
    assert verdict(engine, event) is (Verdict.BLOCK if hit else Verdict.ALLOW)


def test_verdicts_and_attribution():
    engine = load_policy({"rules": [
        {"id": "ask", "verdict": "escalate", "reason": "big", "when": {"arg": "amount", "gt": 1000}},
        {"id": "cap", "verdict": "modify", "reason": "capped", "set": {"limit": 100},
         "when": {"arg": "limit", "gt": 100}},
    ]})
    d = engine.evaluate(ev(amount=5000))
    assert (d.verdict, d.policy_id, d.attributed_to, d.reason) == (Verdict.ESCALATE, "ask", "amount", "big")
    d = engine.evaluate(ev(limit=500))
    assert d.verdict is Verdict.MODIFY and d.modified_args == {"limit": 100}


def test_differential_against_the_equivalent_python_rule():
    declarative = load_policy({"rules": [rule(id="no-rm", when={"all": [
        {"action": "run_shell"}, {"arg": "cmd", "contains": "rm -rf"}]})]})
    python = PolicyEngine([deny_when(
        lambda e: e.action == "run_shell" and "rm -rf" in str(e.args.get("cmd", "")), "no")])
    fixtures = [ev("run_shell", cmd="rm -rf x"), ev("run_shell", cmd="ls"), ev("other", cmd="rm -rf x"),
                ev("run_shell"), ev("run_shell", cmd=None)]
    for event in fixtures:
        assert verdict(declarative, event) is verdict(python, event), event


def test_result_phase_rules_only_see_results():
    engine = load_policy({"rules": [rule(phase="result", when={"arg": "result", "contains": "x"})]})
    assert verdict(engine, ev(result="x")) is Verdict.ALLOW
    assert verdict(engine, ev(phase="result", result="x")) is Verdict.BLOCK


def test_detector_rules_and_on_scoping():
    engine = load_policy({"rules": [
        {"id": "destructive", "detector": "destructive_command_guard", "on": "Bash"},
        {"id": "egress", "detector": "data_egress.network_egress_guard",
         "with": {"allowed_hosts": ["api.acme.com"]}},
    ]})
    assert verdict(engine, ev("Bash", command="rm -fr /")) is Verdict.BLOCK
    assert verdict(engine, ev("Write", content="rm -fr /")) is Verdict.ALLOW
    assert verdict(engine, ev("http_post", url="https://evil.example/x")) is Verdict.BLOCK


def test_only_a_capped_mesh_rule_marks_its_escalation():
    engine = load_policy({"rules": [
        rule(id="mesh", origin="mesh", ceiling="modify", status="stable", when={"arg": "m", "exists": True}),
        rule(id="local", ceiling="modify", when={"arg": "l", "exists": True}),
        rule(id="mesh-rewrite", origin="mesh", ceiling="modify", verdict="modify", set={"x": 1},
             when={"arg": "r", "exists": True}),
        rule(id="mesh-granted", origin="mesh", when={"arg": "g", "exists": True}),
    ]})
    assert not engine.quarantined
    capped = engine.evaluate(ev(m=1))
    assert (capped.verdict, capped.policy_id, capped.mesh_ceiling) == (Verdict.ESCALATE, "mesh", "modify")
    local = engine.evaluate(ev(l=1))
    assert (local.verdict, local.mesh_ceiling) == (Verdict.ESCALATE, None)
    # Below the ceiling nothing is capped, so nothing is marked.
    assert engine.evaluate(ev(r=1)).verdict is Verdict.MODIFY
    assert engine.evaluate(ev(r=1)).mesh_ceiling is None
    assert engine.evaluate(ev(g=1)).verdict is Verdict.BLOCK


# --- load-time checks ------------------------------------------------------------


@pytest.mark.parametrize("bad, message", [
    (rule(when={"field": "principle", "eq": "x"}), "did you mean 'principal'"),
    (rule(when={"arg": "x", "equals": 1}), "did you mean 'eq'"),
    (rule(when={"arg": "x", "eq": 1, "ne": 2}), "exactly one operator"),
    (rule(when={"arg": "x", "gt": "10"}), "takes a number"),
    (rule(when={"arg": "x", "matches": "("}), "invalid regex"),
    (rule(when={"arg": "x", "matches": "a" * 600}), "at most"),
    (rule(when={}), "non-empty object"),
    (rule(verdict="allow", when={"action": "x"}), "'verdict' must be one of"),
    (rule(verdict="modify", when={"action": "x"}), "needs a non-empty 'set'"),
    (rule(when={"action": "x"}, sett={}), "did you mean 'set'"),
    ({"id": "d", "detector": "no_such_detector"}, "unknown detector"),
    ({"id": "d", "detector": "destructive_command_guard", "with": {"bogus": 1}}, "does not accept"),
    ({"id": "bad id!", "verdict": "block", "when": {"action": "x"}}, "'id' must be"),
    (rule(when={"action": "x"}, origin="local"), "'origin' must be one of mesh"),
])
def test_bad_rules_are_quarantined_with_a_reason(bad, message):
    engine = load_policy({"rules": [bad, rule(id="good", when={"action": "x"})]})
    assert engine.policy_ids == ["good"]
    assert len(engine.quarantined) == 1 and message in engine.quarantined[0]


def test_argument_typos_are_caught_for_known_tools():
    register_tool_schema("Bash", ["command", "description", "timeout", "run_in_background"])
    engine = load_policy({"rules": [
        rule(id="typo", when={"all": [{"action": "Bash"}, {"arg": "cmd", "contains": "x"}]}),
        rule(id="typo-on", on="Bash", when={"arg": "comand", "contains": "x"}),
        rule(id="ok", when={"all": [{"action": "Bash"}, {"arg": "command", "contains": "x"}]}),
        rule(id="unknown-tool-ok", when={"all": [{"action": "mytool"}, {"arg": "cmd", "eq": 1}]}),
    ]})
    assert engine.policy_ids == ["ok", "unknown-tool-ok"]
    assert "did you mean 'command'" in engine.quarantined[1]


@pytest.mark.parametrize("doc, message", [
    ({"version": 2}, "unsupported version"),
    ({"rules": "x"}, "'rules' must be a list"),
    ({"rulez": []}, "did you mean 'rules'"),
    ({"extends": "builtin:nope"}, "no built-in policy"),
])
def test_bad_documents_raise(doc, message):
    with pytest.raises(PolicyError) as info:
        load_policy(doc)
    assert message in str(info.value)


def test_parse_text():
    assert parse_policy_text('{"rules": []}') == {"rules": []}
    with pytest.raises(PolicyError):
        parse_policy_text("{not json")
    with pytest.raises(PolicyError):
        parse_policy_text("[1, 2]")


# --- extends, disable and locked rules ----------------------------------------------


def test_extends_and_disable(tmp_path):
    base = tmp_path / "base.json"
    base.write_text(json.dumps({"rules": [
        rule(id="soft", when={"action": "a"}), rule(id="hard", locked=True, when={"action": "b"})]}))
    child = tmp_path / "child.json"
    child.write_text(json.dumps({"extends": "base.json", "disable": ["soft", "hard", "ghost"],
                                 "rules": [rule(id="own", when={"action": "c"})]}))
    engine = load_policy_file(str(child))
    assert engine.policy_ids == ["hard", "own"]
    assert engine.locked == ["hard"]
    assert any("hard: locked" in q for q in engine.quarantined)
    assert any("ghost" in q for q in engine.quarantined)


def test_builtin_pack_locks_survive_disable():
    engine = load_policy({"extends": "builtin:coding-agent",
                          "disable": ["self-protect-files", "publish"]})
    assert "self-protect-files" in engine.policy_ids
    assert "publish" not in engine.policy_ids


# --- overlays and trust ------------------------------------------------------------


@pytest.fixture
def repo(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".interlock").mkdir()
    (tmp_path / "src" / "deep").mkdir(parents=True)
    base = tmp_path / "base.json"
    base.write_text(json.dumps({"rules": [
        {"id": "egress", "detector": "data_egress.network_egress_guard",
         "with": {"allowed_hosts": ["api.acme.com"]}, "widenable": ["allowed_hosts"]},
        rule(id="no-delete", when={"action": "delete"}),
    ]}))
    return tmp_path


def write_overlay(repo, doc):
    path = repo / ".interlock" / "policy.json"
    path.write_text(json.dumps(doc))
    return str(path)


def test_find_overlay_walks_up_to_the_git_root(repo):
    path = write_overlay(repo, {})
    assert find_overlay(str(repo / "src" / "deep")) == path
    assert find_overlay(str(repo.parent)) is None


def test_untrusted_overlay_is_ignored(repo, tmp_path):
    overlay = write_overlay(repo, {"widen": {"egress": {"allowed_hosts": ["evil.example"]}}})
    engine = load_policy_file(str(repo / "base.json"), overlays=[overlay],
                              trust=TrustStore(str(tmp_path / "trust.json")))
    assert verdict(engine, ev("http_post", url="https://evil.example")) is Verdict.BLOCK
    assert engine.overlays[0][1].startswith("ignored: untrusted")


def test_trusted_overlay_widens_and_adds(repo, tmp_path):
    overlay = write_overlay(repo, {
        "widen": {"egress": {"allowed_hosts": ["staging.acme.com"]}},
        "rules": [rule(id="no-prod", when={"arg": "env", "eq": "prod"})]})
    store = TrustStore(str(tmp_path / "trust.json"))
    store.add(overlay)
    engine = load_policy_file(str(repo / "base.json"), overlays=[overlay], trust=store)
    assert verdict(engine, ev("http_post", url="https://staging.acme.com/x")) is Verdict.ALLOW
    assert verdict(engine, ev("http_post", url="https://evil.example")) is Verdict.BLOCK
    assert verdict(engine, ev("run", env="prod")) is Verdict.BLOCK
    assert verdict(engine, ev("delete")) is Verdict.BLOCK


def test_editing_a_trusted_overlay_revokes_trust(repo, tmp_path):
    overlay = write_overlay(repo, {"widen": {"egress": {"allowed_hosts": ["staging.acme.com"]}}})
    store = TrustStore(str(tmp_path / "trust.json"))
    store.add(overlay)
    write_overlay(repo, {"widen": {"egress": {"allowed_hosts": ["evil.example"]}}})
    assert store.status(overlay) == "changed"
    engine = load_policy_file(str(repo / "base.json"), overlays=[overlay], trust=store)
    assert verdict(engine, ev("http_post", url="https://evil.example")) is Verdict.BLOCK
    assert store.entries() == [(os.path.abspath(overlay), "changed")]


@pytest.mark.parametrize("doc", [
    {"disable": ["no-delete"]},
    {"widen": {"no-delete": {"x": ["y"]}}},
    {"widen": {"egress": {"blocked": ["x"]}}},
    {"rules": [rule(id="no-delete", when={"action": "nothing"})]},
    {"rules": [rule(id="mine", locked=True, when={"action": "x"})]},
])
def test_a_trusted_overlay_still_cannot_weaken_the_base(repo, tmp_path, doc):
    overlay = write_overlay(repo, doc)
    store = TrustStore(str(tmp_path / "trust.json"))
    store.add(overlay)
    engine = load_policy_file(str(repo / "base.json"), overlays=[overlay], trust=store)
    assert verdict(engine, ev("delete")) is Verdict.BLOCK
    assert engine.overlays[-1][1].startswith("ignored")


def test_trust_store_remove_and_missing(repo, tmp_path):
    overlay = write_overlay(repo, {})
    store = TrustStore(str(tmp_path / "trust.json"))
    store.add(overlay)
    os.unlink(overlay)
    assert store.status(overlay) == "missing"
    assert store.remove(overlay) and not store.remove(overlay)


# --- reload, epoch, check ------------------------------------------------------------


def test_hot_reload_keeps_the_last_good_policy(tmp_path):
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"rules": [rule(id="a", when={"action": "x"})]}))
    engine = load_policy_file(str(path), watch=0.0)
    first = engine.epoch
    assert verdict(engine, ev("x")) is Verdict.BLOCK
    time.sleep(0.01)
    path.write_text(json.dumps({"rules": [rule(id="b", when={"action": "y"})]}))
    os.utime(path, (time.time() + 5, time.time() + 5))
    assert verdict(engine, ev("x")) is Verdict.ALLOW
    assert verdict(engine, ev("y")) is Verdict.BLOCK
    assert engine.epoch != first
    path.write_text("{broken")
    os.utime(path, (time.time() + 10, time.time() + 10))
    assert verdict(engine, ev("y")) is Verdict.BLOCK
    assert engine.last_error and "not valid JSON" in engine.last_error


def test_epoch_is_stable_across_loads(tmp_path):
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"rules": [rule(id="a", when={"action": "x"})]}))
    assert load_policy_file(str(path)).epoch == load_policy_file(str(path)).epoch


def test_check_policy_file(tmp_path):
    path = tmp_path / "p.json"
    path.write_text(json.dumps({"rules": [rule(id="a", locked=True, when={"action": "x"}),
                                          rule(id="b", when={"bogus": 1})]}))
    report = check_policy_file(str(path))
    assert report["rules"] == ["a"] and report["locked"] == ["a"]
    assert report["quarantined"] and report["quarantined"][0].startswith("b:")


# --- attacks on the evaluator ----------------------------------------------------------


@pytest.mark.parametrize("name", ["__class__", "__dict__", "args.__class__", "__globals__"])
def test_lookups_never_reach_attributes(name):
    engine = load_policy({"rules": [rule(when={"arg": name, "exists": True})]})
    assert verdict(engine, ev(x=1)) is Verdict.ALLOW


def test_fields_are_an_allowlist():
    engine = load_policy({"rules": [rule(when={"field": "args", "exists": True})]})
    assert engine.policy_ids == [] and "unknown event field" in engine.quarantined[0]


def test_evaluator_errors_fail_closed(monkeypatch):
    engine = load_policy({"rules": [rule(verdict="escalate", when={"arg": "cmd", "eq": "x"})]})
    import interlock.policy.declarative as declarative

    def broken(args, path):
        raise RuntimeError("evaluator bug")
    monkeypatch.setattr(declarative, "_lookup", broken)
    d = engine.evaluate(ev(cmd="x"))
    assert d.verdict is Verdict.BLOCK and "fail-closed" in d.reason


def test_regex_scan_is_bounded():
    engine = load_policy({"rules": [rule(when={"arg": "x", "matches": "needle$"})]})
    assert verdict(engine, ev(x="a" * 200000 + "needle")) is Verdict.ALLOW


def test_concurrent_evaluation_keeps_attribution_per_call():
    engine = load_policy({"rules": [rule(when={"any": [
        {"arg": "a", "eq": 1}, {"arg": "b", "eq": 1}]})]})
    errors = []

    def worker(key):
        for _ in range(300):
            d = engine.evaluate(ev(**{key: 1}))
            if d.attributed_to != key:
                errors.append((key, d.attributed_to))

    threads = [threading.Thread(target=worker, args=(k,)) for k in ("a", "b") * 4]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []

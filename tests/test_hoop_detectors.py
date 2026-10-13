"""Runbooks (H4), HTTP request/status rules (H5), MCP elicitation and result
size (H7) from the hoop review."""
import json

import pytest

from interlock import SensorEvent, Verdict
from interlock.detectors.http_request_guard import http_request_guard, resource_matches
from interlock.detectors.http_status_guard import http_status_guard
from interlock.detectors.mcp_elicitation_guard import mcp_elicitation_guard
from interlock.detectors.result_size_guard import result_size_guard
from interlock.detectors.runbook_guard import load_runbooks, runbook_guard

RUNBOOKS = [
    {"name": "restart-deployment",
     "templates": ["kubectl rollout restart deployment/{name} -n {namespace}"],
     "params": {"name": {"pattern": "^[a-z0-9-]{1,63}$"},
                "namespace": {"options": ["staging", "prod"]}}},
    {"name": "tail-logs", "templates": ["kubectl logs {pod} --tail={lines}"],
     "params": {"lines": {"type": "integer", "min": 1, "max": 500}}},
    {"name": "cat-config", "templates": ["cat {file}"], "params": {"file": {"type": "path"}}},
    {"name": "status", "template": "git status"},
]


def bash(command):
    return SensorEvent("Bash", {"command": command})


# --- runbooks -----------------------------------------------------------------


@pytest.mark.parametrize("command", [
    "kubectl rollout restart deployment/api -n staging",
    "kubectl rollout restart deployment/web-2 -n prod",
    "kubectl logs api-7d9f --tail=100",
    "cat config/app.yaml",
    "git status",
    "kubectl   logs   api-7d9f   --tail=5",
])
def test_runbook_commands_are_allowed(command):
    assert runbook_guard(RUNBOOKS)(bash(command)) is None


@pytest.mark.parametrize("command, why", [
    ("kubectl delete deployment/api -n prod", "matches no runbook"),
    ("kubectl rollout restart deployment/api -n qa", "namespace must be one of staging, prod"),
    ("kubectl rollout restart deployment/API -n prod", "name does not match its pattern"),
    ("kubectl logs api --tail=5000", "lines is above 500"),
    ("kubectl logs api --tail=all", "lines must be an integer"),
    ("cat ../../etc/passwd", "file must be a plain path"),
    ("cat -n secrets", "matches no runbook"),
    ("git status && rm -rf /", "not a single plain command"),
    ("git status; rm -rf /", "not a single plain command"),
    ("git status | sh", "not a single plain command"),
    ("cat $(echo /etc/passwd)", "not a single plain command"),
    ("git status > /tmp/out", "not a single plain command"),
    ("kubectl logs 'api x' --tail=5", "pod has characters outside"),
    ("git status --porcelain", "matches no runbook"),
])
def test_everything_else_is_refused_with_a_reason(command, why):
    decision = runbook_guard(RUNBOOKS)(bash(command))
    assert decision is not None and decision.verdict is Verdict.BLOCK
    assert why in decision.reason
    assert "passwd" not in decision.reason and "rm -rf" not in decision.reason


def test_runbook_escalate_and_scope():
    guard = runbook_guard(RUNBOOKS, verdict="escalate", actions=["Bash"])
    assert guard(bash("rm x")).verdict is Verdict.ESCALATE
    assert guard(SensorEvent("Other", {"command": "rm x"})) is None
    assert runbook_guard(RUNBOOKS)(SensorEvent("Bash", {"description": "rm x"})) is None


def test_runbook_validation():
    with pytest.raises(ValueError):
        runbook_guard([])
    with pytest.raises(ValueError):
        runbook_guard([{"name": "x"}])
    with pytest.raises(ValueError):
        runbook_guard([{"name": "x", "template": "a {b}", "params": {"b": {"regex": "."}}}])
    with pytest.raises(ValueError):
        runbook_guard(RUNBOOKS, verdict="allow")


def test_repeated_parameter_must_agree():
    guard = runbook_guard([{"name": "copy", "template": "cp {f} {f}.bak"}])
    assert guard(bash("cp a.txt a.txt.bak")) is None
    assert "f differs" in guard(bash("cp a.txt b.txt.bak")).reason


def test_load_runbooks(tmp_path):
    (tmp_path / "a.runbook.json").write_text(json.dumps(RUNBOOKS[0]))
    (tmp_path / "b.runbook.json").write_text(json.dumps(RUNBOOKS[1:]))
    (tmp_path / "ignored.json").write_text("{}")
    assert [r["name"] for r in load_runbooks(str(tmp_path))] == [
        "restart-deployment", "tail-logs", "cat-config", "status"]


def test_runbooks_in_a_declarative_policy():
    from interlock.policy.declarative import load_policy
    engine = load_policy({"rules": [{"id": "only-runbooks", "detector": "runbook_guard",
                                     "on": "Bash", "with": {"runbooks": RUNBOOKS}}]})
    assert engine.evaluate(bash("git status")).verdict is Verdict.ALLOW
    assert engine.evaluate(bash("git push")).verdict is Verdict.BLOCK


# --- HTTP request rules -------------------------------------------------------------


@pytest.mark.parametrize("pattern, path, hit", [
    ("/admin/**", "/admin", True), ("/admin/**", "/admin/users/1", True),
    ("/admin/**", "/administrator", False), ("/users/*", "/users/7", True),
    ("/users/*", "/users/7/delete", False), ("/v*/orders", "/v2/orders", True),
    ("/", "/", True),
])
def test_resource_globs(pattern, path, hit):
    assert resource_matches(pattern, path) is hit


RULES = [
    {"name": "no-admin", "resources": ["/admin/**"], "message": "admin API is off limits"},
    {"name": "billing-writes", "hosts": ["billing.acme.com"],
     "methods": ["POST", "PUT", "PATCH", "DELETE"], "verdict": "escalate"},
    {"name": "no-debug", "headers": {"X-Debug": ["*"]}},
    {"name": "svc-token", "hosts": ["*.internal"], "headers_not": {"Authorization": ["Bearer svc_*"]}},
]


@pytest.mark.parametrize("action, args, verdict, rule", [
    ("http_get", {"url": "https://api.acme.com/admin/users"}, Verdict.BLOCK, "no-admin"),
    ("http_post", {"url": "https://billing.acme.com/charges"}, Verdict.ESCALATE, "billing-writes"),
    ("http", {"url": "https://billing.acme.com/charges", "method": "delete"}, Verdict.ESCALATE, "billing-writes"),
    ("fetch", {"url": "https://x.com/", "headers": {"x-debug": "1"}}, Verdict.BLOCK, "no-debug"),
    ("fetch", {"url": "https://db.internal/q"}, Verdict.BLOCK, "svc-token"),
    ("fetch", {"url": "https://db.internal/q", "headers": {"authorization": "Bearer usr_1"}},
     Verdict.BLOCK, "svc-token"),
])
def test_http_rules_fire(action, args, verdict, rule):
    decision = http_request_guard(RULES)(SensorEvent(action, args))
    assert decision is not None and decision.verdict is verdict and rule in decision.reason


@pytest.mark.parametrize("action, args", [
    ("http_get", {"url": "https://billing.acme.com/charges"}),
    ("http_get", {"url": "https://api.acme.com/users"}),
    ("fetch", {"url": "https://db.internal/q", "headers": {"Authorization": "Bearer svc_ab"}}),
    ("send_email", {"to": "x@y.z"}),
])
def test_http_rules_stay_quiet(action, args):
    assert http_request_guard(RULES)(SensorEvent(action, args)) is None


def test_http_rule_validation():
    with pytest.raises(ValueError):
        http_request_guard([{"name": "empty"}])
    with pytest.raises(ValueError):
        http_request_guard([{"name": "x", "resources": ["/"], "paths": ["/"]}])
    with pytest.raises(ValueError):
        http_request_guard([])


# --- HTTP status, elicitation, result size -------------------------------------------


def result(action, payload):
    return SensorEvent(action, payload, phase="result")


def test_http_status_guard():
    guard = http_status_guard(["5xx", 403])
    assert guard(result("http_get", {"status": 503, "body": "trace"})).verdict is Verdict.BLOCK
    assert guard(result("http_get", {"status_code": "403"})).verdict is Verdict.BLOCK
    assert guard(result("http_get", {"status": 200})) is None
    assert guard(result("http_get", {"status": True})) is None
    assert guard(SensorEvent("http_get", {"status": 500})) is None  # call phase
    with pytest.raises(ValueError):
        http_status_guard(["server-error"])


def test_mcp_elicitation_guard():
    guard = mcp_elicitation_guard(allow_servers=["trusted"])
    assert guard(SensorEvent("mcp.elicitation", {"__origin__": "shady"})).verdict is Verdict.BLOCK
    assert guard(SensorEvent("elicitation/create", {})).verdict is Verdict.BLOCK
    assert guard(SensorEvent("mcp.elicitation", {"__origin__": "trusted"})) is None
    assert guard(SensorEvent("tools/call", {})) is None


def test_result_size_guard():
    guard = result_size_guard(100)
    assert guard(result("read", {"result": "x" * 200})).verdict is Verdict.BLOCK
    assert guard(result("read", {"result": "small"})) is None
    assert guard(SensorEvent("read", {"result": "x" * 200})) is None
    with pytest.raises(ValueError):
        result_size_guard(0)

"""The console API behind the designed web app: the write gate, the review
queue, activity, the policy editor, overlays, audit filters and ops.

Every claim runs against a real server on loopback with real interlock parts
underneath - a FileSink-written receipt log, a ReviewQueue with reviews filed
the way the hook files them, the declarative loader, the trust store.
"""
from __future__ import annotations

import contextlib
import http.client
import json
import os
import stat
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple

import pytest

from interlock import Decision
from interlock.approval import make_request
from interlock.console import session as console_session
from interlock.console.server import ConsoleServer
from interlock.console.session import MAX_FAILURES, configure
from interlock.event import SensorEvent
from interlock.receipt import Receipt
from interlock.reviews import ReviewQueue, binding_hash
from interlock.sink import FileSink

KEY = bytes.fromhex("c0ffee" * 10 + "c0ff")
CODE = "Abcd-Efgh-Jkmn"


@contextlib.contextmanager
def serve(tmp: Path, *, receipts: Optional[Path] = None, key: Optional[bytes] = KEY,
          four_eyes: bool = False) -> Iterator[ConsoleServer]:
    static = tmp / "static"
    (static / "assets").mkdir(parents=True, exist_ok=True)
    (static / "index.html").write_text("<!doctype html><title>console</title>")
    (static / "assets" / "app-abc123.js").write_text("console.log(1)")
    server = ConsoleServer(("127.0.0.1", 0), static,
                           receipts_path=str(receipts) if receipts else None,
                           receipts_key=key if receipts else None)
    configure(server, policy_path=str(tmp / "home" / "policy.json"), reviews_db=str(tmp / "reviews.db"),
              trust_path=str(tmp / "trusted.json"), four_eyes=four_eyes, cwd=str(tmp / "project"),
              unlock_code=CODE)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


def call(server: ConsoleServer, method: str, path: str, body: Any = None,
         token: Optional[str] = None) -> Tuple[int, Dict[str, Any], Dict[str, str]]:
    port = server.server_address[1]
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Host": "127.0.0.1:{}".format(port)}
    payload = None
    if body is not None:
        payload = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["X-Interlock-Unlock"] = token
    conn.request(method, path, body=payload, headers=headers)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    try:
        data = json.loads(raw) if raw else {}
    except ValueError:
        data = {"raw": raw.decode(errors="replace")}
    return resp.status, data, {k.lower(): v for k, v in resp.getheaders()}


def unlock(server: ConsoleServer) -> str:
    status, body, _ = call(server, "POST", "/api/unlock", {"code": CODE})
    assert status == 200
    return body["token"]


def write_receipts(path: Path, rows) -> None:
    sink = FileSink(str(path), key=KEY)
    for row in rows:
        sink.write(Receipt(**row))


def file_review(db: Path, *, action="git_push", policy_id="no-force-push", args=None) -> str:
    queue = ReviewQueue(str(db))
    event = SensorEvent(action=action, args=args or {"branch": "main", "force": True},
                        principal="claude-code")
    request = make_request(event, Decision.escalate("needs a human", policy_id), "epoch-1")
    return queue.lookup_or_file(binding_hash(request), request).id


# --- the write gate -----------------------------------------------------------------


def test_session_starts_locked_and_unlocks_only_with_this_launchs_code(tmp_path):
    with serve(tmp_path) as server:
        status, body, _ = call(server, "GET", "/api/session")
        assert status == 200 and body["locked"] is True and body["me"]
        status, body, _ = call(server, "POST", "/api/unlock", {"code": "aaaa-bbbb-cccc"})
        assert (status, body["error"]["code"]) == (403, "bad_unlock_code")
        status, body, _ = call(server, "POST", "/api/unlock", {"code": "nonsense"})
        assert status == 403 and "Paste the link" in body["error"]["message"]
        link = "http://127.0.0.1:{}/#/unlock/{}".format(server.server_address[1], CODE)
        status, body, _ = call(server, "POST", "/api/unlock", {"code": link})
        assert status == 200 and len(body["token"]) > 20
        token = body["token"]
        assert call(server, "GET", "/api/session", token=token)[1]["locked"] is False
        assert call(server, "GET", "/api/session")[1]["locked"] is True  # another tab
        call(server, "POST", "/api/lock", {}, token=token)
        assert call(server, "GET", "/api/session", token=token)[1]["locked"] is True


def test_the_gate_shuts_after_too_many_wrong_codes(tmp_path):
    with serve(tmp_path) as server:
        for _ in range(MAX_FAILURES):
            call(server, "POST", "/api/unlock", {"code": "zzzz-zzzz-zzzz"})
        status, body, _ = call(server, "POST", "/api/unlock", {"code": CODE})
        assert (status, body["error"]["code"]) == (429, "unlock_shut")


def test_unlock_needs_a_json_body(tmp_path):
    with serve(tmp_path) as server:
        port = server.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", port)
        conn.request("POST", "/api/unlock", body=CODE, headers={"Host": "127.0.0.1:{}".format(port),
                                                              "Content-Type": "text/plain"})
        assert conn.getresponse().status == 415


def test_generated_codes_are_three_groups_of_four():
    code = console_session.WriteGate().code
    assert len(code) == 14 and code.count("-") == 2


# --- reviews ---------------------------------------------------------------------------


def test_reading_reviews_never_creates_the_queue(tmp_path):
    with serve(tmp_path) as server:
        status, body, _ = call(server, "GET", "/api/reviews")
        assert status == 200 and body["configured"] is False and body["reviews"] == []
        assert not (tmp_path / "reviews.db").exists()


def test_decisions_go_through_the_queue_and_need_an_unlocked_tab(tmp_path):
    rid = file_review(tmp_path / "reviews.db")
    other = file_review(tmp_path / "reviews.db", action="send_email", policy_id="mail",
                        args={"to": "x@partner.io"})
    with serve(tmp_path) as server:
        body = call(server, "GET", "/api/reviews")[1]
        assert {r["id"] for r in body["reviews"]} == {rid, other}
        assert all(r["status"] == "pending" and r["self_ok"] for r in body["reviews"])
        assert call(server, "POST", "/api/reviews/{}/approve".format(rid), {})[0] == 403
        token = unlock(server)
        status, body, _ = call(server, "POST", "/api/reviews/{}/approve".format(rid), {}, token)
        assert status == 200 and body["review"]["status"] == "approved"
        status, body, _ = call(server, "POST", "/api/reviews/{}/approve".format(rid), {}, token)
        assert (status, body["error"]["code"]) == (409, "review_state")
        status, body, _ = call(server, "POST", "/api/reviews/{}/reject".format(other), {}, token)
        assert (status, body["error"]["code"]) == (400, "reason_required")
        status, body, _ = call(server, "POST", "/api/reviews/{}/reject".format(other),
                               {"reason": "not during the freeze"}, token)
        assert body["review"]["status"] == "rejected"
        assert body["review"]["rejection_reason"] == "not during the freeze"
        status, body, _ = call(server, "POST", "/api/reviews/{}/revoke".format(rid), {}, token)
        assert body["review"]["status"] == "revoked"
        assert call(server, "GET", "/api/reviews/r-nope")[0] == 404


def test_four_eyes_refuses_the_requester(tmp_path):
    rid = file_review(tmp_path / "reviews.db")
    with serve(tmp_path, four_eyes=True) as server:
        review = call(server, "GET", "/api/reviews/" + rid)[1]["review"]
        assert review["self_ok"] is False
        token = unlock(server)
        status, body, _ = call(server, "POST", "/api/reviews/{}/approve".format(rid), {}, token)
        assert status == 409 and "may not approve" in body["error"]["message"]


# --- activity -------------------------------------------------------------------------------


def _receipt(ts, action, verdict, **extra):
    row = {"ts": ts, "action": action, "verdict": verdict, "reason": "r", "phase": "call",
           "principal": "claude-code", "span_id": "s1"}
    row.update(extra)
    return row


def test_activity_aggregates_the_window_and_leaves_bookkeeping_out(tmp_path):
    now = time.time()
    log = tmp_path / "receipts.jsonl"
    write_receipts(log, [
        _receipt(now - 10 * 86400, "shell", "BLOCK", policy_id="old"),  # a log is append-only
        _receipt(now - 7200, "read_file", "ALLOW", elapsed_us=40),
        _receipt(now - 3600, "shell", "BLOCK", policy_id="no-rm", elapsed_us=300),
        _receipt(now - 1800, "git_push", "ALLOW", policy_id="force-push", policy_verdict="ESCALATE",
                 approval="approved:review r-1a2b3c4d", elapsed_us=90),
        _receipt(now - 900, "write_file", "BLOCK", policy_id="dotfiles", observed=True),
        _receipt(now - 600, "policy.overlay", "BLOCK", policy_id="policy_overlay"),
        _receipt(now - 500, "http_get", "ALLOW", phase="outcome", outcome="failed", enforcer="tool"),
        _receipt(now - 200, "http_post", "MODIFY", policy_id="pii", masked={"EMAIL": 2}, elapsed_us=120),
    ])
    with serve(tmp_path, receipts=log) as server:
        status, body, _ = call(server, "GET", "/api/activity?window=24h")
        assert status == 200
        s = body["summary"]
        assert s["verdicts"] == {"ALLOW": 2, "MODIFY": 1, "BLOCK": 1}
        assert s["decisions"] == 4 and s["escalated"] == 1
        assert s["escalations"] == {"approved:review": 1}
        assert s["would"] == [{"rule": "dotfiles", "action": "write_file", "verdict": "BLOCK", "count": 1}]
        assert s["failed"] == 1 and s["masked"] == {"EMAIL": 2}
        assert "old" not in {r["id"] for r in s["rules"]}
        assert s["latency"]["samples"] == 4 and len(s["latency"]["hist"]) == 24
        assert len(body["timeline"]) == 24
        assert sum(b["BLOCK"] for b in body["timeline"]) == 1
        assert body["recent"][-1]["action"] == "http_post"
        assert all(r["action"] != "policy.overlay" for r in body["recent"])
        b = body["timeline"][-1]
        focus = call(server, "GET", "/api/activity?window=24h&from={}&to={}".format(b["from"], b["to"]))[1]
        assert focus["focus"] and focus["summary"]["verdicts"]["MODIFY"] == 1
        assert len(call(server, "GET", "/api/activity?window=7d")[1]["timeline"]) == 28
        assert call(server, "GET", "/api/activity?window=1y")[0] == 400


def test_activity_needs_a_receipt_log(tmp_path):
    with serve(tmp_path) as server:
        status, body, _ = call(server, "GET", "/api/activity")
        assert (status, body["error"]["code"]) == (404, "receipts_not_configured")


# --- audit filters ------------------------------------------------------------------------------


def test_audit_filters_escalations_observed_rules_text_and_one_index(tmp_path):
    now = time.time()
    log = tmp_path / "receipts.jsonl"
    write_receipts(log, [
        _receipt(now - 30, "shell", "BLOCK", policy_id="no-rm"),
        _receipt(now - 20, "git_push", "ALLOW", policy_id="force-push", policy_verdict="ESCALATE"),
        _receipt(now - 10, "write_file", "BLOCK", policy_id="dotfiles", observed=True,
                 span_id="sess-xyz"),
    ])
    with serve(tmp_path, receipts=log) as server:
        get = lambda q: call(server, "GET", "/api/receipts" + q)[1]  # noqa: E731
        assert [r["action"] for r in get("?verdict=ESCALATE")["receipts"]] == ["git_push"]
        assert [r["action"] for r in get("?verdict=OBSERVED")["receipts"]] == ["write_file"]
        assert [r["action"] for r in get("?verdict=BLOCK")["receipts"]] == ["shell"]
        assert [r["action"] for r in get("?policy=force-push")["receipts"]] == ["git_push"]
        assert [r["action"] for r in get("?q=sess-xyz")["receipts"]] == ["write_file"]
        assert get("")["rules"] == ["dotfiles", "force-push", "no-rm"]
        one = get("?index=1")["receipts"]
        assert len(one) == 1 and one[0]["action"] == "git_push"


def test_verify_names_the_line_of_a_broken_chain(tmp_path):
    log = tmp_path / "receipts.jsonl"
    now = time.time()
    write_receipts(log, [_receipt(now - 3, "a", "ALLOW"), _receipt(now - 2, "b", "ALLOW"),
                         _receipt(now - 1, "c", "ALLOW")])
    lines = log.read_text().splitlines()
    lines[1] = lines[1].replace('"action":"b"', '"action":"x"')
    log.write_text("\n".join(lines) + "\n")
    with serve(tmp_path, receipts=log) as server:
        body = call(server, "GET", "/api/receipts/verify")[1]
        assert body["status"] == "broken" and body["broken_index"] == 1


# --- policy -------------------------------------------------------------------------------------


def test_policy_reads_the_default_when_no_file_exists(tmp_path):
    with serve(tmp_path) as server:
        body = call(server, "GET", "/api/policy")[1]
        assert body["exists"] is False and body["sha"] is None
        assert json.loads(body["text"])["extends"] == "builtin:coding-agent"
        analysis = body["analysis"]
        assert analysis["ok"] and analysis["locked"]
        assert {r["source"] for r in analysis["rules"]} == {"inherited"}


def test_check_reports_quarantine_with_did_you_mean_and_parse_errors_with_a_line(tmp_path):
    with serve(tmp_path) as server:
        draft = {"version": 1, "extends": "builtin:coding-agent", "disable": ["self-protect-files"],
                 "rules": [{"id": "big", "verdict": "block", "when": {"arg": "size", "equals": 5}}]}
        a = call(server, "POST", "/api/policy/check", {"text": json.dumps(draft)})[1]["analysis"]
        assert a["ok"]
        assert any("did you mean 'eq'" in q for q in a["quarantined"])
        assert any(q.startswith("self-protect-files: locked") for q in a["quarantined"])
        big = next(r for r in a["rules"] if r["id"] == "big")
        assert big["source"] == "own" and big["quarantined"]
        bad = call(server, "POST", "/api/policy/check", {"text": '{\n  "rules": [\n'})[1]["analysis"]
        assert bad["ok"] is False and bad["line"] == 3


def test_saving_needs_unlock_refuses_conflicts_and_voids_approvals(tmp_path):
    policy = tmp_path / "home" / "policy.json"
    policy.parent.mkdir()
    policy.write_text(json.dumps({"version": 1, "extends": "builtin:coding-agent"}))
    queue = ReviewQueue(str(tmp_path / "reviews.db"))
    rid = file_review(tmp_path / "reviews.db")
    queue.approve(rid, "someone")
    new_text = json.dumps({"version": 1, "extends": "builtin:coding-agent",
                           "rules": [{"id": "cap", "verdict": "modify", "set": {"limit": 100},
                                      "when": {"all": [{"action": "query_db"}, {"arg": "limit", "gt": 100}]}}]})
    with serve(tmp_path) as server:
        current = call(server, "GET", "/api/policy")[1]
        assert call(server, "PUT", "/api/policy", {"text": new_text, "base_sha": current["sha"]})[0] == 403
        token = unlock(server)
        status, body, _ = call(server, "PUT", "/api/policy", {"text": new_text, "base_sha": "stale"}, token)
        assert (status, body["error"]["code"]) == (409, "conflict")
        status, body, _ = call(server, "PUT", "/api/policy", {"text": "{", "base_sha": current["sha"]}, token)
        assert (status, body["error"]["code"]) == (400, "does_not_load")
        status, body, _ = call(server, "PUT", "/api/policy", {"text": new_text, "base_sha": current["sha"]}, token)
        assert status == 200 and body["voided"] == [rid]
        assert body["analysis"]["epoch"] != current["analysis"]["epoch"]
    assert json.loads(policy.read_text())["rules"][0]["id"] == "cap"
    assert stat.S_IMODE(os.stat(policy).st_mode) == 0o600
    review = ReviewQueue(str(tmp_path / "reviews.db")).get(rid)
    assert review.status == "revoked" and review.decided_by == "epoch change"


def test_overlays_report_untrusted_trusted_changed_and_loosening(tmp_path):
    from interlock.policy.trust import TrustStore

    project = tmp_path / "project"
    (project / ".git").mkdir(parents=True)
    overlay = project / ".interlock" / "policy.json"
    overlay.parent.mkdir()
    overlay.write_text(json.dumps({"rules": [{"id": "no-prod", "verdict": "block",
                                              "when": {"arg": "env", "eq": "prod"}}]}))
    with serve(tmp_path) as server:
        found = call(server, "GET", "/api/trust")[1]["overlays"]
        assert [(o["status"], o["cmd"].split()[:3]) for o in found] == [("untrusted", ["interlock", "trust", "add"])]
        store = TrustStore(str(tmp_path / "trusted.json"))
        store.add(str(overlay))
        ok = call(server, "GET", "/api/trust")[1]["overlays"][0]
        assert ok["status"] == "ok" and "Adds 1 rule" in ok["line"]
        overlay.write_text(json.dumps({"disable": ["self-protect-files"]}))
        assert call(server, "GET", "/api/trust")[1]["overlays"][0]["status"] == "changed"
        store.add(str(overlay))
        loosen = call(server, "GET", "/api/trust")[1]["overlays"][0]
        assert loosen["status"] == "loosens" and "only tighten" in loosen["line"]


# --- ops -----------------------------------------------------------------------------------------


def test_ops_reads_doctor_hooks_mcp_sidecar_and_log(tmp_path, monkeypatch):
    home = tmp_path / "userhome"
    (home / ".claude").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path / "run"))
    log = tmp_path / "receipts.jsonl"
    write_receipts(log, [_receipt(time.time(), "a", "ALLOW")])
    with serve(tmp_path, receipts=log) as server:
        doctor = call(server, "GET", "/api/doctor")[1]
        assert doctor["level"] in ("enforced", "degraded", "unprotected")
        assert {"id", "status", "summary", "fix"} <= set(doctor["checks"][0])
        hooks = {h["agent"]: h for h in call(server, "GET", "/api/hooks")[1]["hooks"]}
        assert hooks["claude-code"]["state"] == "not installed"
        assert hooks["claude-code"]["cmd"] == "interlock install-hook --for claude-code"
        assert hooks["codex"]["state"] == "not on this machine" and hooks["codex"]["cmd"] == ""
        mcp = call(server, "GET", "/api/mcp")[1]
        assert mcp["servers"] == [] and mcp["clients_known"] == 7
        assert call(server, "GET", "/api/sidecar")[1]["state"] == "not configured"
        info = call(server, "GET", "/api/receipt-log")[1]
        assert info["configured"] and info["key"] and info["writable"] and info["dropped"] == 0


def test_mcp_lists_risks_and_offers_the_starter_rule(tmp_path, monkeypatch):
    home = tmp_path / "userhome"
    home.mkdir()
    (home / ".claude.json").write_text(json.dumps({"mcpServers": {
        "github": {"command": "npx", "args": ["@modelcontextprotocol/server-github"]}}}))
    monkeypatch.setenv("HOME", str(home))
    with serve(tmp_path) as server:
        server_row = call(server, "GET", "/api/mcp")[1]["servers"][0]
        assert server_row["client"] == "Claude Code"
        assert server_row["risks"][0]["tag"] == "unpinned package"
        rule = call(server, "GET", "/api/mcp/starter")[1]["rule"]
        assert rule["verdict"] == "block" and "github" in json.dumps(rule)


# --- static ---------------------------------------------------------------------------------------


def test_the_page_is_revalidated_and_hashed_assets_are_cached(tmp_path):
    with serve(tmp_path) as server:
        assert call(server, "GET", "/")[2]["cache-control"] == "no-cache"
        assert "immutable" in call(server, "GET", "/assets/app-abc123.js")[2]["cache-control"]


# --- outside the console ---------------------------------------------------------------------------


def test_metrics_snapshot_reports_bucket_percentiles():
    from interlock import metrics

    metrics.reset()
    for us in (40, 60, 120, 120, 300, 900, 4000):
        metrics.record("ALLOW", "call", None, elapsed_us=us)
    latency = metrics.snapshot()["latency_us"]
    assert (latency["p50"], latency["p99"]) == (250, 5000)
    metrics.reset()
    assert metrics.snapshot()["latency_us"]["p99"] is None


@pytest.mark.parametrize("command, flagged", [
    ("curl -X POST -d '{}' http://127.0.0.1:8787/api/reviews/r-1a2b3c4d/approve", True),
    ("curl http://localhost:7878/api/unlock -d '{\"code\":\"x\"}'", True),
    ("curl -X PUT localhost:9000/api/policy", True),
    ("python3 -c 'import urllib.request; urllib.request.urlopen(\"http://127.0.0.1:8787/api/unlock\")'", True),
    ("node -e \"fetch('http://[::1]:8787/api/reviews/r-1/reject',{method:'POST'})\"", True),
    ("wget -qO- http://127.0.0.1:8787/api/receipts", False),
    ("curl http://127.0.0.1:8787/api/reviews", False),
    ("curl https://example.com/api/unlock", False),
])
def test_calling_the_console_write_api_is_tampering(command, flagged):
    from interlock.shell.intents import analyze

    hits = [i for i in analyze(command) if i.kind == "interlock.tamper" and i.detail == "console"]
    assert bool(hits) is flagged

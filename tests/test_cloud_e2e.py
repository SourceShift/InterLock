"""The whole cloud plane end to end: enroll, review, policy, receipts, console.

This is the acceptance walk for the operations milestone. It is skipped unless
an operator points it at a disposable Postgres database::

    IL_CLOUD_E2E=1 IL_CLOUD_DSN=postgresql://... \\
        python3 -m pytest -q tests/test_cloud_e2e.py

It uses the real :class:`~interlock.cloud.store.PostgresStore`, the real ASGI
app through an in-process HTTP transport, a real
:class:`~interlock.cloud.connector.runner.Connector` in a temporary
``IL_CLOUD_HOME``, and a real :class:`interlock.reviews.ReviewQueue`. Nothing
between the host and the plane is mocked: the enrollment token is consumed by
the route, the grant is signed by the plane and verified by the host, the
policy artifact is compiled, signed, fetched and swapped, and the receipts are
signed by the host key the plane pinned at enrollment.

The six steps map to the milestone's acceptance list:

1. bootstrap an org and an owner through the store/admin seam;
2. enroll a host and prove the connector wrote a 0600 config;
3. file a review locally, upload it, approve it over HTTP, and prove the
   connector applies the signed grant and the local queue settles;
4. compile and publish a policy, prove the connector swaps it and that the
   active artifact's sha matches the signed manifest, then evaluate one event;
5. write a receipt, upload it, verify it through ``/v1/audit`` and export it
   as JSONL;
6. prove the loopback console still refuses a non-loopback bind.

The long polls are shortened to zero in this process: their timing is covered
by the route tests, and a six-step flow should not spend a minute asleep.
"""
from __future__ import annotations

import asyncio
import json
import os
import stat
import time
import uuid
from urllib.parse import urlsplit

import pytest

if os.environ.get("IL_CLOUD_E2E") != "1" or not os.environ.get("IL_CLOUD_DSN"):
    pytest.skip(
        "set IL_CLOUD_E2E=1 and IL_CLOUD_DSN to run the cloud end-to-end flow",
        allow_module_level=True,
    )

pytest.importorskip("psycopg")

from interlock import Decision  # noqa: E402
from interlock.approval import make_request  # noqa: E402
from interlock.cloud import migrate  # noqa: E402
from interlock.cloud.api import grant_routes, policy_routes  # noqa: E402
from interlock.cloud.app import CloudApp  # noqa: E402
from interlock.cloud.config import CloudConfig  # noqa: E402
from interlock.cloud.connector.config import CloudHome  # noqa: E402
from interlock.cloud.connector.runner import Connector  # noqa: E402
from interlock.cloud.connector.transport import TransportError  # noqa: E402
from interlock.cloud.store import PostgresStore  # noqa: E402
from interlock.enforce import Verdict  # noqa: E402
from interlock.event import SensorEvent  # noqa: E402
from interlock.mesh.ed25519 import generate_seed  # noqa: E402
from interlock.receipt import Receipt, verify_chain  # noqa: E402
from interlock.receipt_ed25519 import ed25519_verifier, public_key  # noqa: E402
from interlock.reviews import ReviewQueue, binding_hash  # noqa: E402
from tests._c4_helpers import KEK, ed25519_chain  # noqa: E402
from tests.fixtures.cloud.rules_module import scope_document  # noqa: E402

RULES_MODULE = "tests.fixtures.cloud.rules_module:templates"
PLANE_URL = "http://127.0.0.1:8787"


class _AsgiTransport:
    """Drive the ASGI app exactly where the connector would use a socket."""

    base_url = PLANE_URL

    def __init__(self, app: CloudApp) -> None:
        self.app = app

    def request(self, method, path, body=None, headers=None, timeout=None):
        target = urlsplit(path)
        sent = []
        payload = b"" if body is None else bytes(body)

        async def receive():
            return {"type": "http.request", "body": payload,
                    "more_body": False}

        async def send(message):
            sent.append(message)

        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": method,
            "scheme": "http",
            "path": target.path,
            "raw_path": target.path.encode(),
            "query_string": target.query.encode(),
            "headers": [(str(name).lower().encode(), str(value).encode())
                        for name, value in (headers or {}).items()],
            "client": ("127.0.0.1", 40000),
            "server": ("127.0.0.1", 8787),
        }
        try:
            asyncio.run(self.app(scope, receive, send))
        except Exception as exc:  # the connector's retry seam
            raise TransportError("in-process transport failed: {}".format(exc))
        start = next(message for message in sent
                     if message["type"] == "http.response.start")
        response_headers = {}
        for name, value in start["headers"]:
            response_headers.setdefault(name.decode().lower(),
                                        value.decode())
        raw = b"".join(message.get("body", b"") for message in sent
                       if message["type"] == "http.response.body")
        return start["status"], response_headers, raw


def _call(transport, path, *, method="GET", headers=None, body=None):
    status, response_headers, raw = transport.request(
        method, path, body=body, headers=headers)
    try:
        decoded = json.loads(raw) if raw else None
    except (UnicodeDecodeError, ValueError):
        decoded = None
    return status, response_headers, decoded, raw


def _post(transport, path, headers, payload):
    merged = dict(headers)
    merged.setdefault("content-type", "application/json")
    return _call(transport, path, method="POST", headers=merged,
                 body=json.dumps(payload).encode())


def _session_headers(app, org, user):
    raw = app.sessions.login(user)
    session = app.store.session_by_token_hash(app.sessions.hash(raw),
                                              org_id=org.id)
    app.sessions.mark_step_up(session, "webauthn", now=time.time())
    return {
        "cookie": "__Host-il_session=" + app.sessions.cookie_value(org.id, raw),
        "x-csrf-token": app.sessions.csrf_token(session.id),
    }, session


def _age_step_up(app, session):
    """Persist a step-up old enough that the freshness rule must refuse it."""
    app.sessions.mark_step_up(session, "totp", now=time.time() - 3600)


def _refresh_step_up(app, session):
    app.sessions.mark_step_up(session, "webauthn", now=time.time())


def _scope(slug):
    document = scope_document()
    document["bindings"] = {
        slug: [
            {"template": "shell_allowlist",
             "params": {"allow": ["ls", "pwd"]}},
        ],
    }
    return document


@pytest.fixture()
def flow(monkeypatch):
    """One org, one owner, one app sharing the operator's Postgres."""
    # The long poll is proven by its own route tests; this walk must not
    # sleep for 25 seconds between steps.
    monkeypatch.setattr(grant_routes, "MAX_WAIT_SECONDS", 0)
    monkeypatch.setattr(policy_routes, "MAX_WAIT_SECONDS", 0)

    dsn = os.environ["IL_CLOUD_DSN"]
    migrate.run(dsn)
    store = PostgresStore(dsn)
    slug = "e2e" + uuid.uuid4().hex[:10]
    org = store.create_org(slug=slug, name="E2E")
    user = store.create_user(org.id, issuer="https://idp.example.test",
                             subject="owner-" + slug, email="owner@e2e.test",
                             role="owner")
    app = CloudApp(
        CloudConfig(session_secret="s" * 32, preview_kek=KEK),
        store=store, ping=lambda _dsn: True, clock=time.time,
        approval_seed=generate_seed(), policy_seed=generate_seed(),
    )
    headers, session = _session_headers(app, org, user)
    return {
        "store": store, "org": org, "user": user, "app": app,
        "headers": headers, "session": session, "slug": slug,
        "transport": _AsgiTransport(app),
    }


# -- 1. bootstrap -------------------------------------------------------

def test_step_one_bootstraps_the_org_and_owner(flow):
    store, org = flow["store"], flow["org"]
    assert store.org_by_slug(flow["slug"]).id == org.id
    status, _h, body, _raw = _call(
        flow["transport"], "/v1/org", headers=flow["headers"])
    assert status == 200, body
    assert body["slug"] == flow["slug"]
    status, _h, members, _raw = _call(
        flow["transport"], "/v1/members", headers=flow["headers"])
    assert status == 200, members
    assert members["members"][0]["role"] == "owner"


# -- 2. enrollment ------------------------------------------------------

def test_step_two_enrolls_a_host_with_a_0600_config(flow, tmp_path):
    token_id, raw_token = flow["store"].create_enrollment_token(
        flow["org"].id, host_name="e2e-host", now=time.time())
    assert token_id

    home = CloudHome(tmp_path / "home")
    connector = Connector(home, flow["transport"], clock=time.time,
                          sleep=lambda _seconds: None, max_attempts=1)
    result = connector.enroll(PLANE_URL, raw_token, "e2e-host")

    assert result["ok"] is True, result
    assert connector.config["org_id"] == flow["org"].id
    assert connector.config["host_id"] == result["host_id"]
    assert connector.config["plane_public_keys"]["approval"]
    assert stat.S_IMODE(home.config_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(home.seed_path.stat().st_mode) == 0o600
    assert (home.root / "receipts.jsonl").parent == home.root
    token = flow["store"].enrollment_token_by_id(flow["org"].id, token_id)
    assert token.used_at is not None


# -- 3. review -> decision -> grant ------------------------------------

def test_step_three_files_uploads_approves_and_applies_a_review(flow, tmp_path):
    store, org = flow["store"], flow["org"]
    token_id, raw_token = store.create_enrollment_token(
        org.id, host_name="e2e-host", now=time.time())
    assert token_id

    queue = ReviewQueue(str(tmp_path / "reviews.db"))
    home = CloudHome(tmp_path / "home")
    connector = Connector(home, flow["transport"], queue=queue,
                          clock=time.time, sleep=lambda _seconds: None,
                          max_attempts=1)
    enrolled = connector.enroll(PLANE_URL, raw_token, "e2e-host")
    assert enrolled["ok"] is True, enrolled

    request = make_request(
        SensorEvent("run", {"cmd": "npm publish"}, principal="agent"),
        Decision.escalate("publishing", "publish"), "epoch1")
    review = queue.lookup_or_file(binding_hash(request), request)
    assert review.status == "pending"

    first = connector.run_once()
    assert first["reviews"] == 1, first
    assert first["uploaded"] >= 1, first

    status, _h, body, _raw = _call(
        flow["transport"], "/v1/reviews", headers=flow["headers"])
    assert status == 200, body
    assert [item["id"] for item in body["reviews"]] == [review.id]

    # A stale step-up is refused at the decision boundary; only a refresh
    # through the session service lets the decision through.
    _age_step_up(flow["app"], flow["session"])
    status, _h, stale, _raw = _post(
        flow["transport"],
        "/v1/reviews/{}/decision".format(review.id),
        flow["headers"], {"decision": "approve"})
    assert status == 403, stale
    assert stale["error"]["code"] == "step_up_required", stale

    _refresh_step_up(flow["app"], flow["session"])
    status, _h, decision, _raw = _post(
        flow["transport"],
        "/v1/reviews/{}/decision".format(review.id),
        flow["headers"], {"decision": "approve"})
    assert status == 200, decision
    assert decision["grant_id"]

    second = connector.run_once()
    assert second["uploaded"] >= 0, second
    assert queue.get(review.id).status == "approved"
    status = connector.status()
    assert status["grants_applied"] == 1, status
    assert status["grants_acked"] == 1, status


# -- 4. policy compile -> publish -> swap -> evaluate -------------------

def test_step_four_publishes_a_policy_the_connector_swaps_and_evaluates(
        flow, tmp_path):
    store, org = flow["store"], flow["org"]
    _token_id, raw_token = store.create_enrollment_token(
        org.id, host_name="e2e-host", now=time.time())

    home = CloudHome(tmp_path / "home")
    connector = Connector(home, flow["transport"], clock=time.time,
                          sleep=lambda _seconds: None, max_attempts=1)
    assert connector.enroll(PLANE_URL, raw_token, "e2e-host")["ok"] is True

    _refresh_step_up(flow["app"], flow["session"])
    compile_body = {
        "documents": [],
        "scope": _scope(flow["slug"]),
        "rules_module": RULES_MODULE,
    }
    status, _h, compiled, _raw = _post(
        flow["transport"], "/v1/policy/compile", flow["headers"], compile_body)
    assert status == 200, compiled

    # Compiling is read-only; publishing is the step-up boundary. Prove the
    # stale session is refused there, then refresh and publish.
    _age_step_up(flow["app"], flow["session"])
    status, _h, stale, _raw = _post(
        flow["transport"], "/v1/policy/publish", flow["headers"], {
            "sha256": compiled["sha256"],
            "target": {"kind": "ring", "id": "stable"},
            "mode": "enforce",
            "expires_in": 3600,
        })
    assert status == 403, stale
    assert stale["error"]["code"] == "step_up_required", stale
    _refresh_step_up(flow["app"], flow["session"])

    status, _h, published, _raw = _post(
        flow["transport"], "/v1/policy/publish", flow["headers"], {
            "sha256": compiled["sha256"],
            "target": {"kind": "ring", "id": "stable"},
            "mode": "enforce",
            "expires_in": 3600,
        })
    assert status == 201, published
    manifest_sha = published["manifest"]["artifact"]["sha256"]
    assert manifest_sha == compiled["sha256"]

    connector.poll_policy = True
    cycle = connector.run_once()
    assert cycle["policy"]["ok"] is True, cycle
    status = connector.policy_distributor.status()
    assert status["artifact_sha256"] == manifest_sha, status
    assert status["manifest_version"] == published["manifest"]["version"]
    assert status["mode"] == "enforce"

    policy = connector.policy_distributor.active_policy()
    blocked = policy.evaluate(SensorEvent(
        "run_shell", {"cmd": "rm -rf /"}, principal=flow["slug"]))
    allowed = policy.evaluate(SensorEvent(
        "run_shell", {"cmd": "ls -la"}, principal=flow["slug"]))
    assert blocked.verdict is Verdict.BLOCK
    assert allowed.verdict is not Verdict.BLOCK


# -- 5. receipts -> audit -> export ------------------------------------

def test_step_five_uploads_receipts_verifies_the_chain_and_exports_jsonl(
        flow, tmp_path):
    store, org = flow["store"], flow["org"]
    _token_id, raw_token = store.create_enrollment_token(
        org.id, host_name="e2e-host", now=time.time())

    home = CloudHome(tmp_path / "home")
    connector = Connector(home, flow["transport"], clock=time.time,
                          sleep=lambda _seconds: None, max_attempts=1)
    assert connector.enroll(PLANE_URL, raw_token, "e2e-host")["ok"] is True

    seed = home.load_seed()
    receipts = ed25519_chain(seed, count=3, base_ts=time.time() - 60)
    log = home.root / "receipts.jsonl"
    log.write_text("".join(receipt.to_json() + "\n" for receipt in receipts),
                   encoding="utf-8")

    cycle = connector.run_once()
    assert cycle["receipts_spooled"] == 3, cycle
    assert cycle["uploaded"] >= 1, cycle

    host_id = connector.config["host_id"]
    status, _h, audit, _raw = _call(
        flow["transport"], "/v1/audit?host=" + host_id,
        headers=flow["headers"])
    assert status == 200, audit
    assert len(audit["receipts"]) == 3
    assert {item["action"] for item in audit["receipts"]} == {"shell"}
    assert all(item["verification"] is not None
               for item in audit["receipts"])

    status, response_headers, _decoded, raw = _call(
        flow["transport"], "/v1/audit/export?host=" + host_id,
        headers=flow["headers"])
    assert status == 200
    assert response_headers["content-type"].startswith(
        "application/x-ndjson")
    lines = [line for line in raw.decode("utf-8").splitlines() if line]
    assert len(lines) == 3
    exported = [Receipt.from_json(line) for line in lines]
    assert [item.mac for item in exported] == [item.mac for item in receipts]
    # The export is only served after the plane verified the whole chain;
    # the host can verify it again with the key it enrolled.
    assert verify_chain(exported, None, b"",
                        verifier=ed25519_verifier(public_key(seed))) is None


# -- 6. the loopback console invariant --------------------------------

def test_step_six_the_console_refuses_a_non_loopback_bind():
    from interlock.console.__main__ import main as console_main

    assert console_main(["--host", "0.0.0.0", "--port", "0"]) == 2

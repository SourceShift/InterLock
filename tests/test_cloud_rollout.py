"""The plane's C5 surface: compile, publish, fetch, hints, kills and rollouts.

The human routes are session + step-up; the agent routes are bearer-key and
scoped to the key's host. Hints carry a version and a kill epoch and nothing
else. A rollout advances canary -> 10 -> 100, holds on a health regression and
rolls back by publishing the old source at a *higher* version.
"""
from __future__ import annotations

import asyncio
import hashlib
import json

from interlock.cloud.app import CloudApp
from interlock.cloud.config import CloudConfig
from interlock.cloud.enrollment import generate_agent_key
from interlock.cloud.policy.compile import compile_from_source
from interlock.cloud.policy.manifest import verify_kill, verify_manifest
from interlock.cloud.store import MemoryStore
from interlock.event import SensorEvent
from interlock.mesh.ed25519 import generate_seed, public_key
from tests.fixtures.cloud.rules_module import scope_document

NOW = 2_000_000_000.0
MODULE = "tests.fixtures.cloud.rules_module:templates"


class _Clock:
    def __init__(self, value=NOW):
        self.value = float(value)

    def __call__(self):
        return self.value


def _call(instance, path, method="GET", headers=None, body=b"", query=b""):
    sent = []

    async def receive():
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        sent.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": method, "scheme": "http", "path": path,
        "raw_path": path.encode(), "query_string": query,
        "headers": [(k.encode(), v.encode()) for k, v in (headers or {}).items()],
        "client": ("127.0.0.1", 1234), "server": ("127.0.0.1", 8787),
    }
    asyncio.run(instance(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    single = {}
    for name, value in start["headers"]:
        single.setdefault(name.decode(), value.decode())
    raw = b"".join(m.get("body", b"") for m in sent
                   if m["type"] == "http.response.body")
    payload = json.loads(raw) if raw else None
    return start["status"], single, raw, payload


def _post(app, path, headers, body):
    return _call(app, path, method="POST", headers=headers,
                 body=json.dumps(body).encode())


def _setup(role="admin", scopes=("pull:policy",)):
    clock = _Clock()
    store = MemoryStore()
    org = store.create_org(slug="acme", name="Acme")
    host = store.create_host(org.id, "box", owner_subject="u1")
    user = store.create_user(org, issuer="https://idp.example",
                             subject="u1", email="a@acme.test", role=role)
    seed = generate_seed()
    app = CloudApp(CloudConfig(session_secret="s" * 32), store=store,
                   ping=lambda dsn: True, clock=clock, policy_seed=seed)
    raw = app.sessions.login(user)
    session = store.session_by_token_hash(app.sessions.hash(raw),
                                          org_id=org.id)
    app.sessions.mark_step_up(session, "webauthn", now=clock.value)
    headers = {
        "cookie": "__Host-il_session=" + app.sessions.cookie_value(org.id, raw),
        "x-csrf-token": app.sessions.csrf_token(session.id),
        "content-type": "application/json",
    }
    agent_raw, prefix, digest = generate_agent_key()
    store.create_agent_key(org.id, host.id, prefix=prefix, secret_hash=digest,
                           scopes=list(scopes))
    agent_headers = {
        "authorization": "Bearer " + agent_raw,
        "x-interlock-org": org.id,
        "content-type": "application/json",
    }
    return {
        "app": app, "store": store, "org": org, "host": host, "user": user,
        "session": session, "headers": headers, "agent": agent_headers,
        "seed": seed, "clock": clock,
    }


def _scope(allow=("ls", "pwd")):
    document = scope_document()
    document["bindings"]["acme"] = [
        {"template": "shell_allowlist", "params": {"allow": list(allow)}},
    ]
    return document


def _publish(ctx, *, allow=("ls", "pwd"), version_target="ring",
             rollout=None, expires_in=3600):
    body = {
        "documents": [],
        "scope": _scope(allow),
        "rules_module": MODULE,
        "target": {"kind": version_target,
                   "id": "stable" if version_target == "ring" else ctx["host"].id},
        "mode": "enforce",
        "expires_in": expires_in,
    }
    if rollout is not None:
        body["rollout"] = rollout
    return _post(ctx["app"], "/v1/policy/publish", ctx["headers"], body)


def _public(ctx):
    return public_key(ctx["seed"])


def _verify(ctx, manifest):
    return verify_manifest(
        manifest, _public(ctx), org_id=ctx["org"].id,
        host_id=ctx["host"].id, ring="stable", now=NOW,
        agent_version="0.0.1")


# -- compile ------------------------------------------------------------

def test_compile_stores_the_artifact_without_publishing():
    ctx = _setup()
    body = {"documents": [], "scope": _scope(), "rules_module": MODULE}
    first_status, _h, _raw, first = _post(
        ctx["app"], "/v1/policy/compile", ctx["headers"], body)
    second_status, _h, _raw, second = _post(
        ctx["app"], "/v1/policy/compile", ctx["headers"], body)

    assert (first_status, second_status) == (200, 200)
    assert first["sha256"] == second["sha256"]
    assert first["artifact"]["epoch"] == first["epoch"]
    assert ctx["store"].policy_manifests == {}
    # Compiling stores the bytes and their source so publish can sign exactly
    # what the admin reviewed; compiling twice is one source version.
    assert ctx["store"].artifact_bytes(ctx["org"].id, first["sha256"]) is not None
    assert first["source_version"] == second["source_version"] == 1


def test_publish_signs_a_previously_compiled_artifact_by_sha():
    ctx = _setup()
    body = {"documents": [], "scope": _scope(), "rules_module": MODULE}
    _status, _h, _raw, compiled = _post(
        ctx["app"], "/v1/policy/compile", ctx["headers"], body)

    status, _h, _raw, published = _post(
        ctx["app"], "/v1/policy/publish", ctx["headers"], {
            "sha256": compiled["sha256"],
            "target": {"kind": "ring", "id": "stable"},
            "mode": "enforce",
            "expires_in": 3600,
        })
    assert status == 201, published
    manifest = published["manifest"]
    assert manifest["artifact"]["sha256"] == compiled["sha256"]
    assert manifest["epoch"] == compiled["epoch"]
    assert published["source_version"] == compiled["source_version"]
    assert _verify(ctx, manifest) is None


def test_publishing_an_unknown_sha_is_a_404():
    ctx = _setup()
    status, _h, _raw, payload = _post(
        ctx["app"], "/v1/policy/publish", ctx["headers"], {
            "sha256": "0" * 64,
            "target": {"kind": "ring", "id": "stable"},
        })
    assert status == 404
    assert payload["error"]["code"] == "unknown_artifact"


def test_compile_refuses_a_broken_binding_and_a_bad_failure_policy():
    ctx = _setup()
    broken = _scope()
    broken["bindings"]["acme"].append({"template": "ghost", "params": {}})
    status, _h, _raw, payload = _post(
        ctx["app"], "/v1/policy/compile", ctx["headers"],
        {"documents": [], "scope": broken, "rules_module": MODULE})
    assert status == 422 and payload["error"]["code"] == "bad_artifact"

    status, _h, _raw, payload = _post(
        ctx["app"], "/v1/policy/compile", ctx["headers"],
        {"documents": [], "scope": _scope(), "rules_module": MODULE,
         "failure_policy": {"shell": "maybe"}})
    assert status == 422 and payload["error"]["code"] == "bad_artifact"


# -- publish and fetch --------------------------------------------------

def test_publish_stores_bytes_and_a_manifest_a_host_can_verify():
    ctx = _setup()
    status, _h, raw, payload = _publish(ctx)
    assert status == 201, payload
    manifest = payload["manifest"]
    assert manifest["version"] == 1
    assert manifest["org_id"] == ctx["org"].id
    assert manifest["target"] == {"kind": "ring", "id": "stable"}
    assert _verify(ctx, manifest) is None
    assert manifest["sig"] and len(bytes.fromhex(manifest["sig"])) == 64

    sha = manifest["artifact"]["sha256"]
    stored = ctx["store"].artifact_bytes(ctx["org"].id, sha)
    assert stored is not None
    assert hashlib.sha256(stored).hexdigest() == sha
    assert len(stored) == manifest["artifact"]["size"]
    assert json.loads(stored.decode("utf-8"))["epoch"] == manifest["epoch"]


def test_an_agent_fetches_its_manifest_and_artifact_by_bearer_key():
    ctx = _setup()
    _status, _h, _raw, published = _publish(ctx)
    sha = published["manifest"]["artifact"]["sha256"]

    status, _h, _raw, manifest = _call(
        ctx["app"], "/v1/manifest", headers=ctx["agent"],
        query=b"ring=stable")
    assert status == 200 and manifest["version"] == 1
    assert manifest["sig"] == published["manifest"]["sig"]

    status, headers, raw, payload = _call(
        ctx["app"], "/v1/artifacts/" + sha, headers=ctx["agent"])
    assert status == 200
    assert headers["content-type"].startswith("application/json")
    assert raw == ctx["store"].artifact_bytes(ctx["org"].id, sha)
    assert payload == json.loads(raw.decode("utf-8"))  # bytes, not an envelope


def test_host_targets_beat_ring_targets_which_beat_org_targets():
    ctx = _setup()
    assert _publish(ctx, version_target="org")[0] == 201
    assert _publish(ctx, version_target="ring")[0] == 201
    assert _publish(ctx, version_target="host")[0] == 201

    status, _h, _raw, manifest = _call(
        ctx["app"], "/v1/manifest", headers=ctx["agent"], query=b"ring=stable")
    assert status == 200
    assert manifest["version"] == 3
    assert manifest["target"]["kind"] == "host"


def test_hints_carry_only_the_version_and_kill_epoch():
    ctx = _setup()
    _publish(ctx)
    status, _h, _raw, hint = _call(
        ctx["app"], "/v1/hints", headers=ctx["agent"],
        query=b"since=0&kill=0&ring=stable&wait=0")
    assert status == 200
    assert set(hint) == {"version", "kill_epoch", "poll_after"}
    assert hint["version"] == 1 and hint["kill_epoch"] == 0


def test_an_unknown_or_foreign_artifact_is_404():
    ctx = _setup()
    _publish(ctx)
    status, _h, _raw, payload = _call(
        ctx["app"], "/v1/artifacts/" + "0" * 64, headers=ctx["agent"])
    assert status == 404 and payload["error"]["code"] == "not_found"
    status, _h, _raw, payload = _call(
        ctx["app"], "/v1/artifacts/not-a-hash", headers=ctx["agent"])
    assert status == 404 and payload["error"]["code"] == "not_found"


def test_another_orgs_agent_sees_neither_the_manifest_nor_the_artifact():
    ctx = _setup()
    _status, _h, _raw, published = _publish(ctx)
    sha = published["manifest"]["artifact"]["sha256"]

    store = ctx["store"]
    other = store.create_org(slug="other", name="Other")
    other_host = store.create_host(other.id, "other-box", owner_subject="u2")
    raw, prefix, digest = generate_agent_key()
    store.create_agent_key(other.id, other_host.id, prefix=prefix,
                           secret_hash=digest, scopes=["pull:policy"])
    headers = {"authorization": "Bearer " + raw, "x-interlock-org": other.id}

    status, _h, _raw, payload = _call(
        ctx["app"], "/v1/manifest", headers=headers, query=b"ring=stable")
    assert status == 404 and payload["error"]["code"] == "no_manifest"
    status, _h, _raw, payload = _call(
        ctx["app"], "/v1/artifacts/" + sha, headers=headers)
    assert status == 404 and payload["error"]["code"] == "not_found"


# -- authorisation ------------------------------------------------------

def test_publishing_needs_a_fresh_step_up():
    ctx = _setup()
    ctx["session"].step_up_at = None
    status, _h, _raw, payload = _publish(ctx)
    assert status == 403
    assert payload["error"]["code"] == "step_up_required"


def test_an_auditor_may_list_rollouts_but_not_publish():
    ctx = _setup(role="auditor")
    status, _h, _raw, payload = _call(
        ctx["app"], "/v1/policy/rollouts", headers=ctx["headers"])
    assert status == 200 and payload["rollouts"] == []
    status, _h, _raw, payload = _publish(ctx)
    assert status == 403


# -- kills --------------------------------------------------------------

def test_a_kill_is_signed_recorded_and_visible_to_its_ring_only():
    ctx = _setup(role="owner")
    _publish(ctx)
    status, _h, _raw, payload = _post(
        ctx["app"], "/v1/policy/kill", ctx["headers"],
        {"id": "k-1", "reason": "credential leak",
         "target": {"kind": "ring", "id": "stable"}})
    assert status == 201, payload
    assert verify_kill(payload["kill"], _public(ctx), org_id=ctx["org"].id,
                       host_id=ctx["host"].id, ring="stable") is None

    status, _h, _raw, listed = _call(
        ctx["app"], "/v1/kills", headers=ctx["agent"],
        query=b"since=0&ring=stable")
    assert status == 200
    assert [kill["id"] for kill in listed["kills"]] == ["k-1"]

    status, _h, _raw, listed = _call(
        ctx["app"], "/v1/kills", headers=ctx["agent"],
        query=b"since=0&ring=canary")
    assert status == 200 and listed["kills"] == []

    status, _h, _raw, hint = _call(
        ctx["app"], "/v1/hints", headers=ctx["agent"],
        query=b"since=0&kill=0&ring=stable&wait=0")
    assert status == 200 and hint["kill_epoch"] == 1


# -- rollouts -----------------------------------------------------------

def test_a_rollout_advances_canary_to_ten_to_one_hundred_and_holds():
    ctx = _setup()
    _publish(ctx)
    status, _h, _raw, second = _publish(
        ctx, allow=("cat",), rollout={"id": "r1", "ring": "stable",
                                      "percent": 0})
    assert status == 201, second
    assert second["manifest"]["version"] == 2
    assert second["rollout"]["state"] == "canary"

    status, _h, _raw, promoted = _post(
        ctx["app"], "/v1/policy/rollouts/r1/promote", ctx["headers"],
        {"id": "r1"})
    assert status == 200 and promoted["rollout"]["percent"] == 10

    status, _h, _raw, held = _post(
        ctx["app"], "/v1/policy/rollouts/r1/promote", ctx["headers"],
        {"id": "r1", "health": "regressed"})
    assert status == 200 and held["held"] is True
    assert held["rollout"]["percent"] == 10
    assert held["rollout"]["health"] == "failed"
    assert held["rollout"]["reason"] == "regressed"

    status, _h, _raw, promoted = _post(
        ctx["app"], "/v1/policy/rollouts/r1/promote", ctx["headers"],
        {"id": "r1", "percent": 100})
    assert status == 200 and promoted["rollout"]["percent"] == 100

    status, _h, _raw, listed = _call(
        ctx["app"], "/v1/policy/rollouts", headers=ctx["headers"])
    assert status == 200
    assert [(row["id"], row["percent"]) for row in listed["rollouts"]] == [
        ("r1", 100)]


def test_rollback_republishes_the_previous_source_above_every_host():
    ctx = _setup()
    v1 = _publish(ctx, allow=("ls",))[3]
    v2 = _publish(ctx, allow=("cat",),
                  rollout={"id": "r1", "ring": "stable", "percent": 0})[3]
    assert (v1["manifest"]["version"], v2["manifest"]["version"]) == (1, 2)

    status, _h, _raw, rolled = _post(
        ctx["app"], "/v1/policy/rollouts/r1/promote", ctx["headers"],
        {"id": "r1", "action": "rollback"})
    assert status == 200, rolled
    manifest = rolled["manifest"]
    assert manifest["version"] == 3
    assert manifest["target"] == {"kind": "ring", "id": "stable"}
    assert _verify(ctx, manifest) is None
    assert rolled["rollout"]["state"] == "rolled_back"

    # The rollback artifact is the source v1, recompiled at a higher version.
    expected = compile_from_source([], _scope(("ls",)), rules_module=MODULE)
    assert manifest["epoch"] == expected.epoch
    assert manifest["artifact"]["sha256"] == expected.sha256
    stored = ctx["store"].artifact_bytes(ctx["org"].id, expected.sha256)
    assert stored == expected.artifact_bytes

    status, _h, _raw, current = _call(
        ctx["app"], "/v1/manifest", headers=ctx["agent"], query=b"ring=stable")
    assert status == 200 and current["version"] == 3


def test_rollback_without_source_history_is_refused_not_guessed():
    ctx = _setup()
    _publish(ctx, rollout={"id": "r1", "ring": "stable", "percent": 0})
    status, _h, _raw, payload = _post(
        ctx["app"], "/v1/policy/rollouts/r1/promote", ctx["headers"],
        {"id": "r1", "action": "rollback"})
    assert status == 422
    assert payload["error"]["code"] == "no_previous_source"
    assert ctx["store"].next_manifest_version(ctx["org"].id) == 2


def test_an_artifact_is_evaluable_by_the_evaluator_that_fetched_it():
    ctx = _setup()
    _status, _h, _raw, published = _publish(ctx, allow=("ls",))
    from interlock.policy.artifact import load_artifact

    sha = published["manifest"]["artifact"]["sha256"]
    raw = ctx["store"].artifact_bytes(ctx["org"].id, sha)
    policy = load_artifact(raw)
    event = SensorEvent("run_shell", {"cmd": "ls"}, principal="acme")
    assert policy.evaluate(event).verdict.name == "ALLOW"
    assert policy.epoch == published["manifest"]["epoch"]

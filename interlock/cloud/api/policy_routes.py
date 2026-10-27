"""Policy compilation, publication and distribution routes (C5).

The plane compiles once and publishes a *signed manifest* naming immutable
artifact bytes by sha256.  The four human routes are administrative (publish,
kill and promote require a fresh step-up); the four agent routes are scoped to
the authenticated key's host.  Hints are untrusted: they carry only the
current version and kill epoch, and a host always verifies the manifest it
fetches before acting on it.

Cross-org access is a 404, never a 403: an artifact or manifest belonging to
another org simply does not exist for this caller.
"""
from __future__ import annotations

import asyncio
import re
import time
import uuid
from functools import partial
from typing import Any, Dict, List

from ..auth.stepup import StepUpError, StepUpService
from ..http import ApiError, Request, Response, json_response, parse_json_body
from ..policy.compile import CompileError, compile_from_source
from ...policy.artifact import ArtifactError, load_artifact
from ..policy.manifest import (
    MANIFEST_MAX_TTL,
    MANIFEST_MODES,
    TARGET_KINDS,
    kill_applies,
    policy_key_id,
    sign_kill,
    sign_manifest,
)
from ...mesh.ed25519 import public_key

#: The longest a hints poll may block, matching the grants poll.
MAX_WAIT_SECONDS = 25
POLL_TICK_SECONDS = 0.25

#: A manifest may not outlive FR-043's seven days.
DEFAULT_MANIFEST_TTL = 24 * 60 * 60
MIN_MANIFEST_TTL = 60

#: Artifact hashes are lowercase sha256 hex.
_SHA256 = re.compile(r"^[0-9a-f]{64}$")

#: Health observations that stop a rollout where it is.  A canary that is
#: failing must not advance just because the next promotion was requested.
REGRESSED_HEALTH = frozenset((
    "failed", "regressed", "regression", "unhealthy", "error",
))


def _now(app: Any) -> float:
    clock = getattr(app, "_clock", None)
    return float(clock()) if callable(clock) else time.time()


def _require_step_up(app: Any, request: Request, action: str) -> None:
    session = getattr(request, "session", None)
    at = getattr(session, "step_up_at", None)
    if not StepUpService.fresh(at, now=_now(app)):
        raise StepUpError("step_up_required",
                          "a fresh step-up is required to {}".format(action))


def _int_query(request: Request, name: str, default: int) -> int:
    raw = request.query_one(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise ApiError(422, "invalid_request",
                       "{} must be an integer".format(name)) from None


def _compile(app: Any, body: Dict[str, Any]):
    try:
        return compile_from_source(
            body.get("documents") or [],
            body.get("scope") or {"version": 1, "bindings": {}},
            rules_module=body.get("rules_module"),
            failure_policy=body.get("failure_policy"),
        )
    except CompileError as exc:
        raise ApiError(422, exc.code, exc.message) from None
    except Exception as exc:  # malformed input is a refusal, not a 500
        raise ApiError(422, "bad_artifact",
                       "could not compile policy: {}".format(type(exc).__name__)) from None


def _public_hex(app: Any) -> str:
    try:
        return public_key(app.policy_seed()).hex()
    except Exception:
        raise ApiError(503, "policy_key_missing",
                       "policy signing key is not configured") from None


async def compile_policy(app: Any, request: Request) -> Response:
    """Compile authored documents/scope, store the artifact, return the report.

    Storing here is what lets ``POST /v1/policy/publish`` sign *the bytes the
    admin reviewed* by sha256, rather than recompiling and hoping the
    environment (notably the detector catalog id) did not move in between.
    """
    body = parse_json_body(request.body, request.headers, (
        "documents", "scope", "rules_module", "failure_policy"))
    result = _compile(app, body)
    now = _now(app)
    oid = request.org.id
    source = _store_source(app, oid, body, result, now)
    report = result.to_dict()
    report["artifact"] = _parse(result.artifact_bytes)
    report["source_version"] = source["source_version"] if source else None
    return json_response(200, report)


def _store_source(app: Any, oid: str, body: Dict[str, Any], result: Any,
                  now: float) -> Any:
    """Store the compiled artifact and the source it was compiled from."""
    app.store.put_artifact(
        oid, result.sha256, result.artifact_bytes,
        epoch=result.epoch, compiler_version="c5", now=now)
    return app.store.put_policy_source(
        oid, body.get("documents") or [], body.get("scope") or {},
        rules_module=result.rules_module, sha256=result.sha256, now=now)


def _parse(raw: bytes) -> Dict[str, Any]:
    import json

    return json.loads(raw.decode("utf-8"))


def _target(body: Dict[str, Any]) -> Dict[str, str]:
    target = body.get("target")
    if not isinstance(target, dict):
        # A bare ``ring`` is the publish shorthand for a ring target.
        ring = body.get("ring")
        target = ({"kind": "ring", "id": ring} if isinstance(ring, str) and ring
                  else {"kind": "org", "id": ""})
    kind = target.get("kind")
    identifier = target.get("id")
    if kind not in TARGET_KINDS:
        raise ApiError(422, "invalid_request",
                       "target.kind must be one of {}".format(", ".join(TARGET_KINDS)))
    if not isinstance(identifier, str) or not identifier:
        raise ApiError(422, "invalid_request", "target.id must be a non-empty string")
    return {"kind": str(kind), "id": identifier}


def _expires(body: Dict[str, Any], now: float) -> float:
    if "expires_at" in body:
        value = body["expires_at"]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ApiError(422, "invalid_request", "expires_at must be a number")
        expires = float(value)
        if expires <= now:
            raise ApiError(422, "invalid_request", "expires_at must be in the future")
        if expires - now > MANIFEST_MAX_TTL:
            raise ApiError(422, "invalid_request",
                           "a manifest may not be valid for more than seven days")
        return expires
    ttl = body.get("expires_in", DEFAULT_MANIFEST_TTL)
    if isinstance(ttl, bool) or not isinstance(ttl, (int, float)):
        raise ApiError(422, "invalid_request", "expires_in must be a number")
    ttl = max(MIN_MANIFEST_TTL, min(MANIFEST_MAX_TTL, int(ttl)))
    return now + ttl


def _artifact_for_publish(app: Any, oid: str, body: Dict[str, Any],
                          now: float) -> Dict[str, Any]:
    """The artifact to sign: a compiled sha256, or source compiled here.

    ``sha256`` publishes exactly the bytes an admin reviewed at compile time.
    The source form stays accepted so a one-shot publish remains possible; it
    compiles, stores and links the source exactly as ``/v1/policy/compile``.
    """
    sha = body.get("sha256")
    if sha is not None:
        if not isinstance(sha, str) or not _SHA256.match(sha):
            raise ApiError(422, "invalid_request",
                           "sha256 must be lowercase 64-character hex")
        raw = app.store.artifact_bytes(oid, sha)
        if raw is None:
            raise ApiError(404, "unknown_artifact",
                           "no compiled artifact with that sha256")
        try:
            # Validation is metadata only; do not build a native plan on a
            # control-plane host that will never evaluate this artifact.
            compiled = load_artifact(raw, native_enabled=False)
        except ArtifactError as exc:
            raise ApiError(422, "bad_artifact", str(exc)) from None
        return {
            "sha256": sha, "epoch": compiled.epoch, "size": len(raw),
            "source": app.store.policy_source(oid, sha256=sha), "report": None,
        }
    result = _compile(app, body)
    return {
        "sha256": result.sha256, "epoch": result.epoch,
        "size": len(result.artifact_bytes), "report": result.to_dict(),
        "source": _store_source(app, oid, body, result, now),
    }


async def publish_manifest(app: Any, request: Request) -> Response:
    """Sign a manifest for a compiled artifact and open its rollout."""
    _require_step_up(app, request, "publish policy")
    body = parse_json_body(request.body, request.headers, (
        "sha256", "documents", "scope", "rules_module", "failure_policy",
        "target", "ring", "mode", "expires_at", "expires_in", "minimum_agent",
        "rollout"))
    mode = body.get("mode", "enforce")
    if mode not in MANIFEST_MODES:
        raise ApiError(422, "invalid_request",
                       "mode must be one of {}".format(", ".join(MANIFEST_MODES)))
    minimum_agent = body.get("minimum_agent")
    if minimum_agent is not None and not isinstance(minimum_agent, str):
        raise ApiError(422, "invalid_request", "minimum_agent must be a string")
    target = _target(body)
    org = request.org
    oid = org.id
    target_id = target["id"]
    if target["kind"] == "org":
        target_id = oid
    now = _now(app)
    try:
        artifact = _artifact_for_publish(app, oid, body, now)
        source = artifact["source"]
        version = app.store.next_manifest_version(oid)
        public_hex = _public_hex(app)
        envelope = sign_manifest(app.policy_seed(), {
            "v": 1,
            "manifest_id": "m-" + uuid.uuid4().hex[:16],
            "org_id": oid,
            "version": version,
            "epoch": artifact["epoch"],
            "target": {"kind": target["kind"], "id": target_id},
            "mode": mode,
            "issued_at": now,
            "expires_at": _expires(body, now),
            "minimum_agent": minimum_agent,
            "artifact": {
                "format": 1,
                "sha256": artifact["sha256"],
                "size": artifact["size"],
            },
            "rules_digest": artifact["epoch"],
            "key_id": policy_key_id(bytes.fromhex(public_hex)),
        })
        app.store.put_manifest(
            oid, envelope, author=getattr(request.user, "id", None), now=now)
    except ValueError as exc:
        raise ApiError(422, "invalid_request", str(exc)) from None

    rollout = None
    spec = body.get("rollout")
    if spec is not None:
        if not isinstance(spec, dict) or not isinstance(spec.get("id"), str):
            raise ApiError(422, "invalid_request", "rollout.id is required")
        ring = spec.get("ring") or (
            target_id if target["kind"] == "ring" else None)
        if not isinstance(ring, str) or not ring:
            raise ApiError(422, "invalid_request", "rollout.ring is required")
        percent = spec.get("percent", 0)
        if isinstance(percent, bool) or not isinstance(percent, int) \
                or not 0 <= percent <= 100:
            raise ApiError(422, "invalid_request",
                           "rollout.percent must be 0..100")
        try:
            rollout = app.store.rollout_open(
                oid, spec["id"], version, ring,
                percent=percent, now=now,
            )
        except ValueError as exc:
            raise ApiError(422, "invalid_request", str(exc)) from None

    source_version = source["source_version"] if source else None
    app.store.audit_append(
        oid, "policy.published",
        actor=getattr(request.user, "id", None),
        detail={"version": version, "epoch": artifact["epoch"],
                "sha256": artifact["sha256"], "target": target,
                "mode": mode, "source_version": source_version},
    )
    return json_response(201, {
        "manifest": envelope,
        "artifact": {"sha256": artifact["sha256"], "epoch": artifact["epoch"],
                     "size": artifact["size"]},
        "source_version": source_version,
        "rollout": rollout,
        "report": artifact["report"],
    })


async def get_manifest(app: Any, request: Request) -> Response:
    """The manifest that applies to the authenticated host (agent route)."""
    context = request.key
    ring = request.query_one("ring") or "stable"
    document = app.store.manifest_for_host(
        context.org_id, context.host_id, ring=ring)
    if document is None:
        raise ApiError(404, "no_manifest", "no policy manifest is published")
    return json_response(200, document)


async def get_artifact(app: Any, request: Request) -> Response:
    """Immutable artifact bytes by sha256 (agent route)."""
    sha = request.params.get("sha256") or ""
    if not _SHA256.match(sha):
        raise ApiError(404, "not_found", "no such artifact")
    data = app.store.artifact_bytes(request.key.org_id, sha)
    if data is None:
        raise ApiError(404, "not_found", "no such artifact")
    return Response(status=200, body=data, content_type="application/json")


async def get_hints(app: Any, request: Request) -> Response:
    """Long-poll the minimal change hint: version and kill epoch only."""
    since = _int_query(request, "since", 0)
    kill_since = _int_query(request, "kill", 0)
    wait = max(0, min(MAX_WAIT_SECONDS, _int_query(request, "wait", MAX_WAIT_SECONDS)))
    context = request.key
    ring = request.query_one("ring") or "stable"
    deadline = time.monotonic() + wait
    while True:
        document = app.store.manifest_for_host(
            context.org_id, context.host_id, ring=ring)
        version = int(document.get("version") or 0) if document else 0
        epoch = app.store.kill_epoch(context.org_id)
        if version > since or epoch > kill_since \
                or time.monotonic() >= deadline:
            break
        await asyncio.sleep(min(POLL_TICK_SECONDS,
                                max(0.0, deadline - time.monotonic())))
    return json_response(200, {
        "version": version,
        "kill_epoch": epoch,
        "poll_after": MAX_WAIT_SECONDS,
    })


async def publish_kill(app: Any, request: Request) -> Response:
    """Sign and record an org/ring/host kill switch (owner + step-up)."""
    _require_step_up(app, request, "publish a kill")
    body = parse_json_body(request.body, request.headers, (
        "id", "reason", "target", "issued_at"))
    kill_id = body.get("id")
    reason = body.get("reason")
    if not isinstance(kill_id, str) or not kill_id:
        raise ApiError(422, "invalid_request", "id is required")
    if not isinstance(reason, str) or not reason:
        raise ApiError(422, "invalid_request", "reason is required")
    target = _target(body)
    oid = request.org.id
    if target["kind"] == "org":
        target["id"] = oid
    now = _now(app)
    envelope = sign_kill(app.policy_seed(), {
        "v": 1,
        "id": kill_id,
        "org_id": oid,
        "reason": reason,
        "target": target,
        "issued_at": now,
    })
    record = app.store.put_kill(
        oid, envelope, author=getattr(request.user, "id", None), now=now)
    app.store.audit_append(
        oid, "policy.kill_published",
        actor=getattr(request.user, "id", None),
        detail={"id": kill_id, "target": target, "kill_epoch": record["kill_epoch"]},
    )
    return json_response(201, {"kill": envelope,
                               "kill_epoch": record["kill_epoch"]})


async def list_kills(app: Any, request: Request) -> Response:
    """Signed kills since an epoch that apply to this host (agent route)."""
    since = _int_query(request, "since", 0)
    context = request.key
    ring = request.query_one("ring") or "stable"
    documents: List[Dict[str, Any]] = []
    for document in app.store.kills_since(context.org_id, since):
        if kill_applies(document, org_id=context.org_id,
                        host_id=context.host_id, ring=ring):
            documents.append(document)
    return json_response(200, {
        "kills": documents,
        "kill_epoch": app.store.kill_epoch(context.org_id),
    })


def _rollout(app: Any, org_id: str, rollout_id: str) -> Dict[str, Any]:
    for record in app.store.list_rollouts(org_id):
        if record["id"] == rollout_id:
            return record
    raise ApiError(404, "not_found", "no such rollout")


def _republish_previous(app: Any, request: Request, org_id: str,
                        rollout: Dict[str, Any], now: float) -> Dict[str, Any]:
    """Re-publish the source before the rollout's manifest at version+1."""
    version = app.store.next_manifest_version(org_id)
    target = {"kind": "ring", "id": rollout["ring"]}
    source = app.store.policy_source(org_id)
    previous = (app.store.policy_source(
        org_id, version=source["source_version"] - 1) if source else None)
    if previous is not None:
        result = _compile(app, {
            "documents": previous["documents"],
            "scope": previous["scope"],
            "rules_module": previous["rules_module"],
        })
        epoch, sha, size = result.epoch, result.sha256, len(result.artifact_bytes)
        app.store.put_artifact(org_id, sha, result.artifact_bytes,
                               epoch=epoch, now=now)
    else:
        # No source history (a plane restored from before C5 source storage)
        # cannot prove what the prior manifest was compiled from; refuse
        # rather than sign a body this plane did not author.
        raise ApiError(422, "no_previous_source",
                       "no previous policy source is available to roll back to")
    envelope = sign_manifest(app.policy_seed(), {
        "v": 1,
        "manifest_id": "m-" + uuid.uuid4().hex[:16],
        "org_id": org_id,
        "version": version,
        "epoch": epoch,
        "target": target,
        "mode": "enforce",
        "issued_at": now,
        "expires_at": now + DEFAULT_MANIFEST_TTL,
        "minimum_agent": None,
        "artifact": {"format": 1, "sha256": sha, "size": size},
        "rules_digest": epoch,
        "key_id": policy_key_id(public_key(app.policy_seed())),
    })
    app.store.put_manifest(
        org_id, envelope, author=getattr(request.user, "id", None), now=now)
    return {"manifest": envelope, "source_version": previous["source_version"]}


async def promote_rollout(app: Any, request: Request) -> Response:
    """Move a rollout canary -> 10 -> 100, or roll it back at version+1."""
    _require_step_up(app, request, "promote a rollout")
    body = parse_json_body(request.body, request.headers, (
        "id", "percent", "action", "health"))
    rollout_id = request.params.get("id") or body.get("id")
    if not isinstance(rollout_id, str) or not rollout_id:
        raise ApiError(422, "invalid_request", "id is required")
    oid = request.org.id
    rollout = _rollout(app, oid, rollout_id)
    now = _now(app)
    action = body.get("action", "promote")
    if action == "rollback":
        republished = _republish_previous(app, request, oid, rollout, now)
        record = app.store.rollout_promote(
            oid, rollout_id, percent=0, state="rolled_back", now=now)
        app.store.audit_append(
            oid, "policy.rollout_rolled_back",
            actor=getattr(request.user, "id", None),
            detail={"id": rollout_id,
                    "manifest_version": republished["manifest"]["version"]},
        )
        return json_response(200, {"rollout": record, **republished})
    if action != "promote":
        raise ApiError(422, "invalid_request", "action must be promote or rollback")
    health = body.get("health")
    if health is not None and not isinstance(health, str):
        raise ApiError(422, "invalid_request", "health must be a string")
    if isinstance(health, str) and health.strip().lower() in REGRESSED_HEALTH:
        # Hold: record the failure and keep the current percentage.  Advancing
        # a canary the plane has evidence against would be the opposite of a
        # canary.
        record = app.store.rollout_record_failure(oid, rollout_id, health, now=now)
        app.store.audit_append(
            oid, "policy.rollout_held",
            actor=getattr(request.user, "id", None),
            detail={"id": rollout_id, "health": health},
        )
        return json_response(200, {"rollout": record, "held": True})
    percent = body.get("percent")
    if percent is None:
        # The next stage in the canary -> 10 -> 100 ladder.
        current = int(rollout.get("percent") or 0)
        percent = 10 if current < 10 else (100 if current < 100 else 100)
    if isinstance(percent, bool) or not isinstance(percent, int) \
            or percent not in (0, 10, 100):
        raise ApiError(422, "invalid_request",
                       "percent must be one of 0, 10, 100")
    record = app.store.rollout_promote(
        oid, rollout_id, percent=percent, health=health, now=now)
    app.store.audit_append(
        oid, "policy.rollout_promoted",
        actor=getattr(request.user, "id", None),
        detail={"id": rollout_id, "percent": percent},
    )
    return json_response(200, {"rollout": record})


async def list_rollouts(app: Any, request: Request) -> Response:
    records = app.store.list_rollouts(request.org.id)
    return json_response(200, {"rollouts": records})


def register(app: Any) -> None:
    app.add_route("/v1/policy/compile", "POST", partial(compile_policy, app))
    app.add_route("/v1/policy/publish", "POST", partial(publish_manifest, app))
    app.add_route("/v1/manifest", "GET", partial(get_manifest, app))
    app.add_pattern("/v1/artifacts/{sha256}", "GET", partial(get_artifact, app))
    app.add_route("/v1/hints", "GET", partial(get_hints, app))
    app.add_route("/v1/policy/kill", "POST", partial(publish_kill, app))
    app.add_route("/v1/kills", "GET", partial(list_kills, app))
    app.add_pattern("/v1/policy/rollouts/{id}/promote", "POST",
                  partial(promote_rollout, app))
    app.add_route("/v1/policy/rollouts", "GET", partial(list_rollouts, app))


__all__ = [
    "DEFAULT_MANIFEST_TTL",
    "MAX_WAIT_SECONDS",
    "MIN_MANIFEST_TTL",
    "compile_policy",
    "get_artifact",
    "get_hints",
    "get_manifest",
    "list_kills",
    "list_rollouts",
    "promote_rollout",
    "publish_kill",
    "publish_manifest",
    "register",
]

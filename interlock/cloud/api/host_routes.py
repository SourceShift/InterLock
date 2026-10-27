"""Host enrollment, heartbeat and fleet routes (C2).

There is no plane-initiated connection in v1: the plane cannot dial a host.
The heartbeat here is a request the *connector* makes outbound; the routes
below never open a socket of their own.

Authentication split:

* ``POST /v1/enroll`` is public at the session layer because its body carries
  the single-use enrollment token, which this handler consumes. It never
  accepts a session cookie as an alternative.
* ``POST /v1/hosts/self`` is an agent-key route (:data:`rbac.AGENT_ROUTES`);
  the app authenticates the bearer key before calling in and hands the route a
  :class:`~interlock.cloud.auth.agent.KeyContext` on ``request.key``.
* The token, fleet and key admin routes are session routes in
  :data:`rbac.PERMISSIONS`; key rotation and revocation also require a fresh
  step-up (FR-020's freshness rule, reused for admin actions).

No handler echoes a raw token or agent key except the two creation responses
whose entire purpose is to hand the secret to its owner exactly once.
"""
from __future__ import annotations

import time
from functools import partial
from typing import Any, Dict, Iterable, Optional

from .. import webhooks as _webhooks
from ..auth.stepup import StepUpError, StepUpService
from ..enrollment import AGENT_SCOPES, generate_agent_key
from ..http import ApiError, Request, Response, json_response, parse_json_body
from ..identity import is_public_key_hex, key_id as derive_key_id
from ..receipts import CHECKPOINT_MAX_AGE
from ..store import Host, keys_version

#: How long the connector should wait between polls, in seconds.
DEFAULT_POLL_AFTER = 300

#: A rotated key's predecessor is accepted for at most this long (FR-005).
ROTATION_OVERLAP_SECONDS = 24 * 60 * 60

#: Enrollment token lifetime bounds for the admin route.
MIN_TOKEN_TTL = 60
MAX_TOKEN_TTL = 7 * 24 * 60 * 60

#: The three plane verification keys an enrolling host pins. C3/C5 fill these
#: from the org's signing material; an empty string means "not configured yet"
#: and is never used as a key.
PLANE_KEY_NAMES = ("approval", "policy", "receipt")


def _now(app: Any) -> float:
    clock = getattr(app, "_clock", None)
    return float(clock()) if callable(clock) else time.time()


def _iso(value: Optional[float]) -> Optional[str]:
    if value is None:
        return None
    import datetime

    return datetime.datetime.fromtimestamp(
        value, tz=datetime.timezone.utc
    ).isoformat()


def _json_body(request: Request, allowed: Iterable[str]) -> Dict[str, Any]:
    return parse_json_body(request.body, request.headers, allowed)


def _audit(app: Any, request: Request, event: str, *,
           target: Optional[str], detail: Optional[Dict[str, Any]] = None) -> None:
    app.store.audit_append(
        request.org.id, event,
        actor=getattr(request.user, "id", None),
        detail=dict(detail or {}, target=target, ip=request.client_ip),
    )


def _host_or_404(app: Any, org_id: str, host_id: str) -> Host:
    host = app.store.host_by_id(org_id, host_id)
    if host is None:
        raise ApiError(404, "not_found", "host not found")
    return host


def _require_step_up(app: Any, request: Request) -> None:
    if not StepUpService.fresh(request.session.step_up_at, now=_now(app)):
        raise StepUpError("step_up_required",
                          "a fresh step-up is required for this action")


def _host_view(app: Any, host: Host) -> Dict[str, Any]:
    keys = app.store.list_agent_keys(host.org_id, host.id)
    view = host.public()
    view["key_ids"] = [key.id for key in keys]
    view["keys"] = [key.public() for key in keys]
    view["keys_version"] = keys_version(keys)
    # A host is "revoked" once every key it holds is revoked (or the host
    # itself was revoked). A host with no key at all is not reported revoked.
    view["revoked"] = (
        host.state == "revoked"
        or (bool(keys) and all(key.revoked_at is not None for key in keys))
    )
    # C3 delivery state: how far the host has been granted and how far it has
    # acknowledged. Both are plane-side counters, never a host-supplied value.
    view["grant_seq"] = int(app.store.grant_head(host.org_id, host.id)["seq"])
    view["last_ack_seq"] = int(app.store.last_ack_seq(host.org_id, host.id))
    # C4 chain state: the verification level is never a boolean (FR-033 ..
    # FR-035). A linkage-only chain whose newest signed checkpoint is older
    # than 24 hours is reported as ``receipts_unverified``. Before the first
    # checkpoint, the time the head moved stands in for "when we last saw
    # evidence"; a host that never ingested anything stays unverified.
    head = app.store.receipt_head(host.org_id, host.id)
    level = str(head.get("verification") or "receipts_unverified")
    if level == "linkage_only":
        attested = head.get("last_checkpoint_at") or head.get("updated_at")
        if attested is None \
                or _now(app) - float(attested) > CHECKPOINT_MAX_AGE:
            level = "receipts_unverified"
    view["verification"] = level
    view["receipts_head"] = head.get("head_mac")
    view["receipts_count"] = int(head.get("count") or 0)
    view["last_checkpoint_at"] = _iso(head.get("last_checkpoint_at"))
    return view


def _scopes(body: Dict[str, Any]) -> list:
    requested = body.get("scopes")
    if requested is None:
        return list(AGENT_SCOPES)
    if not isinstance(requested, list) \
            or any(not isinstance(scope, str) for scope in requested):
        raise ApiError(422, "invalid_request", "scopes must be a list of strings")
    unknown = sorted(set(requested) - set(AGENT_SCOPES))
    if unknown:
        raise ApiError(422, "invalid_request",
                       "unknown scope: {}".format(unknown[0]))
    return list(dict.fromkeys(requested))


# -- enrollment ---------------------------------------------------------

async def create_enrollment_token(app: Any, request: Request) -> Response:
    """Mint a single-use token; the value is returned once and audited by id."""
    body = _json_body(request, ("host_name", "ttl"))
    host_name = body.get("host_name")
    if host_name is not None:
        if not isinstance(host_name, str) or not host_name.strip():
            raise ApiError(422, "invalid_request", "host_name must be a string")
        host_name = host_name.strip()[:200]
    ttl = body.get("ttl", 3600)
    if isinstance(ttl, bool) or not isinstance(ttl, int) \
            or not MIN_TOKEN_TTL <= ttl <= MAX_TOKEN_TTL:
        raise ApiError(422, "invalid_request",
                       "ttl must be an integer between {} and {}".format(
                           MIN_TOKEN_TTL, MAX_TOKEN_TTL))
    token_id, raw = app.store.create_enrollment_token(
        request.org.id, host_name, ttl=ttl,
        created_by=request.user.id, now=_now(app),
    )
    _audit(app, request, "enrollment.token_created", target=token_id,
           detail={"host_name": host_name, "ttl": ttl})
    return json_response(201, {
        "id": token_id,
        "token": raw,
        "host_name": host_name,
        "expires_at": _iso(_now(app) + ttl),
    })


async def enroll(app: Any, request: Request) -> Response:
    """Consume a token and register one host with exactly one agent key."""
    body = _json_body(request, ("token", "host_name", "host_public_key",
                                "host_key_id", "connector_version"))
    raw_token = body.get("token")
    if not isinstance(raw_token, str) or not raw_token:
        raise ApiError(401, "token_invalid", "the enrollment token is not valid")

    public_hex = body.get("host_public_key")
    if not is_public_key_hex(public_hex):
        raise ApiError(422, "invalid_request",
                       "host_public_key must be 32-byte Ed25519 hex")
    derived_id = derive_key_id(public_hex)
    submitted_id = body.get("host_key_id")
    if submitted_id is not None:
        if not isinstance(submitted_id, str) or not submitted_id:
            raise ApiError(422, "invalid_request", "host_key_id must be a string")
        if submitted_id != derived_id:
            raise ApiError(422, "invalid_request",
                           "host_key_id does not match host_public_key")

    host_name = body.get("host_name")
    if host_name is not None and not isinstance(host_name, str):
        raise ApiError(422, "invalid_request", "host_name must be a string")
    if isinstance(host_name, str):
        host_name = host_name.strip()[:200] or None
    version = body.get("connector_version")
    if version is not None and not isinstance(version, str):
        raise ApiError(422, "invalid_request", "connector_version must be a string")

    # Consuming the token is the one atomic claim. Everything after it may
    # fail and leave a used token behind, which is the safe direction: the
    # operator asks an admin for a fresh token rather than replaying one.
    token = app.store.consume_enrollment_token(raw_token, now=_now(app))
    if token is None:
        raise ApiError(401, "token_invalid", "the enrollment token is not valid")

    host = app.store.create_host(
        token.org_id,
        host_name or token.host_name or "unnamed-host",
        owner_subject="enrollment-token:{}".format(token.id),
        public_keys=[{"id": derived_id, "public_key": public_hex}],
        state="active",
        last_seen=None,
    )
    raw_key, prefix, secret_hash = generate_agent_key()
    agent_key = app.store.create_agent_key(
        token.org_id, host.id, prefix=prefix, secret_hash=secret_hash,
        scopes=list(AGENT_SCOPES),
    )
    app.store.audit_append(
        token.org_id, "host.enrolled", actor=None,
        detail={
            "target": host.id,
            "token_id": token.id,
            "host_id": host.id,
            "agent_key_id": agent_key.id,
            "connector_version": version,
        },
    )
    # C3 owns the approval key; C5 owns policy and receipt signing. Empty
    # strings are explicit "not configured", never a usable pin.
    plane_keys = {name: "" for name in PLANE_KEY_NAMES}
    plane_keys["approval"] = app.approval_public_key_hex()
    plane_keys["policy"] = app.policy_public_key_hex()
    return json_response(201, {
        "host_id": host.id,
        "agent_key": raw_key,
        "agent_key_id": agent_key.id,
        "org_id": token.org_id,
        "plane_public_keys": plane_keys,
        "poll_after": DEFAULT_POLL_AFTER,
    })


# -- heartbeat and fleet ------------------------------------------------

async def heartbeat(app: Any, request: Request) -> Response:
    """Record a connector heartbeat; the plane never initiates one."""
    # Validate the body's shape even though no field is persisted yet.
    _json_body(request, ("connector_version", "last_seen", "spool_depth",
                         "spool_bytes", "queue_lag", "cursor", "status"))
    context = request.key
    now = _now(app)
    host = app.store.touch_host(context.org_id, context.host_id, now)
    if host is None:
        raise ApiError(401, "unauthenticated", "host no longer exists")
    # ``connector_version``/``queue_lag`` are accepted for forward
    # compatibility; the schema has nowhere to persist them yet, so the
    # durable facts are last_seen and the derived key generation.
    return json_response(200, {
        "host_id": host.id,
        "server_time": now,
        "keys_version": context.keys_version,
        "poll_after": DEFAULT_POLL_AFTER,
    })


async def list_hosts(app: Any, request: Request) -> Response:
    hosts = app.store.list_hosts(request.org.id)
    return json_response(200, {"hosts": [_host_view(app, host) for host in hosts]})


async def get_host(app: Any, request: Request) -> Response:
    host_id = (request.params or {}).get("id", "")
    host = _host_or_404(app, request.org.id, host_id)
    return json_response(200, {"host": _host_view(app, host)})


# -- key lifecycle ------------------------------------------------------

async def rotate_key(app: Any, request: Request) -> Response:
    """Issue a new key and retire the host's previous keys after 24 hours."""
    _require_step_up(app, request)
    body = _json_body(request, ("host_id", "scopes"))
    host_id = body.get("host_id")
    if not isinstance(host_id, str) or not host_id:
        raise ApiError(422, "invalid_request", "host_id is required")
    scopes = _scopes(body)
    host = _host_or_404(app, request.org.id, host_id)

    now = _now(app)
    retire_at = now + ROTATION_OVERLAP_SECONDS
    for key in app.store.list_agent_keys(request.org.id, host.id):
        if key.revoked_at is not None:
            continue
        if key.expires is None or key.expires > retire_at:
            app.store.retire_agent_key(request.org.id, key.id, expires=retire_at)

    raw_key, prefix, secret_hash = generate_agent_key()
    key = app.store.create_agent_key(
        request.org.id, host.id, prefix=prefix, secret_hash=secret_hash,
        scopes=scopes,
    )
    _audit(app, request, "agent_key.rotated", target=host.id,
           detail={"host_id": host.id, "agent_key_id": key.id})
    return json_response(201, {
        "agent_key": raw_key,
        "agent_key_id": key.id,
        "host_id": host.id,
        "keys_version": keys_version(
            app.store.list_agent_keys(request.org.id, host.id)),
        "previous_keys_expire_at": _iso(retire_at),
    })


async def revoke_key(app: Any, request: Request) -> Response:
    """Revoke one key immediately (FR-006); every route reads the row."""
    _require_step_up(app, request)
    key_id = (request.params or {}).get("id", "")
    key = app.store.agent_key_by_id(request.org.id, key_id)
    if key is None:
        raise ApiError(404, "not_found", "agent key not found")
    updated = app.store.revoke_agent_key(request.org.id, key.id, now=_now(app))
    _audit(app, request, "agent_key.revoked", target=key.id,
           detail={"host_id": key.host_id, "agent_key_id": key.id})
    remaining = [item for item in app.store.list_agent_keys(
        request.org.id, key.host_id) if item.revoked_at is None]
    if not remaining:
        # The host has no usable key left. That is the observable "revoked"
        # event a subscriber can act on; the key-level row is already in the
        # audit trail.
        _webhooks.emit(app.store, request.org.id, "host.revoked", {
            "host_id": key.host_id,
            "agent_key_id": key.id,
            "status": "revoked",
        }, now=_now(app))
    return json_response(200, {
        "id": updated.id,
        "host_id": updated.host_id,
        "revoked": True,
        "revoked_at": _iso(updated.revoked_at),
        "keys_version": keys_version(
            app.store.list_agent_keys(request.org.id, updated.host_id)),
    })


def register(app: Any) -> None:
    """Add the C2 routes to a :class:`~interlock.cloud.app.CloudApp`."""
    app.add_route("/v1/admin/enrollment-tokens", "POST",
                  partial(create_enrollment_token, app))
    app.add_route("/v1/enroll", "POST", partial(enroll, app))
    # Register the literal agent route before the variable fleet route so the
    # dispatcher's exact table always wins.
    app.add_route("/v1/hosts/self", "POST", partial(heartbeat, app))
    app.add_route("/v1/hosts", "GET", partial(list_hosts, app))
    app.add_pattern("/v1/hosts/{id}", "GET", partial(get_host, app))
    app.add_route("/v1/keys", "POST", partial(rotate_key, app))
    app.add_pattern("/v1/keys/{id}/revoke", "POST", partial(revoke_key, app))


__all__ = ["register"]

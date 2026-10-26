"""Grant delivery routes: the connector's long poll and acknowledgement (C3).

The plane never dials a host, so a decision reaches its host only when that
host asks. ``GET /v1/grants`` is a long poll over a per-host, strictly
increasing sequence; ``POST /v1/grants/ack`` records what the host applied and
what it refused.

Both routes are agent-key routes (:data:`interlock.cloud.auth.rbac.AGENT_ROUTES`)
and are scoped to the authenticated key's own host: a host can neither read
nor acknowledge another host's grants. Polling doubles as a heartbeat, which
is what keeps the plane's "host is stale" check (FR-024) meaningful.
"""
from __future__ import annotations

import asyncio
import time
from functools import partial
from typing import Any, Dict, List

from ..auth.agent import AgentAuthError, AgentRevoked
from ..http import ApiError, Request, Response, json_response, parse_json_body

#: The longest a poll may block. The connector asks for this; a client that
#: asks for more is clamped rather than refused.
MAX_WAIT_SECONDS = 25

#: How long the poll sleeps between store reads while waiting.
POLL_TICK_SECONDS = 0.25

#: One acknowledgement may name at most this many grants.
MAX_ACK_IDS = 1000


def _now(app: Any) -> float:
    clock = getattr(app, "_clock", None)
    return float(clock()) if callable(clock) else time.time()


def _live_key(app: Any, request: Request) -> Any:
    """Re-read the key and host while a poll is parked.

    Authentication ran before the handler, but a long poll can outlive a
    revocation. The row is the authority: a key revoked (or a host disabled)
    during the wait is refused before a grant is handed over.
    """
    context = request.key
    key = app.store.agent_key_by_id(context.org_id, context.key_id)
    if key is None or key.revoked_at is not None:
        raise AgentRevoked("agent key revoked")
    host = app.store.host_by_id(context.org_id, context.host_id)
    if host is None or host.state not in ("active", "ingest_frozen"):
        raise AgentAuthError("host is not active")
    return key


def _int_query(request: Request, name: str, default: int) -> int:
    raw = request.query_one(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except (TypeError, ValueError):
        raise ApiError(422, "invalid_request",
                       "{} must be an integer".format(name)) from None
    return value


async def get_grants(app: Any, request: Request) -> Response:
    """Long-poll the grants after ``cursor``; ordered by ``seq``."""
    cursor = _int_query(request, "cursor", 0)
    if cursor < 0:
        raise ApiError(422, "invalid_request", "cursor must not be negative")
    wait = max(0, min(MAX_WAIT_SECONDS, _int_query(request, "wait", MAX_WAIT_SECONDS)))
    context = request.key
    now = _now(app)
    # The poll is a heartbeat: a host that is polling is not stale even if it
    # has nothing new to collect.
    app.store.touch_host(context.org_id, context.host_id, now)

    deadline = time.monotonic() + wait
    grants: List[Dict[str, Any]] = []
    while True:
        _live_key(app, request)
        grants = app.store.grants_after(
            context.org_id, context.host_id, cursor)
        if grants or time.monotonic() >= deadline:
            break
        await asyncio.sleep(min(POLL_TICK_SECONDS,
                                max(0.0, deadline - time.monotonic())))
    if grants:
        app.store.touch_host(context.org_id, context.host_id, _now(app))

    highest = max(
        [cursor] + [int(grant.get("seq", 0)) for grant in grants])
    server_time = _now(app)
    return json_response(200, {
        "grants": grants,
        # Two names for one cursor: C2's connector reads ``cursor``; the C3
        # kickoff names ``next_cursor``. Both are the last delivered seq.
        "cursor": highest,
        "next_cursor": highest,
        "server_time": server_time,
        "poll_after": MAX_WAIT_SECONDS,
    })


def _string_list(body: Dict[str, Any], name: str) -> List[str]:
    value = body.get(name)
    if value is None:
        return []
    if not isinstance(value, list) or any(
            not isinstance(item, str) or not item for item in value):
        raise ApiError(422, "invalid_request",
                       "{} must be a list of strings".format(name))
    if len(value) > MAX_ACK_IDS:
        raise ApiError(422, "invalid_request",
                       "{} may name at most {} grants".format(name, MAX_ACK_IDS))
    return list(dict.fromkeys(value))


async def ack_grants(app: Any, request: Request) -> Response:
    """Acknowledge applied grants and report refusals; both are audited."""
    body = parse_json_body(request.body, request.headers,
                           ("cursor", "grant_ids", "refusals"))
    ids = _string_list(body, "grant_ids")
    refusals = body.get("refusals", [])
    if not isinstance(refusals, list):
        raise ApiError(422, "invalid_request", "refusals must be a list")
    context = request.key
    now = _now(app)
    acked = app.store.ack_grants(
        context.org_id, context.host_id, ids, now=now)
    for refusal in refusals:
        if not isinstance(refusal, dict):
            raise ApiError(422, "invalid_request",
                           "each refusal must be an object")
        grant_id = refusal.get("grant_id")
        code = refusal.get("code")
        if not isinstance(grant_id, str) or not grant_id \
                or not isinstance(code, str) or not code:
            raise ApiError(422, "invalid_request",
                           "a refusal needs grant_id and code")
        if grant_id in ids:
            # An applied grant is not refused; the ack list wins.
            continue
        app.store.audit_append(
            context.org_id, "grant.refused",
            actor=None,
            detail={"host_id": context.host_id, "grant_id": grant_id,
                    "code": code[:100], "at": now},
        )
    return json_response(200, {
        "acked": acked,
        "last_ack_seq": app.store.last_ack_seq(
            context.org_id, context.host_id),
    })


def register(app: Any) -> None:
    app.add_route("/v1/grants", "GET", partial(get_grants, app))
    app.add_route("/v1/grants/ack", "POST", partial(ack_grants, app))


__all__ = ["MAX_ACK_IDS", "MAX_WAIT_SECONDS", "register"]

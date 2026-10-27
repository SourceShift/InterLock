"""Webhook registration and delivery history (C7).

Registration and disabling are administrative actions with a fresh step-up.
The URL policy (https everywhere except loopback, no userinfo, no fragment)
and the event list are validated by :mod:`interlock.cloud.webhooks`, which is
also where signing, retries and the outbox worker live.

The signing secret is shown exactly once, when the endpoint is created. What
is stored is a SHA-256 hash (for identification) and an AES-GCM-sealed copy
under the plane's preview KEK (so the worker can sign without a plaintext
secret at rest). No route ever returns the secret again, and no route returns
a delivery body: only its status, timing and response-body digest.
"""
from __future__ import annotations

import time
from functools import partial
from typing import Any, Dict

from ..auth.stepup import StepUpError, StepUpService
from ..db import CloudDependencyMissing
from ..http import ApiError, Request, Response, json_response, parse_json_body
from .. import webhooks

#: Delivery history pages are bounded; an operator walks the cursor.
MAX_DELIVERY_PAGE = 100

#: A client-supplied secret must be long enough to be a signing key. The
#: normal path is a generated ``whsec_`` value, returned once.
MIN_SECRET_LENGTH = 16


def _now(app: Any) -> float:
    clock = getattr(app, "_clock", None)
    return float(clock()) if callable(clock) else time.time()


def _require_step_up(app: Any, request: Request, action: str) -> None:
    at = getattr(getattr(request, "session", None), "step_up_at", None)
    if not StepUpService.fresh(at, now=_now(app)):
        raise StepUpError("step_up_required",
                          "a fresh step-up is required to {}".format(action))


def _audit(app: Any, request: Request, event: str,
           detail: Dict[str, Any]) -> None:
    app.store.audit_append(
        request.org.id, event,
        actor=getattr(request.user, "id", None),
        detail=dict(detail, ip=request.client_ip),
    )


def _endpoint_or_404(app: Any, request: Request, endpoint_id: str) -> Dict[str, Any]:
    endpoint = app.store.webhook_endpoint_by_id(request.org.id, endpoint_id)
    if endpoint is None:
        raise ApiError(404, "not_found", "no such webhook endpoint")
    return endpoint


def _public_endpoint(app: Any, request: Request,
                     endpoint_id: str) -> Dict[str, Any]:
    """The listing shape: never ``secret_hash`` or the sealed secret."""
    for item in app.store.webhook_list_endpoints(request.org.id):
        if item.get("id") == endpoint_id:
            return item
    raise ApiError(404, "not_found", "no such webhook endpoint")


#: Delivery metadata safe to return. The stored outbox row also carries the
#: signed payload and the org/endpoint ids; neither belongs in an API body.
_DELIVERY_FIELDS = (
    "id", "event", "status", "attempts", "last_error", "next_attempt",
    "delivered_at", "duration_ms", "response_status", "body_digest", "created",
)


def _public_delivery(row: Dict[str, Any]) -> Dict[str, Any]:
    return {name: row.get(name) for name in _DELIVERY_FIELDS}


async def create_webhook(app: Any, request: Request) -> Response:
    """Register one endpoint; the signing secret is returned only here."""
    _require_step_up(app, request, "register a webhook")
    body = parse_json_body(request.body, request.headers, (
        "url", "events", "secret"))
    try:
        url = webhooks.validate_url(body.get("url"))
        events = webhooks.validate_events(body.get("events"))
    except webhooks.WebhookError as exc:
        raise ApiError(422, "invalid_request", str(exc)) from None

    supplied = body.get("secret")
    if supplied is not None:
        if not isinstance(supplied, str) or len(supplied) < MIN_SECRET_LENGTH:
            raise ApiError(422, "invalid_request",
                           "secret must be a string of at least {} "
                           "characters".format(MIN_SECRET_LENGTH))
        secret_text = supplied
    else:
        secret_text = webhooks.generate_secret()
    secret = secret_text.encode("utf-8")
    try:
        sealed = webhooks.seal_secret(
            secret, kek=app.preview_kek(), org_id=request.org.id)
    except CloudDependencyMissing:
        raise ApiError(503, "webhooks_unconfigured",
                       "webhook signing needs IL_CLOUD_PREVIEW_KEK") from None
    except webhooks.WebhookError as exc:
        raise ApiError(503, "webhooks_unconfigured", str(exc)) from None

    endpoint = app.store.webhook_create_endpoint(
        request.org.id, url, events, webhooks.hash_secret(secret), sealed,
        now=_now(app))
    _audit(app, request, "webhook.registered", {
        "webhook_id": endpoint["id"], "url": endpoint["url"],
        "events": list(endpoint["events"]),
    })
    return json_response(201, {
        "webhook": endpoint,
        # Shown once, never stored in plaintext and never returned again.
        "secret": secret_text,
    })


async def list_webhooks(app: Any, request: Request) -> Response:
    """List endpoints with last delivery, failure and pending counts."""
    return json_response(200, {
        "webhooks": app.store.webhook_list_endpoints(request.org.id),
    })


async def list_deliveries(app: Any, request: Request) -> Response:
    """Page one endpoint's delivery history (metadata only, never a body)."""
    endpoint = _endpoint_or_404(
        app, request, (request.params or {}).get("id", ""))
    try:
        cursor = int(request.query_one("cursor") or 0)
        limit = int(request.query_one("limit") or 50)
    except (TypeError, ValueError):
        raise ApiError(422, "invalid_request",
                       "cursor and limit must be integers") from None
    if cursor < 0:
        raise ApiError(422, "invalid_request", "cursor must not be negative")
    if limit < 1 or limit > MAX_DELIVERY_PAGE:
        raise ApiError(422, "invalid_request",
                       "limit must be between 1 and {}".format(
                           MAX_DELIVERY_PAGE))
    rows, next_cursor = app.store.webhook_deliveries(
        request.org.id, endpoint["id"], cursor=cursor, limit=limit)
    return json_response(200, {
        "webhook": _public_endpoint(app, request, endpoint["id"]),
        "deliveries": [_public_delivery(row) for row in rows],
        "next_cursor": next_cursor,
    })


async def disable_webhook(app: Any, request: Request) -> Response:
    """Disable an endpoint; its delivery history is retained."""
    _require_step_up(app, request, "disable a webhook")
    endpoint_id = (request.params or {}).get("id", "")
    _endpoint_or_404(app, request, endpoint_id)
    endpoint = app.store.webhook_disable_endpoint(
        request.org.id, endpoint_id, now=_now(app))
    _audit(app, request, "webhook.disabled", {
        "webhook_id": endpoint_id, "url": endpoint["url"]})
    return json_response(200, {"webhook": endpoint, "disabled": True})


def register(app: Any) -> None:
    app.add_route("/v1/webhooks", "POST", partial(create_webhook, app))
    app.add_route("/v1/webhooks", "GET", partial(list_webhooks, app))
    app.add_pattern("/v1/webhooks/{id}/deliveries", "GET",
                    partial(list_deliveries, app))
    app.add_pattern("/v1/webhooks/{id}", "DELETE",
                    partial(disable_webhook, app))


__all__ = [
    "MAX_DELIVERY_PAGE",
    "MIN_SECRET_LENGTH",
    "create_webhook",
    "disable_webhook",
    "list_deliveries",
    "list_webhooks",
    "register",
]

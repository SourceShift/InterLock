"""Org deletion (C7).

Deleting an org is a tombstone, never a cascade. The evidence an operator must
retain - receipts and the audit trail - stays for the configured retention
period with the org marked deleted; everything that could grant access goes at
once:

* every agent key is revoked (a deleted org's key answers ``410 revoked``),
* every session is deleted,
* every unredeemed enrollment token is spent,
* review preview ciphertext is dropped,
* every webhook secret is destroyed and the endpoint disabled.

The action needs the owner role, a fresh step-up and the org slug typed into
the request body. It writes exactly one audit row.
"""
from __future__ import annotations

import time
from functools import partial
from typing import Any

from ..auth.stepup import StepUpError, StepUpService
from ..http import ApiError, Request, Response, json_response, parse_json_body


def _now(app: Any) -> float:
    clock = getattr(app, "_clock", None)
    return float(clock()) if callable(clock) else time.time()


def _require_step_up(app: Any, request: Request) -> None:
    at = getattr(getattr(request, "session", None), "step_up_at", None)
    if not StepUpService.fresh(at, now=_now(app)):
        raise StepUpError("step_up_required",
                          "a fresh step-up is required to delete an org")


async def delete_org(app: Any, request: Request) -> Response:
    """Tombstone this org and revoke everything that could still reach it."""
    _require_step_up(app, request)
    body = parse_json_body(request.body, request.headers, ("confirm",))
    confirmation = body.get("confirm")
    if not isinstance(confirmation, str):
        raise ApiError(422, "invalid_request",
                       "confirm must repeat the org slug")
    org = request.org
    if confirmation.strip() != org.slug:
        raise ApiError(422, "invalid_request",
                       "confirm must exactly repeat the org slug")
    if getattr(org, "deleted_at", None) is not None:
        raise ApiError(409, "org_deleted", "this org is already deleted")

    now = _now(app)
    org_id = org.id
    # Access first: a deletion that leaves a live key or cookie for even one
    # request is a failed deletion.
    revoked_keys = app.store.revoke_org_keys(org_id, now=now)
    sessions = app.store.delete_org_sessions(org_id)
    enrollment = app.store.stop_org_enrollment(org_id, now=now)
    previews = app.store.delete_org_previews(org_id)
    secrets = app.store.delete_org_webhook_secrets(org_id)
    tombstone = app.store.org_tombstone(org_id, now=now)

    app.store.audit_append(
        org_id, "org.deleted",
        actor=getattr(request.user, "id", None),
        detail={
            "org_id": org_id,
            "slug": org.slug,
            "ip": request.client_ip,
            "at": now,
            "revoked_keys": revoked_keys,
            "sessions": sessions,
            "enrollment_tokens": enrollment,
            "previews": previews,
            "webhooks": secrets,
            # Retained by policy; named so the audit row is self-contained.
            "retained": ["receipts", "audit"],
        },
    )
    return json_response(200, {
        "org": tombstone.public(),
        "deleted": True,
        "revoked_keys": revoked_keys,
        "sessions": sessions,
        "retained": ["receipts", "audit"],
    })


def register(app: Any) -> None:
    app.add_route("/v1/org", "DELETE", partial(delete_org, app))


__all__ = ["delete_org", "register"]

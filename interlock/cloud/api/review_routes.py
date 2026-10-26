"""Review upload, list, detail and decision routes (C3, FR-015 .. FR-024).

Two callers share this module:

* the **connector**, an agent-key caller, uploads a masked review. The body is
  allow-listed here as well as in the connector: a field named ``event``,
  ``args``, ``raw`` or ``arguments`` (or anything else outside the documented
  schema) is ``422 invalid_request`` (FR-016). The plane never trusts the host
  to have redacted.
* a **reviewer**, a session caller, lists, opens and decides. A decision needs
  a fresh step-up (FR-020), a distinct subject per approval (FR-021), no
  self-approval where the org forbids it (FR-022), a pending review (FR-023)
  and, for a stale host, an explicit ``approve_anyway`` with a reason
  (FR-024).

The plane never decides and never dials a host. A decision commits a signed
grant; the host verifies it and moves its own queue.
"""
from __future__ import annotations

import secrets
import threading
import time
from functools import partial
from typing import Any, Dict, Iterable, Optional

from ..auth.stepup import StepUpError, StepUpService
from ..crypto import encrypt_preview
from ..grants import GRANT_MAX_TTL, sign_grant
from ..http import ApiError, Request, Response, json_response, parse_json_body
from ..store import ReviewConflict, ReviewRecord

#: The exact fields the connector may upload. Anything else is refused.
UPLOAD_FIELDS = (
    "review_id", "binding", "action", "phase", "principal", "requester",
    "policy_id", "reason", "args_digest", "preview", "mask_counts", "created",
    "pending_until", "min_approvals", "allow_self_approval", "approval_ttl",
)

#: Names that would leak the raw call if they ever reached the plane.
FORBIDDEN_UPLOAD_FIELDS = ("event", "args", "raw", "arguments")

#: A remote grant is short-lived; the host clamps the local approval to it.
GRANT_TTL_SECONDS = 300

#: The plane's "last sync is stale" window (FR-024).
STALE_SYNC_SECONDS = 300

#: Serialises seq allocation + signing + the grant insert *per process*. The
#: store's `add_grant` keeps the head monotonic; this keeps one process from
#: handing two grants the same seq while the CPU signs. Deployment assumption:
#: one plane process per database. A multi-worker layout must move this
#: allocation into the grant_heads row (a `SELECT ... FOR UPDATE` held across
#: signing) or two decisions can race to the same `seq` and break a host's
#: chain, which the connector refuses as a `seq` failure.
_GRANT_LOCK = threading.RLock()


def _now(app: Any) -> float:
    clock = getattr(app, "_clock", None)
    return float(clock()) if callable(clock) else time.time()


def _require_step_up(app: Any, request: Request) -> None:
    session = getattr(request, "session", None)
    at = getattr(session, "step_up_at", None)
    if not StepUpService.fresh(at, now=_now(app)):
        raise StepUpError("step_up_required",
                          "a fresh step-up is required to decide a review")


def _json(request: Request, allowed: Iterable[str]) -> Dict[str, Any]:
    return parse_json_body(request.body, request.headers, allowed)


def _text(record: Dict[str, Any], name: str, *, required: bool = False,
          limit: int = 4000) -> Optional[str]:
    value = record.get(name)
    if value is None:
        if required:
            raise ApiError(422, "invalid_request", "{} is required".format(name))
        return None
    if not isinstance(value, str) or (required and not value):
        raise ApiError(422, "invalid_request",
                       "{} must be a non-empty string".format(name))
    return value[:limit]


def _number(record: Dict[str, Any], name: str) -> Optional[float]:
    value = record.get(name)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ApiError(422, "invalid_request", "{} must be a number".format(name))
    return float(value)


def _review_id_of(record: Dict[str, Any]) -> str:
    review_id = record.get("review_id")
    if not isinstance(review_id, str) or not review_id:
        raise ApiError(422, "invalid_request", "review_id is required")
    return review_id


def _upload_record(app: Any, request: Request) -> ReviewRecord:
    body = _json(request, UPLOAD_FIELDS)
    for forbidden in FORBIDDEN_UPLOAD_FIELDS:
        if forbidden in body:  # belt and braces: allowed_fields already refuses
            raise ApiError(422, "invalid_request",
                           "field {!r} may not be uploaded".format(forbidden))
    review_id = _review_id_of(body)
    binding = _text(body, "binding", required=True)
    action = _text(body, "action", required=True)
    phase = _text(body, "phase", required=True) or "call"
    args_digest = _text(body, "args_digest", required=True)
    preview = body.get("preview")
    if preview is not None and not isinstance(preview, str):
        raise ApiError(422, "invalid_request", "preview must be a string")
    mask_counts = body.get("mask_counts") or {}
    if not isinstance(mask_counts, dict) or any(
            not isinstance(key, str) or isinstance(value, bool)
            or not isinstance(value, int) or value < 0
            for key, value in mask_counts.items()):
        raise ApiError(422, "invalid_request",
                       "mask_counts must be an object of counts")
    min_approvals = body.get("min_approvals", 1)
    if isinstance(min_approvals, bool) or not isinstance(min_approvals, int) \
            or min_approvals < 1:
        raise ApiError(422, "invalid_request",
                       "min_approvals must be a positive integer")
    allow_self = body.get("allow_self_approval", True)
    if not isinstance(allow_self, bool):
        raise ApiError(422, "invalid_request",
                       "allow_self_approval must be a boolean")
    approval_ttl = _number(body, "approval_ttl")
    preview_enc = None
    if preview:
        preview_enc = encrypt_preview(
            preview, kek=app.preview_kek(), org_id=request.org.id)
    try:
        return app.store.upsert_review(
            request.org.id, request.key.host_id, review_id,
            binding=binding, action=action, phase=phase,
            principal=_text(body, "principal"),
            requester=_text(body, "requester"),
            policy_id=_text(body, "policy_id"),
            reason=_text(body, "reason"),
            args_digest=args_digest,
            preview_enc=preview_enc,
            mask_counts=mask_counts,
            metadata={"source": "connector"},
            created=_number(body, "created"),
            pending_until=_number(body, "pending_until"),
            min_approvals=min_approvals,
            allow_self_approval=allow_self,
            approval_ttl=900.0 if approval_ttl is None else approval_ttl,
        )
    except ReviewConflict as exc:
        raise ApiError(409, "review_conflict", str(exc)) from None


async def upload_reviews(app: Any, request: Request) -> Response:
    """Upsert one masked pending review; idempotent by ``(host, review_id)``."""
    record = _upload_record(app, request)
    return json_response(200, {"review": record.public()})


async def list_reviews(app: Any, request: Request) -> Response:
    status = request.query_one("status")
    host_id = request.query_one("host")
    try:
        cursor = int(request.query_one("cursor") or 0)
        limit = int(request.query_one("limit") or 50)
    except (TypeError, ValueError):
        raise ApiError(422, "invalid_request", "cursor and limit must be integers")
    if limit < 1 or limit > 100:
        raise ApiError(422, "invalid_request", "limit must be between 1 and 100")
    try:
        records, next_cursor = app.store.list_reviews(
            request.org.id, status=status, host_id=host_id,
            cursor=cursor, limit=limit)
    except ValueError:
        raise ApiError(422, "invalid_request", "unknown status") from None
    return json_response(200, {
        "reviews": [record.public() for record in records],
        "next_cursor": next_cursor,
    })


def load_preview(app: Any, request: Request, record: ReviewRecord) -> str:
    """Decrypt one preview and append the disclosure audit entry.

    Both the JSON detail route and the hosted page go through here, so a
    preview read has exactly one audit shape. A ciphertext that does not open
    is a corrupt row: the caller sees an empty preview rather than an error
    that would distinguish "wrong org key" from "not a ciphertext".
    """
    from ..crypto import decrypt_preview

    preview = ""
    if record.preview_enc:
        try:
            preview = decrypt_preview(
                record.preview_enc, kek=app.preview_kek(),
                org_id=request.org.id)
        except (ValueError, TypeError):
            preview = ""
    app.store.audit_append(
        request.org.id, "review.disclosed",
        actor=getattr(request.user, "id", None),
        detail={"review_id": record.id, "host_id": record.host_id,
                "ip": request.client_ip, "at": _now(app)},
    )
    return preview


async def review_detail(app: Any, request: Request) -> Response:
    """Detail plus the decrypted preview; every read is an audited disclosure."""
    if getattr(request.user, "role", None) == "auditor":
        # Auditors may search receipts, never open a preview (FR-017/FR-018).
        raise ApiError(404, "not_found", "no such review")
    review_id = (request.params or {}).get("id", "")
    record = app.store.review_by_id(request.org.id, review_id)
    if record is None:
        raise ApiError(404, "not_found", "no such review")
    preview = load_preview(app, request, record)
    payload = record.public()
    return json_response(200, {
        "review": payload,
        "preview": preview,
        "mask_counts": dict(record.mask_counts),
    })


def decide_review(app: Any, request: Request, review_id: str, *,
                  decision: str, reason: Optional[str],
                  approve_anyway: bool) -> Dict[str, Any]:
    """Shared decision core for the JSON route and the server-rendered UI.

    Returns either a committed grant reference or, for a four-eyes review
    that still needs another subject, ``{"status": "pending_approvals"}``.
    Raises :class:`~interlock.cloud.http.ApiError` for every refusal.
    """
    if decision not in ("approve", "reject", "revoke"):
        raise ApiError(422, "invalid_request",
                       "decision must be approve, reject or revoke")
    # FR-020 belongs to the decision itself, not to one route: the hosted form
    # posts here directly, so a check that lived only on the JSON route would
    # let a session with no step-up mint a grant asserting one.
    _require_step_up(app, request)
    record = app.store.review_by_id(request.org.id, review_id)
    if record is None:
        raise ApiError(404, "not_found", "no such review")
    host = app.store.host_by_id(request.org.id, record.host_id)
    if host is None:
        raise ApiError(404, "not_found", "no such review")
    now = _now(app)
    if record.status != "pending":
        raise ApiError(409, "review_not_pending",
                       "review {} is {}".format(review_id, record.status))
    if record.pending_until is not None and now >= record.pending_until:
        raise ApiError(409, "review_expired", "review {} has expired".format(review_id))

    user = request.user
    session = request.session
    subject = str(getattr(user, "subject", "") or user.id)
    if not record.allow_self_approval and subject == host.owner_subject:
        raise ApiError(403, "forbidden",
                       "the host owner may not decide this review")

    prior = app.store.pending_decisions(request.org.id, review_id)
    if decision == "approve":
        if subject in prior:
            raise ApiError(409, "distinct_approver_required",
                           "this reviewer already approved the review")
        approvers = prior + [subject]
        if len(approvers) < record.min_approvals:
            app.store.record_decision(
                request.org.id, review_id, reviewer=subject,
                step_up_method=session.step_up_method or "unknown",
                step_up_at=session.step_up_at or now,
                decision="approve", approve_anyway=approve_anyway,
                reason=reason, now=now)
            return {"status": "pending_approvals",
                    "approvals": len(approvers),
                    "required": record.min_approvals}

    stale = host.last_seen is None or now - float(host.last_seen) > STALE_SYNC_SECONDS
    if stale and (not approve_anyway or not (reason or "").strip()):
        raise ApiError(409, "approve_anyway_required",
                       "the host has not synced recently; approve_anyway and a "
                       "reason are required")

    issuer = str(getattr(user, "issuer", "") or "")
    decided_by = "{}#{}".format(issuer, subject)
    with _GRANT_LOCK:
        seq, prev = app.store.next_grant_seq(request.org.id, host.id)
        grant = sign_grant(app.approval_seed(), {
            "v": 1,
            "grant_id": "g-" + secrets.token_hex(4),
            "org_id": request.org.id,
            "host_id": host.id,
            "review_id": record.id,
            "binding": record.binding,
            "decision": decision,
            "approver": {"issuer": issuer, "subject": subject,
                         "email": str(getattr(user, "email", "") or "")},
            "step_up": {"method": session.step_up_method or "unknown",
                        "at": float(session.step_up_at or now)},
            "issued_at": now,
            "expires_at": now + min(GRANT_TTL_SECONDS, GRANT_MAX_TTL),
            "seq": seq,
            "prev": prev,
        })
        app.store.add_grant(
            request.org.id, host.id, grant_id=grant["grant_id"],
            review_id=record.id, seq=seq, envelope=grant, now=now)
        status = {"approve": "approved", "reject": "rejected",
                  "revoke": "revoked"}[decision]
        approval_until = None
        if decision == "approve":
            approval_until = min(
                now + float(record.approval_ttl),
                float(grant["expires_at"]))
        app.store.record_decision(
            request.org.id, review_id, reviewer=subject,
            step_up_method=session.step_up_method or "unknown",
            step_up_at=session.step_up_at or now, decision=decision,
            grant_id=grant["grant_id"], grant_seq=seq,
            approve_anyway=bool(approve_anyway), reason=reason,
            status=status, decided_by=decided_by,
            approval_until=approval_until, now=now)
    return {"status": status, "grant_id": grant["grant_id"], "seq": seq}


async def decide(app: Any, request: Request) -> Response:
    """POST a decision; the grant row is committed before the id is returned."""
    body = _json(request, ("decision", "reason", "approve_anyway"))
    decision = body.get("decision")
    if not isinstance(decision, str):
        raise ApiError(422, "invalid_request", "decision is required")
    reason = body.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise ApiError(422, "invalid_request", "reason must be a string")
    approve_anyway = body.get("approve_anyway", False)
    if not isinstance(approve_anyway, bool):
        raise ApiError(422, "invalid_request", "approve_anyway must be a boolean")
    review_id = (request.params or {}).get("id", "")
    result = decide_review(app, request, review_id, decision=decision,
                           reason=reason, approve_anyway=approve_anyway)
    return json_response(200 if "grant_id" in result else 202, result)


def register(app: Any) -> None:
    app.add_route("/v1/reviews", "POST", partial(upload_reviews, app))
    app.add_route("/v1/reviews", "GET", partial(list_reviews, app))
    app.add_pattern("/v1/reviews/{id}", "GET", partial(review_detail, app))
    app.add_pattern("/v1/reviews/{id}/decision", "POST", partial(decide, app))


__all__ = [
    "FORBIDDEN_UPLOAD_FIELDS",
    "GRANT_TTL_SECONDS",
    "STALE_SYNC_SECONDS",
    "UPLOAD_FIELDS",
    "decide_review",
    "load_preview",
    "register",
]

"""Receipt ingest, checkpoint ingest, audit search/export and retention (C4).

The host writes its receipt chain; the plane only reads it. Three rules shape
this module:

* **The plane never mutates a chain.** ``POST /v1/receipts`` accepts only
  receipts that continue the stored head (or are an exact replay of stored
  macs), verifies Ed25519 signatures with the host's pinned key when it has
  one, and otherwise checks ``prev`` linkage only (FR-033 .. FR-037).
* **A fork freezes ingest, not the host.** ``409 chain_fork`` records the
  break, opens an admin alert and sets ``ingest_frozen``. Grants and
  heartbeats keep working, so an administrator can investigate and unfreeze
  deliberately (FR-036).
* **An export is verified before its first byte.** The export route walks the
  selected chain with the host's verifier and refuses a broken result rather
  than handing an auditor bytes it cannot defend (FR-040).

The audit routes return receipt fields only. There is no preview or raw
argument field here, and the query parser refuses those names outright.
"""
from __future__ import annotations

import dataclasses
import datetime
import zlib
from functools import partial
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..auth.stepup import StepUpError, StepUpService
from ..http import ApiError, Request, Response, json_response, parse_json_body
from ...receipt import Receipt
from ..receipts import (
    VERIFICATION_LEVELS,
    receipt_public_key,
    verify_batch,
    verify_checkpoint,
    verify_export,
)
from ..retention import run as run_retention_job
from ..store import ReceiptFork

#: The exact wire fields ``POST /v1/receipts`` accepts.
INGEST_FIELDS = ("receipts", "host_id")

#: A checkpoint document is signed over exactly these fields.
CHECKPOINT_FIELDS = ("v", "org_id", "host_id", "head_mac", "count",
                     "issued_at", "sig")

#: The receipt dataclass fields a host may send; ``prev`` and ``mac`` are part
#: of the chain and are required for verification.
RECEIPT_WIRE_FIELDS = frozenset(field.name for field in dataclasses.fields(Receipt))

MAX_BATCH_RECEIPTS = 2_000

#: The largest decompressed body a receipt or checkpoint upload may produce.
MAX_DECOMPRESSED_BYTES = 8 * 1024 * 1024

#: Audit search is cursor paged; one page never exceeds this many receipts.
MAX_AUDIT_LIMIT = 100

#: FR-038: the free-text needle is bounded so one query cannot force a long
#: pattern match over every stored receipt.
MAX_QUERY_CHARS = 200

#: An export is bounded so one request cannot pull an unbounded chain into
#: memory. An operator exports larger histories in windows by time.
MAX_EXPORT_RECEIPTS = 10_000

_SEARCH_FILTERS = frozenset((
    "host", "from", "to", "action", "verdict", "principal", "policy_id",
    "policy_epoch", "q", "limit", "cursor",
))

#: Query names that would imply raw or unredacted content. They are refused
#: rather than ignored, so a client cannot believe it searched a field.
_FORBIDDEN_QUERY = frozenset(("preview", "raw", "args", "arguments"))


def _now(app: Any) -> float:
    clock = getattr(app, "_clock", None)
    return float(clock()) if callable(clock) else 0.0


def _iso(value: Optional[float]) -> Optional[str]:
    if value is None:
        return None
    return datetime.datetime.fromtimestamp(
        value, tz=datetime.timezone.utc).isoformat()


def _audit(app: Any, request: Request, event: str, *,
           actor: Optional[str] = None,
           detail: Optional[Dict[str, Any]] = None) -> None:
    app.store.audit_append(
        request.org.id, event,
        actor=actor if actor is not None else getattr(request.user, "id", None),
        detail=dict(detail or {}, ip=request.client_ip),
    )


def _require_step_up(app: Any, request: Request) -> None:
    session = getattr(request, "session", None)
    if not StepUpService.fresh(getattr(session, "step_up_at", None),
                               now=_now(app)):
        raise StepUpError("step_up_required",
                          "a fresh step-up is required for this action")


# -- body decoding ------------------------------------------------------

def _gunzip(body: bytes) -> bytes:
    """Decompress a gzip body with a hard cap on the decompressed size."""
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = decompressor.decompress(body, MAX_DECOMPRESSED_BYTES + 1)
    except zlib.error:
        raise ApiError(422, "invalid_request", "malformed gzip body") from None
    if len(out) > MAX_DECOMPRESSED_BYTES or decompressor.unconsumed_tail:
        raise ApiError(
            413, "payload_too_large",
            "decompressed body exceeds {} bytes".format(MAX_DECOMPRESSED_BYTES))
    try:
        out += decompressor.flush()
    except zlib.error:
        raise ApiError(422, "invalid_request", "malformed gzip body") from None
    if len(out) > MAX_DECOMPRESSED_BYTES:
        raise ApiError(
            413, "payload_too_large",
            "decompressed body exceeds {} bytes".format(MAX_DECOMPRESSED_BYTES))
    return out


def _json_body(request: Request, allowed: Iterable[str]) -> Dict[str, Any]:
    encoding = (request.header("content-encoding") or "identity").strip().lower()
    body = request.body
    if encoding == "gzip":
        body = _gunzip(body)
    elif encoding not in ("", "identity"):
        raise ApiError(415, "unsupported_encoding",
                       "content-encoding must be identity or gzip")
    return parse_json_body(body, request.headers, allowed)


# -- ingest -------------------------------------------------------------

def _ingest_host(app: Any, request: Request) -> Any:
    host = app.store.host_by_id(request.key.org_id, request.key.host_id)
    if host is None:
        raise ApiError(401, "unauthenticated", "host no longer exists")
    if host.state == "ingest_frozen":
        raise ApiError(409, "ingest_frozen",
                       "receipt ingest is frozen after a chain fork")
    if host.state != "active":
        raise ApiError(403, "forbidden", "host is not active")
    return host


def _check_host_field(body: Dict[str, Any], host: Any) -> None:
    declared = body.get("host_id")
    if declared is not None and str(declared) != str(host.id):
        raise ApiError(422, "invalid_request",
                       "host_id does not match the authenticated key")


def _receipts(body: Dict[str, Any]) -> List[Receipt]:
    items = body.get("receipts")
    if not isinstance(items, list):
        raise ApiError(422, "invalid_request", "receipts must be a list")
    if len(items) > MAX_BATCH_RECEIPTS:
        raise ApiError(422, "invalid_request",
                       "a batch may carry at most {} receipts".format(
                           MAX_BATCH_RECEIPTS))
    receipts: List[Receipt] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            raise ApiError(422, "invalid_request",
                           "receipt {} must be an object".format(index))
        unknown = sorted(set(item) - RECEIPT_WIRE_FIELDS)
        if unknown:
            raise ApiError(422, "invalid_request",
                           "receipt {} has unknown field: {}".format(
                               index, unknown[0]))
        try:
            receipts.append(Receipt(**item))
        except TypeError:
            raise ApiError(422, "invalid_request",
                           "receipt {} is missing a required field".format(
                               index)) from None
    return receipts


def _fork(app: Any, request: Request, host: Any, result: Any = None) -> None:
    """Freeze ingest, record the break and open an admin alert (FR-036)."""
    try:
        app.store.freeze_host(host.org_id, host.id)
    except Exception:  # the refusal still stands if the freeze write fails
        pass
    detail = {
        "host_id": host.id,
        "first_bad": getattr(result, "first_bad", None),
        "reason": getattr(result, "reason", None),
        "ip": request.client_ip,
    }
    _audit(app, request, "receipts.fork", actor=request.key.key_id,
           detail=detail)
    _audit(app, request, "alert.opened", actor="system:receipts",
           detail=dict(detail, kind="receipt_chain_fork"))
    raise ApiError(409, "chain_fork",
                   "receipt batch does not continue the stored chain")


async def upload_receipts(app: Any, request: Request) -> Response:
    """Verify and append one batch; idempotent by ``mac`` (FR-032 .. FR-037)."""
    host = _ingest_host(app, request)
    body = _json_body(request, INGEST_FIELDS)
    _check_host_field(body, host)
    receipts = _receipts(body)

    head = app.store.receipt_head(host.org_id, host.id)
    previous_head = head.get("head_mac") or None
    count = int(head.get("count") or 0)
    known = app.store.receipt_macs(host.org_id, host.id) if receipts else []
    result = verify_batch(
        receipts,
        host=host,
        previous_head=previous_head,
        checkpoints=app.store.list_checkpoints(host.org_id, host.id),
        now=_now(app),
        previous_count=count,
        known_macs=known,
        host_id=host.id,
        org_id=host.org_id,
    )
    if result.status == "fork":
        _fork(app, request, host, result)

    level = result.verification if result.status in VERIFICATION_LEVELS else None
    try:
        stored = app.store.append_receipts(
            host.org_id, host.id, receipts, result,
            verification=level, now=_now(app))
    except ReceiptFork:
        # The store re-validated against the locked head: another upload won
        # the race and this batch does not continue the chain it left.
        _fork(app, request, host, result)

    _audit(app, request, "receipts.ingested", actor=request.key.key_id,
           detail={
               "host_id": host.id,
               "accepted": int(stored.get("accepted") or 0),
               "replay": bool(stored.get("replay")),
               "status": result.status,
               "verification": stored.get("verification"),
               "head": stored.get("head"),
           })
    return json_response(200, {
        "status": result.status,
        "accepted": int(stored.get("accepted") or 0),
        "replay": bool(stored.get("replay")),
        "head": stored.get("head"),
        "count": int(stored.get("count") or 0),
        "verification": stored.get("verification"),
    })


async def upload_checkpoint(app: Any, request: Request) -> Response:
    """Append one signed checkpoint for the stored chain head (FR-034)."""
    host = _ingest_host(app, request)
    body = _json_body(request, CHECKPOINT_FIELDS)
    doc = {name: body.get(name) for name in CHECKPOINT_FIELDS}
    if doc.get("org_id") is None:
        doc["org_id"] = request.org.id
    if doc.get("host_id") is None:
        doc["host_id"] = host.id

    problem = verify_checkpoint(
        doc, receipt_public_key(host),
        host_id=host.id, org_id=host.org_id)
    if problem is not None:
        raise ApiError(422, "invalid_checkpoint",
                       "checkpoint failed the {} check".format(problem))

    head = app.store.receipt_head(host.org_id, host.id)
    if not head.get("head_mac") or str(doc.get("head_mac")) != str(head["head_mac"]):
        raise ApiError(409, "checkpoint_not_at_head",
                       "checkpoint does not cover the stored chain head")
    if int(doc.get("count")) != int(head.get("count") or 0):
        raise ApiError(409, "checkpoint_count_mismatch",
                       "checkpoint count does not match the stored count")
    latest = app.store.latest_checkpoint(host.org_id, host.id)
    if latest is not None and float(doc.get("issued_at") or 0.0) <= float(
            latest.get("issued_at") or 0.0):
        raise ApiError(409, "checkpoint_not_newer",
                       "checkpoint is not newer than the last one stored")

    stored = app.store.append_checkpoint(host.org_id, host.id, doc,
                                         now=_now(app))
    stored.pop("_stored_at", None)
    _audit(app, request, "receipts.checkpoint", actor=request.key.key_id,
           detail={"host_id": host.id, "head_mac": doc.get("head_mac"),
                   "count": int(doc.get("count") or 0),
                   "issued_at": float(doc.get("issued_at") or 0.0)})
    head = app.store.receipt_head(host.org_id, host.id)
    return json_response(200, {
        "checkpoint": stored,
        "verification": head.get("verification"),
    })


# -- audit search and export -------------------------------------------

def _time_param(request: Request, name: str) -> Optional[float]:
    raw = request.query_one(name)
    if raw is None or raw == "":
        return None
    try:
        return float(raw)
    except ValueError:
        pass
    try:
        return datetime.datetime.fromisoformat(
            raw.replace("Z", "+00:00")).timestamp()
    except ValueError:
        raise ApiError(422, "invalid_request",
                       "{} must be an epoch or ISO-8601 time".format(name)) from None


def _query_int(request: Request, name: str, default: int) -> int:
    raw = request.query_one(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise ApiError(422, "invalid_request",
                       "{} must be an integer".format(name)) from None


def _search_filters(request: Request) -> Dict[str, Any]:
    for name in request.query:
        if name in _FORBIDDEN_QUERY:
            raise ApiError(422, "invalid_request",
                           "{} may not be searched".format(name))
        if name not in _SEARCH_FILTERS:
            raise ApiError(422, "invalid_request",
                           "unknown filter: {}".format(name))
    limit = _query_int(request, "limit", 50)
    if limit < 1 or limit > MAX_AUDIT_LIMIT:
        raise ApiError(422, "invalid_request",
                       "limit must be between 1 and {}".format(MAX_AUDIT_LIMIT))
    cursor = _query_int(request, "cursor", 0)
    if cursor < 0:
        raise ApiError(422, "invalid_request", "cursor must not be negative")
    q = request.query_one("q")
    if q is not None and len(q) > MAX_QUERY_CHARS:
        raise ApiError(422, "invalid_request",
                       "q must be at most {} characters".format(
                           MAX_QUERY_CHARS))
    return {
        "host_id": request.query_one("host"),
        "from_ts": _time_param(request, "from"),
        "to_ts": _time_param(request, "to"),
        "action": request.query_one("action"),
        "verdict": request.query_one("verdict"),
        "principal": request.query_one("principal"),
        "policy_id": request.query_one("policy_id"),
        "policy_epoch": request.query_one("policy_epoch"),
        "q": request.query_one("q"),
        "limit": limit,
        "cursor": cursor,
    }


def _matches(item: Dict[str, Any], filters: Dict[str, Any]) -> bool:
    """Apply the same filters in Python for a bounded export walk."""
    # Keep the time base identical to ``search_receipts``: the receipt's own
    # ``ts`` wins and ingest time is the fallback. Using ``created`` alone
    # would let an export and the search that preceded it disagree about which
    # receipts fall in the window.
    raw_ts = item.get("ts")
    try:
        when: Optional[float] = float(
            raw_ts if raw_ts is not None else item.get("created"))
    except (TypeError, ValueError):
        when = None
    if filters["from_ts"] is not None and (
            when is None or when < float(filters["from_ts"])):
        return False
    if filters["to_ts"] is not None and (
            when is None or when > float(filters["to_ts"])):
        return False
    for column, key in (("action", "action"), ("verdict", "verdict"),
                        ("principal", "principal"),
                        ("policy_id", "policy_id"),
                        ("policy_epoch", "policy_epoch")):
        wanted = filters.get(column)
        if wanted is not None and str(item.get(key)) != str(wanted):
            return False
    needle = (filters.get("q") or "").lower()
    if needle and not any(
            needle in str(item.get(name) or "").lower()
            for name in ("action", "reason", "policy_id")):
        return False
    return True


async def search_audit(app: Any, request: Request) -> Response:
    """Search this org's receipts; auditors may never read a preview (FR-038)."""
    filters = _search_filters(request)
    host_id = filters.get("host_id")
    if host_id and app.store.host_by_id(request.org.id, host_id) is None:
        # A host in another org is indistinguishable from a missing one, so a
        # probe learns nothing about the other tenant.
        raise ApiError(404, "not_found", "no such host")
    result = app.store.search_receipts(request.org.id, **filters)
    _audit(app, request, "audit.searched", detail={
        "host_id": filters.get("host_id"),
        "filters": {key: value for key, value in filters.items()
                    if value is not None and key != "cursor"},
    })
    return json_response(200, result)


def _export_rows(app: Any, org_id: str, host_id: str) -> List[Dict[str, Any]]:
    rows = app.store.receipts_since(org_id, host_id, 0, MAX_EXPORT_RECEIPTS + 1)
    if len(rows) > MAX_EXPORT_RECEIPTS:
        raise ApiError(
            422, "invalid_request",
            "export is larger than {} receipts; narrow the time range".format(
                MAX_EXPORT_RECEIPTS))
    return rows


async def export_audit(app: Any, request: Request) -> Response:
    """Export a host's matching receipts as verified JSONL (FR-038, FR-040)."""
    filters = _search_filters(request)
    host_id = filters.get("host_id")
    if not host_id:
        raise ApiError(422, "invalid_request",
                       "host is required to verify an export")
    host = app.store.host_by_id(request.org.id, host_id)
    if host is None:
        raise ApiError(404, "not_found", "no such host")

    rows = _export_rows(app, request.org.id, host_id)
    whole_chain: List[Receipt] = []
    selected: List[Tuple[Dict[str, Any], Receipt]] = []
    for row in rows:
        body = dict(row.get("body") or {})
        body.update({"host_id": row.get("host_id"),
                     "verification": row.get("verification"),
                     "seq": row.get("seq"),
                     "created": row.get("created")})
        receipt_fields = {name: body.get(name)
                          for name in RECEIPT_WIRE_FIELDS}
        receipt = Receipt(**receipt_fields)
        whole_chain.append(receipt)
        if _matches(body, filters):
            selected.append((body, receipt))

    # Verify the retained chain itself, not only the filtered subset: an
    # action/verdict filter selects non-contiguous receipts by design, and a
    # filtered export must still refuse a tampered host chain.
    start_prev = whole_chain[0].prev if whole_chain else None
    problem = verify_export(whole_chain, host=host, start_prev=start_prev)
    if problem is not None:
        _audit(app, request, "receipts.export_refused", detail={
            "host_id": host_id, "reason": problem})
        raise ApiError(409, "chain_broken",
                       "the selected chain does not verify: {}".format(problem))

    lines = b"".join(
        (receipt.to_json() + "\n").encode("utf-8") for _row, receipt in selected)
    _audit(app, request, "receipts.exported", detail={
        "host_id": host_id, "count": len(selected),
        "filters": {key: value for key, value in filters.items()
                    if value is not None and key not in ("cursor", "host_id")},
    })
    return Response(
        status=200,
        body=lines,
        content_type="application/x-ndjson",
        headers=[("content-disposition",
                  'attachment; filename="receipts-{}.jsonl"'.format(host_id))],
    )


# -- retention and unfreeze --------------------------------------------

async def run_retention(app: Any, request: Request) -> Response:
    """Run the retention job now, with a required reason (FR-039)."""
    _require_step_up(app, request)
    body = parse_json_body(request.body, request.headers,
                           ("dry_run", "days", "reason"))
    dry_run = body.get("dry_run", False)
    if not isinstance(dry_run, bool):
        raise ApiError(422, "invalid_request", "dry_run must be a boolean")
    days = body.get("days")
    if days is None:
        days = getattr(request.org, "retention_days", None)
    if isinstance(days, bool) or not isinstance(days, int):
        raise ApiError(422, "invalid_request", "days must be an integer")
    reason = body.get("reason")
    if reason is not None and not isinstance(reason, str):
        raise ApiError(422, "invalid_request", "reason must be a string")
    if not dry_run and not (reason or "").strip():
        raise ApiError(422, "invalid_request",
                       "a reason is required to delete receipts")
    result = run_retention_job(
        app.store, _now(app), days=days, dry_run=dry_run)
    _audit(app, request, "retention.requested", detail={
        "days": days, "dry_run": dry_run, "reason": (reason or "")[:4000],
        "receipts": result.get("receipts"),
        "checkpoints": result.get("checkpoints"),
    })
    return json_response(200, {"retention": result})


async def unfreeze_host(app: Any, request: Request) -> Response:
    """Clear ``ingest_frozen`` deliberately, with a reason (FR-036)."""
    _require_step_up(app, request)
    host_id = (request.params or {}).get("id", "")
    host = app.store.host_by_id(request.org.id, host_id)
    if host is None:
        raise ApiError(404, "not_found", "host not found")
    body = parse_json_body(request.body, request.headers, ("reason",))
    reason = body.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        raise ApiError(422, "invalid_request",
                       "a reason is required to unfreeze ingest")
    if host.state != "ingest_frozen":
        raise ApiError(409, "host_not_frozen",
                       "host {} is {}".format(host.id, host.state))
    host = app.store.unfreeze_host(request.org.id, host.id)
    _audit(app, request, "host.unfrozen", detail={
        "host_id": host.id, "reason": reason[:4000]})
    return json_response(200, {"host": {"id": host.id, "state": host.state}})


def register(app: Any) -> None:
    app.add_route("/v1/receipts", "POST", partial(upload_receipts, app))
    app.add_route("/v1/checkpoints", "POST", partial(upload_checkpoint, app))
    app.add_route("/v1/audit", "GET", partial(search_audit, app))
    app.add_route("/v1/audit/export", "GET", partial(export_audit, app))
    app.add_route("/v1/admin/retention/run", "POST",
                  partial(run_retention, app))
    app.add_pattern("/v1/hosts/{id}/unfreeze", "POST",
                    partial(unfreeze_host, app))


__all__ = [
    "CHECKPOINT_FIELDS",
    "INGEST_FIELDS",
    "MAX_AUDIT_LIMIT",
    "MAX_BATCH_RECEIPTS",
    "MAX_DECOMPRESSED_BYTES",
    "MAX_EXPORT_RECEIPTS",
    "RECEIPT_WIRE_FIELDS",
    "export_audit",
    "register",
    "run_retention",
    "search_audit",
    "unfreeze_host",
    "upload_checkpoint",
    "upload_receipts",
]

"""Server-rendered admin audit and fleet pages (C7, FR-038).

Two read-only pages, both under C1's CSP and both role-gated by the RBAC table
(owner, admin and auditor). They exist for the incident-response case where an
operator needs the audit trail and the fleet state without a JSON client.

What they must never do:

* print a raw payload, preview, argument, key or token;
* print a review's decrypted preview (C3 audits every such read separately);
* accept a filter that could be mistaken for a content search.

The only tenant text rendered is the actor, the action name and an id; every
one is escaped. A "hash" column shows the recorded ``before_sha256`` /
``after_sha256`` when an action wrote one, and otherwise the SHA-256 of the
audit entry's own detail object - never the detail itself.
"""
from __future__ import annotations

import datetime
import hashlib
import json
from functools import partial
from typing import Any, Dict, List, Optional, Tuple

from ..http import ApiError, Request, Response
from ..ui import _page as render_page
from ..ui import _field, _url
from .receipt_routes import export_audit

#: Rows per page on both admin pages.
PAGE_SIZE = 25

#: Audit filters, and nothing else. A raw-content filter is refused by name.
_AUDIT_FILTERS = frozenset(("actor", "action", "from", "to", "cursor"))
_FORBIDDEN_FILTERS = frozenset(("preview", "raw", "args", "arguments",
                                "payload", "body"))


def _iso(value: float) -> str:
    return datetime.datetime.fromtimestamp(
        value, tz=datetime.timezone.utc).isoformat()


def _query_int(request: Request, name: str, default: int) -> int:
    raw = request.query_one(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except (TypeError, ValueError):
        raise ApiError(422, "invalid_request",
                       "{} must be an integer".format(name)) from None


def _time_param(request: Request, name: str) -> Optional[float]:
    """Parse an ISO date or datetime; a date-only ``to`` is inclusive."""
    raw = request.query_one(name)
    if raw is None or raw == "":
        return None
    text = raw.strip()
    try:
        if len(text) == 10:
            day = datetime.date.fromisoformat(text)
            start = datetime.datetime(
                day.year, day.month, day.day, tzinfo=datetime.timezone.utc)
            stamp = start.timestamp()
            return stamp + 86399.999999 if name == "to" else stamp
        when = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ApiError(422, "invalid_request",
                       "{} must be an ISO date or datetime".format(name)) \
            from None
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    return when.timestamp()


def _digest(value: Any) -> str:
    body = json.dumps(value, sort_keys=True, separators=(",", ":"),
                      default=str).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def _as_hash(value: Any) -> str:
    """A 64-hex value is already a digest; anything else is hashed."""
    if isinstance(value, str):
        lowered = value.lower()
        if len(lowered) == 64 and all(ch in "0123456789abcdef"
                                      for ch in lowered):
            return lowered
    return _digest(value)


def _entry_hashes(entry: Any) -> Tuple[str, str]:
    detail = dict(getattr(entry, "detail", None) or {})
    before = None
    for name in ("before_sha256", "prev_sha256", "previous_sha256",
                 "args_digest"):
        if detail.get(name) is not None:
            before = detail[name]
            break
    after = None
    for name in ("after_sha256", "result_sha256", "sha256"):
        if detail.get(name) is not None:
            after = detail[name]
            break
    return (
        _as_hash(before) if before is not None else "",
        _as_hash(after) if after is not None else _digest(detail),
    )


_TARGET_KEYS = ("target", "host_id", "review_id", "webhook_id",
                "agent_key_id", "policy_id", "rollout_id", "grant_id", "id")


def _entry_target(detail: Dict[str, Any]) -> str:
    for name in _TARGET_KEYS:
        value = detail.get(name)
        if value in (None, ""):
            continue
        if isinstance(value, dict):
            kind = value.get("kind")
            target_id = value.get("id")
            if kind is not None and target_id is not None:
                return "{}:{}".format(kind, target_id)
            if target_id is not None:
                return str(target_id)
            continue
        return str(value)
    return ""


def _hash_cell(value: str) -> str:
    if not value:
        return "<span class=\"hint\">—</span>"
    return "<code title=\"{}\">{}</code>".format(
        _field(value), _field(value[:16]))


def _filtered_entries(app: Any, request: Request) -> List[Any]:
    """Newest first, then the actor/action/date filters."""
    actor = (request.query_one("actor") or "").strip().lower()
    action = (request.query_one("action") or "").strip().lower()
    from_ts = _time_param(request, "from")
    to_ts = _time_param(request, "to")
    entries = list(app.store.audit_list(request.org.id))
    entries.sort(key=lambda entry: (entry.created, entry.id), reverse=True)
    out = []
    for entry in entries:
        if actor and actor not in str(entry.actor or "").lower():
            continue
        if action and action not in str(entry.event or "").lower():
            continue
        if from_ts is not None and float(entry.created or 0) < from_ts:
            continue
        if to_ts is not None and float(entry.created or 0) > to_ts:
            continue
        out.append(entry)
    return out


def _nav() -> str:
    return ("<a href=\"/reviews\">Reviews</a> "
            "<a href=\"/admin/audit\">Audit</a> "
            "<a href=\"/admin/hosts\">Hosts</a>")


def _audit_query(request: Request, cursor: int) -> str:
    return _url(
        "/admin/audit",
        actor=request.query_one("actor"),
        action=request.query_one("action"),
        **{"from": request.query_one("from"), "to": request.query_one("to"),
           "cursor": cursor},
    )


async def audit_page(app: Any, request: Request) -> Response:
    """The audit trail: actor, action, target, time, IP and hashes."""
    for name in request.query:
        if name in _FORBIDDEN_FILTERS:
            raise ApiError(422, "invalid_request",
                           "{} may not be filtered".format(name))
        if name not in _AUDIT_FILTERS:
            raise ApiError(422, "invalid_request",
                           "unknown filter: {}".format(name))
    cursor = max(0, _query_int(request, "cursor", 0))
    entries = _filtered_entries(app, request)
    page = entries[cursor:cursor + PAGE_SIZE]
    next_cursor = (cursor + len(page)
                   if cursor + len(page) < len(entries) else None)

    if page:
        rows = []
        for entry in page:
            detail = dict(getattr(entry, "detail", None) or {})
            before, after = _entry_hashes(entry)
            rows.append(
                "<tr>"
                "<td>{}<br><span class=\"hint\">{}</span></td>"
                "<td>{}</td><td>{}</td>"
                "<td><code>{}</code></td>"
                "<td>{}</td><td>{}</td>"
                "</tr>".format(
                    _field(_iso(float(entry.created or 0))),
                    _field(entry.event),
                    _field(entry.actor or "system"),
                    _field(_entry_target(detail) or "—"),
                    _field(str(detail.get("ip") or "—")),
                    _hash_cell(before), _hash_cell(after),
                ))
        listing = (
            "<table><thead><tr><th>Time / action</th><th>Actor</th>"
            "<th>Target</th><th>IP</th><th>Before</th><th>After</th>"
            "</tr></thead><tbody>{}</tbody></table>".format("".join(rows)))
        if next_cursor is not None:
            listing += "<p><a href=\"{}\">Next page</a></p>".format(
                _field(_audit_query(request, next_cursor)))
    else:
        listing = "<p class=\"hint\">No audit entries match.</p>"

    body = (
        "<h2>Audit</h2>"
        "<p class=\"hint\">Newest first. Hashes are recorded before/after "
        "digests; payloads are never shown.</p>"
        "<form method=\"get\" action=\"/admin/audit\">"
        "<label for=\"actor\">Actor</label>"
        "<input id=\"actor\" type=\"text\" name=\"actor\" value=\"{}\">"
        "<label for=\"action\">Action</label>"
        "<input id=\"action\" type=\"text\" name=\"action\" value=\"{}\">"
        "<label for=\"from\">From (ISO date)</label>"
        "<input id=\"from\" type=\"text\" name=\"from\" value=\"{}\">"
        "<label for=\"to\">To (ISO date)</label>"
        "<input id=\"to\" type=\"text\" name=\"to\" value=\"{}\">"
        "<button type=\"submit\">Filter</button></form>{}"
        "<p class=\"hint\">Export a verified receipt chain as JSONL from "
        "<a href=\"/admin/audit/export\">/admin/audit/export</a> "
        "(a host is required, as in the C4 export).</p>"
    ).format(
        _field(request.query_one("actor") or ""),
        _field(request.query_one("action") or ""),
        _field(request.query_one("from") or ""),
        _field(request.query_one("to") or ""),
        listing,
    )
    return render_page("Audit", body, nav=_nav())


async def hosts_page(app: Any, request: Request) -> Response:
    """The fleet: state, last sync and active key count per host."""
    cursor = max(0, _query_int(request, "cursor", 0))
    hosts = sorted(app.store.list_hosts(request.org.id),
                   key=lambda host: host.id)
    page = hosts[cursor:cursor + PAGE_SIZE]
    next_cursor = (cursor + len(page)
                   if cursor + len(page) < len(hosts) else None)
    if page:
        rows = []
        for host in page:
            keys = app.store.list_agent_keys(request.org.id, host.id)
            active = sum(1 for key in keys if key.revoked_at is None)
            rows.append(
                "<tr><td><code>{}</code><br>{}</td><td>{}</td>"
                "<td>{}</td><td>{}</td></tr>".format(
                    _field(host.id), _field(host.name),
                    _field(host.state),
                    _field(_iso(float(host.last_seen))
                           if host.last_seen else "never"),
                    "{} active / {} total".format(active, len(keys)),
                ))
        listing = (
            "<table><thead><tr><th>Host</th><th>State</th>"
            "<th>Last seen</th><th>Keys</th></tr></thead>"
            "<tbody>{}</tbody></table>".format("".join(rows)))
        if next_cursor is not None:
            listing += "<p><a href=\"{}\">Next page</a></p>".format(
                _field(_url("/admin/hosts", cursor=next_cursor)))
    else:
        listing = "<p class=\"hint\">No hosts enrolled.</p>"
    body = ("<h2>Hosts</h2><p class=\"hint\">Fleet state for this org, "
            "newest page as a slice of the host id order.</p>" + listing)
    return render_page("Hosts", body, nav=_nav())


async def audit_export(app: Any, request: Request) -> Response:
    """JSONL receipts for auditors, straight through C4's export path."""
    if not request.query_one("host"):
        raise ApiError(422, "invalid_request",
                       "host is required to verify an export")
    return await export_audit(app, request)


def register(app: Any) -> None:
    app.add_route("/admin/audit", "GET", partial(audit_page, app))
    app.add_route("/admin/audit/export", "GET", partial(audit_export, app))
    app.add_route("/admin/hosts", "GET", partial(hosts_page, app))


__all__ = [
    "PAGE_SIZE",
    "audit_export",
    "audit_page",
    "hosts_page",
    "register",
]

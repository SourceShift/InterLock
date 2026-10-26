"""The hosted, server-rendered review UI (C3, FR-017 .. FR-024).

Two pages and three form posts, all server-rendered: a reviewer opens the
plane on a phone, reads the decrypted preview of one review, completes a
step-up, and decides. The list page never decrypts anything, and no page puts
preview text in a URL or a link.

Constraints this module keeps deliberately:

* **No third-party assets.** The stylesheet is inline; the only external
  request is the same-origin ``/static/stepup.js``, which is what the per-page
  CSP allows. C1's :data:`~interlock.cloud.http.CSP` is a prefix of
  :data:`UI_CSP`, so the admin pages' policy is unchanged.
* **Forms carry the CSRF token.** A plain HTML form cannot set a header, so
  the token travels in a hidden field and the app accepts it from the
  urlencoded body (:func:`interlock.cloud.app._form_csrf`).
* **Everything rendered from tenant data is escaped** with
  :func:`interlock.cloud.http.escape`.
* **Step-up is reusable, not reimplemented.** TOTP works with no JavaScript;
  ``static/stepup.js`` adds a WebAuthn assertion for browsers that support it.
"""
from __future__ import annotations

import json
import time
from functools import partial
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, quote

from .api.review_routes import decide_review, load_preview
from .auth.stepup import StepUpError, StepUpService
from .http import (
    CSP,
    ApiError,
    Request,
    Response,
    escape,
    redirect_response,
)
from .store import PLANE_REVIEW_STATUSES, ReviewRecord

#: C1's policy with the one addition the UI needs: a same-origin script.
UI_CSP = (CSP + "; script-src 'self'; base-uri 'none'; frame-ancestors 'none'")

#: The viewport the kickoff fixes: a 390 px phone, no horizontal scroll.
VIEWPORT = "width=390, initial-scale=1"

STATIC_DIR = Path(__file__).with_name("static")
STEPUP_SCRIPT = STATIC_DIR / "stepup.js"

_UI_STYLE = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { margin: 0 auto; max-width: 390px; padding: 16px;
       font: 16px/1.45 -apple-system, "Segoe UI", system-ui, sans-serif; }
header { display: flex; align-items: baseline; justify-content: space-between;
         gap: 8px; margin-bottom: 12px; }
h1 { font-size: 1.25rem; margin: 0; }
h2 { font-size: 1rem; margin: 20px 0 6px; }
a { color: #0b5fff; }
ul { list-style: none; padding: 0; margin: 0; }
li.review { border: 1px solid #767680; border-radius: 10px;
            padding: 10px 12px; margin: 8px 0; }
li.review a { display: block; text-decoration: none; color: inherit; }
.k { color: #5c5c66; font-size: .8rem; text-transform: uppercase;
     letter-spacing: .04em; }
.meta { color: #5c5c66; font-size: .85rem; }
.badge { display: inline-block; border-radius: 999px; padding: 1px 8px;
         border: 1px solid #767680; font-size: .75rem; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; background: #f3f3f7;
      color: #16161a; border-radius: 10px; padding: 10px; margin: 6px 0; }
dl { display: grid; grid-template-columns: 7.5rem 1fr; gap: 4px 8px;
     margin: 0; }
dt { color: #5c5c66; font-size: .85rem; }
dd { margin: 0; overflow-wrap: anywhere; }
form { margin: 16px 0; display: grid; gap: 10px; }
label { font-weight: 600; }
textarea, input[type=text] { width: 100%; min-height: 44px; padding: 8px;
      border: 1px solid #767680; border-radius: 8px; font: inherit;
      background: transparent; color: inherit; }
button { min-height: 44px; padding: 10px 14px; border-radius: 10px;
         border: 1px solid #0b5fff; font: inherit; font-weight: 600;
         background: #0b5fff; color: #fff; }
button.secondary { background: transparent; color: inherit;
                   border-color: #767680; }
button.danger { background: transparent; color: #b00020; border-color: #b00020; }
:focus-visible { outline: 3px solid #ffb000; outline-offset: 2px; }
.notice { border-left: 4px solid #b00020; padding: 8px 10px;
          margin: 12px 0; background: #fff1f1; color: #4a000c; }
.hint { color: #5c5c66; font-size: .85rem; }
.actions { display: grid; gap: 10px; }
[hidden] { display: none !important; }
"""


def _now(app: Any) -> float:
    clock = getattr(app, "_clock", None)
    return float(clock()) if callable(clock) else time.time()


def _url(base: str, **query: Any) -> str:
    pairs = ["{}={}".format(quote(str(name)), quote(str(value)))
             for name, value in query.items() if value is not None]
    return base + ("?" + "&".join(pairs) if pairs else "")


def _page(title: str, body: str, *, status: int = 200,
          script: bool = False) -> Response:
    script_tag = ('<script src="/static/stepup.js" defer></script>'
                  if script else "")
    document = (
        "<!doctype html><html lang=\"en\"><head>"
        "<meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"{}\">"
        "<title>{} · interlock</title>"
        "<style>{}</style>{}"
        "</head><body><header><h1>interlock</h1>"
        "<a href=\"/reviews\">Reviews</a></header>{}</body></html>"
    ).format(VIEWPORT, escape(title), _UI_STYLE, script_tag, body)
    # One policy, not C1's plus the UI's: two CSP headers are both enforced,
    # and C1's ``default-src 'none'`` would block the same-origin script.
    return Response(
        status=status, body=document.encode("utf-8"),
        content_type="text/html; charset=utf-8",
        headers=[("content-security-policy", UI_CSP),
                 ("x-content-type-options", "nosniff")],
    )


def _csrf(app: Any, request: Request) -> str:
    return app.sessions.csrf_token(request.session.id)


def _field(value: Any) -> str:
    return escape("" if value is None else value)


def _review_url(review_id: str) -> str:
    return "/reviews/" + quote(review_id, safe="")


def _list_item(record: ReviewRecord, now: float) -> str:
    age = max(0, int(now - record.created))
    minutes = age // 60
    age_text = "{}m".format(minutes) if minutes else "{}s".format(age)
    masked = ", ".join("{}={}".format(name, count)
                       for name, count in sorted(record.mask_counts.items()))
    detail = " · ".join(part for part in (
        _field(record.phase),
        _field(record.requester or record.principal or "unknown requester"),
        _field(record.host_id), age_text,
        "{} approval(s)".format(record.min_approvals),
        ("masked: " + escape(masked)) if masked else "",
        _field(record.reason) if record.reason else "",
    ) if part)
    return (
        "<li class=\"review\"><a href=\"{}\">"
        "<span class=\"badge\">{}</span> "
        "<strong>{}</strong>"
        "<div class=\"meta\">{}</div>"
        "</a></li>"
    ).format(
        _field(_review_url(record.id)), _field(record.status),
        _field(record.action), detail,
    )


async def reviews_page(app: Any, request: Request) -> Response:
    """The list: no preview is read, so none can leak into HTML or a URL."""
    status = request.query_one("status")
    if status is not None and status not in PLANE_REVIEW_STATUSES:
        raise ApiError(422, "invalid_request", "unknown status")
    try:
        cursor = int(request.query_one("cursor") or 0)
    except (TypeError, ValueError):
        raise ApiError(422, "invalid_request", "cursor must be an integer") from None
    records, next_cursor = app.store.list_reviews(
        request.org.id, status=status, cursor=max(0, cursor), limit=50)
    now = _now(app)
    filters = [("Pending", _url("/reviews", status="pending")),
               ("All", "/reviews"),
               ("Approved", _url("/reviews", status="approved"))]
    nav = " ".join("<a href=\"{}\">{}</a>".format(escape(href), escape(label))
                   for label, href in filters)
    if records:
        items = "".join(_list_item(record, now) for record in records)
        listing = "<ul>{}</ul>".format(items)
        if next_cursor is not None:
            listing += "<p><a href=\"{}\">Next page</a></p>".format(
                _field(_url("/reviews", status=status, cursor=next_cursor)))
    else:
        listing = "<p class=\"hint\">Nothing to review.</p>"
    body = ("<h2>Reviews</h2><p class=\"meta\">{}</p>{}"
            "<p class=\"hint\">Signed in as {}. A decision needs a fresh "
            "step-up.</p>").format(
        nav, listing, _field(getattr(request.user, "email", "")))
    return _page("Reviews", body)


def _step_up_service(app: Any) -> StepUpService:
    """The injected service (tests, a deployment with TOTP) or a bare one."""
    service = getattr(app, "step_up_service", None)
    if service is None:
        service = StepUpService(clock=getattr(app, "_clock", None) or time.time)
        app.step_up_service = service
    return service


def _challenge(app: Any, request: Request) -> Optional[Dict[str, Any]]:
    if StepUpService.fresh(request.session.step_up_at, now=_now(app)):
        return None
    try:
        return _step_up_service(app).begin(request.user.id, "totp")
    except StepUpError:
        return None


def _detail_body(app: Any, request: Request, record: ReviewRecord,
                 preview: str, error: Optional[str] = None,
                 status: int = 200) -> str:
    csrf = _csrf(app, request)
    rows = [
        ("Status", record.status), ("Action", record.action),
        ("Phase", record.phase), ("Host", record.host_id),
        ("Requested by", record.requester or record.principal or "unknown"),
        ("Policy", record.policy_id or "—"),
        ("Reason", record.reason or "—"),
        ("Arguments", record.args_digest or "—"),
        ("Approvals", "{} of {}".format(len(record.approvers),
                                        record.min_approvals)),
        ("Decided by", record.decided_by or "—"),
    ]
    facts = "".join("<dt>{}</dt><dd>{}</dd>".format(escape(name), _field(value))
                    for name, value in rows)
    masks = ("<p class=\"meta\">Masked: {}</p>".format(
        escape(", ".join("{}={}".format(k, v)
                         for k, v in sorted(record.mask_counts.items()))))
        if record.mask_counts else "")
    notice = ("<div class=\"notice\" role=\"alert\">{}</div>".format(escape(error))
              if error else "")

    form = ""
    if record.status == "pending":
        form = (
            "<h2>Decide</h2>"
            "<form method=\"post\" action=\"{action}\">"
            "<input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">"
            "<label for=\"reason\">Reason (required to approve anyway)</label>"
            "<textarea id=\"reason\" name=\"reason\" rows=\"3\" "
            "maxlength=\"4000\"></textarea>"
            "<label><input type=\"checkbox\" name=\"approve_anyway\" "
            "value=\"1\"> Approve anyway (host has not synced recently)</label>"
            "<div class=\"actions\">"
            "<button type=\"submit\" name=\"decision\" value=\"approve\">Approve</button>"
            "<button class=\"danger\" type=\"submit\" name=\"decision\" "
            "value=\"reject\">Reject</button>"
            "<button class=\"secondary\" type=\"submit\" name=\"decision\" "
            "value=\"revoke\">Revoke</button>"
            "</div></form>"
        ).format(action=escape(_review_url(record.id) + "/decision"),
                 csrf=escape(csrf))

    step_up = ""
    if not StepUpService.fresh(request.session.step_up_at, now=_now(app)):
        challenge = _challenge(app, request)
        challenge_id = (challenge or {}).get("challenge_id", "")
        step_up = (
            "<h2>Step-up</h2>"
            "<p class=\"hint\">A fresh step-up is required before a decision. "
            "Enter your authenticator code, or use a passkey.</p>"
            "<form method=\"post\" action=\"{action}\">"
            "<input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">"
            "<input type=\"hidden\" name=\"method\" value=\"totp\">"
            "<input type=\"hidden\" name=\"challenge_id\" value=\"{challenge}\">"
            "<label for=\"code\">One-time code</label>"
            "<input id=\"code\" name=\"code\" type=\"text\" inputmode=\"numeric\" "
            "autocomplete=\"one-time-code\" pattern=\"[0-9]*\" maxlength=\"8\">"
            "<button type=\"submit\">Verify code</button>"
            "</form>"
            "<button class=\"secondary\" type=\"button\" "
            "data-stepup-webauthn=\"1\" data-challenge=\"{challenge}\" "
            "data-action=\"{action}\">Use a passkey</button>"
        ).format(action=escape(_review_url(record.id) + "/step-up"),
                 csrf=escape(csrf), challenge=escape(challenge_id))

    return (
        "{notice}<h2>{action}</h2><dl>{facts}</dl>{masks}"
        "<h2>Preview</h2><pre>{preview}</pre>"
        "<p class=\"hint\">Every preview read is audited.</p>"
        "{step_up}{form}"
    ).format(notice=notice, action=_field(record.action), facts=facts,
             masks=masks, preview=_field(preview), step_up=step_up, form=form)


async def review_page(app: Any, request: Request) -> Response:
    review_id = (request.params or {}).get("id", "")
    record = app.store.review_by_id(request.org.id, review_id)
    if record is None:
        return _page("Not found", "<p class=\"notice\">No such review.</p>",
                     status=404)
    if getattr(request.user, "role", None) == "auditor":
        return _page("Not found", "<p class=\"notice\">No such review.</p>",
                     status=404)
    preview = load_preview(app, request, record)
    return _page(record.action,
                 _detail_body(app, request, record, preview),
                 script=True)


def _form(request: Request) -> Dict[str, str]:
    content_type = (request.header("content-type") or "").split(
        ";", 1)[0].strip().lower()
    if content_type != "application/x-www-form-urlencoded":
        raise ApiError(415, "unsupported_media_type",
                       "this form must be urlencoded")
    try:
        values = parse_qs(request.body.decode("utf-8"), keep_blank_values=True)
    except (UnicodeDecodeError, ValueError):
        raise ApiError(422, "invalid_request", "malformed form body") from None
    return {name: items[0] for name, items in values.items() if items}


def _see_other(location: str) -> Response:
    response = redirect_response(location)
    response.status = 303
    return response


async def decide_page(app: Any, request: Request) -> Response:
    review_id = (request.params or {}).get("id", "")
    form = _form(request)
    decision = form.get("decision", "")
    reason = form.get("reason") or None
    approve_anyway = form.get("approve_anyway") in ("1", "on", "true")
    record = app.store.review_by_id(request.org.id, review_id)
    if record is None:
        return _page("Not found", "<p class=\"notice\">No such review.</p>",
                     status=404)
    try:
        result = decide_review(app, request, review_id, decision=decision,
                               reason=reason, approve_anyway=approve_anyway)
    except StepUpError as exc:
        preview = load_preview(app, request, record)
        return _page(record.action,
                     _detail_body(app, request, record, preview,
                                  error=exc.message, status=403),
                     status=403, script=True)
    except ApiError as exc:
        preview = load_preview(app, request, record)
        return _page(record.action,
                     _detail_body(app, request, record, preview,
                                  error=exc.message, status=exc.status),
                     status=exc.status, script=True)
    if result.get("status") == "pending_approvals":
        return _see_other(_review_url(review_id))
    return _see_other(_review_url(review_id))


async def step_up_page(app: Any, request: Request) -> Response:
    review_id = (request.params or {}).get("id", "")
    record = app.store.review_by_id(request.org.id, review_id)
    if record is None:
        return _page("Not found", "<p class=\"notice\">No such review.</p>",
                     status=404)
    form = _form(request)
    method = form.get("method", "totp")
    challenge_id = form.get("challenge_id", "")
    assertion: Any = form.get("code", "")
    if method == "webauthn":
        try:
            assertion = json.loads(form.get("assertion") or "{}")
        except ValueError:
            assertion = {}
    try:
        finished = _step_up_service(app).finish(challenge_id, assertion,
                                                now=_now(app))
    except StepUpError as exc:
        preview = load_preview(app, request, record)
        return _page(record.action,
                     _detail_body(app, request, record, preview,
                                  error=exc.message, status=403),
                     status=403, script=True)
    app.sessions.mark_step_up(request.session, finished["method"],
                              now=finished["at"])
    app.store.audit_append(
        request.org.id, "review.step_up",
        actor=request.user.id,
        detail={"review_id": review_id, "method": finished["method"],
                "ip": request.client_ip, "at": finished["at"]},
    )
    return _see_other(_review_url(review_id))


async def stepup_script(app: Any, request: Request) -> Response:
    """Serve the one same-origin asset; no tenant data, no directory listing."""
    try:
        body = STEPUP_SCRIPT.read_bytes()
    except OSError:
        raise ApiError(404, "not_found", "not found") from None
    return Response(
        status=200, body=body, content_type="text/javascript; charset=utf-8",
        headers=[("x-content-type-options", "nosniff"),
                 ("cache-control", "public, max-age=300")],
    )


def register(app: Any) -> None:
    app.add_route("/reviews", "GET", partial(reviews_page, app))
    app.add_pattern("/reviews/{id}", "GET", partial(review_page, app))
    app.add_pattern("/reviews/{id}/decision", "POST", partial(decide_page, app))
    app.add_pattern("/reviews/{id}/step-up", "POST", partial(step_up_page, app))
    app.add_route("/static/stepup.js", "GET", partial(stepup_script, app))


__all__ = ["UI_CSP", "VIEWPORT", "register"]

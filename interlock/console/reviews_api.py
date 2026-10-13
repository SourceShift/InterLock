"""The review queue over HTTP: list, read, approve, reject, revoke.

Reads open the queue's SQLite file only when it exists - looking must never
create ``~/.interlock/reviews.db``. Decisions go through
:class:`interlock.reviews.ReviewQueue` exactly as ``interlock reviews`` does
(same exactly-once claim, same four-eyes rule), as the OS user running the
console, and only from an unlocked tab (:func:`session.require_unlocked`).

``--four-eyes`` on the console refuses an approval by the account that filed
the review; the queue enforces it, the response says so per review
(``self_ok``) so the page can explain the disabled button before a click.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Tuple
from urllib.parse import parse_qs, urlsplit

from .server import PREFIX_ROUTES, ROUTES
from .session import ApiError, handles_errors, read_json_body, require_unlocked, setting, whoami

LIST_LIMIT = 300


def _queue(handler: Any, *, create: bool = False):
    from ..reviews import ReviewQueue

    path = setting(handler, "reviews_db")
    if path is None:
        from ..reviews import default_path
        path = default_path()
    if not create and not os.path.exists(path):
        return None
    return ReviewQueue(path, allow_self_approval=not setting(handler, "four_eyes", False))


def _encode(review: Any, four_eyes: bool, me: str) -> Dict[str, Any]:
    out = review.to_dict()
    out["self_ok"] = not (four_eyes and review.requester == me)
    return out


@handles_errors
def _list(handler: Any) -> Tuple[int, dict]:
    from ..reviews import ReviewError

    queue = _queue(handler)
    path = setting(handler, "reviews_db")
    if queue is None:
        return 200, {"configured": False, "path": path, "reviews": []}
    qs = parse_qs(urlsplit(handler.path).query)
    status = (qs.get("status") or [None])[0]
    try:
        reviews = queue.list(status=status, limit=LIST_LIMIT)
    except ReviewError as exc:
        raise ApiError(400, "bad_query", str(exc))
    four_eyes, me = bool(setting(handler, "four_eyes", False)), whoami()
    return 200, {"configured": True, "path": path,
                 "reviews": [_encode(r, four_eyes, me) for r in reviews]}


@handles_errors
def _review_route(handler: Any) -> Tuple[int, dict]:
    from ..reviews import ReviewError

    parts = [p for p in handler.path_tail.split("/") if p]
    if handler.command == "GET":
        if len(parts) != 1:
            raise ApiError(404, "not_found", "no such API path")
        queue = _queue(handler)
        if queue is None:
            raise ApiError(404, "no_review", "no review {}".format(parts[0]))
        try:
            review = queue.get(parts[0])
        except ReviewError as exc:
            raise ApiError(404, "no_review", str(exc))
        return 200, {"review": _encode(review, bool(setting(handler, "four_eyes", False)), whoami())}

    if len(parts) != 2 or parts[1] not in ("approve", "reject", "revoke"):
        raise ApiError(404, "not_found", "no such API path")
    review_id, action = parts
    body = read_json_body(handler)
    require_unlocked(handler)
    queue = _queue(handler)
    if queue is None:
        raise ApiError(404, "no_review", "no review {}".format(review_id))
    me = whoami()
    try:
        if action == "approve":
            review = queue.approve(review_id, me)
        elif action == "reject":
            reason = str(body.get("reason") or "").strip()
            if not reason:
                raise ApiError(400, "reason_required",
                               "Add a reason. The agent is told why it was rejected.")
            review = queue.reject(review_id, reason[:500], me)
        else:
            review = queue.revoke(review_id, me)
    except ReviewError as exc:
        raise ApiError(409, "review_state", str(exc))
    return 200, {"review": _encode(review, bool(setting(handler, "four_eyes", False)), me)}


ROUTES["/api/reviews"] = {"GET": _list}
PREFIX_ROUTES["/api/reviews/"] = {"GET": _review_route, "POST": _review_route}

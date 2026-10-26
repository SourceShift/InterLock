"""Build the masked review upload (FR-015, FR-016, FR-018).

The host never uploads a call's arguments or its raw event. It uploads the
metadata the reviewer needs, an argument *digest*, and - when a preview
exists - the masking engine's output for that preview plus per-entity counts.

:func:`build_record` is the only constructor for the body, and
:func:`assert_allow_list` checks the finished dict against the exact wire
schema before it can be spooled. The plane enforces the same schema in
:mod:`interlock.cloud.api.review_routes`; this side's assertion turns a
programming error into a raised :class:`ValueError`, never a silent drop.

The requester is a stable HMAC label derived from the host's agent key unless
``share_usernames`` is on in ``cloud.json``. Two hosts cannot correlate their
labels, and the plane cannot invert one.
"""
from __future__ import annotations

import hashlib
import hmac
from typing import Any, Dict, Optional

from ...masking import Masker

#: The exact keys the plane accepts (see ``UPLOAD_FIELDS`` server-side).
ALLOWED_FIELDS = (
    "review_id", "binding", "action", "phase", "principal", "requester",
    "policy_id", "reason", "args_digest", "preview", "mask_counts", "created",
    "pending_until", "min_approvals", "allow_self_approval", "approval_ttl",
)

#: A payload carrying one of these names would leak the raw call.
FORBIDDEN_FIELDS = ("event", "args", "raw", "arguments")

REQUESTER_LABEL_PREFIX = "hmac:"


def requester_label(requester: Optional[str], agent_key: Optional[str], *,
                    share_usernames: bool = False) -> Optional[str]:
    """Return the upload label for ``requester``.

    With ``share_usernames`` on, the plain name is allowed for orgs that have
    decided the reviewer needs it. Otherwise it is HMAC-SHA256 under a key
    derived from the host agent key, truncated to 32 hex characters: stable
    for one host, opaque to the plane and to every other host.
    """
    if requester is None or share_usernames:
        return requester
    key_material = (agent_key or "").encode("utf-8")
    key = hmac.new(key_material, b"interlock-requester-label-v1",
                   hashlib.sha256).digest()
    digest = hmac.new(key, str(requester).encode("utf-8"),
                      hashlib.sha256).hexdigest()
    return REQUESTER_LABEL_PREFIX + digest[:32]


def _field(review: Any, name: str, default: Any = None) -> Any:
    if isinstance(review, dict):
        return review.get(name, default)
    return getattr(review, name, default)


def assert_allow_list(record: Dict[str, Any]) -> None:
    """Raise when the payload is not exactly the documented schema.

    A *programming* error, not a runtime skip: the caller fixes the builder
    rather than quietly uploading something narrower or wider.
    """
    if not isinstance(record, dict):
        raise ValueError("a review upload must be an object")
    keys = set(record)
    extra = keys - set(ALLOWED_FIELDS)
    if extra:
        raise ValueError("review upload has unknown field: {}".format(
            sorted(extra)[0]))
    missing = set(ALLOWED_FIELDS) - keys
    if missing:
        raise ValueError("review upload is missing field: {}".format(
            sorted(missing)[0]))
    for forbidden in FORBIDDEN_FIELDS:
        if forbidden in keys:
            raise ValueError("review upload may not carry {!r}".format(forbidden))


def build_record(review: Any, *, binding: str, agent_key: Optional[str] = None,
                 share_usernames: bool = False,
                 masker: Optional[Masker] = None) -> Dict[str, Any]:
    """Turn one local :class:`~interlock.reviews.Review` into a wire record."""
    preview = _field(review, "preview")
    mask_counts: Dict[str, int] = {}
    if preview:
        preview, mask_counts = (masker or Masker()).mask_text(str(preview))
    requester = requester_label(
        _field(review, "requester"), agent_key,
        share_usernames=share_usernames)
    record = {
        "review_id": _field(review, "id"),
        "binding": binding,
        "action": _field(review, "action") or "",
        "phase": _field(review, "phase") or "call",
        "principal": _field(review, "principal"),
        "requester": requester,
        "policy_id": _field(review, "policy_id"),
        "reason": _field(review, "reason"),
        "args_digest": _field(review, "args_digest") or "",
        "preview": preview,
        "mask_counts": mask_counts,
        "created": _field(review, "created"),
        "pending_until": _field(review, "pending_until"),
        "min_approvals": int(_field(review, "min_approvals", 1) or 1),
        "allow_self_approval": bool(_field(review, "allow_self_approval", True)),
        "approval_ttl": float(_field(review, "approval_ttl", 900.0) or 900.0),
    }
    assert_allow_list(record)
    return record


__all__ = [
    "ALLOWED_FIELDS",
    "FORBIDDEN_FIELDS",
    "REQUESTER_LABEL_PREFIX",
    "assert_allow_list",
    "build_record",
    "requester_label",
]

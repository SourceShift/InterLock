"""One-way notification when a review needs a human (Slack or a JSON webhook).

The review queue is pull-based: a call is refused with a review id and a human
has to look. This module closes the "has to look" half without moving the
decision - it posts a message when a review is **filed**, and never accepts an
answer. Approval stays in ``interlock reviews`` or the console, both of which
run outside the agent.

What the message carries is deliberate. A review's ``preview`` holds the call's
arguments, which may hold secrets, so it is never sent. Every field that does
go out - action, principal, rule, reason - passes through the guard's own
secret redactor first, because a rule's reason can quote an argument (a
destination URL, a sensitive path).

Fail-open by construction: a webhook that is slow, down, or answers 500 must
never change a decision. :class:`ReviewNotifier` catches everything, logs one
line per failure kind, and returns whether the post landed.

The hook reads its configuration from the environment::

    INTERLOCK_REVIEW_WEBHOOK=https://hooks.slack.com/services/...
    INTERLOCK_REVIEW_WEBHOOK_FORMAT=slack      # or json (default: slack)
    INTERLOCK_REVIEW_CONSOLE_URL=http://127.0.0.1:7878   # link in the message

From Python, pass ``on_file=`` to the queue::

    from interlock.notify import from_env
    from interlock.reviews import ReviewQueue, queue_approver

    queue = ReviewQueue(on_file=from_env())     # or ReviewNotifier(url)
    interlock.install(approver=queue_approver(queue))

The webhook URL is a credential (anyone holding a Slack incoming-webhook URL
can post to it). Keep it in the environment or a secret store, not in a policy
file, and note that it never appears in an interlock log line.
"""
from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Mapping, Optional, Set, Tuple
from urllib.parse import urlparse

_log = logging.getLogger("interlock.notify")

#: Seconds a post may take. A hook should not hold the agent's call for longer.
DEFAULT_TIMEOUT = 2.5
#: Where the message links to by default: the console's loopback address.
DEFAULT_CONSOLE_URL = "http://127.0.0.1:7878"
#: Accepted payload shapes. ``slack`` posts ``{"text": ...}``; ``json`` posts
#: the structured event below, for any receiver that wants fields.
FORMATS = ("slack", "json")

ENV_WEBHOOK = "INTERLOCK_REVIEW_WEBHOOK"
ENV_FORMAT = "INTERLOCK_REVIEW_WEBHOOK_FORMAT"
ENV_CONSOLE = "INTERLOCK_REVIEW_CONSOLE_URL"

#: Argument names that say what a call acted on, the same set the console's
#: receipt drawer uses. The command, file or URL is what makes a ping
#: actionable; the rest of the arguments stay on this machine.
_TARGET_KEYS = ("file_path", "notebook_path", "path", "command", "cmd", "url", "pattern",
                "query", "description", "prompt", "skill")

_WARNED: Set[Tuple[str, str]] = set()


def _warn(kind: str, detail: str) -> None:
    """Log one line per (kind, detail). A retry loop must not flood stderr."""
    key = (kind, detail)
    if key in _WARNED:
        return
    _WARNED.add(key)
    _log.warning("interlock notify %s failed: %s", kind, detail)


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse a 3xx: a redirect would carry the payload to wherever it points."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        del req, fp, code, msg, headers, newurl  # the protocol passes them; refusing is all
        return None


def _checked_url(url: str) -> str:
    """Only http(s) with a host. The URL itself is never quoted: it is a secret."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("the webhook must be an http(s) URL with a host")
    return url


def _masked(value: Any) -> str:
    """Text as it may leave the machine: the guard's own secret redactor."""
    from .detectors.tool_output_secret_redactor import redact_text

    text = "" if value is None else str(value)
    return redact_text(text)[0]


def _target(preview: Optional[str]) -> str:
    """The one argument that says what the call acts on, masked and bounded."""
    if not preview:
        return ""
    try:
        args = json.loads(preview)
    except ValueError:
        return ""
    if not isinstance(args, dict):
        return ""
    for key in _TARGET_KEYS:
        value = args.get(key)
        if isinstance(value, list):
            value = " ".join(map(str, value))
        if isinstance(value, str) and value.strip():
            text = _masked(" ".join(value.split()))
            return text if len(text) <= 200 else text[:197] + "..."
    return ""


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")


@dataclass(frozen=True)
class ReviewMessage:
    """What one notification says. Never carries the call's arguments."""

    review_id: str
    action: str
    principal: str
    rule: str
    reason: str
    target: str
    pending_until: float
    min_approvals: int
    console_url: str


def message_for(review: Any, *, console_url: str = DEFAULT_CONSOLE_URL) -> ReviewMessage:
    """Build the message for a filed review, masking every free-text field."""
    base = (console_url or DEFAULT_CONSOLE_URL).rstrip("/")
    return ReviewMessage(
        review_id=str(review.id),
        action=_masked(review.action),
        principal=_masked(getattr(review, "principal", None) or "unknown"),
        rule=_masked(getattr(review, "policy_id", None) or ""),
        reason=_masked(getattr(review, "reason", None) or ""),
        target=_target(getattr(review, "preview", None)),
        pending_until=float(review.pending_until),
        min_approvals=int(getattr(review, "min_approvals", 1) or 1),
        console_url="{}/#/reviews/{}".format(base, review.id),
    )


def slack_text(message: ReviewMessage) -> str:
    """The ``text`` of a Slack incoming-webhook post: readable in a phone push."""
    need = "needs approval" if message.min_approvals <= 1 else \
        "needs {} distinct approvers".format(message.min_approvals)
    what = message.action if not message.target else "{}: `{}`".format(
        message.action, message.target)
    lines = [
        ":lock: interlock review {} {}".format(message.review_id, need),
        "{}  ·  principal `{}`".format(what, message.principal),
    ]
    if message.rule:
        lines.append("rule `{}`".format(message.rule))
    if message.reason:
        reason = message.reason
        lines.append(reason if len(reason) <= 600 else reason[:597] + "...")
    lines.append("decide: {}".format(message.console_url))
    lines.append("expires {}".format(_iso(message.pending_until)))
    return "\n".join(lines)


def payload_for(message: ReviewMessage, fmt: str = "slack") -> Dict[str, Any]:
    if fmt == "slack":
        return {"text": slack_text(message)}
    if fmt == "json":
        return {
            "event": "interlock.review.filed",
            "review_id": message.review_id,
            "action": message.action,
            "principal": message.principal,
            "rule": message.rule,
            "reason": message.reason,
            "target": message.target,
            "min_approvals": message.min_approvals,
            "pending_until": _iso(message.pending_until),
            "console_url": message.console_url,
        }
    raise ValueError("format must be one of {}".format(", ".join(FORMATS)))


def post(url: str, payload: Dict[str, Any], *, timeout: float = DEFAULT_TIMEOUT,
         opener: Optional[Any] = None) -> bool:
    """POST ``payload`` as JSON. True when the receiver answered 2xx.

    Never raises: a notification is best-effort by design, and the caller is a
    decision path that must not inherit a network error.
    """
    body = json.dumps(payload, sort_keys=True).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "interlock-notify/1"},
    )
    if opener is None:
        opener = urllib.request.build_opener(_RefuseRedirects())
    try:
        with opener.open(request, timeout=timeout) as response:
            response.read(256)  # drain a small body so the server closes cleanly
            return 200 <= int(getattr(response, "status", 0) or 0) < 300
    except urllib.error.HTTPError as exc:
        _warn("post", "receiver answered {} {}".format(exc.code, exc.reason))
        return False
    except Exception as exc:  # timeout, refused, DNS, TLS, bad response
        _warn("post", "{}: {}".format(type(exc).__name__, exc))
        return False


class ReviewNotifier:
    """Post one message when a review is filed. Never decides, never blocks.

    Pass an instance as ``ReviewQueue(on_file=...)``. It accepts a
    :class:`interlock.reviews.Review` and returns whether the post landed.
    """

    def __init__(self, webhook: str, *, fmt: str = "slack",
                 timeout: float = DEFAULT_TIMEOUT,
                 console_url: str = DEFAULT_CONSOLE_URL,
                 post_fn: Callable[..., bool] = post) -> None:
        if fmt not in FORMATS:
            raise ValueError("format must be one of {}".format(", ".join(FORMATS)))
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.webhook = _checked_url(webhook)
        self.fmt = fmt
        self.timeout = float(timeout)
        self.console_url = console_url
        self._post = post_fn

    def __call__(self, review: Any) -> bool:
        try:
            message = message_for(review, console_url=self.console_url)
            return self._post(self.webhook, payload_for(message, self.fmt),
                              timeout=self.timeout)
        except Exception as exc:  # a message that cannot be built is not fatal
            _warn("build", "{}: {}".format(type(exc).__name__, exc))
            return False


def from_env(environ: Optional[Mapping[str, str]] = None) -> Optional[ReviewNotifier]:
    """The notifier the environment asks for, or None when no webhook is set.

    A malformed setting logs one warning and returns None: a typo in an
    optional integration must not turn every escalated call into an error.
    """
    env = os.environ if environ is None else environ
    url = (env.get(ENV_WEBHOOK) or "").strip()
    if not url:
        return None
    fmt = (env.get(ENV_FORMAT) or "slack").strip().lower()
    console_url = (env.get(ENV_CONSOLE) or DEFAULT_CONSOLE_URL).strip()
    try:
        return ReviewNotifier(url, fmt=fmt, console_url=console_url)
    except ValueError as exc:
        _warn("config", str(exc))
        return None

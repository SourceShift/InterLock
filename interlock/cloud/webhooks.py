"""Webhook endpoints, signing, retries and the in-process outbox worker.

A control-plane event (a review was filed, a grant was issued, a manifest was
published) is written to the ``webhook_deliveries`` outbox with the mutation
that caused it. Delivery happens later: the ASGI lifespan starts one worker
task that drains due rows, so a slow or broken subscriber can never slow an
API request, and a failed delivery never rolls the mutation back.

Two privacy rules are enforced here, not in the routes:

* **The subscriber never sees row content.** :func:`build_payload` accepts
  only ids, statuses, timestamps and counts. A key that looks like a preview,
  argument, receipt, key, token, session or body is refused at build time.
* **Redirects are never followed.** :func:`post_delivery` uses the connector's
  vetted transport (TLS-only except loopback, redirect handler that returns
  ``None``). A 3xx is a permanent delivery failure, never a hop to another
  host.

The signing header is ``x-interlock-signature: t=<unix>,v1=<hex>`` where the
digest is ``HMAC-SHA256(secret, "<t>.<body>")``. A receiver checks the
signature over the exact bytes it received and refuses an old timestamp.

The retry ladder is 1 s, 5 s, 30 s, 5 min, 30 min, 2 h, capped at the last
step. ``Retry-After`` is honoured; a 4xx other than 408/429 is permanent.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import logging
import secrets
import socket
import time
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urlsplit

#: The events the plane publishes. A registration naming anything else is
#: refused; the list is the public contract.
EVENTS = (
    "review.created",
    "review.decided",
    "grant.issued",
    "host.frozen",
    "host.revoked",
    "manifest.published",
    "policy.killed",
    "retention.ran",
)

#: The retry ladder in seconds. Attempt ``n`` (zero-based) waits
#: ``RETRY_SCHEDULE[min(n, len - 1)]``; the last step repeats.
RETRY_SCHEDULE = (1, 5, 30, 300, 1800, 7200)

#: A delivery attempt is abandoned after this many seconds.
DELIVERY_TIMEOUT = 10

#: Retrying is bounded by FR-060 ("retry with backoff for 24 hours"). The
#: ladder caps at 2 h, so a dead subscriber gets about a dozen attempts before
#: the delivery is marked failed and never rescheduled.
RETRY_HORIZON = 24 * 3600

#: The header the receiver verifies.
SIGNATURE_HEADER = "x-interlock-signature"

#: Keys that are never allowed into a payload, whatever their value.
FORBIDDEN_PAYLOAD_KEYS = frozenset((
    "preview", "args", "arguments", "raw", "event_body", "receipt",
    "receipts", "secret", "secrets", "token", "session", "cookie",
    "body", "response", "response_body", "key", "keys", "seed",
))

#: Keys that are always safe: ids, status, time and counts.
SAFE_PAYLOAD_KEYS = frozenset((
    "event", "status", "result", "action", "verdict", "level", "reason_code",
    "at", "timestamp", "created", "issued_at", "decided_at", "published_at",
    "count", "attempt", "version", "epoch", "percent", "days", "mode",
    "target_kind", "ring",
))


class WebhookError(ValueError):
    """A URL, event, secret or payload breaks the webhook contract."""


_log = logging.getLogger(__name__)


# -- URL policy --------------------------------------------------------

def is_loopback_host(host: Optional[str]) -> bool:
    """True for ``localhost`` and any IP literal in a loopback network."""
    if not host:
        return False
    name = host.strip("[]").lower()
    if name == "localhost":
        return True
    try:
        address = ipaddress.ip_address(name)
    except ValueError:
        return False
    return address.is_loopback


#: Host names that resolve to a cloud metadata service. ``localhost`` is not
#: here: it is the documented local receiver and is handled by
#: :func:`is_loopback_host`.
_INTERNAL_HOSTNAMES = frozenset((
    "metadata.google.internal", "metadata.goog",
))
_INTERNAL_HOST_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa")


def _ipv4_mapped(address: Any) -> Any:
    return getattr(address, "ipv4_mapped", None)


def _address_is_loopback(address: Any) -> bool:
    mapped = _ipv4_mapped(address)
    return bool(address.is_loopback or (mapped is not None and mapped.is_loopback))


def _address_is_public(address: Any) -> bool:
    """True for a routable address; loopback is public enough for a receiver."""
    if _address_is_loopback(address):
        return True
    mapped = _ipv4_mapped(address)
    return bool((mapped if mapped is not None else address).is_global)


def _refuse_internal_target(host: str) -> None:
    """Refuse a target that points back into the plane's network (SSRF).

    An IP literal in a private, link-local (cloud metadata) or otherwise
    non-global range is refused outright. A name is resolved and every
    address it yields must be public or loopback; a name that does not resolve
    is allowed to save (delivery will fail, and nothing internal is reachable
    by a name that resolves to nothing).
    """
    name = host.strip("[]").rstrip(".").lower()
    if name in _INTERNAL_HOSTNAMES or any(
            name.endswith(suffix) for suffix in _INTERNAL_HOST_SUFFIXES):
        raise WebhookError("url must not name an internal host")
    try:
        literal = ipaddress.ip_address(name)
    except ValueError:
        try:
            resolved = socket.getaddrinfo(
                name, None, proto=socket.IPPROTO_TCP)
        except OSError:
            return
        for info in resolved:
            try:
                address = ipaddress.ip_address(info[4][0])
            except (ValueError, IndexError):
                continue
            if not _address_is_public(address):
                raise WebhookError(
                    "url must resolve to a public address")
        return
    if not _address_is_public(literal):
        raise WebhookError(
            "url must not point at a private or link-local address")


def validate_url(url: Any) -> str:
    """Return a normalised URL or raise :class:`WebhookError`.

    ``https`` is required for every non-loopback target; plain ``http`` is
    accepted only for a loopback host, which is how a local test receiver is
    wired without weakening the production rule. Userinfo and fragments are
    refused because both are a way to smuggle a different destination past a
    string check. A target that resolves into a private, link-local or
    metadata address is refused so an owner cannot aim the plane at its own
    network (SSRF).
    """
    if not isinstance(url, str) or not url.strip():
        raise WebhookError("url is required")
    text = url.strip()
    parsed = urlsplit(text)
    if parsed.scheme not in ("https", "http"):
        raise WebhookError("url must use https (http is allowed only for loopback)")
    if not parsed.hostname:
        raise WebhookError("url must name a host")
    if parsed.username or parsed.password:
        raise WebhookError("url must not carry userinfo")
    if parsed.fragment:
        raise WebhookError("url must not carry a fragment")
    _refuse_internal_target(parsed.hostname)
    if parsed.scheme == "http" and not is_loopback_host(parsed.hostname):
        raise WebhookError("plain http is allowed only for a loopback host")
    return text


def validate_events(events: Any) -> List[str]:
    """Return a de-duplicated, ordered event list or raise."""
    if not isinstance(events, (list, tuple)) or not events:
        raise WebhookError("events must be a non-empty list")
    out: List[str] = []
    for event in events:
        if not isinstance(event, str) or event not in EVENTS:
            raise WebhookError("unknown event {!r}".format(event))
        if event not in out:
            out.append(event)
    return out


# -- payload privacy ---------------------------------------------------

def build_payload(event: str, data: Optional[Mapping[str, Any]] = None,
                  *, now: Optional[float] = None) -> Dict[str, Any]:
    """Build an event payload from ids, statuses, times and counts only.

    A caller cannot widen this: a forbidden key is refused even when its value
    is innocuous, and a nested object is refused outright. The result always
    names the event, so a receiver can route on it.
    """
    if event not in EVENTS:
        raise WebhookError("unknown event {!r}".format(event))
    payload: Dict[str, Any] = {"event": event}
    for key, value in dict(data or {}).items():
        if not isinstance(key, str) or not key:
            raise WebhookError("payload keys must be non-empty strings")
        lowered = key.lower()
        if lowered in FORBIDDEN_PAYLOAD_KEYS or any(
                forbidden in lowered for forbidden in FORBIDDEN_PAYLOAD_KEYS):
            raise WebhookError("payload field {!r} is not allowed".format(key))
        allowed = (lowered in SAFE_PAYLOAD_KEYS
                   or lowered.endswith("_id")
                   or lowered.endswith("_count")
                   or lowered.endswith("_total"))
        if not allowed:
            raise WebhookError("payload field {!r} is not an id/count".format(key))
        if isinstance(value, bool):
            payload[key] = value
        elif isinstance(value, (int, float)):
            payload[key] = value
        elif isinstance(value, str):
            if len(value) > 200:
                raise WebhookError(
                    "payload field {!r} is longer than 200 characters".format(key))
            payload[key] = value
        elif value is None:
            payload[key] = None
        else:
            raise WebhookError(
                "payload field {!r} must be a scalar".format(key))
    if now is not None and "at" not in payload:
        payload["at"] = float(now)
    return payload


# -- signing -----------------------------------------------------------

def sign_delivery(secret: bytes, body: bytes, *, t: int) -> str:
    """Return ``t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>``."""
    if not isinstance(secret, (bytes, bytearray)) or not secret:
        raise WebhookError("a signing secret is required")
    if not isinstance(body, (bytes, bytearray)):
        raise WebhookError("the signed body must be bytes")
    timestamp = str(int(t))
    digest = hmac.new(
        bytes(secret), timestamp.encode("ascii") + b"." + bytes(body),
        hashlib.sha256,
    ).hexdigest()
    return "t={},v1={}".format(timestamp, digest)


def verify_delivery(secret: bytes, body: bytes, header: str, *,
                    now: Optional[float] = None,
                    tolerance: int = 300) -> bool:
    """Verify a signature header; a stale ``t`` is refused when ``now`` is set."""
    try:
        parts = dict(item.split("=", 1) for item in header.split(","))
        timestamp = int(parts["t"])
        signature = parts["v1"]
    except (KeyError, ValueError, AttributeError):
        return False
    if now is not None and abs(float(now) - timestamp) > tolerance:
        return False
    expected = sign_delivery(secret, body, t=timestamp).split("v1=", 1)[1]
    return hmac.compare_digest(expected, signature)


# -- retry policy ------------------------------------------------------

def delivery_plan(status: int, attempt: int, *,
                  retry_after: Optional[float] = None) -> Optional[float]:
    """Seconds until the next attempt, or ``None`` when delivery is final.

    A 2xx is success. A 3xx is final because redirects are never followed. A
    4xx other than 408/429 is final: the receiver said the request itself is
    wrong, so retrying the same bytes cannot help. A 5xx, a 408, a 429 or a
    transport failure (``status == 0``) retries on the ladder.
    """
    if 200 <= int(status) < 300:
        return None
    if 300 <= int(status) < 400:
        return None
    if 400 <= int(status) < 500 and int(status) not in (408, 429):
        return None
    if retry_after is not None:
        try:
            seconds = float(retry_after)
        except (TypeError, ValueError):
            seconds = 0.0
        if seconds > 0:
            return min(seconds, float(RETRY_SCHEDULE[-1]))
    index = max(0, min(int(attempt), len(RETRY_SCHEDULE) - 1))
    return float(RETRY_SCHEDULE[index])


def next_attempt_at(now: float, status: int, attempt: int, *,
                    retry_after: Optional[float] = None) -> Optional[float]:
    delay = delivery_plan(status, attempt, retry_after=retry_after)
    return None if delay is None else float(now) + delay


def _retry_after_seconds(headers: Mapping[str, str]) -> Optional[float]:
    raw = headers.get("retry-after")
    if raw is None:
        return None
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


# -- secret storage ----------------------------------------------------

def hash_secret(secret: bytes) -> str:
    """The one-way hash stored for listing/verification; never reversible."""
    if not isinstance(secret, (bytes, bytearray)) or not secret:
        raise WebhookError("a webhook secret is required")
    return hashlib.sha256(bytes(secret)).hexdigest()


def _webhook_key(kek: bytes, org_id: str) -> bytes:
    from .crypto import _hkdf_expand, _hkdf_extract

    prk = _hkdf_extract(b"interlock-webhook-kek-v1", bytes(kek))
    return _hkdf_expand(prk, (str(org_id) + ":webhook").encode("utf-8"), 32)


def seal_secret(secret: bytes, *, kek: bytes, org_id: str,
                nonce: Optional[bytes] = None) -> bytes:
    """Encrypt the signing copy under a key derived from the operator KEK."""
    import os

    from .crypto import _aesgcm

    if not isinstance(secret, (bytes, bytearray)) or not secret:
        raise WebhookError("a webhook secret is required")
    aesgcm = _aesgcm()
    value = os.urandom(12) if nonce is None else bytes(nonce)
    if len(value) != 12:
        raise WebhookError("the GCM nonce is 12 bytes")
    aes = aesgcm(_webhook_key(kek, org_id))
    return value + aes.encrypt(
        value, bytes(secret), (str(org_id) + ":webhook").encode("utf-8"))


def open_secret(blob: Optional[bytes], *, kek: bytes, org_id: str) -> bytes:
    """Decrypt the stored signing copy; a bad tag raises ``ValueError``."""
    from .crypto import _aesgcm

    if not blob or len(blob) < 12 + 16:
        raise WebhookError("the stored webhook secret is missing or corrupt")
    aes = _aesgcm()(_webhook_key(kek, org_id))
    nonce, sealed = bytes(blob[:12]), bytes(blob[12:])
    try:
        return aes.decrypt(
            nonce, sealed, (str(org_id) + ":webhook").encode("utf-8"))
    except Exception:
        raise WebhookError("the stored webhook secret failed authentication") \
            from None


def generate_secret() -> str:
    """A new signing secret, shown once at registration and then only hashed."""
    return "whsec_" + secrets.token_urlsafe(32)


# -- outbox helpers ----------------------------------------------------

def emit(store: Any, org_id: str, event: str, data: Optional[Mapping[str, Any]] = None,
         *, now: Optional[float] = None) -> int:
    """Fan an event out to matching endpoints; never raise into a route.

    The caller is on the request path. A broken store or a malformed payload
    must not turn a successful review decision into a 500, so every failure is
    swallowed and reported as zero deliveries.
    """
    try:
        payload = build_payload(event, data, now=now)
        return int(store.webhook_fanout(org_id, event, payload,
                                        now=time.time() if now is None else now))
    except Exception:
        # The request must not fail because a subscriber cannot be told about
        # it, but a silent zero hides a broken outbox: log the event and the
        # traceback so an operator can replay it.
        _log.warning("webhook fanout failed for %s", event, exc_info=True)
        return 0


def _deliver_once(app: Any, row: Mapping[str, Any]) -> Dict[str, Any]:
    """One blocking delivery attempt; the worker calls this in a thread.

    Returns the store update fields. The response body is never stored - only
    its SHA-256 digest - and only ``Retry-After`` is read from the headers.
    """
    from .connector.transport import TransportError, UrllibTransport

    org_id = str(row["org_id"])
    endpoint = app.store.webhook_endpoint_by_id(org_id, row["endpoint_id"])
    now = float(app._clock())
    if endpoint is None or not endpoint.get("active"):
        return {"status": "failed", "attempts": int(row.get("attempts") or 0) + 1,
                "last_error": "endpoint disabled", "next_attempt": None,
                "response_status": None, "duration_ms": 0,
                "body_digest": None, "delivered_at": None}
    try:
        secret = open_secret(endpoint.get("secret_enc"), kek=app.preview_kek(),
                             org_id=org_id)
    except Exception as exc:
        return {"status": "failed", "attempts": int(row.get("attempts") or 0) + 1,
                "last_error": "secret unavailable: {}".format(type(exc).__name__),
                "next_attempt": None, "response_status": None,
                "duration_ms": 0, "body_digest": None, "delivered_at": None}
    import json

    body = json.dumps(row.get("payload") or {}, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")
    signature = sign_delivery(secret, body, t=int(now))
    started = time.monotonic()
    try:
        status, headers, response = UrllibTransport("").request(
            "POST", endpoint["url"], body, timeout=DELIVERY_TIMEOUT,
            headers={
                SIGNATURE_HEADER: signature,
                "content-type": "application/json",
                "user-agent": "interlock-cloud-webhook/1",
            },
        )
    except TransportError as exc:
        status, headers, response = 0, {}, b""
        error = type(exc).__name__
    except Exception as exc:  # defensive: a subscriber must not crash the worker
        status, headers, response = 0, {}, b""
        error = type(exc).__name__
    else:
        error = None if 200 <= int(status) < 300 else "http {}".format(status)
    elapsed_ms = int(max(0.0, time.monotonic() - started) * 1000)
    attempt = int(row.get("attempts") or 0)
    delay = delivery_plan(status, attempt,
                          retry_after=_retry_after_seconds(headers))
    if delay is not None:
        created = float(row.get("created") or now)
        if now - created >= RETRY_HORIZON:
            # FR-060 bounds retrying at 24 hours. The ladder would keep
            # repeating its last step forever, so give up here instead.
            delay = None
            error = "retry horizon reached"
    status_text = "delivered" if delay is None and 200 <= int(status) < 300 \
        else ("pending" if delay is not None else "failed")
    return {
        "status": status_text,
        "attempts": attempt + 1,
        "last_error": (error or "")[:200] or None,
        "next_attempt": None if delay is None else now + delay,
        "response_status": int(status) if status else None,
        "duration_ms": elapsed_ms,
        "body_digest": hashlib.sha256(response or b"").hexdigest(),
        "delivered_at": now if status_text == "delivered" else None,
    }


async def drain_once(app: Any, *, now: Optional[float] = None,
                     limit: int = 50) -> int:
    """Drain the due outbox once. Returns the number of attempts made."""
    import asyncio

    from .metrics import inc

    at = float(app._clock() if now is None else now)
    attempts = 0
    for org in app.store.list_orgs():
        if getattr(org, "deleted_at", None) is not None:
            continue
        rows = app.store.webhook_due(org.id, at, limit=limit)
        for row in rows:
            update = await asyncio.to_thread(_deliver_once, app, row)
            app.store.webhook_update_delivery(
                org.id, row["id"], **update)
            inc("il_webhook_deliveries_total", outcome=update["status"])
            attempts += 1
    return attempts


async def worker(app: Any, *, interval: float = 1.0) -> None:
    """The lifespan task: drain due deliveries until cancelled."""
    import asyncio

    try:
        while True:
            try:
                await drain_once(app)
            except asyncio.CancelledError:
                raise
            except Exception:
                # One bad row must not stop the worker forever. The next tick
                # retries whatever is still due.
                pass
            await asyncio.sleep(interval)
    except asyncio.CancelledError:
        return


__all__ = [
    "DELIVERY_TIMEOUT",
    "EVENTS",
    "FORBIDDEN_PAYLOAD_KEYS",
    "RETRY_SCHEDULE",
    "SIGNATURE_HEADER",
    "WebhookError",
    "build_payload",
    "delivery_plan",
    "drain_once",
    "emit",
    "generate_secret",
    "hash_secret",
    "is_loopback_host",
    "next_attempt_at",
    "open_secret",
    "seal_secret",
    "sign_delivery",
    "validate_events",
    "validate_url",
    "verify_delivery",
    "worker",
]

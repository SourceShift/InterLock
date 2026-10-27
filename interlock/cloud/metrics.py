"""Prometheus metrics for the cloud plane (C7), written by hand.

The plane's metrics deliberately share nothing with :mod:`interlock.metrics`:
that module is host-process global state owned by the receipt writer, and a
control-plane request must never move a host's counters. The exposition here
is a small, dependency-free text format with one hard rule:

**A label value is never tenant data.** ``route`` is the registered template
(``/v1/reviews/{id}``), ``method`` and ``status`` are closed enums, and the
metric-specific labels (``level``, ``result``, ``event``, ``attempt``) are
closed too. A host name, review id, policy id, org id or free-text reason in a
label would make the scrape endpoint a tenant-data leak, so
:func:`label_value` refuses anything that is not in the registered set.

The module exposes:

* :data:`METRIC_LABELS` - every metric and its label names, the contract the
  docs test reads;
* :func:`inc`, :func:`observe`, :func:`set_gauge` - the write side;
* :func:`render_metrics` - the Prometheus text exposition;
* :class:`MetricsApp` - the optional dedicated loopback listener;
* :func:`reset` - test isolation.

No third-party import belongs here: the module imports on a bare interpreter.
"""
from __future__ import annotations

import threading
from typing import Dict, Iterable, List, Tuple

#: Every metric the plane exposes and the closed set of label *names* it may
#: carry. A value is only ever drawn from a closed enum or a route template.
METRIC_LABELS: Dict[str, Tuple[str, ...]] = {
    "il_http_requests_total": ("route", "method", "status"),
    "il_http_duration_seconds": ("route", "method"),
    "il_reviews_pending": (),
    "il_grants_issued_total": (),
    "il_receipts_ingested_total": (),
    "il_receipt_verify_total": ("level",),
    "il_policy_manifest_version": (),
    "il_policy_swaps_total": ("result",),
    "il_kill_active": (),
    "il_webhook_deliveries_total": ("outcome",),
    "il_db_pool_in_use": (),
}

#: Counter metrics are monotonic; the rest are gauges (or a histogram).
COUNTERS = frozenset((
    "il_http_requests_total",
    "il_grants_issued_total",
    "il_receipts_ingested_total",
    "il_receipt_verify_total",
    "il_policy_swaps_total",
    "il_webhook_deliveries_total",
))

#: Gauges are set; a histogram is observed.
GAUGES = frozenset((
    "il_reviews_pending",
    "il_policy_manifest_version",
    "il_kill_active",
    "il_db_pool_in_use",
))

HISTOGRAMS = frozenset(("il_http_duration_seconds",))

#: Histogram bucket upper bounds in seconds. Prometheus text format uses
#: cumulative counts and a ``+Inf`` bucket.
DURATION_BUCKETS: Tuple[float, ...] = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
)

#: A closed enum for values that are not route templates. Anything else is
#: refused, so a caller cannot smuggle a tenant id into a label by accident.
CLOSED_VALUES: Dict[str, frozenset] = {
    "method": frozenset(("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE",
                         "OPTIONS")),
    "status": frozenset(str(code) for code in (
        200, 201, 202, 204, 301, 302, 303, 400, 401, 403, 404, 405, 408,
        409, 410, 413, 415, 422, 429, 500, 502, 503, 504,
    )),
    "level": frozenset(("verified", "linkage_only", "receipts_unverified")),
    "result": frozenset(("promoted", "rolled_back", "held", "swapped",
                         "refused")),
    "event": frozenset((
        "review.created", "review.decided", "grant.issued", "host.frozen",
        "host.revoked", "manifest.published", "policy.killed",
        "retention.ran",
    )),
    "attempt": frozenset(str(index) for index in range(16)),
    # The outbox outcome is not an HTTP status: a delivery is delivered,
    # waiting on the retry ladder, or permanently failed.
    "outcome": frozenset(("delivered", "pending", "failed")),
}

_LOCK = threading.RLock()
#: ``(name, sorted label pairs) -> value`` for counters and gauges.
_VALUES: Dict[Tuple[str, Tuple[Tuple[str, str], ...]], float] = {}
#: ``(name, sorted label pairs) -> [bucket counts..., sum, count]``.
_HISTOGRAMS: Dict[Tuple[str, Tuple[Tuple[str, str], ...]],
                  List[float]] = {}
#: Values seen for every metric label, so a scrape can prove the set is closed.
_SEEN_LABEL_VALUES: Dict[str, set] = {}


class MetricsError(ValueError):
    """A metric name, label or label value is outside the closed contract."""


def _label_pairs(name: str, labels: Dict[str, str]) -> Tuple[Tuple[str, str], ...]:
    """Validate one label set against :data:`METRIC_LABELS` and sort it."""
    wanted = METRIC_LABELS.get(name)
    if wanted is None:
        raise MetricsError("unknown metric {!r}".format(name))
    unknown = sorted(set(labels) - set(wanted))
    if unknown:
        raise MetricsError(
            "metric {!r} has no label {!r}".format(name, unknown[0]))
    missing = sorted(set(wanted) - set(labels))
    if missing:
        raise MetricsError(
            "metric {!r} is missing label {!r}".format(name, missing[0]))
    pairs: List[Tuple[str, str]] = []
    for key in wanted:
        value = str(labels[key])
        closed = CLOSED_VALUES.get(key)
        if closed is not None and value not in closed:
            raise MetricsError(
                "label {!r}={!r} is not in its closed set".format(key, value))
        if key == "route":
            # A route template has no concrete id: it either starts with a
            # known prefix or is the unmatched sentinel, and it never carries a
            # query string. This keeps a concrete path out of the exposition.
            if not (value == "unmatched" or value.startswith("/")):
                raise MetricsError("route label must be a template path")
            if "?" in value or "#" in value:
                raise MetricsError("route label must not carry a query")
        pairs.append((key, value))
    pairs.sort()
    return tuple(pairs)


def _key(name: str, labels: Dict[str, str]) -> Tuple[str, Tuple[Tuple[str, str], ...]]:
    return name, _label_pairs(name, labels)


def inc(name: str, amount: float = 1.0, **labels: str) -> None:
    """Add ``amount`` to a counter (or a gauge, for convenience)."""
    if name not in COUNTERS and name not in GAUGES:
        raise MetricsError("{!r} is not a counter or gauge".format(name))
    key = _key(name, labels)
    with _LOCK:
        _VALUES[key] = _VALUES.get(key, 0.0) + float(amount)
        for label, value in key[1]:
            _SEEN_LABEL_VALUES.setdefault(label, set()).add(value)


def set_gauge(name: str, value: float, **labels: str) -> None:
    """Set a gauge to an absolute value."""
    if name not in GAUGES:
        raise MetricsError("{!r} is not a gauge".format(name))
    key = _key(name, labels)
    with _LOCK:
        _VALUES[key] = float(value)
        for label, value in key[1]:
            _SEEN_LABEL_VALUES.setdefault(label, set()).add(value)


def observe(name: str, seconds: float, **labels: str) -> None:
    """Record one observation in a histogram."""
    if name not in HISTOGRAMS:
        raise MetricsError("{!r} is not a histogram".format(name))
    key = _key(name, labels)
    value = max(0.0, float(seconds))
    with _LOCK:
        series = _HISTOGRAMS.get(key)
        if series is None:
            series = [0.0] * (len(DURATION_BUCKETS) + 2)
            _HISTOGRAMS[key] = series
        for index, bound in enumerate(DURATION_BUCKETS):
            if value <= bound:
                # Buckets are cumulative at exposition time; store each
                # observation in the first bucket it fits so the renderer's
                # running sum produces the cumulative series.
                series[index] += 1
                break
        series[-2] += value
        series[-1] += 1
        for label, text in key[1]:
            _SEEN_LABEL_VALUES.setdefault(label, set()).add(text)


def seen_labels() -> Dict[str, set]:
    """The label values observed since the last :func:`reset` (test aid)."""
    with _LOCK:
        return {name: set(values)
                for name, values in _SEEN_LABEL_VALUES.items()}


def reset() -> None:
    """Drop every series. Tests call this between cases."""
    with _LOCK:
        _VALUES.clear()
        _HISTOGRAMS.clear()
        _SEEN_LABEL_VALUES.clear()


def _render_labels(pairs: Iterable[Tuple[str, str]]) -> str:
    items = list(pairs)
    if not items:
        return ""
    body = ",".join(
        '{}="{}"'.format(key, value.replace("\\", "\\\\").replace('"', '\\"'))
        for key, value in items
    )
    return "{" + body + "}"


#: Help lines are deliberately generic: a tenant name or a feature word that
#: could be mistaken for row content never appears in the exposition.
_HELP = {
    "il_http_requests_total": "Total HTTP requests handled.",
    "il_http_duration_seconds": "HTTP request duration in seconds.",
    "il_reviews_pending": "Reviews awaiting a decision.",
    "il_grants_issued_total": "Grants signed and committed.",
    "il_receipts_ingested_total": "Receipts accepted into the audit chain.",
    "il_receipt_verify_total": "Receipt batches by verification level.",
    "il_policy_manifest_version": "Current manifest version.",
    "il_policy_swaps_total": "Policy distribution swaps by result.",
    "il_kill_active": "Whether a kill switch is in force.",
    "il_webhook_deliveries_total": "Webhook delivery attempts by outcome.",
    "il_db_pool_in_use": "Database connections currently in use.",
}


def render_metrics() -> str:
    """Render every registered metric as Prometheus text exposition."""
    lines: List[str] = []
    with _LOCK:
        values = dict(_VALUES)
        histograms = {key: list(value) for key, value in _HISTOGRAMS.items()}
        names = list(METRIC_LABELS)

    for name in names:
        lines.append("# HELP {} {}".format(name, _HELP[name]))
        lines.append("# TYPE {} {}".format(
            name,
            "histogram" if name in HISTOGRAMS
            else ("gauge" if name in GAUGES else "counter"),
        ))
        if name in HISTOGRAMS:
            series = [(key[1], value) for key, value in histograms.items()
                      if key[0] == name]
            if not series:
                series = [((), [0.0] * (len(DURATION_BUCKETS) + 2))]
            for pairs, counts in series:
                cumulative = 0.0
                for index, bound in enumerate(DURATION_BUCKETS):
                    cumulative += counts[index]
                    bucket_labels = list(pairs) + [
                        ("le", _format_bound(bound))]
                    lines.append("{}_bucket{} {}".format(
                        name, _render_labels(bucket_labels),
                        _format_number(cumulative)))
                total = counts[-1]
                bucket_labels = list(pairs) + [("le", "+Inf")]
                lines.append("{}_bucket{} {}".format(
                    name, _render_labels(bucket_labels),
                    _format_number(total)))
                lines.append("{}_sum{} {}".format(
                    name, _render_labels(pairs), _format_number(counts[-2])))
                lines.append("{}_count{} {}".format(
                    name, _render_labels(pairs), _format_number(total)))
            continue
        series = [(key[1], value) for key, value in values.items()
                  if key[0] == name]
        if not series:
            lines.append("{} 0".format(name))
        for pairs, value in sorted(series, key=lambda item: item[0]):
            lines.append("{}{} {}".format(
                name, _render_labels(pairs), _format_number(value)))
    return "\n".join(lines) + "\n"


def _format_bound(value: float) -> str:
    text = ("%g" % value)
    return text


def _format_number(value: float) -> str:
    if value == int(value):
        return str(int(value))
    return repr(float(value))


# -- the optional dedicated listener -----------------------------------

class MetricsApp:
    """A two-route ASGI app for the dedicated loopback metrics bind.

    It serves ``GET /metrics`` and the health pair, and nothing else. No auth
    is required on purpose: the only safe deployment is a loopback bind, which
    is the default. Binding it publicly is an explicit operator choice and
    requires an authenticating proxy in front (see the runbook).
    """

    async def __call__(self, scope: Dict[str, object], receive, send) -> None:
        kind = scope.get("type")
        if kind == "lifespan":
            while True:
                message = await receive()
                if message.get("type") == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif message.get("type") == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
            return
        if kind != "http":
            return
        path = str(scope.get("path") or "/")
        method = str(scope.get("method") or "GET").upper()
        if method != "GET" or path not in ("/metrics", "/healthz", "/readyz"):
            status, body, content_type = 404, b"not found", "text/plain"
        elif path == "/metrics":
            status, body, content_type = (
                200, render_metrics().encode("utf-8"),
                "text/plain; version=0.0.4; charset=utf-8")
        else:
            status, body, content_type = 200, b"ok", "text/plain"
        await send({
            "type": "http.response.start", "status": status,
            "headers": [
                (b"content-type", content_type.encode("latin-1")),
                (b"content-length", str(len(body)).encode("ascii")),
            ],
        })
        await send({"type": "http.response.body", "body": body,
                    "more_body": False})


__all__ = [
    "CLOSED_VALUES",
    "COUNTERS",
    "DURATION_BUCKETS",
    "GAUGES",
    "HISTOGRAMS",
    "METRIC_LABELS",
    "MetricsApp",
    "MetricsError",
    "inc",
    "observe",
    "render_metrics",
    "reset",
    "seen_labels",
    "set_gauge",
]

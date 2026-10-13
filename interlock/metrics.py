"""In-process counters for what the guard decided, and a Prometheus rendering.

Every decision passes through :func:`interlock.receipt.emit_receipt`, which
records it here whether or not a receipt sink is installed: decisions by
verdict, phase and policy; escalations by how they were settled; entities
masked; receipts dropped; and a histogram of evaluation latency. Nothing here
holds an argument value. ``snapshot()`` returns plain data (for ``/stats``),
``render_prometheus()`` the text exposition format (for ``/metrics``).
"""
from __future__ import annotations

import threading
import time
from collections import Counter
from typing import Dict, Optional, Tuple

#: Latency histogram bucket bounds, in microseconds.
BUCKETS_US = (50, 100, 250, 500, 1000, 2500, 5000, 10000, 50000, 100000)

_lock = threading.Lock()
_decisions: Counter = Counter()  # (verdict, phase, policy_id) -> n
_escalations: Counter = Counter()  # approval outcome -> n
_masked: Counter = Counter()  # entity -> n
_latency_buckets = [0] * (len(BUCKETS_US) + 1)
_latency_sum = 0
_latency_count = 0
_dropped = 0
_started = time.time()


def record(verdict: str, phase: str, policy_id: Optional[str], *,
           approval: Optional[str] = None, masked: Optional[Dict[str, int]] = None,
           elapsed_us: Optional[int] = None, observed: bool = False) -> None:
    global _latency_sum, _latency_count
    label = verdict + ("_observed" if observed else "")
    with _lock:
        _decisions[(label, phase, policy_id or "")] += 1
        if approval:
            _escalations[approval.split(":", 1)[0]] += 1
        for entity, count in (masked or {}).items():
            _masked[entity] += count
        if isinstance(elapsed_us, int) and elapsed_us >= 0:
            index = next((i for i, bound in enumerate(BUCKETS_US) if elapsed_us <= bound),
                         len(BUCKETS_US))
            _latency_buckets[index] += 1
            _latency_sum += elapsed_us
            _latency_count += 1


def record_drop() -> None:
    global _dropped
    with _lock:
        _dropped += 1


def reset() -> None:
    """Zero every counter (tests, or a fresh measurement window)."""
    global _latency_sum, _latency_count, _dropped, _started
    with _lock:
        _decisions.clear()
        _escalations.clear()
        _masked.clear()
        for i in range(len(_latency_buckets)):
            _latency_buckets[i] = 0
        _latency_sum = _latency_count = _dropped = 0
        _started = time.time()


def snapshot() -> Dict[str, object]:
    with _lock:
        by_verdict: Counter = Counter()
        for (verdict, _phase, _policy), n in _decisions.items():
            by_verdict[verdict] += n
        top = Counter()
        for (verdict, _phase, policy), n in _decisions.items():
            if policy and not verdict.startswith("ALLOW"):
                top[policy] += n
        return {
            "since": _started,
            "decisions": sum(_decisions.values()),
            "by_verdict": dict(by_verdict),
            "top_policies": dict(top.most_common(10)),
            "escalations": dict(_escalations),
            "masked": dict(_masked),
            "receipts_dropped": _dropped,
            "latency_us": {"count": _latency_count, "sum": _latency_sum,
                           "mean": (_latency_sum / _latency_count) if _latency_count else None,
                           "p50": _bucket_bound(0.50), "p99": _bucket_bound(0.99)},
        }


def _bucket_bound(q: float) -> Optional[int]:
    """The histogram bucket bound at or below which a fraction ``q`` of the
    evaluations fall: an upper estimate, never an interpolation. None past the
    largest bound, or with no samples. Call with ``_lock`` held."""
    if not _latency_count:
        return None
    target, seen = q * _latency_count, 0
    for bound, n in zip(BUCKETS_US, _latency_buckets):
        seen += n
        if seen >= target:
            return bound
    return None


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def render_prometheus() -> str:
    lines = [
        "# HELP interlock_decisions_total Decisions by verdict, phase and policy.",
        "# TYPE interlock_decisions_total counter",
    ]
    with _lock:
        decisions: Tuple = tuple(sorted(_decisions.items()))
        escalations = tuple(sorted(_escalations.items()))
        masked = tuple(sorted(_masked.items()))
        buckets = list(_latency_buckets)
        total, count, dropped = _latency_sum, _latency_count, _dropped
    for (verdict, phase, policy), n in decisions:
        lines.append('interlock_decisions_total{{verdict="{}",phase="{}",policy="{}"}} {}'.format(
            _escape(verdict), _escape(phase), _escape(policy), n))
    lines += ["# HELP interlock_escalations_total Escalations by how they were settled.",
              "# TYPE interlock_escalations_total counter"]
    for outcome, n in escalations:
        lines.append('interlock_escalations_total{{outcome="{}"}} {}'.format(_escape(outcome), n))
    lines += ["# HELP interlock_masked_total Values masked, by entity.",
              "# TYPE interlock_masked_total counter"]
    for entity, n in masked:
        lines.append('interlock_masked_total{{entity="{}"}} {}'.format(_escape(entity), n))
    lines += ["# HELP interlock_receipts_dropped_total Receipts that failed to write.",
              "# TYPE interlock_receipts_dropped_total counter",
              "interlock_receipts_dropped_total {}".format(dropped),
              "# HELP interlock_evaluation_microseconds Policy evaluation latency.",
              "# TYPE interlock_evaluation_microseconds histogram"]
    cumulative = 0
    for bound, n in zip(BUCKETS_US, buckets):
        cumulative += n
        lines.append('interlock_evaluation_microseconds_bucket{{le="{}"}} {}'.format(bound, cumulative))
    cumulative += buckets[-1]
    lines.append('interlock_evaluation_microseconds_bucket{{le="+Inf"}} {}'.format(cumulative))
    lines.append("interlock_evaluation_microseconds_sum {}".format(total))
    lines.append("interlock_evaluation_microseconds_count {}".format(count))
    return "\n".join(lines) + "\n"

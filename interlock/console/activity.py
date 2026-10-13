"""``GET /api/activity``: what the guard decided over a window, for the home page.

Computed from the receipt log - the durable record - never from counters
inside the agent's process, which the console can't see. One request returns
everything the page draws: totals and the verdict mix, the top rules, the top
blocked actions, what monitor mode *would* have done, how escalations were
settled, problems, masked counts, a latency distribution, a bucketed timeline
of the whole window, and the newest decisions for the live stream.

``from``/``to`` narrow the aggregates to one slot of the timeline (the chart
stays the whole window), so focusing a bar re-reads one slice, not the log.
Bookkeeping receipts (``policy.overlay``, ``receipts.dropped``) are not
decisions and are left out of every count except ``dropped``.
"""
from __future__ import annotations

import re
import time
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple

from .audit import _read_receipts
from .server import ROUTES
from .session import ApiError, handles_errors

#: window -> (seconds, timeline buckets)
WINDOWS: Dict[str, Tuple[int, int]] = {"30m": (1800, 30), "24h": (86400, 24), "7d": (7 * 86400, 28)}
BOOKKEEPING = ("policy.overlay", "receipts.dropped")
RECENT = 60
HIST_BINS = 24


def settled(approval: str) -> str:
    """How an escalation was settled, without the review id the hook appends:
    ``approved:review r-1a2b`` -> ``approved:review``, ``pending:r-1a2b`` ->
    ``pending``, ``delegated:claude-code`` -> ``delegated``."""
    head, _, rest = approval.partition(":")
    if head in ("pending", "declined", "delegated") or (head == "declined" and rest):
        return head
    if head == "approved" and rest.startswith("review"):
        return "approved:review"
    return approval


def _pct(sorted_values: List[int], p: float) -> int:
    if not sorted_values:
        return 0
    return sorted_values[min(len(sorted_values) - 1, int(p * len(sorted_values)))]


def aggregate(receipts: List[Dict[str, Any]], start: float, end: float) -> Dict[str, Any]:
    """Every figure the page shows, for receipts with ``start <= ts < end``."""
    ok = [r for r in receipts if not r.get("unreadable") and start <= r.get("ts", 0) < end]
    dropped = 0
    for r in ok:
        if r.get("action") == "receipts.dropped":
            match = re.match(r"^(\d+)", r.get("reason") or "")
            dropped += int(match.group(1)) if match else 1
    ok = [r for r in ok if r.get("action") not in BOOKKEEPING]
    dec = [r for r in ok if r.get("phase") != "outcome"]
    enf = [r for r in dec if not r.get("observed")]

    verdicts = Counter(r.get("verdict") for r in enf)
    rules: Dict[str, Counter] = defaultdict(Counter)
    for r in enf:
        if r.get("policy_id"):
            rules[r["policy_id"]][r.get("policy_verdict") or r.get("verdict")] += 1
    blocked = Counter(r.get("action") for r in enf if r.get("verdict") == "BLOCK")
    would = Counter((r.get("policy_id") or "(unnamed)", r.get("action"), r.get("verdict"))
                    for r in dec if r.get("observed"))
    masked: Counter = Counter()
    for r in ok:
        for entity, n in (r.get("masked") or {}).items():
            masked[entity] += n
    latencies = sorted(r["elapsed_us"] for r in ok if isinstance(r.get("elapsed_us"), int))
    top = latencies[-1] if latencies else 0
    hist = [0] * HIST_BINS
    for value in latencies:
        hist[min(HIST_BINS - 1, int(value / max(1, top) * HIST_BINS))] += 1

    return {
        "receipts": len(ok),
        "decisions": len(enf),
        "calls": sum(1 for r in ok if r.get("phase") == "call"),
        "results": sum(1 for r in ok if r.get("phase") == "result"),
        "sessions": len({r.get("span_id") for r in ok if r.get("span_id")}),
        "principals": len({r.get("principal") for r in ok if r.get("principal")}),
        "verdicts": {k: verdicts.get(k, 0) for k in ("ALLOW", "MODIFY", "BLOCK")},
        "escalated": sum(1 for r in enf if r.get("policy_verdict") == "ESCALATE"),
        "rules": [{"id": rid, "count": sum(c.values()), "verdicts": dict(c)}
                  for rid, c in sorted(rules.items(), key=lambda kv: (-sum(kv[1].values()), kv[0]))],
        "blocked": [{"action": a, "count": n} for a, n in blocked.most_common()],
        "would": [{"rule": k[0], "action": k[1], "verdict": k[2], "count": n}
                  for k, n in would.most_common()],
        "escalations": dict(Counter(settled(r["approval"]) for r in enf if r.get("approval"))),
        "failed": sum(1 for r in ok if r.get("outcome") == "failed"),
        "dropped": dropped,
        "masked": dict(masked.most_common()),
        "latency": {
            "samples": len(latencies),
            "max": top,
            "p50": _pct(latencies, .5), "p90": _pct(latencies, .9), "p95": _pct(latencies, .95),
            "p99": _pct(latencies, .99),
            "hist": hist,
        },
        "first_ts": min((r["ts"] for r in ok), default=None),
        "last_ts": max((r["ts"] for r in ok), default=None),
    }


def timeline(receipts: List[Dict[str, Any]], start: float, span: float, buckets: int) -> List[Dict[str, Any]]:
    width = span / buckets
    out = [{"from": start + i * width, "to": start + (i + 1) * width,
            "ALLOW": 0, "MODIFY": 0, "BLOCK": 0, "ESC": 0} for i in range(buckets)]
    for r in receipts:
        if (r.get("unreadable") or r.get("phase") == "outcome" or r.get("observed")
                or r.get("action") in BOOKKEEPING):
            continue
        ts = r.get("ts", 0)
        if ts < start:
            continue
        b = out[min(buckets - 1, int((ts - start) / width))]
        if r.get("verdict") in ("ALLOW", "MODIFY", "BLOCK"):
            b[r["verdict"]] += 1
        if r.get("policy_verdict") == "ESCALATE":
            b["ESC"] += 1
    return out


def _float(qs: Dict[str, List[str]], name: str) -> Optional[float]:
    values = qs.get(name)
    if not values:
        return None
    try:
        return float(values[0])
    except ValueError:
        raise ApiError(400, "bad_query", "{} must be a number (Unix seconds)".format(name))


@handles_errors
def _handle_activity(handler: Any) -> Tuple[int, dict]:
    from urllib.parse import parse_qs, urlsplit

    path = handler.server.receipts_path
    if path is None:
        raise ApiError(404, "receipts_not_configured", "the console was started without --receipts")
    qs = parse_qs(urlsplit(handler.path).query)
    window = (qs.get("window") or ["24h"])[0]
    if window not in WINDOWS:
        raise ApiError(400, "bad_query", "window must be one of {}".format(", ".join(WINDOWS)))
    span, buckets = WINDOWS[window]
    now = time.time()
    start = now - span
    receipts = _read_receipts(path)
    lo, hi = _float(qs, "from"), _float(qs, "to")
    focus = (lo, hi) if lo is not None and hi is not None else None
    readable = [r for r in receipts if not r.get("unreadable")]
    recent = [r for r in readable if r.get("phase") != "outcome"
              and r.get("action") not in BOOKKEEPING][-RECENT:]
    return 200, {
        "window": window,
        "now": now,
        "start": start,
        "focus": {"from": focus[0], "to": focus[1]} if focus else None,
        "summary": aggregate(receipts, *(focus or (start, now + 1e9))),
        "unreadable": sum(1 for r in receipts if r.get("unreadable")),
        "timeline": timeline(receipts, start, span, buckets),
        "recent": [{k: r.get(k) for k in ("index", "ts", "action", "verdict", "policy_verdict",
                                           "observed", "policy_id", "principal")} for r in recent],
        "last_ts": readable[-1]["ts"] if readable else None,
        "total": len(receipts),
    }


ROUTES["/api/activity"] = {"GET": _handle_activity}

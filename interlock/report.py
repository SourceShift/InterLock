"""Read a receipt log and say what the guard did - or would have done.

``@monitor()`` exists so a new rule can be trialled against real traffic, but a
monitor receipt only helps if something reads it. This module aggregates a
receipt log into the answers an operator asks for: what was blocked, by which
rule, how often; what monitor mode *would* have blocked; how escalations were
settled; which allowed tools then failed and who stopped them; how long
evaluation took; and whether any receipts were lost.

The chain is verified first when a key (or verifier) is given, and the report
says so either way - an unverified log is labelled, never silently trusted.
Receipts hold digests, not argument values, so nothing here can print one.

The aggregation (:func:`summarize`) is a pure function over receipts, shared by
``python -m interlock report`` and any UI, so the two cannot disagree.

:func:`containment` answers the question a verdict count cannot: once an
instruction-override signature arrived inside a tool result, what did the span
do next? It reads the same receipts - the result-phase verdicts the injection
detectors left, and the call-phase verdicts that followed - and sorts every
exposed span into contained, partial, open or quiet. Receipts carry no
argument values, so it can say a call ran, never that it carried the poison;
"allowed after exposure" is exposure, not proof of leakage.
"""
from __future__ import annotations

import json
import math
import re
import time
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .receipt import Receipt, Verifier, hmac_sha256, verify_chain

_DURATION = re.compile(r"^(\d+(?:\.\d+)?)([smhdw])$")
_UNIT = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_DECISION_PHASES = ("call", "result")

#: The built-in detectors whose verdict says an instruction-override signature
#: arrived inside delivered content. A detector keeps its own ``policy_id`` on
#: the decision (a declarative rule's id is only filled in when the detector
#: left it empty), so these two strings are what a receipt carries.
POISON_DETECTORS: Tuple[str, ...] = ("tool_result_injection",
                                    "tool_result_injection_sanitizer")

#: Exposure statuses, worst first - the order rows are reported in.
_STATUS_ORDER = ("open", "partial", "contained", "quiet")


def parse_since(text: Optional[str]) -> Optional[float]:
    """``"30m"``, ``"24h"``, ``"7d"`` -> seconds; ``None``, ``"0"`` or ``"all"`` -> None."""
    if text is None:
        return None
    value = text.strip().lower()
    if value in ("", "0", "all"):
        return None
    match = _DURATION.match(value)
    if not match:
        raise ValueError("duration must look like 30m, 24h or 7d, got {!r}".format(text))
    return float(match.group(1)) * _UNIT[match.group(2)]


def read_receipts(path: str) -> Tuple[List[Receipt], List[int]]:
    """Every receipt in a log, and the 1-based line numbers that did not parse."""
    receipts: List[Receipt] = []
    bad: List[int] = []
    with open(path, "r", encoding="utf-8") as fh:
        for number, line in enumerate(fh, 1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                receipts.append(Receipt.from_json(stripped))
            except Exception:
                bad.append(number)
    return receipts, bad


def verification(receipts: List[Receipt], *, key: Optional[bytes] = None,
                 verifier: Optional[Verifier] = None,
                 head: Optional[str] = None) -> Dict[str, Optional[str]]:
    """``{"status": verified|broken|unverified, "detail": ...}``."""
    if key is None and verifier is None:
        return {"status": "unverified",
                "detail": "no key given; pass --key-file to verify the chain"}
    problem = verify_chain(receipts, hmac_sha256, key or b"", verifier=verifier, head=head)
    if problem is None:
        return {"status": "verified", "detail": None}
    return {"status": "broken", "detail": problem}


def summarize(
    receipts: Iterable[Receipt],
    *,
    since_seconds: Optional[float] = None,
    now: Optional[float] = None,
    top: int = 10,
    exposure_ids: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Aggregate receipts into a JSON-ready report."""
    now = time.time() if now is None else now
    cutoff = now - since_seconds if since_seconds is not None else None
    window = [r for r in receipts if cutoff is None or r.ts >= cutoff]

    decisions = [r for r in window if r.phase in _DECISION_PHASES
                 and r.action != "receipts.dropped"]
    enforced = [r for r in decisions if not r.observed]
    observed = [r for r in decisions if r.observed and r.verdict != "ALLOW"]
    calls = [r for r in enforced if r.phase == "call"]

    verdicts = Counter(r.verdict for r in enforced)
    blocked_calls = sum(1 for r in calls if r.verdict == "BLOCK")

    rule_counts: Dict[str, Counter] = defaultdict(Counter)
    for r in enforced:
        if r.verdict != "ALLOW" or r.policy_verdict:
            rule_counts[r.policy_id or "(unnamed)"][r.verdict] += 1

    would: Counter = Counter(
        (r.verdict, r.action, r.policy_id or "(unnamed)") for r in observed
    )

    escalations = Counter(r.approval for r in enforced if r.approval)
    # A coverage gap is a delegated action class whose out-of-process second
    # opinion was unavailable and whose failure policy let the primary decide.
    # It is counted across every decision, monitored or enforced: the missing
    # coverage is a property of the deployment, not of what was enforced.
    coverage_gaps = Counter(r.coverage_gap for r in decisions if r.coverage_gap)
    outcomes = Counter(r.enforcer or "tool" for r in window if r.phase == "outcome")
    dropped = 0
    for r in window:
        if r.action == "receipts.dropped":
            match = re.match(r"^(\d+)", r.reason or "")
            dropped += int(match.group(1)) if match else 1

    masked: Counter = Counter()
    for r in enforced:
        for entity, count in (r.masked or {}).items():
            masked[entity] += count
    # Estimated token spend: the per-event estimate a token-accounting rule
    # stamped onto the receipt. Only receipts that carried one are counted.
    token_values = [r.tokens for r in enforced
                    if isinstance(r.tokens, int) and not isinstance(r.tokens, bool)]
    latencies = sorted(r.elapsed_us for r in decisions if isinstance(r.elapsed_us, int))
    days = sorted({time.strftime("%Y-%m-%d", time.localtime(r.ts)) for r in window})

    return {
        "window": {
            "since_seconds": since_seconds,
            "first_ts": window[0].ts if window else None,
            "last_ts": window[-1].ts if window else None,
            "active_days": len(days),
            "first_day": days[0] if days else None,
            "last_day": days[-1] if days else None,
        },
        "totals": {
            "receipts": len(window),
            "decisions": len(enforced),
            "calls": len(calls),
            "results": len(enforced) - len(calls),
            "sessions": len({r.span_id for r in window if r.span_id}),
            "principals": len({r.principal for r in window if r.principal}),
        },
        "verdicts": dict(sorted(verdicts.items())),
        "block_rate": (blocked_calls / len(calls)) if calls else 0.0,
        "top_rules": [
            {"policy_id": rule, "count": sum(c.values()), "verdicts": dict(sorted(c.items()))}
            for rule, c in sorted(rule_counts.items(), key=lambda kv: (-sum(kv[1].values()), kv[0]))[:top]
        ],
        "top_blocked_actions": [
            {"action": action, "count": count}
            for action, count in Counter(
                r.action for r in enforced if r.verdict == "BLOCK").most_common(top)
        ],
        "would_have": {
            "total": len(observed),
            "rows": [
                {"count": count, "verdict": verdict, "action": action, "policy_id": rule}
                for (verdict, action, rule), count in sorted(
                    would.items(), key=lambda kv: (-kv[1], kv[0]))[:top]
            ],
        },
        "escalations": dict(sorted(escalations.items())),
        "coverage_gaps": dict(sorted(coverage_gaps.items())),
        "failed_outcomes": dict(sorted(outcomes.items())),
        "dropped_receipts": dropped,
        "masked": dict(masked.most_common()),
        "tokens": {"total": sum(token_values), "calls": len(token_values)},
        "latency_us": _percentiles(latencies),
        # Already windowed, so no second filter and the same ``now`` agrees.
        "containment": containment(window, top=top, exposure_ids=exposure_ids),
    }


def containment(
    receipts: Iterable[Receipt],
    *,
    since_seconds: Optional[float] = None,
    now: Optional[float] = None,
    top: int = 10,
    exposure_ids: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """What each exposed span did after the injection, not just the verdict.

    A *exposure* is a result-phase receipt the injection detectors wrote: the
    tool returned content carrying an instruction-override signature. Three
    deliveries are distinguished. ``withheld`` (verdict BLOCK) never reached
    the model. ``rewritten`` (verdict MODIFY, from the sanitizer) removed the
    offending lines and delivered the rest. ``delivered`` (``observed``) is
    monitor mode - the policy verdict was recorded, nothing was enforced, and
    the model read the whole payload.

    The window for what followed is the span's *first* exposure: every
    call-phase receipt after it counts, because a call that ran after content
    was poisoned may have carried it. A span is ``contained`` when at least one
    of those calls was blocked and none ran, ``partial`` when some ran anyway,
    ``open`` when nothing was stopped, and ``quiet`` when nothing followed.

    This is trace evaluation, not taint tracking: receipts store verdicts and
    digests, not arguments, so an allowed call is **not** evidence that poison
    crossed the boundary. Read ``open`` as "the guard did not act", never as
    "the agent leaked".
    """
    now = time.time() if now is None else now
    cutoff = now - since_seconds if since_seconds is not None else None
    ids = set(POISON_DETECTORS)
    if exposure_ids is not None:
        ids.update(e for e in exposure_ids if isinstance(e, str) and e)

    spans: Dict[str, List[Receipt]] = {}
    for receipt in receipts:
        if receipt.action == "receipts.dropped":
            continue
        if cutoff is not None and receipt.ts < cutoff:
            continue
        spans.setdefault(receipt.span_id or "(no span)", []).append(receipt)

    rows: List[Dict[str, Any]] = []
    statuses: Counter = Counter()
    detectors: Counter = Counter()
    blocked_actions: Counter = Counter()
    totals = Counter()
    for span_id, events in spans.items():
        marks = [i for i, r in enumerate(events)
                 if r.phase == "result" and r.policy_id in ids]
        if not marks:
            continue
        first = marks[0]
        following = [r for r in events[first + 1:] if r.phase == "call"]
        blocked = [r for r in following if r.verdict == "BLOCK"]
        escalated = [r for r in following if r.verdict == "ESCALATE"]
        allowed = [r for r in following if r.verdict in ("ALLOW", "MODIFY")]
        if not following:
            status = "quiet"
        elif not blocked:
            status = "open"
        elif allowed or escalated:
            status = "partial"
        else:
            status = "contained"
        delivery: Counter = Counter()
        for index in marks:
            receipt = events[index]
            detectors[receipt.policy_id or "?"] += 1
            delivery["delivered" if receipt.observed
                     else "withheld" if receipt.verdict == "BLOCK"
                     else "rewritten"] += 1
        for receipt in blocked:
            blocked_actions[receipt.action] += 1
        statuses[status] += 1
        totals["calls_after"] += len(following)
        totals["blocked_after"] += len(blocked)
        totals["escalated_after"] += len(escalated)
        totals["allowed_after"] += len(allowed)
        rows.append({
            "span_id": span_id,
            "status": status,
            "exposures": len(marks),
            "first_ts": events[first].ts,
            "action": events[first].action,
            "attributed_to": events[first].attributed_to,
            "delivery": dict(sorted(delivery.items())),
            "calls_after": len(following),
            "blocked_after": len(blocked),
            "escalated_after": len(escalated),
            "allowed_after": len(allowed),
            "blocked_actions": [action for action, _ in
                                Counter(r.action for r in blocked).most_common(5)],
        })

    rows.sort(key=lambda row: (_STATUS_ORDER.index(row["status"]), row["first_ts"]))
    return {
        "exposures": sum(row["exposures"] for row in rows),
        "spans": rows[:top],
        "totals": {
            "exposed_spans": len(rows),
            **{status: statuses.get(status, 0) for status in _STATUS_ORDER},
            **{key: totals.get(key, 0) for key in
               ("calls_after", "blocked_after", "escalated_after", "allowed_after")},
        },
        "detectors": dict(sorted(detectors.items())),
        "blocked_actions": [
            {"action": action, "count": count}
            for action, count in blocked_actions.most_common(top)
        ],
    }


def _percentiles(values: List[int]) -> Optional[Dict[str, int]]:
    if not values:
        return None

    def at(p: float) -> int:
        index = max(0, min(len(values) - 1, int(math.ceil(p * len(values))) - 1))
        return values[index]

    return {"p50": at(0.50), "p90": at(0.90), "p95": at(0.95), "p99": at(0.99),
            "max": values[-1], "samples": len(values)}


def render(summary: Dict[str, Any], verified: Dict[str, Optional[str]], *,
           monitor: bool = False, color: bool = False,
           containment_only: bool = False) -> str:
    """The human-readable report."""

    def paint(code: str, text: str) -> str:
        return "\x1b[{}m{}\x1b[0m".format(code, text) if color else text

    lines: List[str] = []
    status = verified["status"]
    status_line = {
        "verified": paint("32", "chain verified"),
        "broken": paint("31", "CHAIN BROKEN: {}".format(verified["detail"])),
        "unverified": paint("33", "chain NOT verified ({})".format(verified["detail"])),
    }[str(status)]
    window = summary["window"]
    span = "all time" if window["since_seconds"] is None else "last {}".format(
        _human_duration(window["since_seconds"]))
    lines.append("interlock activity ({}) - {}".format(span, status_line))
    lines.append("=" * 64)

    if containment_only:
        lines.extend(_containment_lines(summary["containment"], paint))
        return "\n".join(lines)

    if monitor:
        would = summary["would_have"]
        lines.append("Would have intervened in {} call(s){}".format(
            would["total"], ":" if would["rows"] else "."))
        if would["rows"]:
            lines.append("")
            lines.append("{:>6}  {:<9} {:<24} {}".format("COUNT", "VERDICT", "ACTION", "RULE"))
            for row in would["rows"]:
                lines.append("{:>6}  {:<9} {:<24} {}".format(
                    row["count"], row["verdict"], row["action"][:24], row["policy_id"]))
        lines.append("")
        lines.append("A quiet report means the observed calls were clean - and a thin "
                     "rule set flags nothing, which looks identical.")
        return "\n".join(lines)

    totals = summary["totals"]
    verdicts = summary["verdicts"]
    lines.append("Decisions:        {} ({} calls, {} results)".format(
        totals["decisions"], totals["calls"], totals["results"]))
    lines.append("Sessions:         {}   principals: {}".format(
        totals["sessions"], totals["principals"]))
    lines.append("Allow/Rewrite/Block/Escalate: {} / {} / {} / {}".format(
        verdicts.get("ALLOW", 0), verdicts.get("MODIFY", 0), verdicts.get("BLOCK", 0),
        verdicts.get("ESCALATE", 0)))
    if window["first_day"]:
        lines.append("Active days:      {} ({} -> {})".format(
            window["active_days"], window["first_day"], window["last_day"]))
    rate = summary["block_rate"]
    bar = "#" * int(round(rate * 24))
    lines.append("Call block rate:  [{:<24}] {:.1%}".format(bar, rate))
    latency = summary["latency_us"]
    if latency:
        lines.append("Eval latency us:  p50 {p50} / p90 {p90} / p95 {p95} / p99 {p99} / max {max}".format(**latency))
    else:
        lines.append("Eval latency us:  not recorded")
    if summary["would_have"]["total"]:
        lines.append("Monitor mode:     {} call(s) would have been stopped or rewritten "
                     "(see --monitor)".format(summary["would_have"]["total"]))
    if summary["escalations"]:
        lines.append("Escalations:      " + ", ".join(
            "{} {}".format(v, k) for k, v in summary["escalations"].items()))
    if summary.get("coverage_gaps"):
        lines.append("Coverage gaps:    " + ", ".join(
            "{} {}".format(v, k) for k, v in summary["coverage_gaps"].items()))
    if summary["failed_outcomes"]:
        lines.append("Failed after allow: " + ", ".join(
            "{} by {}".format(v, k) for k, v in summary["failed_outcomes"].items()))
    if summary.get("masked"):
        lines.append("Masked:           " + ", ".join(
            "{} x{}".format(k, v) for k, v in summary["masked"].items()))
    tokens = summary.get("tokens") or {}
    if tokens.get("total"):
        lines.append("Est. tokens:      {} across {} call(s)".format(
            tokens["total"], tokens["calls"]))
    if summary["dropped_receipts"]:
        lines.append(paint("31", "Dropped receipts: {} (the log has gaps)".format(
            summary["dropped_receipts"])))
    if summary["top_rules"]:
        lines.append("")
        lines.append("Top rules (non-allow decisions)")
        lines.append("-" * 64)
        width = max(c["count"] for c in summary["top_rules"])
        for index, row in enumerate(summary["top_rules"], 1):
            share = row["count"] / width if width else 0
            lines.append("{:>3}  {:<32} {:>6}  {}".format(
                index, row["policy_id"][:32], row["count"], "#" * max(1, int(share * 10))))
    if summary.get("containment", {}).get("totals", {}).get("exposed_spans"):
        lines.append("")
        lines.extend(_containment_lines(summary["containment"], paint))
    return "\n".join(lines)


def _containment_lines(containment: Dict[str, Any], paint) -> List[str]:
    """The post-exposure section: per-span status and what followed."""
    totals = containment["totals"]
    if not totals["exposed_spans"]:
        return ["No injection signature reached a tool result: nothing to contain."]
    lines = ["Containment (what each exposed span did next)"]
    lines.append("-" * 64)
    lines.append("Exposures:  {} in {} span(s) - {} open, {} partial, "
                 "{} contained, {} quiet".format(
                     containment["exposures"], totals["exposed_spans"], totals["open"],
                     totals["partial"], totals["contained"], totals["quiet"]))
    lines.append("After:      {} call(s) - {} blocked, {} escalated, {} allowed".format(
        totals["calls_after"], totals["blocked_after"],
        totals["escalated_after"], totals["allowed_after"]))
    if containment["blocked_actions"]:
        lines.append("Stopped:    " + ", ".join(
            "{} x{}".format(row["action"], row["count"])
            for row in containment["blocked_actions"]))
    for row in containment["spans"]:
        status = paint("31", "OPEN") if row["status"] == "open" else {
            "partial": paint("33", "PARTIAL"),
            "contained": paint("32", "CONTAINED"),
            "quiet": "QUIET",
        }[row["status"]]
        delivery = ", ".join("{} {}".format(v, k) for k, v in row["delivery"].items())
        lines.append("")
        lines.append("  {} - {} ({} exposure(s): {})".format(
            row["span_id"], row["action"], row["exposures"], delivery))
        lines.append("    after exposure: {} call(s) - {} blocked, {} escalated, {} allowed  {}"
                     .format(row["calls_after"], row["blocked_after"],
                             row["escalated_after"], row["allowed_after"], status))
        if row["blocked_actions"]:
            lines.append("    blocked: " + ", ".join(row["blocked_actions"]))
    lines.append("")
    lines.append("An allowed call after exposure is not proof poison crossed: receipts "
                 "hold verdicts and digests, not arguments.")
    return lines


def _human_duration(seconds: float) -> str:
    for unit, size in (("w", 604800), ("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size and seconds % size == 0:
            return "{}{}".format(int(seconds // size), unit)
    return "{}s".format(int(seconds))


def to_json(summary: Dict[str, Any], verified: Dict[str, Optional[str]]) -> str:
    return json.dumps({"verification": verified, **summary}, indent=2, sort_keys=True)

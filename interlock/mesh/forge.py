"""The forge: from what the network saw to a rule a human can review.

Every rule corpus that lasts has the same loop: evidence in, candidate out,
gates before anyone looks, a human merge, and the gates run again in CI so the
merge cannot skip them. The forge is that loop for the commons. It never
publishes; it writes a **proposal** directory shaped like a pull request:

    proposals/<id>/pack.json      the candidate pack (every rule status experimental)
    proposals/<id>/tests.json     conformance cases: the samples it must catch, benign events it must not
    proposals/<id>/PROPOSAL.md    the evidence: organisations, samples, false-positive rate, recall, cost

Candidates come from three places:

1. **indicators**: the consensus engine's active exact-match digests;
2. **similarity**: its active campaign fingerprints;
3. **patterns**: for a rule with redacted samples from several organisations,
   the longest fragment most samples share, as a ``contains`` condition on
   the argument names the samples named. Deterministic, explainable, and
   deliberately modest: a fragment rule escalates, never blocks.

An optional ``drafter`` callable (an LLM behind a validation loop, the way
GRIDAI and FALCON generate and repair rules) may add candidates; whatever it
returns goes through the same gates. The gates are the harness's: no
quarantined rule, a false-positive rate on the benign corpus under budget, a
p95 cost under budget, and recall over the samples above a floor.

Every ``pack.json`` names its licence and its provenance (decision R4). The
indicator and similarity packs are the consensus engine's exports, data under
``CC0-1.0``; a drafted rule (pattern or drafter) is a rule like any other pack's,
``Apache-2.0``. ``provenance`` says where the candidate came from, how many
organisations stand behind it and when the forge ran. The sample strings in
``tests.json`` are CC0-1.0 whatever the pack's licence (``LICENSE-DATA``).
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
import time
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence

from ..event import SensorEvent
from ._util import atomic_write
from .bundle import DEFAULT_PACK_LICENSE
from .consensus import ConsensusEngine
from .harness import DEFAULT_MAX_FP_RATE, DEFAULT_MAX_P95_US, gate, measure, recall

__all__ = ["forge", "common_fragment", "Proposal", "MIN_FRAGMENT", "DEFAULT_MIN_RECALL"]

MIN_FRAGMENT = 12
WINDOW = 12
DEFAULT_MIN_RECALL = 0.8
MIN_SAMPLE_ORGS = 2
Drafter = Callable[[str, Sequence[Mapping[str, Any]]], Sequence[Mapping[str, Any]]]


class Proposal:
    def __init__(self, proposal_id: str, pack: Dict[str, Any], tests: List[Dict[str, Any]],
                 evidence: Dict[str, Any], passed: bool, reasons: List[str]) -> None:
        self.id = proposal_id
        self.pack = pack
        self.tests = tests
        self.evidence = evidence
        self.passed = passed
        self.reasons = reasons

    def markdown(self) -> str:
        ev = self.evidence
        provenance = self.pack.get("provenance") or {}
        lines = ["# Proposal {}: {}".format(self.id, self.pack.get("name", "")), "",
                 self.pack.get("description", ""), "",
                 "**Gates:** {}".format("PASS" if self.passed else "FAIL: " + "; ".join(self.reasons)), "",
                 "| Evidence | Value |", "|---|---|"]
        for key in ("source", "organisations", "samples", "fp_rate", "false_positives", "benign_events",
                    "recall", "p95_us", "rules"):
            if key in ev:
                value = ev[key]
                if isinstance(value, float):
                    value = "{:.4%}".format(value) if key in ("fp_rate", "recall") else "{:.3f}".format(value)
                lines.append("| {} | {} |".format(key, value))
        lines += ["", "| Licence and provenance | Value |", "|---|---|",
                  "| license | `{}` |".format(self.pack.get("license", ""))]
        lines += ["| provenance.{} | {} |".format(key, provenance[key])
                  for key in ("source", "organisations", "generated") if key in provenance]
        lines += ["", "The strings in `tests.json` are data: CC0-1.0 once in a commons (`LICENSE-DATA`), and the",
                  "pull request that adds them carries the data warranty (lawfully obtained, no personal data,",
                  "no third party's confidential data). Check them before you open it; a sample later found to",
                  "hold personal data is erased as GOVERNANCE.md says.",
                  "", "Every rule is `experimental`: on the canary ring it may only escalate, and it spends",
                  "the monitor window in shadow mode before it decides anything anywhere.", ""]
        return "\n".join(lines)


def common_fragment(texts: Sequence[str], *, min_share: float = 0.6, min_length: int = MIN_FRAGMENT) -> Optional[str]:
    """The longest substring present in at least ``min_share`` of ``texts``.

    Found through shared fixed windows merged into runs, which is linear in
    the total text rather than quadratic per pair; good enough to surface the
    instruction an injection repeats, and cheap enough to run on every rule.
    """
    cleaned = [re.sub(r"\s+", " ", t).strip() for t in texts if isinstance(t, str) and t.strip()]
    if len(cleaned) < 2:
        return None
    needed = max(2, int(round(min_share * len(cleaned))))
    windows: Dict[str, int] = {}
    for text in cleaned:
        seen = set()
        for i in range(max(0, len(text) - WINDOW + 1)):
            seen.add(text[i:i + WINDOW])
        for w in seen:
            windows[w] = windows.get(w, 0) + 1
    shared = {w for w, n in windows.items() if n >= needed}
    if not shared:
        return None
    best = ""
    for text in cleaned:
        run_start: Optional[int] = None
        for i in range(max(0, len(text) - WINDOW + 1) + 1):
            inside = i < len(text) - WINDOW + 1 and text[i:i + WINDOW] in shared
            if inside and run_start is None:
                run_start = i
            if not inside and run_start is not None:
                candidate = text[run_start:i - 1 + WINDOW]
                if len(candidate) > len(best):
                    best = candidate
                run_start = None
        break  # runs from the first text suffice: every shared window appears in it or another text
    if len(best) < min_length:
        # The first text may not hold the longest run; try the others.
        for text in cleaned[1:]:
            run_start = None
            for i in range(max(0, len(text) - WINDOW + 1) + 1):
                inside = i < len(text) - WINDOW + 1 and text[i:i + WINDOW] in shared
                if inside and run_start is None:
                    run_start = i
                if not inside and run_start is not None:
                    candidate = text[run_start:i - 1 + WINDOW]
                    if len(candidate) > len(best):
                        best = candidate
                    run_start = None
    return best if len(best) >= min_length else None


def _pattern_candidates(engine: ConsensusEngine) -> List[Dict[str, Any]]:
    """One escalate rule per rule id whose samples from several orgs share a fragment."""
    out: List[Dict[str, Any]] = []
    for policy_id, samples in sorted(engine.samples.items()):
        orgs = {s["reporter"] for s in samples}
        if len(orgs) < MIN_SAMPLE_ORGS:
            continue
        lowered = [s["text"].lower() for s in samples]
        fragment = None
        # Prefer the fragment every sample shares; widen only when nothing long enough is common to all.
        for share in (1.0, 0.8, 0.6):
            fragment = common_fragment(lowered, min_share=share)
            if fragment:
                break
        if not fragment:
            continue
        fragment = fragment[:200]
        names = sorted({n for s in samples for n in s.get("arg_names", [])}) or ["text"]
        rule_id = "forge-{}-{}".format(re.sub(r"[^A-Za-z0-9_.-]", "-", policy_id)[:40],
                                       hashlib.sha256(fragment.encode("utf-8")).hexdigest()[:8])
        pattern = "(?i)" + re.escape(fragment)
        out.append({
            "id": rule_id, "verdict": "escalate", "status": "experimental",
            "reason": "resembles a payload {} organisations' guards stopped ({})".format(len(orgs), policy_id),
            "description": "fragment shared by {} of {} redacted samples from {} organisation(s)".format(
                sum(1 for t in lowered if fragment in re.sub(r"\s+", " ", t)), len(samples), len(orgs)),
            "when": {"any": [{"arg": name, "matches": pattern} for name in names]},
            "_evidence": {"organisations": len(orgs), "samples": len(samples), "fragment": fragment,
                          "tool_classes": sorted({s.get("tool_class", "other") for s in samples}),
                          "sample_events": [_event_from_sample(s) for s in samples]},
        })
    return out


def _event_from_sample(sample: Mapping[str, Any]) -> Dict[str, Any]:
    names = sample.get("arg_names") or ["text"]
    action = {"shell": "Bash", "http": "WebFetch", "file.read": "Read", "file.write": "Write", "mcp": "mcp__tool",
              "database": "query_db", "message": "send_message", "payment": "pay"}.get(sample.get("tool_class", "other"), "tool")
    return {"action": action, "args": {names[0]: sample["text"]}}


def _orgs_behind(records: Mapping[str, Mapping[str, Any]], keys: Iterable[str]) -> int:
    """Distinct organisations behind the ``keys`` of an engine's indicators or campaigns."""
    return len({org for key in keys for org in records.get(key, {}).get("orgs", [])})


def forge(engine: ConsensusEngine, *, benign: Sequence[SensorEvent], out_dir: str,
          attack_samples: Sequence[SensorEvent] = (), max_fp_rate: float = DEFAULT_MAX_FP_RATE,
          max_p95_us: int = DEFAULT_MAX_P95_US, min_recall: float = DEFAULT_MIN_RECALL,
          drafter: Optional[Drafter] = None, now: Optional[float] = None) -> List[Proposal]:
    """Draft, gate and write every candidate the engine's state supports."""
    now = time.time() if now is None else now
    candidates: List[Dict[str, Any]] = []

    indicators = engine.export_indicators()
    if indicators["rules"][0]["with"]["indicators"]:
        pack = copy.deepcopy(indicators)
        pack["rules"][0]["status"] = "experimental"
        active = {"{}|{}".format(d["policy_id"], d["args_digest"]) for d in engine.decisions() if d["status"] == "active"}
        candidates.append({"source": "indicators", "pack": pack,
                           "evidence": {"organisations": _orgs_behind(engine.indicators, active),
                                        "rules": len(pack["rules"][0]["with"]["indicators"])}})
    similarity = engine.export_similarity()
    if any(r["with"]["fingerprints"] for r in similarity["rules"]):
        pack = copy.deepcopy(similarity)
        for rule in pack["rules"]:
            rule["status"] = "experimental"
        active = {c["id"] for c in engine.campaign_status() if c["status"] == "active"}
        candidates.append({"source": "similarity", "pack": pack,
                           "evidence": {"organisations": _orgs_behind(engine.campaigns, active),
                                        "rules": sum(len(r["with"]["fingerprints"]) for r in pack["rules"])}})
    for rule in _pattern_candidates(engine):
        evidence = rule.pop("_evidence")
        pack = {"version": 1, "name": "forge-" + rule["id"], "channel": engine.config["pack_channel"],
                "license": DEFAULT_PACK_LICENSE,
                "description": "drafted by the forge from redacted samples: {!r}".format(evidence["fragment"][:80]),
                "rules": [rule]}
        candidates.append({"source": "pattern", "pack": pack, "evidence": evidence})
    if drafter is not None:
        for policy_id, samples in sorted(engine.samples.items()):
            try:
                drafted = list(drafter(policy_id, samples))
            except Exception as exc:  # a drafter is untrusted code; its failure is a note, not a crash
                drafted = []
                candidates.append({"source": "drafter", "pack": None, "evidence": {"error": str(exc)}})
            for index, rule in enumerate(drafted):
                if not isinstance(rule, dict):
                    continue
                rule = dict(rule, status="experimental")
                rule.pop("locked", None)
                rule.setdefault("id", "draft-{}-{}".format(re.sub(r"[^A-Za-z0-9_.-]", "-", policy_id)[:40], index))
                pack = {"version": 1, "name": "draft-" + rule["id"], "channel": engine.config["pack_channel"],
                        "license": DEFAULT_PACK_LICENSE,
                        "description": "drafted for {} by the configured drafter".format(policy_id), "rules": [rule]}
                candidates.append({"source": "drafter", "pack": pack,
                                   "evidence": {"organisations": len({s["reporter"] for s in samples}),
                                                "samples": len(samples),
                                                "sample_events": [_event_from_sample(s) for s in samples]}})

    proposals: List[Proposal] = []
    for candidate in candidates:
        pack = candidate["pack"]
        if pack is None:
            continue
        evidence = dict(candidate["evidence"], source=candidate["source"])
        sample_events = [SensorEvent(action=e["action"], args=e["args"])
                         for e in evidence.pop("sample_events", [])] or list(attack_samples)
        try:
            measured = measure(pack, benign, source=pack["name"])
            recalled = recall(pack, sample_events, source=pack["name"]) if sample_events else None
        except Exception as exc:
            measured = {"quarantined": ["{}: {}".format(pack["name"], exc)], "evaluated": 0, "fp_rate": 0.0,
                        "false_positives": 0, "latency_us": {"p95": 0}, "per_rule": {}}
            recalled = None
        passed, reasons = gate(measured, max_fp_rate=max_fp_rate, max_p95_us=max_p95_us,
                               recalled=recalled, min_recall=min_recall if recalled else 0.0)
        evidence.update({"fp_rate": measured["fp_rate"], "false_positives": measured["false_positives"],
                         "benign_events": measured["evaluated"], "p95_us": measured["latency_us"]["p95"]})
        if recalled:
            evidence["recall"] = recalled["recall"]
        proposal_id = "{}-{}".format(candidate["source"], hashlib.sha256(
            json.dumps(pack, sort_keys=True).encode("utf-8")).hexdigest()[:10])
        # After the id, so the same evidence forged again keeps its proposal id.
        pack = dict(pack, provenance={
            "source": candidate["source"], "organisations": evidence.get("organisations"),
            "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))})
        tests = [{"name": "sample {}".format(i), "expect": "ESCALATE_OR_BLOCK",
                  "event": {"action": e.action, "args": e.args}} for i, e in enumerate(sample_events[:20])]
        tests += [{"name": "benign {}".format(i), "expect": "ALLOW", "event": {"action": e.action, "args": e.args}}
                  for i, e in enumerate(list(benign)[:20])]
        proposal = Proposal(proposal_id, pack, tests, evidence, passed, reasons)
        directory = os.path.join(out_dir, proposal_id)
        atomic_write(os.path.join(directory, "pack.json"), json.dumps(pack, indent=1, sort_keys=True).encode("utf-8"))
        atomic_write(os.path.join(directory, "tests.json"), json.dumps(tests, indent=1).encode("utf-8"))
        atomic_write(os.path.join(directory, "PROPOSAL.md"), proposal.markdown().encode("utf-8"))
        atomic_write(os.path.join(directory, "evidence.json"), json.dumps(
            {"passed": passed, "reasons": reasons, **evidence, "generated": now}, indent=1, sort_keys=True,
            default=str).encode("utf-8"))
        proposals.append(proposal)
    return proposals

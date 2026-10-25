"""The consensus engine: from many nodes' reports to a few shared decisions.

Every crowdsourced defence that works does the same four things, and this
module does them in that order: **weight the reporter**, **count distinct
organisations rather than events**, **let receivers push back**, and **expire
everything**.

A reporter's trust starts at a floor and grows with tenure and with agreement
with **canaries**, known-bad payloads the maintainers seed so that a node
reporting them is demonstrably seeing real traffic (the role honeypots play
for CrowdSec). Reporting a known-*benign* canary as blocked is the signature of
a misconfigured or hostile node and costs trust. Reports from an unknown
detector catalog are refused outright: only unmodified, published detectors
count.

An indicator (a rule id plus the digest of the arguments it blocked) becomes
**active** when enough *distinct* reporters saw it, their combined trust clears
a bar, it was seen recently, and the rule it belongs to has not been
**demoted** by false-positive sightings from several organisations. Active
indicators are exported as a policy pack that uses the
``mesh_indicator_guard`` detector, with status ``test``, so no subscriber
enforces them blindly: on the canary and early rings they escalate, and the
stable ring never installs them until a maintainer promotes the pack.

Counts are not here: they go to the aggregators (:mod:`.aggregate`), which is
the point, and a report envelope that carries them is refused
(:func:`~interlock.mesh.report.verify_report`). The consensus engine sees who
reported which digest or sighting, under a pseudonymous key, and nothing about
how often anything happened at any node. Its per-rule statistics count
organisations, never events: a reporter that sent a digest or a sighting for a
rule saw that rule fire.

What the engine exports is data, not code: the indicator and similarity packs
carry ``"license": "CC0-1.0"`` (``LICENSE-DATA``, decision R4). A redacted
sample is kept only with the reporter's attestation (the data warranty,
:func:`~interlock.mesh.report.check_attestation`), and :meth:`forget_sample`
erases one when it turns out to hold personal data.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Set

from ._util import atomic_write, read_bounded
from .report import ReportError, check_attestation, verify_report

__all__ = ["DEFAULT_CONFIG", "DATA_LICENSE", "ConsensusEngine"]

#: The licence of everything the engine exports: machine-generated facts.
DATA_LICENSE = "CC0-1.0"

DEFAULT_CONFIG: Dict[str, Any] = {
    "min_orgs": 3,                 # distinct reporters before an indicator is active
    "min_trust": 2.0,              # their combined trust
    "indicator_ttl_days": 30,      # unseen for this long: no longer active
    "fp_demote_orgs": 2,           # distinct orgs reporting a false positive demote the rule
    "max_digests_per_report": 500,
    "max_reports_per_day": 48,
    "require_known_catalog": True,
    "unknown_reporter_trust": 0.5,
    "pack_name": "mesh-indicators",
    "pack_channel": "indicators",
    "pack_status": "test",
    # Membership credentials (phase 3): when required, a report must carry a
    # certificate from one of ``issuers`` for the key that signed it.
    "require_credential": False,
    "issuers": [],
    "revoked": [],
    "credential_scope": None,
}
STATE_MAX = 64 * 1024 * 1024
FIRE_COUNTS_NOTE = ("rules[*].orgs counts organisations that sent a digest or sighting for the rule; "
                    "rules[*].verdicts is null because fire counts never reach consensus: they come from "
                    "the aggregators' combined totals (interlock mesh consensus export --stats "
                    "--aggregator URL --aggregator URL)")


class ConsensusEngine:
    def __init__(self, config: Optional[Mapping[str, Any]] = None, *,
                 now: Callable[[], float] = time.time) -> None:
        self.config = dict(DEFAULT_CONFIG)
        if config:
            self.config.update(config)
        self._now = now
        self._lock = threading.Lock()
        self.reporters: Dict[str, Dict[str, Any]] = {}
        self.indicators: Dict[str, Dict[str, Any]] = {}   # "policy|digest" -> record
        self.rules: Dict[str, Dict[str, Any]] = {}        # policy_id -> {orgs, last}
        self.sightings: Dict[str, Dict[str, Any]] = {}    # policy_id -> {kind: {orgs}}
        self.catalogs: Set[str] = set()
        self.canaries: Dict[str, str] = {}                # digest -> "bad" | "benign"
        self.campaigns: Dict[str, Dict[str, Any]] = {}    # cluster id -> {fp, alpha, orgs, policy_ids, ...}
        self.samples: Dict[str, List[Dict[str, Any]]] = {}  # policy_id -> redacted samples
        self.rejected = 0
        self._dropped_samples: Dict[str, int] = {}        # digest -> unattested copies load() left on disk

    # --- maintainer inputs ------------------------------------------------------

    def register_catalog(self, catalog_id: str) -> None:
        with self._lock:
            self.catalogs.add(str(catalog_id))

    def add_canary(self, digest: str, kind: str = "bad") -> None:
        if kind not in ("bad", "benign"):
            raise ValueError("a canary is 'bad' or 'benign'")
        with self._lock:
            self.canaries[digest] = kind

    def enroll(self, keyid: str, *, trust: Optional[float] = None) -> Dict[str, Any]:
        """Know a reporter ahead of its first report (optional)."""
        with self._lock:
            record = self.reporters.setdefault(keyid, self._new_reporter(self._now()))
            record["enrolled"] = True
            if trust is not None:
                record["granted"] = float(trust)
            return dict(record)

    # --- ingest -----------------------------------------------------------------

    def ingest(self, envelope: Any) -> Dict[str, Any]:
        """Verify and absorb one report. Returns what happened and why."""
        now = self._now()
        try:
            body = verify_report(envelope)
        except ReportError as exc:
            with self._lock:
                self.rejected += 1
            return {"accepted": False, "reason": "signature: {}".format(exc)}
        reporter = body["reporter"]
        credentialed = False
        if self.config.get("require_credential"):
            from .credential import CredentialError, Revocations, issuer_map, verify_certificate
            try:
                verify_certificate(envelope.get("credential"), issuer_map(self.config.get("issuers", [])), now=now,
                                   revoked=Revocations(self.config.get("revoked", [])),
                                   scope=self.config.get("credential_scope"),
                                   pseudonym_public=bytes.fromhex(envelope["public"]))
            except CredentialError as exc:
                with self._lock:
                    self.rejected += 1
                return {"accepted": False, "reason": "credential: {}".format(exc)}
            credentialed = True
        with self._lock:
            if self.config["require_known_catalog"] and body["catalog"] not in self.catalogs:
                self.rejected += 1
                return {"accepted": False, "reason": "unknown catalog {}".format(body["catalog"])}
            record = self.reporters.setdefault(reporter, self._new_reporter(now))
            if credentialed:
                record["enrolled"] = True
            day = int(now // 86400)
            per_day = record.setdefault("per_day", {})
            per_day[str(day)] = per_day.get(str(day), 0) + 1
            for old in [k for k in per_day if int(k) < day - 7]:
                del per_day[old]
            if per_day[str(day)] > self.config["max_reports_per_day"]:
                self.rejected += 1
                return {"accepted": False, "reason": "rate limit: more than {} reports today".format(
                    self.config["max_reports_per_day"])}
            record["reports"] = record.get("reports", 0) + 1
            record["last_seen"] = now
            if body["catalog"] not in record.setdefault("catalogs", []):
                record["catalogs"].append(body["catalog"])

            counted = 0
            fired: Set[str] = set()
            for entry in body["digests"][: self.config["max_digests_per_report"]]:
                digest = entry["args_digest"]
                kind = self.canaries.get(digest)
                if kind == "benign":
                    record["penalties"] = record.get("penalties", 0) + 1
                    continue
                fired.add(entry["policy_id"])
                if kind == "bad":
                    record["canary_hits"] = record.get("canary_hits", 0) + 1
                key = "{}|{}".format(entry["policy_id"], digest)
                ind = self.indicators.setdefault(key, {
                    "policy_id": entry["policy_id"], "args_digest": digest, "orgs": [],
                    "first": now, "last": now, "tool_classes": []})
                if reporter not in ind["orgs"]:
                    ind["orgs"].append(reporter)
                ind["last"] = now
                klass = entry.get("tool_class", "other")
                if klass not in ind["tool_classes"]:
                    ind["tool_classes"].append(klass)
                counted += 1

            for s in body["sightings"]:
                by_kind = self.sightings.setdefault(s["policy_id"], {})
                orgs = by_kind.setdefault(s.get("kind", "false_positive"), [])
                if reporter not in orgs:
                    orgs.append(reporter)
                fired.add(s["policy_id"])

            # Which rules this organisation saw fire: a set, never a tally.
            for policy_id in sorted(fired):
                rule = self.rules.setdefault(policy_id, {"orgs": [], "last": now})
                if reporter not in rule["orgs"]:
                    rule["orgs"].append(reporter)
                rule["last"] = now

            campaigns_touched = self._ingest_fingerprints(reporter, body.get("fingerprints", []), now)
            samples_kept = self._ingest_samples(reporter, body.get("samples", []), body.get("attestation"), now)
            return {"accepted": True, "reporter": reporter, "digests_counted": counted,
                    "campaigns": campaigns_touched, "samples": samples_kept,
                    "trust": round(self.trust(reporter), 3)}

    def _ingest_fingerprints(self, reporter: str, entries: List[Dict[str, Any]], now: float) -> int:
        """Cluster each fingerprint into a campaign (single link, both sides noised)."""
        from . import fingerprint as fp

        touched = 0
        for entry in entries[: self.config["max_digests_per_report"]]:
            try:
                raw = bytes.fromhex(entry["fp"])
                alpha = float(entry["alpha"])
            except (ValueError, KeyError, TypeError):
                continue
            if len(raw) != fp.BYTES or alpha <= 0:
                continue
            limit = fp.threshold(alpha, both_noisy=True)
            home = None
            for key, camp in self.campaigns.items():
                try:
                    if fp.hamming(raw, bytes.fromhex(camp["fp"])) <= limit:
                        home = camp
                        break
                except ValueError:
                    continue
            if home is None:
                key = entry["fp"][:32]
                home = self.campaigns.setdefault(key, {
                    "fp": entry["fp"], "alpha": alpha, "orgs": [], "policy_ids": [], "tool_classes": [],
                    "first": now, "last": now, "members": 0})
            if reporter not in home["orgs"]:
                home["orgs"].append(reporter)
            if entry["policy_id"] not in home["policy_ids"]:
                home["policy_ids"].append(entry["policy_id"])
            klass = entry.get("tool_class", "other")
            if klass not in home["tool_classes"]:
                home["tool_classes"].append(klass)
            home["last"] = now
            home["members"] = home.get("members", 0) + 1
            touched += 1
        return touched

    def _ingest_samples(self, reporter: str, entries: List[Dict[str, Any]], attestation: Any, now: float) -> int:
        import hashlib

        try:
            warranty = check_attestation(attestation)  # verify_report already refused samples without one
        except ReportError:
            return 0
        kept = 0
        for entry in entries[:20]:
            text = entry.get("text")
            policy_id = entry.get("policy_id")
            if not isinstance(text, str) or not text or not isinstance(policy_id, str):
                continue
            bucket = self.samples.setdefault(policy_id, [])
            digest = hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
            if any(s["digest"] == digest for s in bucket):
                continue
            if sum(1 for s in bucket if s["reporter"] == reporter) >= 20 or len(bucket) >= 200:
                continue
            bucket.append({"digest": digest, "reporter": reporter, "text": text[:4096], "ts": now,
                           "tool_class": str(entry.get("tool_class", "other")),
                           "arg_names": [n for n in (entry.get("arg_names") or []) if isinstance(n, str)][:8],
                           "attestation": dict(warranty)})
            kept += 1
        return kept

    def forget_sample(self, digest: str) -> int:
        """Erase every copy of the sample with this digest (the first 16 hex
        characters of the SHA-256 of its text, as stored), for every rule.
        Returns how many were removed; the caller saves the state. Copies
        :meth:`load` dropped for want of an attestation count too: they are
        still in the file until that save."""
        removed = 0
        with self._lock:
            removed += self._dropped_samples.pop(digest, 0)
            for policy_id in list(self.samples):
                bucket = self.samples[policy_id]
                kept = [s for s in bucket if not (isinstance(s, dict) and s.get("digest") == digest)]
                removed += len(bucket) - len(kept)
                if kept:
                    self.samples[policy_id] = kept
                else:
                    del self.samples[policy_id]
        return removed

    @staticmethod
    def _new_reporter(now: float) -> Dict[str, Any]:
        return {"first_seen": now, "last_seen": now, "reports": 0, "canary_hits": 0, "penalties": 0,
                "enrolled": False, "per_day": {}, "catalogs": []}

    # --- trust and decisions ---------------------------------------------------------

    def trust(self, reporter: str) -> float:
        record = self.reporters.get(reporter)
        if record is None:
            return float(self.config["unknown_reporter_trust"])
        if record.get("granted") is not None:
            base = float(record["granted"])
        else:
            base = 1.0 if record.get("enrolled") else float(self.config["unknown_reporter_trust"])
        tenure_days = max(0.0, (self._now() - record.get("first_seen", self._now())) / 86400)
        base += min(1.0, tenure_days / 30.0)
        base += min(1.0, 0.5 * record.get("canary_hits", 0))
        base -= 1.0 * record.get("penalties", 0)
        return max(0.0, base)

    def demoted_rules(self) -> Set[str]:
        out = set()
        for policy_id, by_kind in self.sightings.items():
            if len(by_kind.get("false_positive", [])) >= self.config["fp_demote_orgs"]:
                out.add(policy_id)
        return out

    def decisions(self) -> List[Dict[str, Any]]:
        """Every indicator with its status: ``active``, ``candidate`` or ``expired``."""
        now = self._now()
        ttl = self.config["indicator_ttl_days"] * 86400
        demoted = self.demoted_rules()
        out = []
        with self._lock:
            for key, ind in sorted(self.indicators.items()):
                orgs = list(ind["orgs"])
                trust_sum = sum(self.trust(o) for o in orgs)
                if now - ind["last"] > ttl:
                    status = "expired"
                elif ind["policy_id"] in demoted:
                    status = "demoted"
                elif len(orgs) >= self.config["min_orgs"] and trust_sum >= self.config["min_trust"]:
                    status = "active"
                else:
                    status = "candidate"
                out.append({"policy_id": ind["policy_id"], "args_digest": ind["args_digest"],
                            "orgs": len(orgs), "trust": round(trust_sum, 3), "status": status,
                            "first": ind["first"], "last": ind["last"], "tool_classes": list(ind["tool_classes"])})
        return out

    def campaign_status(self) -> List[Dict[str, Any]]:
        """Every fingerprint cluster with its status, like :meth:`decisions`."""
        now = self._now()
        ttl = self.config["indicator_ttl_days"] * 86400
        demoted = self.demoted_rules()
        out = []
        with self._lock:
            for key, camp in sorted(self.campaigns.items()):
                orgs = list(camp["orgs"])
                trust_sum = sum(self.trust(o) for o in orgs)
                if now - camp["last"] > ttl:
                    status = "expired"
                elif all(p in demoted for p in camp["policy_ids"]):
                    status = "demoted"
                elif len(orgs) >= self.config["min_orgs"] and trust_sum >= self.config["min_trust"]:
                    status = "active"
                else:
                    status = "candidate"
                out.append({"id": key, "fp": camp["fp"], "alpha": camp["alpha"], "orgs": len(orgs),
                            "members": camp.get("members", 0), "trust": round(trust_sum, 3), "status": status,
                            "policy_ids": list(camp["policy_ids"]), "tool_classes": list(camp["tool_classes"]),
                            "first": camp["first"], "last": camp["last"]})
        return out

    # --- exports -----------------------------------------------------------------------

    def export_similarity(self) -> Dict[str, Any]:
        """Active campaigns as a pack using ``mesh_similarity_guard`` (escalate)."""
        active = [c for c in self.campaign_status() if c["status"] == "active"]
        alphas = sorted({c["alpha"] for c in active}) or [1.5]
        rules = []
        for alpha in alphas:
            fps = sorted(c["fp"] for c in active if c["alpha"] == alpha)
            rules.append({
                "id": "mesh-similarity-a{}".format(str(alpha).replace(".", "_")),
                "status": self.config["pack_status"],
                "detector": "mesh_similarity_guard.mesh_similarity_guard",
                "with": {"fingerprints": fps, "alpha": alpha, "verdict": "escalate"},
                "description": "{} active campaign fingerprint(s) at alpha {}".format(len(fps), alpha),
            })
        return {
            "version": 1,
            "name": self.config["pack_name"] + "-similarity",
            "channel": self.config["pack_channel"],
            "license": DATA_LICENSE,
            "description": "fingerprints of attack payloads at least {} organisations' guards blocked; "
                           "a similar live call is escalated to a human".format(self.config["min_orgs"]),
            "rules": rules,
        }

    def export_indicators(self) -> Dict[str, Any]:
        """The active indicators as a policy pack for the commons to publish."""
        active = sorted(d["args_digest"] for d in self.decisions() if d["status"] == "active")
        return {
            "version": 1,
            "name": self.config["pack_name"],
            "channel": self.config["pack_channel"],
            "license": DATA_LICENSE,
            "description": "exact-match indicators: arguments that at least {} organisations' guards "
                           "blocked, as seen by the mesh consensus engine".format(self.config["min_orgs"]),
            "rules": [{
                "id": "mesh-indicators",
                "status": self.config["pack_status"],
                "detector": "mesh_indicator_guard.mesh_indicator_guard",
                "with": {"indicators": active},
                "description": "{} active indicator(s)".format(len(active)),
            }],
        }

    def export_stats(self) -> Dict[str, Any]:
        """Public statistics: how many organisations saw each rule fire, the
        indicator funnel, and demotions. Nothing per reporter, and no fire
        counts: each rule's ``verdicts`` is ``None`` because counts never reach
        consensus; they come from the aggregators' combined totals
        (:func:`interlock.mesh.aggregate.fire_totals`)."""
        now = self._now()
        decisions = self.decisions()
        funnel: Dict[str, int] = {}
        for d in decisions:
            funnel[d["status"]] = funnel.get(d["status"], 0) + 1
        campaign_funnel: Dict[str, int] = {}
        for c in self.campaign_status():
            campaign_funnel[c["status"]] = campaign_funnel.get(c["status"], 0) + 1
        demoted = self.demoted_rules()
        rules = {}
        with self._lock:
            for policy_id, rule in sorted(self.rules.items()):
                rules[policy_id] = {"orgs": len(rule["orgs"]), "verdicts": None,
                                    "demoted": policy_id in demoted,
                                    "false_positive_orgs": len(self.sightings.get(policy_id, {}).get("false_positive", [])),
                                    "last": rule["last"]}
            reporters = len(self.reporters)
        return {"generated": now, "reporters": reporters, "rejected_reports": self.rejected,
                "indicators": funnel, "campaigns": campaign_funnel,
                "samples": {p: len(v) for p, v in sorted(self.samples.items())},
                "rules": rules, "demoted_rules": sorted(demoted), "note": FIRE_COUNTS_NOTE,
                "config": {k: self.config[k] for k in ("min_orgs", "min_trust", "indicator_ttl_days", "fp_demote_orgs")}}

    # --- persistence ----------------------------------------------------------------------

    def save(self, path: str) -> None:
        with self._lock:
            state = {"version": 1, "config": self.config, "reporters": self.reporters,
                     "indicators": self.indicators, "rules": self.rules, "sightings": self.sightings,
                     "catalogs": sorted(self.catalogs), "canaries": self.canaries, "rejected": self.rejected,
                     "campaigns": self.campaigns, "samples": self.samples}
        atomic_write(path, json.dumps(state, sort_keys=True).encode("utf-8"), mode=0o600)
        with self._lock:
            self._dropped_samples.clear()

    @classmethod
    def load(cls, path: str, *, now: Callable[[], float] = time.time) -> "ConsensusEngine":
        state = json.loads(read_bounded(path, STATE_MAX).decode("utf-8"))
        engine = cls(state.get("config"), now=now)
        engine.reporters = dict(state.get("reporters", {}))
        engine.indicators = dict(state.get("indicators", {}))
        engine.rules = dict(state.get("rules", {}))
        for rule in engine.rules.values():
            if isinstance(rule, dict):
                rule.pop("verdicts", None)  # plaintext counts from an older state; the next save drops them
        engine.sightings = dict(state.get("sightings", {}))
        engine.catalogs = set(state.get("catalogs", []))
        engine.canaries = dict(state.get("canaries", {}))
        engine.rejected = int(state.get("rejected", 0))
        engine.campaigns = dict(state.get("campaigns", {}))
        engine.samples = {}
        for policy_id, bucket in dict(state.get("samples", {})).items():
            # A sample from an older state has no attestation: it is dropped, and the next save drops it.
            kept = []
            for sample in bucket if isinstance(bucket, list) else []:
                if not isinstance(sample, dict):
                    continue
                if _attested(sample):
                    kept.append(sample)
                elif isinstance(sample.get("digest"), str):
                    digest = sample["digest"].lower()
                    engine._dropped_samples[digest] = engine._dropped_samples.get(digest, 0) + 1
            if kept:
                engine.samples[policy_id] = kept
        return engine


def _attested(sample: Mapping[str, Any]) -> bool:
    try:
        check_attestation(sample.get("attestation"))
    except ReportError:
        return False
    return True

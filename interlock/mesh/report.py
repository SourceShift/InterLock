"""Reports: what a node tells the mesh about what its guard stopped.

A report is a projection of the receipts interlock already writes, and the
projection is the whole privacy story. The signed report envelope goes to the
consensus service and carries these kinds of fact and nothing else:

**Digests** (Layer 1): the SHA-256 of the arguments a rule blocked or
escalated, exactly as the receipt already stores it. A digest matches only
someone holding the identical payload, which is what an exact-match indicator
is for. Digests are never taken from rules that redact or mask (a card
number's digest is a card number), from rewrites, from monitor-mode
decisions, or from anything without a published rule id.

**Sightings**: an operator's statement that a rule is wrong here (a false
positive), so the consensus engine can demote it.

**Fingerprints** and **samples**, recorded by the mesh recorder
(:mod:`.fingerprint`) once the operator enabled them. A body that carries
samples also carries the reporter's **attestation**, the data warranty of
decision R4 and when it was given: the samples were lawfully obtained and hold
no personal data and no third party's confidential data (:data:`WARRANTY`).
:func:`build_report` will not put samples in a body without one, and
:func:`verify_report` refuses a body whose samples arrive without it.
Fingerprints and samples are CC0-1.0 (``LICENSE-DATA``).

**Counts** (Layer 0) are not part of a report. How many times each published
rule fired, per verdict, tool class, phase and hour, is a separate projection
(:func:`build_counts`) that stays on the node and leaves it only as additive
secret shares to two or more aggregators (:mod:`.aggregate`), so no single
collector, the consensus service included, learns a deployment's numbers.
:func:`sign_report` and :func:`verify_report` refuse a body that carries
counts.

Never in a report: arguments, prompts, principals, session ids, hostnames,
file paths, or the node's own policy. The reporter signs the report with an
Ed25519 key that identifies the organisation and nothing more.

**Only published rule ids are named.** A node's own policy rules carry ids of
the operator's choosing (``block-prod-db-writes``), and those ids are part of
the policy; a receipt such a rule produced contributes to no layer, and a
sighting naming one is refused. ``published`` on :func:`build_report` and
:func:`build_counts` is that set (:func:`published_rule_ids`: the detector
catalog plus the rules of the packs in the verified cache).

**A digest is only as private as its argument is hard to guess.** The
SHA-256 of ``rm -rf /`` is a known number, so a digest or fingerprint confirms
a guess to anyone who can make one. They are indicators of *attack* payloads;
for a rule whose arguments are the node's own data, they would be a way to
confirm what the node holds. That is why :data:`PRIVATE_POLICY_MARKERS` also
covers rules that watch the node's own data (egress, exfiltration, sensitive
files, authentication), not only the ones that redact.

Each kind of fact is a **layer** (:data:`LAYERS`) that leaves the node only
once the operator enabled it, and never with anything observed before the
enable (decision R3): ``enabled_since`` and ``enabled_layers`` clamp and gate
both projections, and ``interlock mesh report submit`` refuses any layer the
node's consent does not cover. ``INTERLOCK_MESH_NO_REPORT=1`` makes
:func:`submit` refuse every upload.
"""
from __future__ import annotations

import io
import json
import os
import time
import urllib.error
import urllib.request
from email.message import Message
from typing import Any, Container, Dict, FrozenSet, Iterable, List, Mapping, Optional, Sequence

from .. import __version__
from ..receipt import Receipt
from . import ed25519, reporting_killed
from ._util import atomic_write, canonical, read_bounded
from .aggregate import count_key

__all__ = [
    "REPORT_VERSION", "BUCKET_SECONDS", "MAX_DIGESTS", "LAYERS", "BASE_LAYERS", "ReportError", "ReporterKey",
    "tool_class", "build_report", "build_counts", "sign_report", "verify_report", "published_rule_ids",
    "submit", "submit_bytes", "post_bytes",
    "WARRANTY", "new_attestation", "check_attestation",
]

REPORT_VERSION = 1
BUCKET_SECONDS = 3600
MAX_DIGESTS = 500
MAX_ENVELOPE = 2 * 1024 * 1024

#: What a node can report, each enabled on its own (decision R3).
LAYERS = ("counts", "sightings", "digests", "fingerprints", "samples")
#: The layers a bare ``interlock mesh report enable`` turns on.
BASE_LAYERS = ("counts", "sightings")

#: A rule whose id contains one of these saw the node's own data rather than an
#: attacker's payload: it redacts or masks (the digest of what it saw is the
#: secret itself), or it watches secrets, egress, exfiltration, sensitive files
#: or authentication. Such receipts never contribute digests, fingerprints or
#: samples; they still count.
PRIVATE_POLICY_MARKERS = ("redact", "pii", "secret", "mask", "credential", "canary", "token", "_key",
                          "sensitive", "egress", "exfil", "leak", "auth", "password", "private", "uri")

_SHELL = ("bash", "shell", "sh", "exec", "execute", "run", "command", "subprocess", "terminal", "powershell")
_READ = ("read", "cat", "glob", "grep", "search", "list", "ls", "find", "stat", "view", "open")
_WRITE = ("write", "edit", "patch", "notebook", "create", "save", "append", "delete", "remove", "move", "rename", "mkdir")
_HTTP = ("http", "fetch", "request", "url", "web", "curl", "browse", "download", "upload", "post", "get_page")
_DB = ("sql", "query", "db", "database", "table", "postgres", "mysql", "sqlite")
_MESSAGE = ("email", "mail", "slack", "message", "send", "notify", "sms", "chat", "post_to")
_PAY = ("pay", "payment", "transfer", "charge", "refund", "invoice", "order")


class ReportError(ValueError):
    """A report that cannot be built, signed or trusted."""


#: What a reporter warrants about every sample it shares (decision R4,
#: CONTRIBUTING.md): lawfully obtained, no personal data, no third party's
#: confidential data. ``interlock mesh report enable --sample RULE`` records it
#: only with ``--i-warrant-samples``.
WARRANTY = "lawful,no-personal-data,no-confidential"


def new_attestation(at: Optional[float] = None) -> Dict[str, Any]:
    """The data warranty, given now (or at ``at``)."""
    return {"warranty": WARRANTY, "at": float(time.time() if at is None else at)}


def check_attestation(value: Any) -> Dict[str, Any]:
    """Return ``value`` as ``{"warranty", "at"}`` if it is the data warranty,
    or raise :class:`ReportError`."""
    if (not isinstance(value, Mapping) or value.get("warranty") != WARRANTY
            or not isinstance(value.get("at"), (int, float)) or isinstance(value.get("at"), bool)
            or value["at"] <= 0):
        raise ReportError("samples need the reporter's attestation (warranty {}: lawfully obtained, no personal "
                          "data, no third party's confidential data)".format(WARRANTY))
    return {"warranty": WARRANTY, "at": float(value["at"])}


def tool_class(action: Any) -> str:
    """A coarse, non-identifying class for a tool name.

    Keeps the mesh from learning a deployment's tool names while still letting
    it say "shell commands" or "HTTP calls". Unknown names fall into ``other``.
    """
    if not isinstance(action, str) or not action:
        return "other"
    name = action.lower()
    if name.startswith("mcp__") or name.startswith("mcp_") or name.startswith("mcp."):
        return "mcp"
    parts = [p for p in name.replace(".", "_").replace("-", "_").replace("/", "_").split("_") if p]
    tokens = set(parts) | {name}
    for group, label in ((_SHELL, "shell"), (_PAY, "payment"), (_DB, "database"), (_MESSAGE, "message"),
                         (_HTTP, "http"), (_WRITE, "file.write"), (_READ, "file.read")):
        if any(t in group for t in tokens) or any(name.startswith(g) for g in group):
            return label
    return "other"


class ReporterKey:
    """The organisation's reporting identity: an Ed25519 seed on disk (0600)."""

    def __init__(self, seed: bytes) -> None:
        if len(seed) != ed25519.KEY_SIZE:
            raise ReportError("a reporter key is 32 bytes")
        self.seed = seed
        self.public = ed25519.public_key(seed)
        self.keyid = ed25519.keyid(self.public)

    @classmethod
    def load_or_create(cls, path: str) -> "ReporterKey":
        if os.path.exists(path):
            try:
                record = json.loads(read_bounded(path, 4096).decode("utf-8"))
                return cls(bytes.fromhex(record["seed"]))
            except (ValueError, KeyError, TypeError) as exc:
                raise ReportError("{}: not a reporter key: {}".format(path, exc))
        key = cls(ed25519.generate_seed())
        atomic_write(path, json.dumps({"version": 1, "keytype": "ed25519", "seed": key.seed.hex(),
                                       "public": key.public.hex(), "keyid": key.keyid}, indent=1).encode("utf-8"),
                     mode=0o600)
        return key

    def sign(self, message: bytes) -> bytes:
        return ed25519.sign(self.seed, message)


def _private_rule(policy_id: str) -> bool:
    lowered = policy_id.lower()
    return any(marker in lowered for marker in PRIVATE_POLICY_MARKERS)


def _publishable(policy_id: Any, published: Optional[Container[str]]) -> bool:
    """Whether a report may name ``policy_id``: always when no set is given
    (the library caller's choice), else only a published id."""
    return published is None or policy_id in published


def published_rule_ids(subscriber: Any = None) -> FrozenSet[str]:
    """Every rule id a report may name: the installed detectors (module name
    and ``POLICY_ID``) and the rule ids of the packs in ``subscriber``'s
    verified cache (an :class:`interlock.mesh.subscriber.Subscriber`). Nothing
    the operator wrote: a local rule id is policy, and policy never leaves."""
    import importlib

    from .catalog import catalog_entries

    ids = set()
    for name, _ in catalog_entries():
        module = name[:-3]
        if module.startswith("_"):
            continue
        ids.add(module)
        try:
            policy_id = getattr(importlib.import_module("interlock.detectors." + module), "POLICY_ID", None)
        except Exception:  # a detector that does not import stands alone; the name is still its id
            continue
        if isinstance(policy_id, str) and policy_id:
            ids.add(policy_id)
    if subscriber is not None:
        try:
            ids.update(subscriber.cached_rule_ids())
        except Exception:  # no commons, or a cache that does not verify: only the detectors are published
            pass
    return frozenset(ids)


MAX_FINGERPRINTS = 500
MAX_SAMPLES = 20
MAX_SAMPLE_TEXT = 4096
FINGERPRINT_HEX = 192  # 96 bytes


def _counted(r: Receipt, since: float, until: float) -> bool:
    """Whether a receipt is a rule firing a report projects (counts and digests alike)."""
    if not (since <= r.ts < until):
        return False
    if r.action == "receipts.dropped" or r.phase not in ("call", "result"):
        return False
    return not (r.observed or r.verdict == "ALLOW" or not r.policy_id)


def _bucket(ts: float) -> int:
    return int(ts // BUCKET_SECONDS) * BUCKET_SECONDS


def _clamp(since: float, enabled_since: Optional[float]) -> float:
    """Never retroactive: a window never opens before the enable."""
    return since if enabled_since is None else max(float(since), float(enabled_since))


def _enabled(layer: str, enabled_layers: Optional[Sequence[str]]) -> bool:
    return enabled_layers is None or layer in enabled_layers


def _after(record: Mapping[str, Any], since: float) -> bool:
    ts = record.get("ts")
    return isinstance(ts, (int, float)) and not isinstance(ts, bool) and ts >= since


def build_counts(receipts: Iterable[Receipt], since: float, until: float, *,
                 enabled_since: Optional[float] = None,
                 enabled_layers: Optional[Sequence[str]] = None,
                 published: Optional[Container[str]] = None) -> Dict[str, int]:
    """Project receipts in ``[since, until)`` into ``{count_key: n}``: how often
    each rule fired, per verdict, tool class, phase and hour.

    The vector is not part of the report. It stays on the node and is sent
    only as secret shares (:func:`interlock.mesh.aggregate.encode_counts`).
    ``enabled_since`` clamps ``since`` to the operator's enable, and
    ``enabled_layers`` without ``"counts"`` projects nothing; left out, both
    project everything (the local preview). ``published`` keeps only the rule
    ids a report may name; left out, every id counts (a library caller)."""
    since = _clamp(since, enabled_since)
    if not _enabled("counts", enabled_layers):
        return {}
    counts: Dict[str, int] = {}
    for r in receipts:
        if not _counted(r, since, until) or not _publishable(r.policy_id, published):
            continue
        key = count_key(r.policy_id, r.verdict, tool_class(r.action), r.phase, _bucket(r.ts))
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def build_report(receipts: Iterable[Receipt], *, since: float, until: float, catalog_id: str,
                 reporter_id: str, include_digests: bool = True, max_digests: int = MAX_DIGESTS,
                 sightings: Sequence[Mapping[str, Any]] = (),
                 fingerprints: Sequence[Mapping[str, Any]] = (),
                 samples: Sequence[Mapping[str, Any]] = (),
                 enabled_since: Optional[float] = None,
                 enabled_layers: Optional[Sequence[str]] = None,
                 attestation: Optional[Mapping[str, Any]] = None,
                 published: Optional[Container[str]] = None) -> Dict[str, Any]:
    """Project receipts in ``[since, until)`` into an unsigned report body.

    ``published`` is the set of rule ids the body may name
    (:func:`published_rule_ids`): receipts, fingerprints and samples from any
    other id are left out, and a sighting naming one raises
    :class:`ReportError`. Left out, every id passes (a library caller).

    The body carries no counts; :func:`build_counts` projects those separately.
    ``fingerprints`` and ``samples`` come from the mesh recorder
    (:class:`interlock.mesh.fingerprint.Recorder`), which saw the arguments at
    decision time; they are passed through with caps and shape checks. A body
    with samples carries ``attestation`` (see :func:`check_attestation`), and
    samples without one raise :class:`ReportError`.

    ``enabled_since`` (the operator's enable timestamp) clamps ``since``, and
    then fingerprints and samples without a ``ts`` at or after it are left out
    too. ``enabled_layers`` keeps only the digests, sightings, fingerprints and
    samples whose layer it names. Left out, both project everything: the local
    preview ``interlock mesh report build`` shows before any enable.
    """
    since = _clamp(since, enabled_since)
    include_digests = include_digests and _enabled("digests", enabled_layers)
    if not _enabled("sightings", enabled_layers):
        sightings = ()
    if not _enabled("fingerprints", enabled_layers):
        fingerprints = ()
    if not _enabled("samples", enabled_layers):
        samples = ()
    if enabled_since is not None:
        fingerprints = [f for f in fingerprints if _after(f, since)]
        samples = [s for s in samples if _after(s, since)]
    digests: List[Dict[str, Any]] = []
    seen_digests = set()
    for r in receipts:
        if not include_digests or len(digests) >= max_digests:
            break
        if not _counted(r, since, until) or not _publishable(r.policy_id, published):
            continue
        if r.verdict not in ("BLOCK", "ESCALATE") or r.masked or _private_rule(r.policy_id):
            continue
        if not r.args_digest or len(r.args_digest) != 64:
            continue
        dedupe = (r.policy_id, r.args_digest)
        if dedupe in seen_digests:
            continue
        seen_digests.add(dedupe)
        digests.append({"policy_id": r.policy_id, "args_digest": r.args_digest,
                        "tool_class": tool_class(r.action), "bucket": _bucket(r.ts)})
    digests.sort(key=lambda d: (d["bucket"], d["policy_id"], d["args_digest"]))
    clean_sightings = []
    for s in sightings:
        policy_id = s.get("policy_id")
        if not isinstance(policy_id, str) or not policy_id:
            raise ReportError("a sighting needs a policy_id")
        if not _publishable(policy_id, published):
            raise ReportError("sighting names {!r}, which is not a published rule: a report names only "
                              "detector and mesh pack rule ids, never a rule of your own".format(policy_id))
        clean_sightings.append({"policy_id": policy_id, "kind": str(s.get("kind", "false_positive")),
                                "n": int(s.get("n", 1))})
    clean_fps: List[Dict[str, Any]] = []
    for f in fingerprints:
        fp_hex = f.get("fp")
        policy_id = f.get("policy_id")
        if not isinstance(fp_hex, str) or len(fp_hex) != FINGERPRINT_HEX or not isinstance(policy_id, str):
            continue
        if _private_rule(policy_id) or not _publishable(policy_id, published):
            continue
        ts = f.get("ts", since)
        clean_fps.append({"policy_id": policy_id, "fp": fp_hex.lower(), "alpha": float(f.get("alpha", 1.5)),
                          "tool_class": str(f.get("tool_class", "other")),
                          "bucket": int(float(ts) // BUCKET_SECONDS) * BUCKET_SECONDS if isinstance(ts, (int, float)) else 0})
        if len(clean_fps) >= MAX_FINGERPRINTS:
            break
    clean_samples: List[Dict[str, Any]] = []
    for s in samples:
        text = s.get("text")
        policy_id = s.get("policy_id")
        if not isinstance(text, str) or not text or not isinstance(policy_id, str) or _private_rule(policy_id):
            continue
        if not _publishable(policy_id, published):
            continue
        names = [n for n in (s.get("arg_names") or []) if isinstance(n, str)][:8]
        clean_samples.append({"policy_id": policy_id, "tool_class": str(s.get("tool_class", "other")),
                              "text": text[:MAX_SAMPLE_TEXT], "arg_names": names})
        if len(clean_samples) >= MAX_SAMPLES:
            break
    body: Dict[str, Any] = {
        "version": REPORT_VERSION,
        "reporter": reporter_id,
        "catalog": catalog_id,
        "interlock": __version__,
        "period": {"since": since, "until": until},
        "digests": digests,
        "sightings": clean_sightings,
        "fingerprints": clean_fps,
        "samples": clean_samples,
    }
    if clean_samples:
        body["attestation"] = check_attestation(attestation)
    return body


_COUNTS_REFUSED = ("report field 'counts' is not allowed: counts leave a node only as secret shares "
                   "to the aggregators, never in the report envelope")


def sign_report(body: Mapping[str, Any], key: ReporterKey,
                credential: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Sign ``body`` into an envelope; ``credential`` (a membership certificate
    for this key, see :mod:`.credential`) rides alongside when the collectors
    require one."""
    if body.get("reporter") != key.keyid:
        raise ReportError("the report names a different reporter than the signing key")
    if "counts" in body:
        raise ReportError(_COUNTS_REFUSED)
    payload = canonical(body)
    envelope = {"report": dict(body), "public": key.public.hex(), "signature": key.sign(payload).hex()}
    if credential is not None:
        envelope["credential"] = dict(credential)
    return envelope


def verify_report(envelope: Any, *, max_bytes: int = MAX_ENVELOPE) -> Dict[str, Any]:
    """Return the report body if the envelope is well-formed and its signature
    verifies under the public key it carries (whose id the body names)."""
    if not isinstance(envelope, dict):
        raise ReportError("a report envelope is a JSON object")
    body = envelope.get("report")
    if not isinstance(body, dict) or body.get("version") != REPORT_VERSION:
        raise ReportError("unsupported or missing report body")
    if "counts" in body:
        raise ReportError(_COUNTS_REFUSED)
    try:
        public = bytes.fromhex(envelope.get("public", ""))
        signature = bytes.fromhex(envelope.get("signature", ""))
    except (ValueError, TypeError):
        raise ReportError("public key or signature is not hex")
    if len(public) != ed25519.KEY_SIZE or len(signature) != ed25519.SIGNATURE_SIZE:
        raise ReportError("public key or signature has the wrong size")
    if body.get("reporter") != ed25519.keyid(public):
        raise ReportError("the report names a reporter other than its signing key")
    payload = canonical(body)
    if len(payload) > max_bytes:
        raise ReportError("report exceeds {} bytes".format(max_bytes))
    if not ed25519.verify(public, payload, signature):
        raise ReportError("report signature does not verify")
    for field in ("digests", "sightings"):
        if not isinstance(body.get(field), list):
            raise ReportError("report field {!r} must be a list".format(field))
    if not isinstance(body.get("catalog"), str) or not isinstance(body.get("period"), dict):
        raise ReportError("report lacks catalog or period")
    for d in body["digests"]:
        if (not isinstance(d, dict) or not isinstance(d.get("policy_id"), str)
                or not isinstance(d.get("args_digest"), str) or len(d["args_digest"]) != 64):
            raise ReportError("malformed digest entry")
    for s in body["sightings"]:
        if not isinstance(s, dict) or not isinstance(s.get("policy_id"), str) or not s["policy_id"]:
            raise ReportError("malformed sighting entry")
    for f in body.get("fingerprints", []):
        if (not isinstance(f, dict) or not isinstance(f.get("policy_id"), str)
                or not isinstance(f.get("fp"), str) or len(f["fp"]) != FINGERPRINT_HEX
                or not isinstance(f.get("alpha"), (int, float)) or f["alpha"] <= 0):
            raise ReportError("malformed fingerprint entry")
    for s in body.get("samples", []):
        if (not isinstance(s, dict) or not isinstance(s.get("policy_id"), str)
                or not isinstance(s.get("text"), str) or len(s["text"]) > MAX_SAMPLE_TEXT):
            raise ReportError("malformed sample entry")
    if body.get("samples") or "attestation" in body:
        check_attestation(body.get("attestation"))
    return body


def post_bytes(url: str, data: bytes, content_type: str, *, token: Optional[str] = None,
               timeout: float = 30.0, max_reply: int = 8 * 1024 * 1024) -> tuple:
    """POST raw bytes and return ``(status, content_type, body)``.

    HTTP error statuses are returned rather than raised, because DAP reports
    them in a problem document the caller should be able to print. This does
    *not* consult the kill switch; it is also used for aggregator-to-aggregator
    traffic, which carries no counts. A node's own uploads go through
    :func:`submit_bytes`."""
    headers = {"Content-Type": content_type, "User-Agent": "interlock-mesh"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, data=bytes(data), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.status, _reply_type(response.headers), response.read(max_reply)
    except urllib.error.HTTPError as exc:
        return exc.code, _reply_type(exc.headers), exc.read(max_reply)


def _reply_type(headers) -> str:
    """The reply's media type, keeping DAP's ``message`` parameter.

    ``HTTPMessage.get_content_type()`` answers only ``application/ppm-dap``, but
    DAP distinguishes an empty success upload from ``upload-errors`` (and every
    other message) by that parameter, so it must survive.
    """
    value = headers.get("Content-Type", "")
    parts = [part.strip() for part in value.split(";") if part.strip()]
    if not parts:
        return ""
    kind = parts[0].lower()
    params = [part for part in parts[1:] if part.lower().startswith("message=")]
    return ";".join([kind] + params)


def submit_bytes(url: str, data: bytes, content_type: str, *, token: Optional[str] = None,
                 timeout: float = 30.0) -> tuple:
    """A node's own upload: the kill switch applies before any connection.

    With ``INTERLOCK_MESH_NO_REPORT=1`` this raises :class:`ReportError` without
    reaching the network, whichever transport the caller is using."""
    if reporting_killed():
        raise ReportError("INTERLOCK_MESH_NO_REPORT is set: every mesh upload is refused on this node")
    return post_bytes(url, data, content_type, token=token, timeout=timeout)


def submit(url: str, payload: Mapping[str, Any], *, token: Optional[str] = None,
           timeout: float = 10.0) -> Dict[str, Any]:
    """POST a JSON payload and return the JSON reply.

    An HTTP error status raises :class:`urllib.error.HTTPError` (an ``OSError``)
    carrying the reply body, which is what this function always did; the binary
    DAP transport returns the status instead and its callers read the problem
    document themselves."""
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    status, _, raw = submit_bytes(url, data, "application/json", token=token, timeout=timeout)
    if status >= 400:
        raise urllib.error.HTTPError(
            url, status, "HTTP {}".format(status), Message(), io.BytesIO(raw))
    try:
        reply = json.loads(raw.decode("utf-8"))
    except ValueError:
        raise OSError("{}: reply is not JSON".format(url))
    return reply if isinstance(reply, dict) else {"reply": reply}


def default_since_until(now: Optional[float] = None, hours: float = 24.0) -> tuple:
    now = time.time() if now is None else now
    return now - hours * 3600, now

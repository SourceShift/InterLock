"""Reports: what a node tells the mesh about what its guard stopped.

A report is a projection of the receipts interlock already writes, and the
projection is the whole privacy story. It carries three kinds of fact and
nothing else:

**Counts** (Layer 0): how many times each published rule fired, per verdict,
tool class, phase and hour. Counts leave the node as additive secret shares
(:mod:`.aggregate`), so no single collector learns a deployment's numbers.

**Digests** (Layer 1): the SHA-256 of the arguments a rule blocked or
escalated, exactly as the receipt already stores it. A digest matches only
someone holding the identical payload, which is what an exact-match indicator
is for. Digests are never taken from rules that redact or mask (a card
number's digest is a card number), from rewrites, from monitor-mode
decisions, or from anything without a published rule id.

**Sightings**: an operator's statement that a rule is wrong here (a false
positive), so the consensus engine can demote it.

Never in a report: arguments, prompts, principals, session ids, hostnames,
file paths, or the node's own policy. The reporter signs the report with an
Ed25519 key that identifies the organisation and nothing more.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence

from .. import __version__
from ..receipt import Receipt
from . import ed25519
from ._util import atomic_write, canonical, read_bounded

__all__ = [
    "REPORT_VERSION", "BUCKET_SECONDS", "MAX_DIGESTS", "ReportError", "ReporterKey", "tool_class",
    "build_report", "sign_report", "verify_report", "submit",
]

REPORT_VERSION = 1
BUCKET_SECONDS = 3600
MAX_DIGESTS = 500
MAX_ENVELOPE = 2 * 1024 * 1024

#: A rule whose id contains one of these redacts or masks; the digest of what
#: it saw is the secret itself, so such receipts never contribute digests.
PRIVATE_POLICY_MARKERS = ("redact", "pii", "secret", "mask", "credential", "canary", "token", "_key")

_SHELL = ("bash", "shell", "sh", "exec", "execute", "run", "command", "subprocess", "terminal", "powershell")
_READ = ("read", "cat", "glob", "grep", "search", "list", "ls", "find", "stat", "view", "open")
_WRITE = ("write", "edit", "patch", "notebook", "create", "save", "append", "delete", "remove", "move", "rename", "mkdir")
_HTTP = ("http", "fetch", "request", "url", "web", "curl", "browse", "download", "upload", "post", "get_page")
_DB = ("sql", "query", "db", "database", "table", "postgres", "mysql", "sqlite")
_MESSAGE = ("email", "mail", "slack", "message", "send", "notify", "sms", "chat", "post_to")
_PAY = ("pay", "payment", "transfer", "charge", "refund", "invoice", "order")


class ReportError(ValueError):
    """A report that cannot be built, signed or trusted."""


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


MAX_FINGERPRINTS = 500
MAX_SAMPLES = 20
MAX_SAMPLE_TEXT = 4096
FINGERPRINT_HEX = 192  # 96 bytes


def build_report(receipts: Iterable[Receipt], *, since: float, until: float, catalog_id: str,
                 reporter_id: str, include_digests: bool = True, max_digests: int = MAX_DIGESTS,
                 sightings: Sequence[Mapping[str, Any]] = (),
                 fingerprints: Sequence[Mapping[str, Any]] = (),
                 samples: Sequence[Mapping[str, Any]] = ()) -> Dict[str, Any]:
    """Project receipts in ``[since, until)`` into an unsigned report body.

    ``fingerprints`` and ``samples`` come from the mesh recorder
    (:class:`interlock.mesh.fingerprint.Recorder`), which saw the arguments at
    decision time; they are passed through with caps and shape checks.
    """
    counts: Dict[tuple, int] = {}
    digests: List[Dict[str, Any]] = []
    seen_digests = set()
    for r in receipts:
        if not (since <= r.ts < until):
            continue
        if r.action == "receipts.dropped" or r.phase not in ("call", "result"):
            continue
        if r.observed or r.verdict == "ALLOW" or not r.policy_id:
            continue
        bucket = int(r.ts // BUCKET_SECONDS) * BUCKET_SECONDS
        klass = tool_class(r.action)
        key = (r.policy_id, r.verdict, klass, r.phase, bucket)
        counts[key] = counts.get(key, 0) + 1
        if not include_digests or len(digests) >= max_digests:
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
                        "tool_class": klass, "bucket": bucket})
    rows = [{"policy_id": k[0], "verdict": k[1], "tool_class": k[2], "phase": k[3], "bucket": k[4], "n": n}
            for k, n in counts.items()]
    rows.sort(key=lambda row: (row["bucket"], row["policy_id"], row["verdict"], row["tool_class"], row["phase"]))
    digests.sort(key=lambda d: (d["bucket"], d["policy_id"], d["args_digest"]))
    clean_sightings = []
    for s in sightings:
        policy_id = s.get("policy_id")
        if not isinstance(policy_id, str) or not policy_id:
            raise ReportError("a sighting needs a policy_id")
        clean_sightings.append({"policy_id": policy_id, "kind": str(s.get("kind", "false_positive")),
                                "n": int(s.get("n", 1))})
    clean_fps: List[Dict[str, Any]] = []
    for f in fingerprints:
        fp_hex = f.get("fp")
        policy_id = f.get("policy_id")
        if not isinstance(fp_hex, str) or len(fp_hex) != FINGERPRINT_HEX or not isinstance(policy_id, str):
            continue
        if _private_rule(policy_id):
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
        names = [n for n in (s.get("arg_names") or []) if isinstance(n, str)][:8]
        clean_samples.append({"policy_id": policy_id, "tool_class": str(s.get("tool_class", "other")),
                              "text": text[:MAX_SAMPLE_TEXT], "arg_names": names})
        if len(clean_samples) >= MAX_SAMPLES:
            break
    return {
        "version": REPORT_VERSION,
        "reporter": reporter_id,
        "catalog": catalog_id,
        "interlock": __version__,
        "period": {"since": since, "until": until},
        "counts": rows,
        "digests": digests,
        "sightings": clean_sightings,
        "fingerprints": clean_fps,
        "samples": clean_samples,
    }


def sign_report(body: Mapping[str, Any], key: ReporterKey,
                credential: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
    """Sign ``body`` into an envelope; ``credential`` (a membership certificate
    for this key, see :mod:`.credential`) rides alongside when the collectors
    require one."""
    if body.get("reporter") != key.keyid:
        raise ReportError("the report names a different reporter than the signing key")
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
    for field in ("counts", "digests", "sightings"):
        if not isinstance(body.get(field), list):
            raise ReportError("report field {!r} must be a list".format(field))
    if not isinstance(body.get("catalog"), str) or not isinstance(body.get("period"), dict):
        raise ReportError("report lacks catalog or period")
    for d in body["digests"]:
        if (not isinstance(d, dict) or not isinstance(d.get("policy_id"), str)
                or not isinstance(d.get("args_digest"), str) or len(d["args_digest"]) != 64):
            raise ReportError("malformed digest entry")
    for c in body["counts"]:
        if not isinstance(c, dict) or not isinstance(c.get("n"), int) or c["n"] < 0:
            raise ReportError("malformed count entry")
    for f in body.get("fingerprints", []):
        if (not isinstance(f, dict) or not isinstance(f.get("policy_id"), str)
                or not isinstance(f.get("fp"), str) or len(f["fp"]) != FINGERPRINT_HEX
                or not isinstance(f.get("alpha"), (int, float)) or f["alpha"] <= 0):
            raise ReportError("malformed fingerprint entry")
    for s in body.get("samples", []):
        if (not isinstance(s, dict) or not isinstance(s.get("policy_id"), str)
                or not isinstance(s.get("text"), str) or len(s["text"]) > MAX_SAMPLE_TEXT):
            raise ReportError("malformed sample entry")
    return body


def submit(url: str, payload: Mapping[str, Any], *, token: Optional[str] = None,
           timeout: float = 10.0) -> Dict[str, Any]:
    """POST a JSON payload and return the JSON reply (or raise ``OSError``)."""
    data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    headers = {"Content-Type": "application/json", "User-Agent": "interlock-mesh"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        raw = response.read(1024 * 1024)
    try:
        reply = json.loads(raw.decode("utf-8"))
    except ValueError:
        raise OSError("{}: reply is not JSON".format(url))
    return reply if isinstance(reply, dict) else {"reply": reply}


def default_since_until(now: Optional[float] = None, hours: float = 24.0) -> tuple:
    now = time.time() if now is None else now
    return now - hours * 3600, now

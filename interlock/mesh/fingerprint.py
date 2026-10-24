"""Private fingerprints: "find similar" across organisations without sharing text.

An exact digest (Layer 1) matches only the identical payload. Attacks arrive
paraphrased, so the mesh also shares a **fingerprint** built the way
BinaryShield (SaTML 2026) builds one, inside the reporting node:

1. **redact**: strip what a redactor would, emails, card-shaped numbers,
   tokens, IPs, home directories;
2. **embed**: a 768-dimensional signed vector. By default a lexical embedding
   (feature hashing of character and word n-grams, the SimHash family), which
   needs no model and catches re-spellings and partial edits; a semantic
   embedder can be plugged in through ``embedder=`` to catch paraphrases;
3. **quantise**: keep each dimension's sign, one bit each, 96 bytes;
4. **randomised response**: flip every bit independently with probability
   ``p = 1 / (1 + e^alpha)``. This is local differential privacy with budget
   ``alpha`` per fingerprint: whatever anyone later learns, every bit had a
   calibrated chance of being a lie, and the text cannot be reconstructed.

Matching is Hamming distance. Two fingerprints of the *same* text differ in
about ``2p(1-p)`` of their bits when both are noised, ``p`` when one side is
clean (a node comparing live traffic against published fingerprints), and in
half of them when unrelated. :func:`threshold` sits between those expectations,
so ``alpha`` trades privacy for match quality the way the paper measures:
smaller ``alpha`` is more private and misses more variants.

Raw embeddings are never shared: text can be reconstructed from them.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from ._util import atomic_write

__all__ = ["DIM", "DEFAULT_ALPHA", "redact", "embed", "quantize", "randomize", "fingerprint", "hamming",
           "flip_probability", "threshold", "similar", "cluster", "text_of_args", "Recorder"]

DIM = 768
BYTES = DIM // 8
DEFAULT_ALPHA = 1.5
MAX_TEXT = 16 * 1024
MAX_SAMPLE = 4 * 1024

_REDACTIONS: Sequence[Tuple[re.Pattern, str]] = (
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "<email>"),
    (re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"), "<number>"),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "<ip>"),
    (re.compile(r"\b(?:bearer|token|apikey|api_key|secret|password|passwd|pwd)\s*[:=]\s*\S+", re.I), "<credential>"),
    (re.compile(r"\b[A-Fa-f0-9]{32,}\b"), "<hex>"),
    (re.compile(r"\b[A-Za-z0-9+/=_-]{32,}\b"), "<token>"),
    (re.compile(r"/(?:Users|home)/[^/\s]+"), "/<home>"),
    (re.compile(r"\b\+?\d[\d\s().-]{8,}\d\b"), "<number>"),
)

_PRIVATE_MARKERS = ("redact", "pii", "secret", "mask", "credential", "canary", "token", "_key")


def redact(text: str) -> str:
    """Remove the identifying shapes a redactor would, keeping the attack's structure."""
    out = text[:MAX_TEXT]
    for pattern, replacement in _REDACTIONS:
        out = pattern.sub(replacement, out)
    return out


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


#: The most features one text contributes. Longer texts are sampled by keeping
#: the features with the smallest hashes, which similar texts mostly share, so
#: the cost of a fingerprint is bounded and sampling does not break matching.
MAX_FEATURES = 512
_SIGNS = [tuple(1 if (byte >> k) & 1 else -1 for k in range(8)) for byte in range(256)]


def _features(text: str) -> Iterable[str]:
    norm = _normalize(text)
    for i in range(max(0, len(norm) - 3)):
        yield "c4:" + norm[i:i + 4]
    words = norm.split(" ")
    for w in words:
        yield "w1:" + w
    for i in range(len(words) - 1):
        yield "w2:{} {}".format(words[i], words[i + 1])


def embed(text: str) -> List[int]:
    """The default lexical embedding: SimHash over character 4-grams and word
    uni- and bigrams. Every feature contributes a hashed ±1 to *every*
    dimension, so the vector is dense and unrelated texts land about half the
    bits apart; a sparse feature-hash would leave empty dimensions agreeing by
    default and make strangers look alike."""
    hashed = sorted((hashlib.blake2b(f.encode("utf-8"), digest_size=8).digest(), f) for f in _features(text))
    counts = [0] * DIM
    for _, feature in hashed[:MAX_FEATURES]:
        key = feature.encode("utf-8")
        signs = (hashlib.blake2b(key, digest_size=64).digest()
                 + hashlib.blake2b(key, digest_size=32, person=b"il-mesh-simhash").digest())
        for i in range(BYTES):
            s = _SIGNS[signs[i]]
            base = i * 8
            counts[base] += s[0]
            counts[base + 1] += s[1]
            counts[base + 2] += s[2]
            counts[base + 3] += s[3]
            counts[base + 4] += s[4]
            counts[base + 5] += s[5]
            counts[base + 6] += s[6]
            counts[base + 7] += s[7]
    return counts


def _project(vector: Sequence[float]) -> List[float]:
    """Fold a vector of any length into DIM dimensions with hashed signs, so a
    plugged-in embedder need not be 768-dimensional."""
    if len(vector) == DIM:
        return [float(v) for v in vector]
    out = [0.0] * DIM
    for j, value in enumerate(vector):
        digest = hashlib.blake2b(str(j).encode("ascii"), digest_size=8).digest()
        h = int.from_bytes(digest, "little")
        out[h % DIM] += float(value) * (1.0 if (h >> 63) & 1 else -1.0)
    return out


def quantize(vector: Sequence[float]) -> bytes:
    """One bit per dimension: 1 where the component is positive."""
    if len(vector) != DIM:
        vector = _project(vector)
    bits = 0
    for i, value in enumerate(vector):
        if value > 0:
            bits |= 1 << i
    return bits.to_bytes(BYTES, "little")


def flip_probability(alpha: float) -> float:
    if alpha <= 0:
        raise ValueError("alpha must be positive")
    return 1.0 / (1.0 + math.exp(alpha))


def randomize(bits: bytes, alpha: float, rng: Optional[Callable[[int], int]] = None) -> bytes:
    """Randomised response: flip each bit with probability :func:`flip_probability`."""
    if len(bits) != BYTES:
        raise ValueError("a fingerprint is {} bytes".format(BYTES))
    p = flip_probability(alpha)
    draw = rng or (lambda n: secrets.randbelow(n))
    scale = 1 << 32
    cutoff = int(p * scale)
    value = int.from_bytes(bits, "little")
    for i in range(DIM):
        if draw(scale) < cutoff:
            value ^= 1 << i
    return value.to_bytes(BYTES, "little")


def fingerprint(text: str, alpha: Optional[float] = DEFAULT_ALPHA,
                embedder: Optional[Callable[[str], Sequence[float]]] = None,
                rng: Optional[Callable[[int], int]] = None) -> bytes:
    """Redact, embed, quantise and (unless ``alpha`` is None) randomise ``text``.

    ``alpha=None`` yields the clean fingerprint a node computes for its own live
    traffic when matching against published, noised fingerprints. ``rng`` is
    the noise source, ``secrets`` by default; tests pass a seeded one.
    """
    clean = redact(text)
    vector = embedder(clean) if embedder is not None else embed(clean)
    bits = quantize(vector)
    return bits if alpha is None else randomize(bits, alpha, rng)


def hamming(a: bytes, b: bytes) -> int:
    if len(a) != len(b):
        raise ValueError("fingerprints differ in length")
    return bin(int.from_bytes(a, "little") ^ int.from_bytes(b, "little")).count("1")


def threshold(alpha: float, *, both_noisy: bool = False) -> int:
    """The Hamming distance below which two fingerprints are called similar:
    halfway between the expected distance for the same text and for unrelated text."""
    p = flip_probability(alpha)
    same = DIM * (2 * p * (1 - p) if both_noisy else p)
    return int((same + DIM / 2) / 2)


def similar(a: bytes, b: bytes, alpha: float, *, both_noisy: bool = False) -> bool:
    return hamming(a, b) <= threshold(alpha, both_noisy=both_noisy)


def cluster(items: Sequence[Tuple[Any, bytes]], alpha: float) -> List[List[Any]]:
    """Greedy single-link clustering of ``(id, fingerprint)`` pairs, both noised."""
    limit = threshold(alpha, both_noisy=True)
    groups: List[List[Any]] = []
    centres: List[bytes] = []
    for item_id, fp in items:
        for index, centre in enumerate(centres):
            if hamming(fp, centre) <= limit:
                groups[index].append(item_id)
                break
        else:
            groups.append([item_id])
            centres.append(fp)
    return groups


def text_of_args(args: Any) -> str:
    """The string content of a call's arguments, keys sorted, capped."""
    if not isinstance(args, dict):
        return ""
    parts: List[str] = []
    for key in sorted(args, key=str):
        value = args[key]
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, (list, tuple)):
            parts.extend(v for v in value if isinstance(v, str))
        elif isinstance(value, dict):
            parts.append(text_of_args(value))
    return "\n".join(p for p in parts if p)[:MAX_TEXT]


class Recorder:
    """A decision observer that records fingerprints (and, for rules the
    operator opted in, redacted samples) of what the guard blocked or
    escalated, for the next ``interlock mesh report build``.

    Installed through :func:`interlock.receipt.add_decision_observer`. It never
    raises, never records allowed calls, monitor-mode decisions or anything a
    redacting rule saw, and caps every text it keeps.
    """

    def __init__(self, directory: str, *, alpha: float = DEFAULT_ALPHA,
                 sample_rules: Iterable[str] = (), embedder: Optional[Callable[[str], Sequence[float]]] = None,
                 now: Callable[[], float] = time.time) -> None:
        self.directory = directory
        self.alpha = float(alpha)
        self.sample_rules = frozenset(sample_rules)
        self.embedder = embedder
        self._now = now
        self.path = os.path.join(directory, "fingerprints.jsonl")
        self.samples_path = os.path.join(directory, "samples.jsonl")

    def __call__(self, event: Any, decision: Any, receipt: Any) -> None:
        try:
            verdict = getattr(decision.verdict, "name", str(decision.verdict))
            policy_id = getattr(decision, "policy_id", None) or getattr(receipt, "policy_id", None)
            if verdict not in ("BLOCK", "ESCALATE") or not policy_id or getattr(receipt, "observed", False):
                return
            if any(m in policy_id.lower() for m in _PRIVATE_MARKERS) or getattr(decision, "masked", None):
                return
            text = text_of_args(getattr(event, "args", None))
            if not text:
                return
            from .report import tool_class
            record = {"ts": self._now(), "policy_id": policy_id, "tool_class": tool_class(event.action),
                      "args_digest": getattr(receipt, "args_digest", ""),
                      "fp": fingerprint(text, self.alpha, self.embedder).hex(), "alpha": self.alpha}
            self._append(self.path, record)
            if policy_id in self.sample_rules:
                args = getattr(event, "args", None)
                names = sorted(str(k) for k in args if isinstance(args.get(k), str))[:8] if isinstance(args, dict) else []
                self._append(self.samples_path, {"ts": record["ts"], "policy_id": policy_id,
                                                 "tool_class": record["tool_class"], "arg_names": names,
                                                 "text": redact(text)[:MAX_SAMPLE]})
        except Exception:
            return

    def _append(self, path: str, record: Dict[str, Any]) -> None:
        os.makedirs(self.directory, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")


def read_records(path: str, since: float, until: float, limit: int) -> List[Dict[str, Any]]:
    """Records in ``[since, until)`` from a recorder file, oldest first, capped."""
    out: List[Dict[str, Any]] = []
    if not os.path.exists(path):
        return out
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            ts = record.get("ts")
            if isinstance(ts, (int, float)) and since <= ts < until:
                out.append(record)
                if len(out) >= limit:
                    break
    return out


def rewrite_records(path: str, keep: Callable[[Dict[str, Any]], bool]) -> int:
    """Drop records ``keep`` rejects (housekeeping after a report shipped)."""
    if not os.path.exists(path):
        return 0
    kept: List[str] = []
    dropped = 0
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if keep(record):
                kept.append(line if line.endswith("\n") else line + "\n")
            else:
                dropped += 1
    atomic_write(path, "".join(kept).encode("utf-8"), mode=0o600)
    return dropped

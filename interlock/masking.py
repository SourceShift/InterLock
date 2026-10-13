"""One masking engine: detect sensitive values, then rewrite them by a strategy.

interlock's older redactors are one regex each. This module is the engine they
grow into (hoop review H2): an **entity catalog** whose detectors validate what
they match - a card number must pass Luhn, an IBAN mod-97, a CPF its mod-11
digits - **strategies** for what to write instead, and **structure awareness**:
it walks dicts, lists and ``{"columns": [...], "rows": [...]}`` tables, and
column or dotted-path rules mask a field outright, without detection.

    masker = Masker([
        MaskRule(columns=["password", "customer.ssn"], strategy="mask"),
        MaskRule(entities=["CREDIT_CARD"], strategy="partial", keep_last=4),
        MaskRule(entities=["EMAIL_ADDRESS"], strategy="hash"),
        MaskRule(),                                   # every other entity: redact
    ], hash_key=b"...")
    masked, counts = masker.mask(rows)

Strategies:

===========  ================================================================
``redact``   ``[REDACTED:EMAIL_ADDRESS]`` (the default)
``mask``     every character replaced by ``mask_char``, length kept
``partial``  keep the last ``keep_last`` characters, mask letters and digits
             before them, keep punctuation: ``****-****-****-1234``
``hash``     ``hash:<16 hex>``, an HMAC-SHA256 under ``hash_key``. Equal values
             hash equally (joins and GROUP BY survive) but, unlike an unsalted
             hash, a guessable value can't be found by hashing guesses
             without the key. With no key a per-process random one is used
===========  ================================================================

Detection is local - regular expressions, checksums, and context words near a
match for the noisy entities - with no model and no network. Each entity has a
score; matches under ``threshold`` (default 0.5) are left alone, and
:data:`NOISY` documents which entities false-positive on ordinary data.
Personal names and places need a language model and are not detected.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

# --- validators -----------------------------------------------------------------


def _digits(text: str) -> str:
    return re.sub(r"\D", "", text)


def luhn(number: str) -> bool:
    digits = _digits(number)
    if not 12 <= len(digits) <= 19:
        return False
    total = 0
    for index, ch in enumerate(reversed(digits)):
        d = int(ch)
        if index % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


_IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AT": 20, "BE": 16, "BG": 22, "BR": 29, "CH": 21, "CY": 28, "CZ": 24,
    "DE": 22, "DK": 18, "EE": 20, "ES": 24, "FI": 18, "FR": 27, "GB": 22, "GR": 27, "HR": 21,
    "HU": 28, "IE": 22, "IS": 26, "IT": 27, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27,
    "MT": 31, "NL": 18, "NO": 15, "PL": 28, "PT": 25, "RO": 24, "SA": 24, "SE": 24, "SI": 19,
    "SK": 24, "SM": 27, "TR": 26, "UA": 29,
}


def iban(value: str) -> bool:
    compact = re.sub(r"\s", "", value).upper()
    expected = _IBAN_LENGTHS.get(compact[:2])
    if expected is not None and len(compact) != expected:
        return False
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(numeric) % 97 == 1


def us_ssn(value: str) -> bool:
    d = _digits(value)
    if len(d) != 9:
        return False
    area, group, serial = d[:3], d[3:5], d[5:]
    return area not in ("000", "666") and not area.startswith("9") and group != "00" \
        and serial != "0000" and d not in ("078051120", "219099999")


def aba_routing(value: str) -> bool:
    d = _digits(value)
    if len(d) != 9 or d[0] not in "0123678":
        return False
    weights = (3, 7, 1) * 3
    return sum(int(c) * w for c, w in zip(d, weights)) % 10 == 0


def br_cpf(value: str) -> bool:
    d = _digits(value)
    if len(d) != 11 or d == d[0] * 11:
        return False
    for size in (9, 10):
        total = sum(int(d[i]) * (size + 1 - i) for i in range(size))
        check = (total * 10) % 11 % 10
        if check != int(d[size]):
            return False
    return True


def br_cnpj(value: str) -> bool:
    d = _digits(value)
    if len(d) != 14 or d == d[0] * 14:
        return False
    for size, weights in ((12, (5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)),
                          (13, (6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2))):
        total = sum(int(d[i]) * weights[i] for i in range(size))
        check = 0 if total % 11 < 2 else 11 - total % 11
        if check != int(d[size]):
            return False
    return True


_VERHOEFF_D = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
               [2, 3, 4, 0, 1, 7, 8, 9, 5, 6], [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
               [4, 0, 1, 2, 3, 9, 5, 6, 7, 8], [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
               [6, 5, 9, 8, 7, 1, 0, 4, 3, 2], [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
               [8, 7, 6, 5, 9, 3, 2, 1, 0, 4], [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]]
_VERHOEFF_P = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
               [5, 8, 0, 3, 7, 9, 6, 1, 4, 2], [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
               [9, 4, 5, 3, 1, 2, 7, 6, 8, 0], [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
               [2, 7, 9, 3, 8, 0, 6, 4, 1, 5], [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]]


def verhoeff(value: str) -> bool:
    d = _digits(value)
    if len(d) != 12:
        return False
    check = 0
    for index, ch in enumerate(reversed(d)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[index % 8][int(ch)]]
    return check == 0


def de_tax_id(value: str) -> bool:
    """German Steuerliche Identifikationsnummer: 11 digits, ISO 7064 MOD 11,10
    check digit, and in the first ten exactly one digit repeated (two or three
    times) while at least one digit is missing."""
    d = _digits(value)
    if len(d) != 11 or d[0] == "0":
        return False
    counts = [d[:10].count(str(n)) for n in range(10)]
    repeated = [c for c in counts if c > 1]
    if len(repeated) != 1 or repeated[0] not in (2, 3) or 0 not in counts:
        return False
    product = 10
    for ch in d[:10]:
        total = (int(ch) + product) % 10
        if total == 0:
            total = 10
        product = (total * 2) % 11
    check = 11 - product
    return (0 if check == 10 else check) == int(d[10])


def ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def jwt(value: str) -> bool:
    head = value.split(".", 1)[0]
    try:
        data = json.loads(base64.urlsafe_b64decode(head + "=" * (-len(head) % 4)))
    except Exception:
        return False
    return isinstance(data, dict) and isinstance(data.get("alg"), str)


# --- the catalog ------------------------------------------------------------------


@dataclass(frozen=True)
class Entity:
    """One detectable kind of sensitive value."""

    name: str
    pattern: "re.Pattern[str]"
    score: float  # confidence when the pattern (and validator) match
    validator: Optional[Callable[[str], bool]] = None
    group: int = 0  # the part of the match to mask
    context: Tuple[str, ...] = ()  # words nearby that raise the score
    context_boost: float = 0.3


def _re(pattern: str, flags: int = 0) -> "re.Pattern[str]":
    return re.compile(pattern, flags)


ENTITIES: Dict[str, Entity] = {e.name: e for e in [
    Entity("EMAIL_ADDRESS", _re(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b"), 0.9),
    Entity("CREDIT_CARD", _re(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)"), 1.0, luhn),
    Entity("IBAN_CODE", _re(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}\b"), 1.0, iban),
    Entity("US_SSN", _re(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"), 0.8, us_ssn,
           context=("ssn", "social security")),
    Entity("US_ITIN", _re(r"(?<!\d)9\d{2}-(?:5\d|6[0-5]|7\d|8[0-8]|9[0-24-9])-\d{4}(?!\d)"), 0.8),
    Entity("ABA_ROUTING", _re(r"(?<!\d)\d{9}(?!\d)"), 0.3, aba_routing,
           context=("routing", "aba", "rtn", "transit")),
    Entity("PHONE_NUMBER", _re(r"(?<![\w+])(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?|\d{2,4}[ .-])\d{3,4}[ .-]?\d{3,4}(?!\w)"), 0.45,
           context=("phone", "tel", "mobile", "call", "telefon", "handy")),
    Entity("IP_ADDRESS", _re(r"(?<![\w.:])(?:(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4})(?![\w.:])"), 0.6, ip_address,
           context=("ip", "address", "host", "client")),
    Entity("BR_CPF", _re(r"(?<!\d)\d{3}\.?\d{3}\.?\d{3}-?\d{2}(?!\d)"), 0.7, br_cpf, context=("cpf",)),
    Entity("BR_CNPJ", _re(r"(?<!\d)\d{2}\.?\d{3}\.?\d{3}/?\d{4}-?\d{2}(?!\d)"), 0.8, br_cnpj, context=("cnpj",)),
    Entity("IN_AADHAAR", _re(r"(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)"), 0.7, verhoeff, context=("aadhaar", "uid")),
    Entity("DE_TAX_ID", _re(r"(?<!\d)[1-9]\d{10}(?!\d)"), 0.4, de_tax_id,
           context=("steuer", "steuerid", "idnr", "identifikationsnummer", "tax id", "tin")),
    Entity("UK_NINO", _re(r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b"), 0.8),
    Entity("AWS_ACCESS_KEY", _re(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 1.0),
    Entity("GITHUB_TOKEN", _re(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"), 1.0),
    Entity("SLACK_TOKEN", _re(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), 1.0),
    Entity("GOOGLE_API_KEY", _re(r"\bAIza[0-9A-Za-z_-]{35}\b"), 1.0),
    Entity("STRIPE_KEY", _re(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), 1.0),
    Entity("API_KEY", _re(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b"), 0.9),
    Entity("JWT", _re(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), 1.0, jwt),
    Entity("PRIVATE_KEY", _re(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z)"), 1.0),
    Entity("URL_PASSWORD", _re(r"\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s@/]+)@"), 1.0, group=1),
]}

#: Entities that also match ordinary data; they are kept below the default
#: threshold unless a context word is near (or you lower the threshold).
NOISY: Dict[str, str] = {
    "ABA_ROUTING": "any 9-digit number with a valid checksum (about 1 in 10)",
    "DE_TAX_ID": "11-digit numbers passing the check digit and digit-frequency rule",
    "PHONE_NUMBER": "grouped digit runs: order numbers, dates without separators",
    "IP_ADDRESS": "dotted version strings such as 1.2.3.4",
}

DEFAULT_THRESHOLD = 0.5
STRATEGIES = ("redact", "mask", "partial", "hash")


# --- rules and the masker ------------------------------------------------------------


@dataclass(frozen=True)
class MaskRule:
    """Either an entity rule (detects ``entities``; empty means all) or a
    column rule (masks the whole value at matching keys, without detection)."""

    entities: Tuple[str, ...] = ()
    columns: Tuple[str, ...] = ()
    strategy: str = "redact"
    keep_last: int = 4
    mask_char: str = "*"
    name: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "entities", tuple(e.upper() for e in self.entities))
        object.__setattr__(self, "columns", tuple(c.lower() for c in self.columns))
        if self.strategy not in STRATEGIES:
            raise ValueError("strategy must be one of {}".format(", ".join(STRATEGIES)))
        unknown = [e for e in self.entities if e not in ENTITIES]
        if unknown:
            raise ValueError("unknown entities: {}; known: {}".format(
                ", ".join(unknown), ", ".join(sorted(ENTITIES))))
        if len(self.mask_char) != 1:
            raise ValueError("mask_char must be one character")
        if self.keep_last < 0:
            raise ValueError("keep_last must not be negative")


@dataclass
class Masker:
    rules: Sequence[MaskRule] = (MaskRule(),)
    threshold: float = DEFAULT_THRESHOLD
    allow_list: Iterable[str] = ()
    hash_key: Optional[bytes] = None
    max_depth: int = 12
    _allowed: frozenset = field(default=frozenset(), init=False, repr=False)
    _key: bytes = field(default=b"", init=False, repr=False)

    def __post_init__(self) -> None:
        self.rules = tuple(self.rules)
        self._allowed = frozenset(self.allow_list)
        self._key = self.hash_key if self.hash_key is not None else secrets.token_bytes(32)

    # Public ---------------------------------------------------------------
    def mask(self, value: Any) -> Tuple[Any, Dict[str, int]]:
        """``value`` with sensitive data masked, and how many of each entity."""
        counts: Dict[str, int] = {}
        return self._walk(value, [], counts, 0), counts

    def mask_text(self, text: str, path: Sequence[str] = ()) -> Tuple[str, Dict[str, int]]:
        counts: Dict[str, int] = {}
        return self._text(text, [p.lower() for p in path], counts), counts

    def find(self, text: str, entities: Optional[Iterable[str]] = None) -> List[Tuple[str, int, int]]:
        """``(entity, start, end)`` for every accepted match, non-overlapping."""
        wanted = set(e.upper() for e in entities) if entities else set(ENTITIES)
        return [(m[0], m[1], m[2]) for m in self._detect(text, wanted)]

    # Walking --------------------------------------------------------------
    def _walk(self, value: Any, path: List[str], counts: Dict[str, int], depth: int) -> Any:
        if depth > self.max_depth:
            return value
        column = self._column_rule(path) if path else None
        if column is not None and not isinstance(value, (dict, list, tuple)):
            if value is None or isinstance(value, bool):
                return value
            counts[column.name or "COLUMN"] = counts.get(column.name or "COLUMN", 0) + 1
            return self._apply(column, str(value), "COLUMN")
        if isinstance(value, str):
            return self._text(value, path, counts)
        if isinstance(value, dict):
            if _is_table(value):
                return self._table(value, path, counts, depth)
            return {k: self._walk(v, path + [str(k).lower()], counts, depth + 1)
                    for k, v in value.items()}
        if isinstance(value, list):
            return [self._walk(v, path, counts, depth + 1) for v in value]
        if isinstance(value, tuple):
            return tuple(self._walk(v, path, counts, depth + 1) for v in value)
        return value

    def _table(self, table: Dict[str, Any], path: List[str], counts: Dict[str, int],
               depth: int) -> Dict[str, Any]:
        columns = [str(c).lower() for c in table["columns"]]
        # Every other key of the table object is walked like any dict entry:
        # a table shape must never shelter its siblings from masking.
        out = {k: (v if k in ("columns", "rows")
                   else self._walk(v, path + [str(k).lower()], counts, depth + 1))
               for k, v in table.items()}
        rows = []
        for row in table["rows"]:
            if isinstance(row, (list, tuple)):
                cells = [self._walk(cell, path + [columns[i]] if i < len(columns) else path,
                                    counts, depth + 1) for i, cell in enumerate(row)]
                rows.append(type(row)(cells))
            else:
                rows.append(self._walk(row, path, counts, depth + 1))
        out["rows"] = rows
        return out

    def _column_rule(self, path: List[str]) -> Optional[MaskRule]:
        best: Optional[Tuple[Tuple[int, int], MaskRule]] = None
        for rule in self.rules:
            for column in rule.columns:
                segments = column.split(".")
                score = _run_score(path, segments)
                if score is not None and (best is None or score > best[0]):
                    best = (score, rule)
        return best[1] if best else None

    # Text -----------------------------------------------------------------
    def _text(self, text: str, path: List[str], counts: Dict[str, int]) -> str:
        if not text:
            return text
        entity_rules = [r for r in self.rules if not r.columns]
        if not entity_rules:
            return text
        wanted = set()
        for rule in entity_rules:
            wanted.update(rule.entities or ENTITIES)
        matches = self._detect(text, wanted)
        if not matches:
            return text
        out = text
        for entity, start, end in sorted(matches, key=lambda m: -m[1]):
            rule = next((r for r in entity_rules if not r.entities or entity in r.entities), None)
            if rule is None:
                continue
            out = out[:start] + self._apply(rule, out[start:end], entity) + out[end:]
            counts[entity] = counts.get(entity, 0) + 1
        return out

    def _detect(self, text: str, wanted: Iterable[str]) -> List[Tuple[str, int, int]]:
        candidates: List[Tuple[float, int, int, str]] = []
        lowered = text.lower()
        for name in wanted:
            entity = ENTITIES[name]
            for m in entity.pattern.finditer(text):
                value = m.group(entity.group)
                start, end = m.span(entity.group)
                if not value or value in self._allowed or value.startswith("[REDACTED"):
                    continue
                if entity.validator is not None and not entity.validator(value):
                    continue
                score = entity.score
                if entity.context:
                    window = lowered[max(0, start - 40):start]
                    if any(word in window for word in entity.context):
                        score += entity.context_boost
                if score >= self.threshold:
                    candidates.append((score, start, end, name))
        # Highest score first, then longest; drop overlaps.
        candidates.sort(key=lambda c: (-c[0], -(c[2] - c[1]), c[1]))
        taken: List[Tuple[str, int, int]] = []
        for score, start, end, name in candidates:
            if all(end <= s or start >= e for _, s, e in taken):
                taken.append((name, start, end))
        return taken

    def _apply(self, rule: MaskRule, value: str, entity: str) -> str:
        if rule.strategy == "redact":
            return "[REDACTED:{}]".format(entity)
        if rule.strategy == "mask":
            return rule.mask_char * len(value)
        if rule.strategy == "partial":
            keep = rule.keep_last
            head, tail = (value[:-keep], value[-keep:]) if keep else (value, "")
            return "".join(rule.mask_char if ch.isalnum() else ch for ch in head) + tail
        digest = hmac.new(self._key, value.encode("utf-8"), hashlib.sha256).hexdigest()
        return "hash:" + digest[:16]


def _is_table(value: Dict[str, Any]) -> bool:
    return isinstance(value.get("columns"), (list, tuple)) and isinstance(
        value.get("rows"), (list, tuple)) and all(isinstance(c, str) for c in value["columns"])


def _run_score(path: List[str], segments: List[str]) -> Optional[Tuple[int, int]]:
    """Best (length, leaf-nearness) of ``segments`` as an adjacent run in ``path``."""
    best = None
    n = len(segments)
    for start in range(len(path) - n + 1):
        if path[start:start + n] == segments:
            score = (n, start + n - len(path))  # nearer the leaf scores higher
            if best is None or score > best:
                best = score
    return best


def summary(counts: Dict[str, int]) -> str:
    """``EMAIL_ADDRESS x2, CREDIT_CARD x1`` - names and counts, never values."""
    return ", ".join("{} x{}".format(k, v) for k, v in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))

"""DAP task files, role keys and the counts/bucket manifest.

A task is the immutable unit DAP is built around: one VDAF configuration, one
pair of aggregator endpoints, one time precision and one bucket list. Changing
any of them means a new task with a new ID, because the encoded
``TaskConfiguration`` is authenticated as HPKE AAD on every report and every
aggregate share.

Three files carry the parts:

``task.json`` (public, 0644)
    The task ID, endpoints, VDAF parameters, the encoded
    ``TaskConfiguration`` exactly as it goes on the wire, the collector's HPKE
    public config, the aggregators' pinned HPKE public configs, and the ordered
    bucket patterns.

``leader.json`` / ``helper.json`` (private, 0600)
    One aggregator's HPKE secret, the shared VDAF verify key, and the bearer
    tokens its peers will present.

``collector.json`` (private, 0600)
    The collector's HPKE secret and the token the leader requires.

The bucket manifest maps the counts a node already keeps
(``policy|verdict|tool_class|phase|hour``) onto one dense vector. Patterns are
ordered, and each is four or five ``|``-separated components; ``*`` is allowed
only as the hour component, where it sums every hour of the batch. Every count
must match exactly one pattern — an unmatched count is an error rather than a
silent drop, because a dropped count is indistinguishable from "never
happened" at the collector.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import os
import secrets
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

from .. import hpke
from .._util import atomic_write, canonical, load_json
from ..vdaf import Prio3SumVec
from . import DAP_CONTEXT
from . import messages as m

TASK_FILE = "task.json"
LEADER_FILE = "leader.json"
HELPER_FILE = "helper.json"
COLLECTOR_FILE = "collector.json"

TASK_FILE_MAX = 2 * 1024 * 1024
KEY_FILE_MAX = 64 * 1024
MAX_TASK_FILE = TASK_FILE_MAX

#: Hour buckets are what ``report build`` writes; a DAP batch is a whole number
#: of them.
HOUR_SECONDS = 3600

#: How many patterns one task may hold. Pure-Python Prio3 proofs grow with the
#: vector length, and a report is uploaded in one HTTP request.
MAX_BUCKETS = 4096

#: The VDAF's proof is over ``max_measurement.bit_length()`` bits per element;
#: this keeps one report's proof in the tens of kilobytes, not megabytes.
MAX_MEASUREMENT_CEILING = (1 << 20) - 1


class TaskError(ValueError):
    """A task file, key file or bucket manifest is not usable."""


def _is_int(value: object) -> bool:
    """``bool`` is an ``int`` in Python; never let ``True`` become a parameter."""
    return isinstance(value, int) and not isinstance(value, bool)


def b64url(data: bytes) -> str:
    """Unpadded base64url, the convention DAP deployments use in URLs."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def from_b64url(text: str) -> bytes:
    if not isinstance(text, str) or not text:
        raise TaskError("expected an unpadded base64url string")
    padding = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + padding)
    except (ValueError, binascii.Error) as exc:
        raise TaskError("invalid base64url: {}".format(exc))


# --- Bucket patterns ------------------------------------------------------

def parse_pattern(text: str) -> Tuple[str, ...]:
    """``rule|verdict|class|phase|hour`` with ``*`` only in the hour slot."""
    if not isinstance(text, str) or not text.strip():
        raise TaskError("a bucket pattern must be a non-empty string")
    parts = tuple(text.strip().split("|"))
    if len(parts) not in (4, 5):
        raise TaskError(
            "bucket pattern {!r} has {} components; expected 4 or 5 "
            "(policy|verdict|tool_class|phase[|hour])".format(text, len(parts)))
    if any(not part for part in parts):
        raise TaskError("bucket pattern {!r} has an empty component".format(text))
    for part in parts[:4]:
        if part == "*":
            raise TaskError(
                "bucket pattern {!r}: '*' is only allowed in the hour component"
                .format(text))
    if len(parts) == 5 and parts[4] != "*":
        try:
            hour = int(parts[4])
        except ValueError:
            raise TaskError(
                "bucket pattern {!r}: the hour component must be an integer 0..23 "
                "or '*'".format(text))
        if hour < 0:
            raise TaskError("bucket pattern {!r}: hour cannot be negative".format(text))
    return parts


def pattern_label(pattern: Sequence[str]) -> str:
    return "|".join(pattern)


def _parse_count_key(key: str) -> Tuple[str, str, str, str, int]:
    parts = key.split("|")
    if len(parts) != 5:
        raise TaskError(
            "count key {!r} is not policy|verdict|tool_class|phase|hour".format(key))
    try:
        bucket = int(parts[4])
    except ValueError:
        raise TaskError("count key {!r} has a non-integer hour".format(key))
    return parts[0], parts[1], parts[2], parts[3], bucket


def default_chunk_length(length: int, max_measurement: int) -> int:
    """``isqrt(length * bits)``, the balance the VDAF draft suggests.

    The proof is one polynomial per gadget call; too small a chunk makes many
    tiny proofs, too large a chunk makes a few very long ones.
    """
    bits = max(1, int(max_measurement).bit_length())
    return max(1, math.isqrt(length * bits))


@dataclass(frozen=True)
class Task:
    """A loaded task. Construct with :func:`create_task` or :func:`load_task`."""

    task_id: bytes
    leader: str
    helper: str
    time_precision: int
    min_batch_size: int
    buckets: Tuple[Tuple[str, ...], ...]
    max_measurement: int
    chunk_length: int
    task_configuration: bytes
    collector_hpke: m.HpkeConfig
    leader_hpke: Optional[m.HpkeConfig] = None
    helper_hpke: Optional[m.HpkeConfig] = None

    def __post_init__(self) -> None:
        if len(self.task_id) != 32:
            raise TaskError("a task ID is 32 bytes")
        if (not _is_int(self.time_precision) or self.time_precision < HOUR_SECONDS
                or self.time_precision % HOUR_SECONDS):
            raise TaskError("time_precision must be a whole number of hours")
        if not _is_int(self.min_batch_size) or self.min_batch_size < 2:
            raise TaskError("min_batch_size must be an integer of at least 2")
        if not self.buckets:
            raise TaskError("a task needs at least one bucket pattern")

    @property
    def task_id_hex(self) -> str:
        return self.task_id.hex()

    @property
    def task_id_b64(self) -> str:
        return b64url(self.task_id)

    @property
    def hours_per_batch(self) -> int:
        return self.time_precision // HOUR_SECONDS

    @property
    def length(self) -> int:
        return len(self.buckets)

    @property
    def batch_seconds(self) -> int:
        return self.time_precision

    def vdaf(self, shares: int = 2) -> Prio3SumVec:
        return Prio3SumVec(shares, self.length, self.max_measurement, self.chunk_length)

    def context(self) -> bytes:
        """The VDAF context DAP requires: ``"dap-20" || task_id``."""
        return DAP_CONTEXT + self.task_id

    def batch_index(self, now: Optional[float] = None) -> int:
        now = _now() if now is None else now
        return int(now // self.time_precision)

    def batch_start(self, batch_index: int) -> int:
        return batch_index * self.time_precision

    def batch_interval(self, batch_index: int) -> m.Interval:
        return m.Interval(batch_index, 1)

    def batch_start_time(self, batch_index: int) -> int:
        """The batch's first hour bucket, as ``report build`` stamps it."""
        return batch_index * self.time_precision

    def batch_for_counts(self, counts: Mapping[str, int]) -> int:
        """The one batch every count key falls in, or :class:`TaskError`.

        A report is one batch, so counts spanning two batches cannot be sharded
        together; the operator builds the other batch separately.
        """
        if not counts:
            raise TaskError("no counts to place in a batch")
        batches = set()
        for key in counts:
            _, _, _, _, bucket = _parse_count_key(key)
            batches.add(bucket // self.time_precision)
        if len(batches) != 1:
            raise TaskError(
                "the counts span batches {}; a report covers one batch"
                .format(sorted(batches)))
        return batches.pop()

    # --- counts <-> measurement -------------------------------------------

    def measurement(self, counts: Mapping[str, int], batch_index: int) -> List[int]:
        """Map count keys to the dense vector for one batch.

        Every key must fall inside the batch and match exactly one pattern.
        Anything else raises: refusing is the only honest response to a count
        the task cannot attribute.
        """
        start = self.batch_start_time(batch_index)
        end = start + self.time_precision
        vector = [0] * self.length
        for key, value in counts.items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise TaskError("count {!r} is not a non-negative integer".format(key))
            policy_id, verdict, tool_class, phase, bucket = _parse_count_key(key)
            if not start <= bucket < end:
                raise TaskError(
                    "count {!r} is outside batch {} ([{}, {}))".format(
                        key, batch_index, start, end))
            offset = (bucket - start) // HOUR_SECONDS
            matches = [
                index for index, pattern in enumerate(self.buckets)
                if _matches(pattern, policy_id, verdict, tool_class, phase, offset)
            ]
            if not matches:
                raise TaskError(
                    "count {!r} matches no bucket in this task; add a bucket and "
                    "create a new task, or drop the count".format(key))
            if len(matches) > 1:
                raise TaskError(
                    "count {!r} matches buckets {}; task patterns must be disjoint"
                    .format(key, [pattern_label(self.buckets[i]) for i in matches]))
            vector[matches[0]] += value
        for index, value in enumerate(vector):
            if value > self.max_measurement:
                raise TaskError(
                    "bucket {!r} sums to {}, over max_measurement {}"
                    .format(pattern_label(self.buckets[index]), value,
                            self.max_measurement))
        return vector

    def counts(self, vector: Sequence[int], batch_index: int) -> Dict[str, int]:
        """Inverse of :meth:`measurement`, for the collector's output."""
        if len(vector) != self.length:
            raise TaskError("the aggregate result has {} elements, expected {}"
                            .format(len(vector), self.length))
        start = self.batch_start_time(batch_index)
        out: Dict[str, int] = {}
        for pattern, value in zip(self.buckets, vector):
            if not value:
                continue
            if len(pattern) == 5 and pattern[4] != "*":
                key = "|".join(pattern[:4] + (str(start + int(pattern[4]) * HOUR_SECONDS),))
            else:
                key = pattern_label(pattern)
            out[key] = int(value)
        return out

    # --- persistence -------------------------------------------------------

    def to_json(self) -> Dict[str, Any]:
        document: Dict[str, Any] = {
            "version": 1,
            "task_id_hex": self.task_id_hex,
            "task_id_b64": self.task_id_b64,
            "leader": self.leader,
            "helper": self.helper,
            "time_precision": self.time_precision,
            "batch_seconds": self.batch_seconds,
            "hours_per_batch": self.hours_per_batch,
            "min_batch_size": self.min_batch_size,
            "buckets": [pattern_label(pattern) for pattern in self.buckets],
            "vdaf": {
                "type": "Prio3SumVec",
                "codepoint": m.VDAF_TYPE_PRIO3_SUM_VEC,
                "length": self.length,
                "max_measurement": self.max_measurement,
                "chunk_length": self.chunk_length,
            },
            "task_config_b64": base64.b64encode(self.task_configuration).decode("ascii"),
            "collector_hpke": _hpke_config_json(self.collector_hpke),
        }
        if self.leader_hpke is not None:
            document["leader_hpke"] = _hpke_config_json(self.leader_hpke)
        if self.helper_hpke is not None:
            document["helper_hpke"] = _hpke_config_json(self.helper_hpke)
        return document

    def write(self, path: str) -> None:
        if os.path.exists(path):
            raise TaskError("{} already exists; tasks are never overwritten".format(path))
        atomic_write(path, canonical(self.to_json()) + b"\n", 0o644)


def _now() -> float:
    import time

    return time.time()


def _matches(pattern: Sequence[str], policy_id: str, verdict: str,
             tool_class: str, phase: str, offset: int) -> bool:
    if len(pattern) == 4:
        return (pattern[0] == policy_id and pattern[1] == verdict
                and pattern[2] == tool_class and pattern[3] == phase)
    if pattern[4] == "*":
        return (pattern[0] == policy_id and pattern[1] == verdict
                and pattern[2] == tool_class and pattern[3] == phase)
    return (pattern[0] == policy_id and pattern[1] == verdict
            and pattern[2] == tool_class and pattern[3] == phase
            and int(pattern[4]) == offset)


# --- Keys -----------------------------------------------------------------

@dataclass(frozen=True)
class RoleKeys:
    """One role's private material; never logged, never in ``task.json``."""

    role: str
    task_id: bytes
    hpke_config_id: int
    hpke_secret: bytes
    verify_key: Optional[bytes] = None
    tokens: Mapping[str, str] = field(default_factory=dict)

    def to_json(self) -> Dict[str, Any]:
        document: Dict[str, Any] = {
            "version": 1,
            "role": self.role,
            "task_id_hex": self.task_id.hex(),
            "hpke_config_id": self.hpke_config_id,
            "hpke_secret_hex": self.hpke_secret.hex(),
        }
        if self.verify_key is not None:
            document["verify_key_hex"] = self.verify_key.hex()
        if self.tokens:
            document["tokens"] = dict(sorted(self.tokens.items()))
        return document

    def write(self, path: str) -> None:
        if os.path.exists(path):
            raise TaskError("{} already exists; key files are never overwritten".format(path))
        atomic_write(path, canonical(self.to_json()) + b"\n", 0o600)

    def token(self, name: str) -> Optional[str]:
        return self.tokens.get(name)


def load_role_keys(path: str, task: Task) -> RoleKeys:
    document = load_json(path, KEY_FILE_MAX)
    if not isinstance(document, dict):
        raise TaskError("{} is not a key file".format(path))
    role = document.get("role")
    if role not in ("leader", "helper", "collector"):
        raise TaskError("{}: unknown role {!r}".format(path, role))
    try:
        task_id = bytes.fromhex(document["task_id_hex"])
        secret = bytes.fromhex(document["hpke_secret_hex"])
        config_id = int(document["hpke_config_id"])
    except (KeyError, TypeError, ValueError):
        raise TaskError("{}: the key file is incomplete".format(path))
    if task_id != task.task_id:
        raise TaskError("{} belongs to task {}, not {}".format(
            path, task_id.hex(), task.task_id_hex))
    if len(secret) != 32:
        raise TaskError("{}: an X25519 secret is 32 bytes".format(path))
    verify_key = None
    if "verify_key_hex" in document:
        try:
            verify_key = bytes.fromhex(document["verify_key_hex"])
        except (TypeError, ValueError):
            raise TaskError("{}: verify_key_hex is not hex".format(path))
        if len(verify_key) != 32:
            raise TaskError("{}: a VDAF verify key is 32 bytes".format(path))
    if role in ("leader", "helper") and verify_key is None:
        raise TaskError("{}: an aggregator key file needs verify_key_hex".format(path))
    tokens = document.get("tokens") or {}
    if not isinstance(tokens, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in tokens.items()):
        raise TaskError("{}: tokens must be a string map".format(path))
    return RoleKeys(role, task_id, config_id, secret, verify_key, tokens)


def _hpke_config_json(config: m.HpkeConfig) -> Dict[str, Any]:
    return {
        "config_id": config.config_id,
        "kem_id": config.kem_id,
        "kdf_id": config.kdf_id,
        "aead_id": config.aead_id,
        "public_key_hex": config.public_key.hex(),
    }


def _hpke_config_from_json(document: Any) -> m.HpkeConfig:
    if not isinstance(document, dict):
        raise TaskError("an HPKE config must be an object")
    try:
        return m.HpkeConfig(
            int(document["config_id"]),
            int(document["kem_id"]),
            int(document["kdf_id"]),
            int(document["aead_id"]),
            bytes.fromhex(document["public_key_hex"]),
        )
    except (KeyError, TypeError, ValueError):
        raise TaskError("malformed HPKE config")


def _new_hpke_config(config_id: int) -> Tuple[m.HpkeConfig, bytes]:
    secret, public = hpke.generate_keypair()
    return m.HpkeConfig(config_id, hpke.KEM_X25519_HKDF_SHA256,
                        hpke.KDF_HKDF_SHA256, hpke.AEAD_AES_128_GCM, public), secret


def _task_information(buckets: Sequence[Sequence[str]], hours_per_batch: int,
                      max_measurement: int, chunk_length: int) -> bytes:
    """32-byte digest binding the bucket list into ``task_info``.

    ``task_info`` is opaque to DAP and capped at 255 bytes, so it holds a
    digest rather than the manifest. A peer that adopts this task quotes the
    same bytes; it does not need to understand the buckets.
    """
    return hashlib.sha256(canonical({
        "buckets": [pattern_label(pattern) for pattern in buckets],
        "hours_per_batch": hours_per_batch,
        "max_measurement": max_measurement,
        "chunk_length": chunk_length,
    })).digest()


def create_task(*, leader: str, helper: str, buckets: Sequence[str],
                batch_hours: int = 24, min_batch_size: int = 10,
                max_measurement: int = 65535,
                chunk_length: Optional[int] = None,
                task_id: Optional[bytes] = None,
                out_dir: str) -> Tuple[Task, RoleKeys, RoleKeys, RoleKeys]:
    """Create a task and the three role key files under ``out_dir``."""
    leader = leader.rstrip("/")
    helper = helper.rstrip("/")
    if not leader.startswith(("http://", "https://")):
        raise TaskError("the leader URL must be http:// or https://")
    if not helper.startswith(("http://", "https://")):
        raise TaskError("the helper URL must be http:// or https://")
    if not _is_int(batch_hours) or batch_hours < 1:
        raise TaskError("a batch is at least one whole hour")
    if not _is_int(min_batch_size) or min_batch_size < 2:
        raise TaskError("min_batch_size must be an integer of at least 2")
    if not _is_int(max_measurement) or not (
            1 <= max_measurement <= MAX_MEASUREMENT_CEILING):
        raise TaskError("max_measurement must be 1..{}".format(MAX_MEASUREMENT_CEILING))

    patterns = tuple(parse_pattern(text) for text in buckets)
    if not patterns:
        raise TaskError("give at least one --bucket")
    if len(patterns) > MAX_BUCKETS:
        raise TaskError("{} buckets is over the {} cap; split the task"
                        .format(len(patterns), MAX_BUCKETS))
    for index, pattern in enumerate(patterns):
        if len(pattern) == 5 and pattern[4] != "*" and int(pattern[4]) >= batch_hours:
            raise TaskError(
                "bucket {!r} names hour {}, but a {}h batch has hours 0..{}"
                .format(pattern_label(pattern), pattern[4], batch_hours, batch_hours - 1))
        for earlier in patterns[:index]:
            if _overlap(pattern, earlier):
                raise TaskError(
                    "bucket patterns {!r} and {!r} overlap; every count must match "
                    "exactly one".format(pattern_label(earlier), pattern_label(pattern)))

    time_precision = batch_hours * HOUR_SECONDS
    length = len(patterns)
    if chunk_length is None:
        chunk_length = default_chunk_length(length, max_measurement)
    if not _is_int(chunk_length) or chunk_length < 1:
        raise TaskError("chunk_length must be a positive integer")
    if task_id is None:
        task_id = os.urandom(32)
    if not isinstance(task_id, bytes) or len(task_id) != 32:
        raise TaskError("a task ID is 32 bytes")

    leader_config, leader_secret = _new_hpke_config(1)
    helper_config, helper_secret = _new_hpke_config(2)
    collector_config, collector_secret = _new_hpke_config(3)

    vdaf_config = m.Prio3SumVecConfig(length, max_measurement, chunk_length)
    configuration = m.TaskConfiguration(
        task_info=_task_information(patterns, batch_hours, max_measurement, chunk_length),
        leader_aggregator_endpoint=leader,
        helper_aggregator_endpoint=helper,
        time_precision=time_precision,
        min_batch_size=min_batch_size,
        batch_mode=m.BatchMode.TIME_INTERVAL,
        batch_config=b"",
        vdaf_type=m.VDAF_TYPE_PRIO3_SUM_VEC,
        vdaf_configuration=vdaf_config.encode(),
        extensions=(),
    ).encode()

    task = Task(
        task_id=task_id,
        leader=leader,
        helper=helper,
        time_precision=time_precision,
        min_batch_size=min_batch_size,
        buckets=patterns,
        max_measurement=max_measurement,
        chunk_length=chunk_length,
        task_configuration=configuration,
        collector_hpke=collector_config,
        leader_hpke=leader_config,
        helper_hpke=helper_config,
    )

    verify_key = os.urandom(32)
    helper_token = secrets.token_urlsafe(24)
    collector_token = secrets.token_urlsafe(24)
    leader_keys = RoleKeys("leader", task_id, leader_config.config_id, leader_secret,
                           verify_key, {"helper": helper_token,
                                        "collector": collector_token})
    helper_keys = RoleKeys("helper", task_id, helper_config.config_id, helper_secret,
                           verify_key, {"leader": helper_token})
    collector_keys = RoleKeys("collector", task_id, collector_config.config_id,
                              collector_secret, None, {"leader": collector_token})

    os.makedirs(out_dir, exist_ok=True)
    task.write(os.path.join(out_dir, TASK_FILE))
    leader_keys.write(os.path.join(out_dir, LEADER_FILE))
    helper_keys.write(os.path.join(out_dir, HELPER_FILE))
    collector_keys.write(os.path.join(out_dir, COLLECTOR_FILE))
    return task, leader_keys, helper_keys, collector_keys


def _overlap(left: Sequence[str], right: Sequence[str]) -> bool:
    """Whether two patterns can match the same count key."""
    if left[:4] != right[:4]:
        return False
    left_hour = left[4] if len(left) == 5 else "*"
    right_hour = right[4] if len(right) == 5 else "*"
    return left_hour == "*" or right_hour == "*" or left_hour == right_hour


# --- Loading --------------------------------------------------------------

def load_task(path: str) -> Task:
    """Load and cross-check ``task.json``.

    The encoded ``TaskConfiguration`` is re-encoded from its decoded form and
    compared with the stored bytes: a task file whose human fields and wire
    bytes disagree would silently change the HPKE AAD, so it is refused.
    """
    document = load_json(path, TASK_FILE_MAX)
    if not isinstance(document, dict) or document.get("version") != 1:
        raise TaskError("{} is not a version-1 DAP task file".format(path))
    try:
        task_id = bytes.fromhex(document["task_id_hex"])
        configuration_raw = base64.b64decode(document["task_config_b64"], validate=True)
        config = m.TaskConfiguration.from_bytes(configuration_raw)
        vdaf = document["vdaf"]
        buckets = tuple(parse_pattern(text) for text in document["buckets"])
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, TaskError):
            raise
        raise TaskError("{}: malformed task file ({})".format(path, exc))

    if config.encode() != configuration_raw:
        raise TaskError(
            "{}: task_config_b64 does not round-trip; the HPKE AAD would drift"
            .format(path))
    if config.batch_mode is not m.BatchMode.TIME_INTERVAL or config.batch_config:
        raise TaskError("{}: only time_interval batches with empty batch_config are "
                        "supported".format(path))
    if config.vdaf_type != m.VDAF_TYPE_PRIO3_SUM_VEC:
        raise TaskError("{}: only Prio3SumVec (0x{:08x}) is supported".format(
            path, m.VDAF_TYPE_PRIO3_SUM_VEC))
    vdaf_config = m.Prio3SumVecConfig.from_bytes(config.vdaf_configuration)
    if vdaf_config.length != len(buckets):
        raise TaskError("{}: vdaf length {} does not match {} buckets".format(
            path, vdaf_config.length, len(buckets)))
    if document.get("task_id_b64") not in (None, b64url(task_id)):
        raise TaskError("{}: task_id_b64 disagrees with task_id_hex".format(path))
    if document.get("leader", "").rstrip("/") != config.leader_aggregator_endpoint:
        raise TaskError("{}: leader disagrees with task_config_b64".format(path))
    if document.get("helper", "").rstrip("/") != config.helper_aggregator_endpoint:
        raise TaskError("{}: helper disagrees with task_config_b64".format(path))
    if int(document.get("time_precision", -1)) != config.time_precision:
        raise TaskError("{}: time_precision disagrees with task_config_b64".format(path))
    if int(document.get("min_batch_size", -1)) != config.min_batch_size:
        raise TaskError("{}: min_batch_size disagrees with task_config_b64".format(path))
    if isinstance(vdaf, dict):
        if (vdaf.get("length") not in (None, vdaf_config.length)
                or vdaf.get("max_measurement") not in (None, vdaf_config.max_measurement)
                or vdaf.get("chunk_length") not in (None, vdaf_config.chunk_length)):
            raise TaskError("{}: vdaf disagrees with task_config_b64".format(path))

    leader_hpke = _hpke_config_from_json(document["leader_hpke"]) \
        if document.get("leader_hpke") is not None else None
    helper_hpke = _hpke_config_from_json(document["helper_hpke"]) \
        if document.get("helper_hpke") is not None else None
    return Task(
        task_id=task_id,
        leader=config.leader_aggregator_endpoint,
        helper=config.helper_aggregator_endpoint,
        time_precision=config.time_precision,
        min_batch_size=config.min_batch_size,
        buckets=buckets,
        max_measurement=vdaf_config.max_measurement,
        chunk_length=vdaf_config.chunk_length,
        task_configuration=configuration_raw,
        collector_hpke=_hpke_config_from_json(document["collector_hpke"]),
        leader_hpke=leader_hpke,
        helper_hpke=helper_hpke,
    )

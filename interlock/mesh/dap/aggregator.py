"""The two DAP aggregators: the leader and the helper.

Both keep their state in one JSON file (0600) written atomically after every
mutation. The leader holds reports it has accepted but not yet aggregated, the
batches it has committed, and the collection responses it has already produced;
the helper holds committed buckets, the report ids it has seen, and the
aggregate-share responses it has already returned. That is enough for DAP's two
idempotency rules: a repeated ``CollectionJobReq`` returns the same response, and
a repeated ``AggregateShareReq`` returns the same aggregate share instead of
failing the batch as already collected.

Time units
----------
DAP ``Time`` values are *not* seconds: a Time is a POSIX timestamp divided by
the task's ``time_precision`` (draft-ietf-ppm-dap-20 §4.1.1). This task sets
``time_precision`` to a whole batch (24h by default), so a Time value is the
batch index and a batch bucket is ``Interval(start=index, duration=1)``. Fixed,
non-overlapping batches therefore follow from the protocol's bucket rule rather
than from a deployment convention: a query with a different duration cannot
name a valid set of buckets.

The one-round shortcut
----------------------
Prio3 needs one verification round, so the helper's ``AggregationJobInitReq``
handler reaches ``FinishedWithOutbound`` immediately. DAP still wraps that in a
``continue`` VerifyResp (§4.5.3.2 requires the type ``continue`` whenever the
helper has an outbound message, even if it has already committed) and the
leader finishes locally with ``ping_pong_leader_continued``. The continuation
endpoint is unreachable for this profile and answers ``stepMismatch``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from .. import hpke
from .._util import atomic_write, canonical, load_json
from ..report import post_bytes
from ..vdaf import Continued, Finished, FinishedWithOutbound, Rejected
from . import messages as m
from .task import RoleKeys, Task, TaskError

__all__ = ["Leader", "Helper", "MAX_BODY", "input_share_info", "aggregate_share_info"]

MAX_BODY = 8 * 1024 * 1024
STATE_MAX = 64 * 1024 * 1024

INPUT_SHARE_LABEL = b"dap-20 input share"
AGGREGATE_SHARE_LABEL = b"dap-20 aggregate share"

#: How far ahead of the current Time value a report may claim to be, in Time
#: units. One precision unit of slack covers clock skew between a client that
#: stamps just before a batch boundary and a leader that reads just after it.
MAX_TIME_SKEW = 1

#: The only verification key this deployment has; DAP lets the leader name one.
VERIFICATION_KEY_ID = 0


def input_share_info(role: m.Role) -> bytes:
    """``"dap-20 input share" || 0x01 || server_role`` (draft-20 §4.5.3.3)."""
    return INPUT_SHARE_LABEL + bytes([0x01, int(role)])


def aggregate_share_info(role: m.Role) -> bytes:
    """``"dap-20 aggregate share" || server_role || 0x00`` (draft-20 §4.6.7)."""
    return AGGREGATE_SHARE_LABEL + bytes([int(role), 0x00])


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, TypeError):
        raise m.DapProblem("invalidMessage", "corrupt state blob")


def _xor_checksum(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def _report_checksum(report_id: bytes) -> bytes:
    return hashlib.sha256(report_id).digest()


def _overlaps(left: m.Interval, right: m.Interval) -> bool:
    return (left.start < right.start + right.duration
            and right.start < left.start + left.duration)


def _problem_from(status: int, body: bytes, fallback: str) -> m.DapProblem:
    """Turn a peer's RFC 9457 problem document back into an exception."""
    try:
        document = json.loads(body.decode("utf-8"))
        urn = str(document.get("type", ""))
        token = urn.rsplit(":", 1)[-1]
        if token in m.PROBLEM_TYPES:
            return m.DapProblem(token, str(document.get("detail", "")), status)
    except (ValueError, TypeError):
        pass
    return m.DapProblem(fallback, "peer returned HTTP {}".format(status), status)


class _Store:
    """One JSON state file, written atomically under a lock."""

    def __init__(self, path: str, role: str, task: Task):
        self.path = os.path.abspath(path)
        self.lock = threading.RLock()
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self.data = self._load(role, task)

    def _initial(self, role: str, task: Task) -> Dict[str, Any]:
        return {
            "version": 1,
            "role": role,
            "task_id_hex": task.task_id_hex,
            "pending": {},
            "seen": [],
            "buckets": {},
            "collected": [],
            "responses": {},
        }

    def _load(self, role: str, task: Task) -> Dict[str, Any]:
        if not os.path.exists(self.path):
            return self._initial(role, task)
        document = load_json(self.path, STATE_MAX)
        if not isinstance(document, dict) or document.get("version") != 1:
            raise TaskError("{}: not a version-1 DAP state file".format(self.path))
        if document.get("role") != role:
            raise TaskError("{}: state belongs to role {!r}, not {!r}".format(
                self.path, document.get("role"), role))
        if document.get("task_id_hex") != task.task_id_hex:
            raise TaskError("{}: state belongs to task {}, not {}".format(
                self.path, document.get("task_id_hex"), task.task_id_hex))
        for key in ("pending", "seen", "buckets", "collected", "responses"):
            document.setdefault(key, [] if key in ("seen", "collected") else {})
        return document

    def save(self) -> None:
        atomic_write(self.path, canonical(self.data) + b"\n", 0o600)


class _Aggregator:
    """What both roles share: the task, the keys and bucket commitment."""

    role: m.Role = m.Role.LEADER
    name = "aggregator"

    def __init__(self, task: Task, keys: RoleKeys, state_path: str):
        if keys.role != self.name:
            raise TaskError("{} keys belong to role {!r}, not {!r}".format(
                state_path, keys.role, self.name))
        if keys.verify_key is None:
            raise TaskError("an aggregator needs the task's VDAF verify key")
        self.task = task
        self.keys = keys
        self.vdaf = task.vdaf()
        self.state = _Store(state_path, self.name, task)

    # --- bucket bookkeeping ------------------------------------------------

    def _bucket(self, index: int) -> Optional[Dict[str, Any]]:
        return self.state.data["buckets"].get(str(index))

    def _is_collected(self, interval: m.Interval) -> bool:
        return any(_overlaps(interval, m.Interval(start, duration))
                   for start, duration in self.state.data["collected"])

    def _commit(self, index: int, report_id: bytes, out_share: Any) -> Optional[m.ReportError]:
        """Add one output share to a batch bucket; return a report error if not.

        DAP commits an output share exactly once, and never into a collected
        batch (§4.5.4.3). Both are checked here, on the role that commits.
        """
        if self._is_collected(m.Interval(index, 1)):
            return m.ReportError.BATCH_COLLECTED
        marker = report_id.hex()
        if marker in self.state.data["seen"]:
            return m.ReportError.REPORT_REPLAYED
        bucket = self._bucket(index)
        if bucket is None:
            aggregate = self.vdaf.agg_init(None)
            bucket = {"count": 0, "checksum": "00" * 32, "agg": _b64(self.vdaf.encode_agg_share(aggregate))}
            self.state.data["buckets"][str(index)] = bucket
        aggregate = self.vdaf.decode_agg_share(None, _unb64(bucket["agg"]))
        aggregate = self.vdaf.agg_update(None, aggregate, out_share)
        bucket["agg"] = _b64(self.vdaf.encode_agg_share(aggregate))
        bucket["count"] = int(bucket["count"]) + 1
        bucket["checksum"] = _xor_checksum(bytes.fromhex(bucket["checksum"]),
                                           _report_checksum(report_id)).hex()
        self.state.data["seen"].append(marker)
        return None

    def _mark_collected(self, interval: m.Interval) -> None:
        self.state.data["collected"].append([interval.start, interval.duration])

    # --- shared request checks --------------------------------------------

    @staticmethod
    def _collection_interval(collection_job_req: m.CollectionJobReq) -> m.Interval:
        try:
            interval = collection_job_req.batch_interval
        except Exception:
            raise m.DapProblem("invalidMessage",
                               "only time_interval queries are supported")
        if interval.duration < 1:
            raise m.DapProblem("batchInvalid", "the query interval is empty")
        return interval

    @staticmethod
    def _check_extensions(extensions: Tuple[m.Extension, ...]) -> None:
        if extensions:
            raise m.DapProblem("unsupportedExtension",
                               "this deployment defines no extensions")

    def _check_agg_param(self, agg_param: bytes) -> None:
        if agg_param:
            raise m.DapProblem("invalidAggregationParameter",
                               "Prio3SumVec has no aggregation parameter")

    # --- collector-facing encryption --------------------------------------

    def _encrypt_aggregate_share(self, aggregate: Any,
                                 collection_job_req: bytes) -> m.HpkeCiphertext:
        plaintext = self.vdaf.encode_agg_share(aggregate)
        aad = m.AggregateShareAad(self.task.task_id, self.task.task_configuration,
                                  collection_job_req).encode()
        enc, ciphertext = hpke.seal_base(self.task.collector_hpke.public_key,
                                         aggregate_share_info(self.role),
                                         plaintext, aad)
        return m.HpkeCiphertext(self.task.collector_hpke.config_id, enc, ciphertext)


class Leader(_Aggregator):
    """Accepts uploads, drives the aggregation job, and answers the collector."""

    role = m.Role.LEADER
    name = "leader"

    def __init__(self, task: Task, keys: RoleKeys, state_path: str, *,
                 helper_token: Optional[str] = None, timeout: float = 30.0):
        super().__init__(task, keys, state_path)
        self.helper_url = task.helper
        self.helper_token = helper_token if helper_token is not None else keys.token("helper")
        self.collector_token = keys.token("collector")
        self.timeout = timeout

    # --- uploads -----------------------------------------------------------

    def upload(self, body: bytes) -> Tuple[int, str, bytes]:
        """Accept an ``UploadRequest``; return ``(status, media type, body)``."""
        try:
            request = m.UploadRequest.from_bytes(body)
        except m.WireError as exc:
            raise m.DapProblem("invalidMessage", str(exc))
        failures: List[m.ReportUploadStatus] = []
        with self.state.lock:
            for report in request.reports:
                error = self._accept(report)
                if error is not None:
                    failures.append(m.ReportUploadStatus(report.metadata.report_id, error))
            self.state.save()
        if not failures:
            return 200, "", b""
        return 200, m.MEDIA_UPLOAD_ERRORS, m.UploadErrors(tuple(failures)).encode()

    def _accept(self, report: m.Report) -> Optional[m.ReportError]:
        metadata = report.metadata
        try:
            self._check_extensions(metadata.public_extensions)
        except m.DapProblem:
            return m.ReportError.UNSUPPORTED_EXTENSION
        now = int(time.time() // self.task.time_precision)
        if metadata.time > now + MAX_TIME_SKEW:
            return m.ReportError.REPORT_TOO_EARLY
        index = metadata.time
        if self._is_collected(m.Interval(index, 1)):
            return m.ReportError.BATCH_COLLECTED
        marker = metadata.report_id.hex()
        if marker in self.state.data["seen"] or marker in self.state.data["pending"]:
            return m.ReportError.REPORT_REPLAYED
        if report.leader_encrypted_input_share.config_id != self.keys.hpke_config_id:
            return m.ReportError.HPKE_UNKNOWN_CONFIG_ID
        aad = m.InputShareAad(self.task.task_id, self.task.task_configuration,
                              metadata, report.public_share).encode()
        try:
            plaintext = hpke.open_base(
                report.leader_encrypted_input_share.enc, self.keys.hpke_secret,
                input_share_info(m.Role.LEADER),
                report.leader_encrypted_input_share.payload, aad)
        except Exception:
            return m.ReportError.HPKE_DECRYPT_ERROR
        try:
            share = m.PlaintextInputShare.from_bytes(plaintext)
        except m.WireError:
            return m.ReportError.INVALID_MESSAGE
        if share.private_extensions:
            return m.ReportError.UNSUPPORTED_EXTENSION
        try:
            self.vdaf.decode_input_share(0, share.payload)
        except Exception:
            return m.ReportError.INVALID_MESSAGE
        self.state.data["pending"][marker] = {
            "time": index,
            "metadata": _b64(metadata.encode()),
            "public_share": _b64(report.public_share),
            "leader_share": _b64(share.payload),
            "helper_ct": _b64(report.helper_encrypted_input_share.encode()),
        }
        return None

    # --- collection --------------------------------------------------------

    def collection_job(self, body: bytes) -> m.CollectionJobResp:
        """Handle one ``CollectionJobReq`` synchronously (draft-20 §4.6.1)."""
        try:
            request = m.CollectionJobReq.from_bytes(body)
        except m.WireError as exc:
            raise m.DapProblem("invalidMessage", str(exc))
        self._check_extensions(request.extensions)
        self._check_agg_param(request.agg_param)
        interval = self._collection_interval(request)
        if interval.duration != 1:
            raise m.DapProblem(
                "batchInvalid",
                "this task's time_precision is one batch; query exactly one interval")
        digest = hashlib.sha256(body).hexdigest()
        with self.state.lock:
            cached = self.state.data["responses"].get(digest)
            if cached is not None:
                return m.CollectionJobResp.from_bytes(_unb64(cached))
            if self._is_collected(interval):
                raise m.DapProblem("batchOverlap", "this batch was already collected")
            bucket = self._bucket(interval.start)
            candidates = [marker for marker, entry in self.state.data["pending"].items()
                          if entry["time"] == interval.start]
            if bucket is None or int(bucket["count"]) < self.task.min_batch_size:
                if len(candidates) + (int(bucket["count"]) if bucket else 0) < self.task.min_batch_size:
                    raise m.DapProblem(
                        "invalidBatchSize",
                        "batch has {} report(s), the task requires {}".format(
                            len(candidates) + (int(bucket["count"]) if bucket else 0),
                            self.task.min_batch_size))
            if candidates:
                self._aggregate(interval.start, candidates)
            bucket = self._bucket(interval.start) or {"count": 0, "checksum": "00" * 32,
                                                      "agg": ""}
            if int(bucket["count"]) < self.task.min_batch_size:
                raise m.DapProblem(
                    "invalidBatchSize",
                    "only {} report(s) verified, the task requires {}".format(
                        int(bucket["count"]), self.task.min_batch_size))
            response = self._finish_collection(interval, body, bucket)
            self._mark_collected(interval)
            self.state.data["responses"][digest] = _b64(response.encode())
            self.state.save()
            return response

    def _aggregate(self, index: int, candidates: List[str]) -> None:
        """Run one aggregation job with the helper and commit what verifies."""
        ctx = self.task.context()
        inits: List[m.VerifyInit] = []
        states: Dict[str, Any] = {}
        rejected: Dict[str, m.ReportError] = {}
        for marker in candidates:
            entry = self.state.data["pending"][marker]
            metadata = m.ReportMetadata.from_bytes(_unb64(entry["metadata"]))
            public_share = _unb64(entry["public_share"])
            leader_share = _unb64(entry["leader_share"])
            helper_ct = m.HpkeCiphertext.from_bytes(_unb64(entry["helper_ct"]))
            state = self.vdaf.ping_pong_leader_init(
                self.keys.verify_key or b"", ctx, b"", metadata.report_id,
                public_share, leader_share)
            if isinstance(state, Rejected):
                rejected[marker] = m.ReportError.VDAF_VERIFY_ERROR
                continue
            states[marker] = state
            inits.append(m.VerifyInit(
                m.ReportShare(metadata, public_share, helper_ct), state.outbound))
        if not inits:
            return

        url = "{}/tasks/{}/aggregation_jobs".format(
            self.helper_url, self.task.task_id_b64)
        job = m.AggregationJobInitReq(VERIFICATION_KEY_ID, b"", (), tuple(inits))
        status, ctype, payload = post_bytes(
            url, job.encode(), m.MEDIA_AGGREGATION_JOB_INIT_REQ,
            token=self.helper_token, timeout=self.timeout)
        if status != 200:
            raise _problem_from(status, payload, "invalidMessage")
        try:
            response = m.AggregationJobResp.from_bytes(payload)
        except m.WireError as exc:
            raise m.DapProblem("invalidMessage", "bad AggregationJobResp: {}".format(exc))
        expected = [m.ReportMetadata.from_bytes(
            _unb64(self.state.data["pending"][marker]["metadata"])).report_id
            for marker in states]
        actual = [resp.report_id for resp in response.verify_resps]
        if actual != expected:
            raise m.DapProblem(
                "invalidMessage",
                "the helper's report ids do not match the job, in order")

        for marker, resp in zip(states, response.verify_resps):
            if resp.verify_resp_type is m.VerifyRespType.REJECT:
                rejected[marker] = resp.report_error or m.ReportError.VDAF_VERIFY_ERROR
                continue
            if resp.verify_resp_type is not m.VerifyRespType.CONTINUE:
                rejected[marker] = m.ReportError.INVALID_MESSAGE
                continue
            state = self.vdaf.ping_pong_leader_continued(
                ctx, b"", states[marker], resp.payload or b"")
            if not isinstance(state, Finished):
                rejected[marker] = m.ReportError.VDAF_VERIFY_ERROR
                continue
            metadata = m.ReportMetadata.from_bytes(
                _unb64(self.state.data["pending"][marker]["metadata"]))
            error = self._commit(index, metadata.report_id, state.out_share)
            if error is not None:
                rejected[marker] = error
        for marker in candidates:
            self.state.data["pending"].pop(marker, None)
        self.state.save()

    def _finish_collection(self, interval: m.Interval, body: bytes,
                           bucket: Dict[str, Any]) -> m.CollectionJobResp:
        count = int(bucket["count"])
        checksum = bytes.fromhex(bucket["checksum"])
        selector = m.BatchSelector(
            m.BatchMode.TIME_INTERVAL,
            m.TimeIntervalBatchSelectorConfig(interval).encode())
        request = m.AggregateShareReq(body, selector, count, checksum)
        url = "{}/tasks/{}/aggregate_shares".format(
            self.helper_url, self.task.task_id_b64)
        status, ctype, payload = post_bytes(
            url, request.encode(), m.MEDIA_AGGREGATE_SHARE_REQ,
            token=self.helper_token, timeout=self.timeout)
        if status != 200:
            raise _problem_from(status, payload, "batchMismatch")
        try:
            helper_share = m.AggregateShare.from_bytes(payload)
        except m.WireError as exc:
            raise m.DapProblem("invalidMessage", "bad AggregateShare: {}".format(exc))
        aggregate = self.vdaf.decode_agg_share(None, _unb64(bucket["agg"]))
        leader_share = self._encrypt_aggregate_share(aggregate, body)
        return m.CollectionJobResp(count, interval, leader_share,
                                   helper_share.encrypted_aggregate_share)


class Helper(_Aggregator):
    """Verifies report shares, commits output shares, and answers the leader."""

    role = m.Role.HELPER
    name = "helper"

    # --- aggregation jobs --------------------------------------------------

    def aggregation_jobs(self, body: bytes) -> Tuple[str, bytes]:
        """Handle one ``AggregationJobInitReq``; return ``(job id, response)``."""
        try:
            request = m.AggregationJobInitReq.from_bytes(body)
        except m.WireError as exc:
            raise m.DapProblem("invalidMessage", str(exc))
        self._check_extensions(request.extensions)
        self._check_agg_param(request.agg_param)
        job_id = "job_" + base64.urlsafe_b64encode(
            hashlib.sha256(body).digest()[:16]).rstrip(b"=").decode("ascii")
        digest = hashlib.sha256(body).hexdigest()
        with self.state.lock:
            cached = self.state.data["responses"].get(digest)
            if cached is not None:
                return job_id, _unb64(cached)
            responses = [self._verify_init(request.verification_key_id, init)
                         for init in request.verify_inits]
            response = m.AggregationJobResp(tuple(responses))
            self.state.data["responses"][digest] = _b64(response.encode())
            self.state.save()
            return job_id, response.encode()

    def _verify_init(self, key_id: int, init: m.VerifyInit) -> m.VerifyResp:
        metadata = init.report_share.report_metadata
        report_id = metadata.report_id
        if key_id != VERIFICATION_KEY_ID:
            return _reject(report_id, m.ReportError.UNKNOWN_VERIFICATION_KEY_ID)
        if metadata.time > int(time.time() // self.task.time_precision) + MAX_TIME_SKEW:
            return _reject(report_id, m.ReportError.REPORT_TOO_EARLY)
        if metadata.public_extensions:
            return _reject(report_id, m.ReportError.UNSUPPORTED_EXTENSION)
        ciphertext = init.report_share.encrypted_input_share
        if ciphertext.config_id != self.keys.hpke_config_id:
            return _reject(report_id, m.ReportError.HPKE_UNKNOWN_CONFIG_ID)
        public_share = init.report_share.public_share
        aad = m.InputShareAad(self.task.task_id, self.task.task_configuration,
                              metadata, public_share).encode()
        try:
            plaintext = hpke.open_base(
                ciphertext.enc, self.keys.hpke_secret,
                input_share_info(m.Role.HELPER), ciphertext.payload, aad)
            share = m.PlaintextInputShare.from_bytes(plaintext)
        except Exception:
            return _reject(report_id, m.ReportError.HPKE_DECRYPT_ERROR)
        if share.private_extensions:
            return _reject(report_id, m.ReportError.UNSUPPORTED_EXTENSION)
        state = self.vdaf.ping_pong_helper_init(
            self.keys.verify_key or b"", self.task.context(), b"", report_id,
            public_share, share.payload, init.payload)
        if isinstance(state, Rejected):
            return _reject(report_id, m.ReportError.VDAF_VERIFY_ERROR)
        if isinstance(state, FinishedWithOutbound):
            error = self._commit(metadata.time, report_id, state.out_share)
            if error is not None:
                return _reject(report_id, error)
            self.state.save()
            return m.VerifyResp(report_id, m.VerifyRespType.CONTINUE, state.outbound)
        if isinstance(state, Continued):
            # Unreachable for Prio3 (one round); the continuation endpoint will
            # answer stepMismatch because no job state is persisted.
            self.state.save()
            return m.VerifyResp(report_id, m.VerifyRespType.CONTINUE, state.outbound)
        return _reject(report_id, m.ReportError.VDAF_VERIFY_ERROR)

    # --- aggregate shares --------------------------------------------------

    def aggregate_shares(self, body: bytes) -> m.AggregateShare:
        """Handle one ``AggregateShareReq`` (draft-20 §4.6.4)."""
        try:
            request = m.AggregateShareReq.from_bytes(body)
        except m.WireError as exc:
            raise m.DapProblem("invalidMessage", str(exc))
        try:
            collection = m.CollectionJobReq.from_bytes(request.collection_job_req)
        except m.WireError as exc:
            raise m.DapProblem("invalidMessage", "bad collection_job_req: {}".format(exc))
        self._check_extensions(collection.extensions)
        self._check_agg_param(collection.agg_param)
        query_interval = self._collection_interval(collection)
        if request.batch_selector.batch_mode is not m.BatchMode.TIME_INTERVAL:
            raise m.DapProblem("invalidMessage", "only time_interval batches exist")
        try:
            selector_interval = m.TimeIntervalBatchSelectorConfig.from_bytes(
                request.batch_selector.config).batch_interval
        except m.WireError as exc:
            raise m.DapProblem("invalidMessage", "bad batch selector: {}".format(exc))
        if not (query_interval.start <= selector_interval.start
                and selector_interval.start + selector_interval.duration
                <= query_interval.start + query_interval.duration):
            raise m.DapProblem("invalidMessage",
                               "the batch selector is not inside the query")
        if query_interval.duration != 1 or selector_interval.duration != 1:
            raise m.DapProblem(
                "batchInvalid",
                "this task's time_precision is one batch; select exactly one interval")
        digest = hashlib.sha256(body).hexdigest()
        with self.state.lock:
            cached = self.state.data["responses"].get(digest)
            if cached is not None:
                return m.AggregateShare.from_bytes(_unb64(cached))
            if self._is_collected(selector_interval):
                raise m.DapProblem("batchOverlap", "this batch was already collected")
            bucket = self._bucket(selector_interval.start)
            count = int(bucket["count"]) if bucket else 0
            if count < self.task.min_batch_size:
                raise m.DapProblem(
                    "invalidBatchSize",
                    "batch has {} verified report(s), the task requires {}".format(
                        count, self.task.min_batch_size))
            checksum = bytes.fromhex(bucket["checksum"])
            if count != request.report_count or checksum != request.checksum:
                raise m.DapProblem(
                    "batchMismatch",
                    "the leader says {} report(s); this helper committed {}".format(
                        request.report_count, count))
            aggregate = self.vdaf.decode_agg_share(None, _unb64(bucket["agg"]))
            share = m.AggregateShare(
                self._encrypt_aggregate_share(aggregate, request.collection_job_req))
            self._mark_collected(selector_interval)
            self.state.data["responses"][digest] = _b64(share.encode())
            self.state.save()
            return share


def _reject(report_id: bytes, error: m.ReportError) -> m.VerifyResp:
    return m.VerifyResp(report_id, m.VerifyRespType.REJECT, report_error=error)

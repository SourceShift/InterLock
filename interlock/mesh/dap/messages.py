"""DAP message structures (draft-ietf-ppm-dap-20).

Every class here is a frozen dataclass with ``encode()`` and a
``decode(reader)`` classmethod, and the byte layout is the draft's, field for
field. Two fields deserve a note because they appear to be opaque and are not:

* ``AggregateShareReq.collection_job_req`` is a nested ``CollectionJobReq``
  structure, not a length-prefixed blob. It is kept as the raw bytes the
  Collector sent, because those exact bytes are the HPKE AAD of the aggregate
  share; re-encoding a decoded copy would work only while our encoder is
  canonical, and the AAD must survive a peer whose encoder is not.
* ``Query.config`` and ``BatchSelector.config`` *are* opaque, because their
  layout depends on the batch mode.

Media types are constants at the bottom; DAP spells them
``application/ppm-dap;message=<value>``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import List, Optional, Sequence, Tuple, Type, TypeVar

from . import wire
from .wire import Reader, WireError, Writer

M = TypeVar("M", bound="_Message")


# --- Enumerations ---------------------------------------------------------

class Role(IntEnum):
    COLLECTOR = 0
    CLIENT = 1
    LEADER = 2
    HELPER = 3


class BatchMode(IntEnum):
    TIME_INTERVAL = 1
    LEADER_SELECTED = 2

    @classmethod
    def _missing_(cls, value: object) -> None:
        raise WireError("invalid BatchMode {!r}".format(value))


class ReportError(IntEnum):
    BATCH_COLLECTED = 1
    REPORT_REPLAYED = 2
    REPORT_DROPPED = 3
    HPKE_UNKNOWN_CONFIG_ID = 4
    HPKE_DECRYPT_ERROR = 5
    VDAF_VERIFY_ERROR = 6
    INVALID_MESSAGE = 7
    REPORT_TOO_EARLY = 8
    UNKNOWN_VERIFICATION_KEY_ID = 9
    UNSUPPORTED_EXTENSION = 10

    @classmethod
    def _missing_(cls, value: object) -> None:
        raise WireError("invalid ReportError {!r}".format(value))


class VerifyRespType(IntEnum):
    CONTINUE = 0
    FINISH = 1
    REJECT = 2

    @classmethod
    def _missing_(cls, value: object) -> None:
        raise WireError("invalid VerifyRespType {!r}".format(value))


class TaskExtensionType(IntEnum):
    TASK_INTERVAL = 1


VDAF_TYPE_PRIO3_SUM_VEC = 0x00000003


# --- Common helpers -------------------------------------------------------

class _Message:
    def encode(self) -> bytes:  # pragma: no cover - overridden everywhere
        raise NotImplementedError

    @classmethod
    def decode(cls: Type[M], reader: Reader) -> M:  # pragma: no cover
        raise NotImplementedError

    @classmethod
    def from_bytes(cls: Type[M], data: bytes) -> M:
        return wire.decode(data, cls.decode)


def _encode_all(items: Sequence["_Message"]) -> List[bytes]:
    return [item.encode() for item in items]


@dataclass(frozen=True)
class Interval(_Message):
    start: int
    duration: int

    def encode(self) -> bytes:
        return Writer().uint64(self.start).uint64(self.duration).bytes()

    @classmethod
    def decode(cls, reader: Reader) -> "Interval":
        return cls(reader.uint64(), reader.uint64())

    def __post_init__(self) -> None:
        if self.start < 0 or self.duration < 1:
            raise WireError("Interval needs start >= 0 and duration >= 1")

    def contains(self, time: int) -> bool:
        return self.start <= time < self.start + self.duration


@dataclass(frozen=True)
class Extension(_Message):
    """Report, task, aggregation-job and collection-job extensions.

    All four are ``uint16 extension_type; opaque extension_data<0..2^16-1>``,
    so one class serves them and the caller knows which meaning applies.
    """

    extension_type: int
    data: bytes

    def encode(self) -> bytes:
        return Writer().uint16(self.extension_type).var_opaque(self.data, 2).bytes()

    @classmethod
    def decode(cls, reader: Reader) -> "Extension":
        return cls(reader.uint16(), reader.var_opaque(2))


def _decode_extensions(reader: Reader) -> List[Extension]:
    return reader.vector(Extension.decode, 2)


def _check_extension_order(extensions: Sequence[Extension]) -> None:
    types = [extension.extension_type for extension in extensions]
    if types != sorted(set(types)):
        raise WireError("extensions are not in strictly increasing order")


@dataclass(frozen=True)
class HpkeCiphertext(_Message):
    config_id: int
    enc: bytes
    payload: bytes

    def encode(self) -> bytes:
        return (Writer()
                .uint8(self.config_id)
                .var_opaque(self.enc, 2)
                .var_opaque(self.payload, 4)
                .bytes())

    @classmethod
    def decode(cls, reader: Reader) -> "HpkeCiphertext":
        return cls(reader.uint8(), reader.var_opaque(2), reader.var_opaque(4))


@dataclass(frozen=True)
class HpkeConfig(_Message):
    config_id: int
    kem_id: int
    kdf_id: int
    aead_id: int
    public_key: bytes

    def encode(self) -> bytes:
        return (Writer()
                .uint8(self.config_id)
                .uint16(self.kem_id)
                .uint16(self.kdf_id)
                .uint16(self.aead_id)
                .var_opaque(self.public_key, 2)
                .bytes())

    @classmethod
    def decode(cls, reader: Reader) -> "HpkeConfig":
        return cls(reader.uint8(), reader.uint16(), reader.uint16(),
                   reader.uint16(), reader.var_opaque(2))


@dataclass(frozen=True)
class HpkeConfigList(_Message):
    configs: Tuple[HpkeConfig, ...]

    def encode(self) -> bytes:
        return Writer().vector(_encode_all(self.configs), 2).bytes()

    @classmethod
    def decode(cls, reader: Reader) -> "HpkeConfigList":
        return cls(tuple(reader.vector(HpkeConfig.decode, 2)))


# --- Reports --------------------------------------------------------------

@dataclass(frozen=True)
class ReportMetadata(_Message):
    report_id: bytes
    time: int
    public_extensions: Tuple[Extension, ...] = ()

    def __post_init__(self) -> None:
        if len(self.report_id) != 16:
            raise WireError("ReportID must be 16 bytes")
        _check_extension_order(self.public_extensions)

    def encode(self) -> bytes:
        return (Writer()
                .raw(self.report_id)
                .uint64(self.time)
                .vector(_encode_all(self.public_extensions), 2)
                .bytes())

    @classmethod
    def decode(cls, reader: Reader) -> "ReportMetadata":
        report_id = reader.opaque(16)
        time = reader.uint64()
        extensions = tuple(_decode_extensions(reader))
        _check_extension_order(extensions)
        return cls(report_id, time, extensions)


@dataclass(frozen=True)
class Report(_Message):
    metadata: ReportMetadata
    public_share: bytes
    leader_encrypted_input_share: HpkeCiphertext
    helper_encrypted_input_share: HpkeCiphertext

    def encode(self) -> bytes:
        return (self.metadata.encode()
                + Writer().var_opaque(self.public_share, 4).bytes()
                + self.leader_encrypted_input_share.encode()
                + self.helper_encrypted_input_share.encode())

    @classmethod
    def decode(cls, reader: Reader) -> "Report":
        return cls(ReportMetadata.decode(reader), reader.var_opaque(4),
                   HpkeCiphertext.decode(reader), HpkeCiphertext.decode(reader))


@dataclass(frozen=True)
class UploadRequest(_Message):
    """``Report reports[message_length]`` — the whole request body."""

    reports: Tuple[Report, ...]

    def encode(self) -> bytes:
        return b"".join(report.encode() for report in self.reports)

    @classmethod
    def decode(cls, reader: Reader) -> "UploadRequest":
        return cls(tuple(reader.rest(Report.decode)))


@dataclass(frozen=True)
class ReportUploadStatus(_Message):
    report_id: bytes
    error: ReportError

    def encode(self) -> bytes:
        if len(self.report_id) != 16:
            raise WireError("ReportID must be 16 bytes")
        return Writer().raw(self.report_id).uint8(int(self.error)).bytes()

    @classmethod
    def decode(cls, reader: Reader) -> "ReportUploadStatus":
        return cls(reader.opaque(16), ReportError(reader.uint8()))


@dataclass(frozen=True)
class UploadErrors(_Message):
    statuses: Tuple[ReportUploadStatus, ...]

    def encode(self) -> bytes:
        return b"".join(status.encode() for status in self.statuses)

    @classmethod
    def decode(cls, reader: Reader) -> "UploadErrors":
        return cls(tuple(reader.rest(ReportUploadStatus.decode)))


@dataclass(frozen=True)
class PlaintextInputShare(_Message):
    private_extensions: Tuple[Extension, ...]
    payload: bytes

    def __post_init__(self) -> None:
        _check_extension_order(self.private_extensions)

    def encode(self) -> bytes:
        return (Writer()
                .vector(_encode_all(self.private_extensions), 2)
                .var_opaque(self.payload, 4)
                .bytes())

    @classmethod
    def decode(cls, reader: Reader) -> "PlaintextInputShare":
        extensions = tuple(_decode_extensions(reader))
        _check_extension_order(extensions)
        return cls(extensions, reader.var_opaque(4))


@dataclass(frozen=True)
class InputShareAad(_Message):
    task_id: bytes
    task_configuration: bytes
    report_metadata: ReportMetadata
    public_share: bytes

    def encode(self) -> bytes:
        if len(self.task_id) != 32:
            raise WireError("TaskID must be 32 bytes")
        return (Writer()
                .raw(self.task_id)
                .raw(self.task_configuration)
                .raw(self.report_metadata.encode())
                .var_opaque(self.public_share, 4)
                .bytes())

    @classmethod
    def decode(cls, reader: Reader) -> "InputShareAad":
        return cls(reader.opaque(32), _decode_task_configuration_raw(reader),
                   ReportMetadata.decode(reader), reader.var_opaque(4))


@dataclass(frozen=True)
class ReportShare(_Message):
    report_metadata: ReportMetadata
    public_share: bytes
    encrypted_input_share: HpkeCiphertext

    def encode(self) -> bytes:
        return (self.report_metadata.encode()
                + Writer().var_opaque(self.public_share, 4).bytes()
                + self.encrypted_input_share.encode())

    @classmethod
    def decode(cls, reader: Reader) -> "ReportShare":
        return cls(ReportMetadata.decode(reader), reader.var_opaque(4),
                   HpkeCiphertext.decode(reader))


# --- Task configuration ---------------------------------------------------

@dataclass(frozen=True)
class TaskConfiguration(_Message):
    task_info: bytes
    leader_aggregator_endpoint: str
    helper_aggregator_endpoint: str
    time_precision: int
    min_batch_size: int
    batch_mode: BatchMode
    batch_config: bytes
    vdaf_type: int
    vdaf_configuration: bytes
    extensions: Tuple[Extension, ...] = ()

    def encode(self) -> bytes:
        if self.batch_mode is not BatchMode.TIME_INTERVAL:
            raise WireError("this deployment only supports time_interval batches")
        if self.batch_config:
            raise WireError("time_interval takes an empty batch_config")
        _check_extension_order(self.extensions)
        return (Writer()
                .var_opaque(self.task_info, 1)
                .var_opaque(self.leader_aggregator_endpoint.encode("ascii"), 2)
                .var_opaque(self.helper_aggregator_endpoint.encode("ascii"), 2)
                .uint64(self.time_precision)
                .uint64(self.min_batch_size)
                .uint8(int(self.batch_mode))
                .var_opaque(self.batch_config, 2)
                .uint32(self.vdaf_type)
                .var_opaque(self.vdaf_configuration, 2)
                .vector(_encode_all(self.extensions), 2)
                .bytes())

    @classmethod
    def decode(cls, reader: Reader) -> "TaskConfiguration":
        return cls(
            task_info=reader.var_opaque(1),
            leader_aggregator_endpoint=reader.var_opaque(2).decode("ascii"),
            helper_aggregator_endpoint=reader.var_opaque(2).decode("ascii"),
            time_precision=reader.uint64(),
            min_batch_size=reader.uint64(),
            batch_mode=BatchMode(reader.uint8()),
            batch_config=reader.var_opaque(2),
            vdaf_type=reader.uint32(),
            vdaf_configuration=reader.var_opaque(2),
            extensions=tuple(_decode_extensions(reader)),
        )


def _decode_task_configuration_raw(reader: Reader) -> bytes:
    """Read a nested TaskConfiguration and return the bytes it occupied."""
    start = reader.offset
    TaskConfiguration.decode(reader)
    return reader.since(start)


@dataclass(frozen=True)
class Prio3SumVecConfig(_Message):
    length: int
    max_measurement: int
    chunk_length: int

    def encode(self) -> bytes:
        return (Writer()
                .uint32(self.length)
                .uint64(self.max_measurement)
                .uint32(self.chunk_length)
                .bytes())

    @classmethod
    def decode(cls, reader: Reader) -> "Prio3SumVecConfig":
        return cls(reader.uint32(), reader.uint64(), reader.uint32())


# --- Aggregation ----------------------------------------------------------

@dataclass(frozen=True)
class VerifyInit(_Message):
    report_share: ReportShare
    payload: bytes

    def encode(self) -> bytes:
        return self.report_share.encode() + Writer().var_opaque(self.payload, 4).bytes()

    @classmethod
    def decode(cls, reader: Reader) -> "VerifyInit":
        return cls(ReportShare.decode(reader), reader.var_opaque(4))


@dataclass(frozen=True)
class VerifyResp(_Message):
    report_id: bytes
    verify_resp_type: VerifyRespType
    payload: bytes = b""
    report_error: Optional[ReportError] = None

    def encode(self) -> bytes:
        if len(self.report_id) != 16:
            raise WireError("ReportID must be 16 bytes")
        writer = Writer().raw(self.report_id).uint8(int(self.verify_resp_type))
        if self.verify_resp_type is VerifyRespType.CONTINUE:
            writer.var_opaque(self.payload, 4)
        elif self.verify_resp_type is VerifyRespType.REJECT:
            if self.report_error is None:
                raise WireError("a reject response needs a ReportError")
            writer.uint8(int(self.report_error))
        return writer.bytes()

    @classmethod
    def decode(cls, reader: Reader) -> "VerifyResp":
        report_id = reader.opaque(16)
        resp_type = VerifyRespType(reader.uint8())
        if resp_type is VerifyRespType.CONTINUE:
            return cls(report_id, resp_type, reader.var_opaque(4))
        if resp_type is VerifyRespType.REJECT:
            return cls(report_id, resp_type, report_error=ReportError(reader.uint8()))
        return cls(report_id, resp_type)


@dataclass(frozen=True)
class AggregationJobInitReq(_Message):
    verification_key_id: int
    agg_param: bytes
    extensions: Tuple[Extension, ...]
    verify_inits: Tuple[VerifyInit, ...]

    def encode(self) -> bytes:
        # ``verify_inits[verify_inits_length]`` is the rest of the message, so
        # the runs concatenate with no length prefix of their own.
        _check_extension_order(self.extensions)
        return (Writer()
                .uint8(self.verification_key_id)
                .var_opaque(self.agg_param, 4)
                .vector(_encode_all(self.extensions), 2)
                .raw(b"".join(item.encode() for item in self.verify_inits))
                .bytes())

    @classmethod
    def decode(cls, reader: Reader) -> "AggregationJobInitReq":
        verification_key_id = reader.uint8()
        agg_param = reader.var_opaque(4)
        extensions = tuple(_decode_extensions(reader))
        _check_extension_order(extensions)
        return cls(verification_key_id, agg_param, extensions,
                   tuple(reader.rest(VerifyInit.decode)))


@dataclass(frozen=True)
class AggregationJobResp(_Message):
    verify_resps: Tuple[VerifyResp, ...]

    def encode(self) -> bytes:
        return b"".join(item.encode() for item in self.verify_resps)

    @classmethod
    def decode(cls, reader: Reader) -> "AggregationJobResp":
        return cls(tuple(reader.rest(VerifyResp.decode)))


@dataclass(frozen=True)
class VerifyContinue(_Message):
    report_id: bytes
    payload: bytes

    def encode(self) -> bytes:
        if len(self.report_id) != 16:
            raise WireError("ReportID must be 16 bytes")
        return Writer().raw(self.report_id).var_opaque(self.payload, 4).bytes()

    @classmethod
    def decode(cls, reader: Reader) -> "VerifyContinue":
        return cls(reader.opaque(16), reader.var_opaque(4))


@dataclass(frozen=True)
class AggregationJobContinueReq(_Message):
    step: int
    verify_continues: Tuple[VerifyContinue, ...]

    def encode(self) -> bytes:
        return (Writer()
                .uint16(self.step)
                .vector([item.encode() for item in self.verify_continues], 2)
                .bytes())

    @classmethod
    def decode(cls, reader: Reader) -> "AggregationJobContinueReq":
        step = reader.uint16()
        return cls(step, tuple(reader.vector(VerifyContinue.decode, 2)))


# --- Collection -----------------------------------------------------------

@dataclass(frozen=True)
class Query(_Message):
    batch_mode: BatchMode
    config: bytes

    def encode(self) -> bytes:
        return Writer().uint8(int(self.batch_mode)).var_opaque(self.config, 2).bytes()

    @classmethod
    def decode(cls, reader: Reader) -> "Query":
        return cls(BatchMode(reader.uint8()), reader.var_opaque(2))


@dataclass(frozen=True)
class TimeIntervalQueryConfig(_Message):
    batch_interval: Interval

    def encode(self) -> bytes:
        return self.batch_interval.encode()

    @classmethod
    def decode(cls, reader: Reader) -> "TimeIntervalQueryConfig":
        return cls(Interval.decode(reader))


@dataclass(frozen=True)
class CollectionJobReq(_Message):
    query: Query
    agg_param: bytes
    extensions: Tuple[Extension, ...] = ()

    def encode(self) -> bytes:
        _check_extension_order(self.extensions)
        return (self.query.encode()
                + Writer().var_opaque(self.agg_param, 4).bytes()
                + Writer().vector(_encode_all(self.extensions), 2).bytes())

    @classmethod
    def decode(cls, reader: Reader) -> "CollectionJobReq":
        query = Query.decode(reader)
        agg_param = reader.var_opaque(4)
        extensions = tuple(_decode_extensions(reader))
        _check_extension_order(extensions)
        return cls(query, agg_param, extensions)

    @property
    def batch_interval(self) -> Interval:
        if self.query.batch_mode is not BatchMode.TIME_INTERVAL:
            raise WireError("not a time_interval query")
        return TimeIntervalQueryConfig.from_bytes(self.query.config).batch_interval


@dataclass(frozen=True)
class BatchSelector(_Message):
    batch_mode: BatchMode
    config: bytes

    def encode(self) -> bytes:
        return Writer().uint8(int(self.batch_mode)).var_opaque(self.config, 2).bytes()

    @classmethod
    def decode(cls, reader: Reader) -> "BatchSelector":
        return cls(BatchMode(reader.uint8()), reader.var_opaque(2))

    @property
    def batch_interval(self) -> Interval:
        if self.batch_mode is not BatchMode.TIME_INTERVAL:
            raise WireError("not a time_interval selector")
        return TimeIntervalBatchSelectorConfig.from_bytes(self.config).batch_interval


@dataclass(frozen=True)
class TimeIntervalBatchSelectorConfig(_Message):
    batch_interval: Interval

    def encode(self) -> bytes:
        return self.batch_interval.encode()

    @classmethod
    def decode(cls, reader: Reader) -> "TimeIntervalBatchSelectorConfig":
        return cls(Interval.decode(reader))


@dataclass(frozen=True)
class AggregateShareReq(_Message):
    collection_job_req: bytes
    batch_selector: BatchSelector
    report_count: int
    checksum: bytes

    def encode(self) -> bytes:
        if len(self.checksum) != 32:
            raise WireError("the batch checksum is 32 bytes")
        return (Writer()
                .raw(self.collection_job_req)
                .raw(self.batch_selector.encode())
                .uint64(self.report_count)
                .raw(self.checksum)
                .bytes())

    @classmethod
    def decode(cls, reader: Reader) -> "AggregateShareReq":
        start = reader.offset
        CollectionJobReq.decode(reader)
        collection_job_req = reader.since(start)
        return cls(collection_job_req, BatchSelector.decode(reader),
                   reader.uint64(), reader.opaque(32))


@dataclass(frozen=True)
class AggregateShare(_Message):
    encrypted_aggregate_share: HpkeCiphertext

    def encode(self) -> bytes:
        return self.encrypted_aggregate_share.encode()

    @classmethod
    def decode(cls, reader: Reader) -> "AggregateShare":
        return cls(HpkeCiphertext.decode(reader))


@dataclass(frozen=True)
class AggregateShareAad(_Message):
    task_id: bytes
    task_configuration: bytes
    collection_job_req: bytes

    def encode(self) -> bytes:
        if len(self.task_id) != 32:
            raise WireError("TaskID must be 32 bytes")
        return Writer().raw(self.task_id).raw(self.task_configuration).raw(
            self.collection_job_req).bytes()

    @classmethod
    def decode(cls, reader: Reader) -> "AggregateShareAad":
        task_id = reader.opaque(32)
        task_configuration = _decode_task_configuration_raw(reader)
        start = reader.offset
        CollectionJobReq.decode(reader)
        return cls(task_id, task_configuration, reader.since(start))


@dataclass(frozen=True)
class CollectionJobResp(_Message):
    report_count: int
    interval: Interval
    leader_encrypted_agg_share: HpkeCiphertext
    helper_encrypted_agg_share: HpkeCiphertext

    def encode(self) -> bytes:
        return (Writer().uint64(self.report_count).bytes()
                + self.interval.encode()
                + self.leader_encrypted_agg_share.encode()
                + self.helper_encrypted_agg_share.encode())

    @classmethod
    def decode(cls, reader: Reader) -> "CollectionJobResp":
        return cls(reader.uint64(), Interval.decode(reader),
                   HpkeCiphertext.decode(reader), HpkeCiphertext.decode(reader))


# --- Media types and problem details -------------------------------------

MEDIA_TYPE_PREFIX = "application/ppm-dap;message="

MEDIA_HPKE_CONFIG_LIST = MEDIA_TYPE_PREFIX + "hpke-config-list"
MEDIA_UPLOAD_REQ = MEDIA_TYPE_PREFIX + "upload-req"
MEDIA_UPLOAD_ERRORS = MEDIA_TYPE_PREFIX + "upload-errors"
MEDIA_AGGREGATION_JOB_INIT_REQ = MEDIA_TYPE_PREFIX + "aggregation-job-init-req"
MEDIA_AGGREGATION_JOB_CONTINUE_REQ = MEDIA_TYPE_PREFIX + "aggregation-job-continue-req"
MEDIA_AGGREGATION_JOB_RESP = MEDIA_TYPE_PREFIX + "aggregation-job-resp"
MEDIA_AGGREGATE_SHARE_REQ = MEDIA_TYPE_PREFIX + "aggregate-share-req"
MEDIA_AGGREGATE_SHARE = MEDIA_TYPE_PREFIX + "aggregate-share"
MEDIA_COLLECTION_JOB_REQ = MEDIA_TYPE_PREFIX + "collection-job-req"
MEDIA_COLLECTION_JOB_RESP = MEDIA_TYPE_PREFIX + "collection-job-resp"
MEDIA_PROBLEM_JSON = "application/problem+json"

PROBLEM_URN_PREFIX = "urn:ietf:params:ppm:dap:error:"

PROBLEM_TYPES = (
    "invalidMessage",
    "unrecognizedTask",
    "unrecognizedAggregationJob",
    "batchInvalid",
    "invalidBatchSize",
    "invalidAggregationParameter",
    "batchMismatch",
    "stepMismatch",
    "batchOverlap",
    "unsupportedExtension",
    "invalidExtension",
)


class DapProblem(Exception):
    """A DAP error that turns into an RFC 9457 problem document."""

    def __init__(self, problem_type: str, detail: str = "",
                 status: int = 400, task_id: Optional[bytes] = None):
        if problem_type not in PROBLEM_TYPES:
            raise ValueError("unknown DAP problem type {!r}".format(problem_type))
        super().__init__(detail or problem_type)
        self.problem_type = problem_type
        self.detail = detail
        self.status = status
        self.task_id = task_id

    @property
    def type_urn(self) -> str:
        return PROBLEM_URN_PREFIX + self.problem_type

    def to_json(self) -> dict:
        import base64

        document = {
            "title": self.problem_type,
            "type": self.type_urn,
            "status": self.status,
        }
        if self.detail:
            document["detail"] = self.detail
        if self.task_id is not None:
            document["taskid"] = base64.urlsafe_b64encode(
                self.task_id).rstrip(b"=").decode("ascii")
        return document

    def __str__(self) -> str:
        return "{}: {}".format(self.problem_type, self.detail) if self.detail \
            else self.problem_type

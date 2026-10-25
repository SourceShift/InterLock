"""DAP draft-20 wire codec: exact layouts, round trips and hostile input."""

import json

import pytest

from interlock.mesh.dap import messages as m
from interlock.mesh.dap import wire
from interlock.mesh.dap.wire import Reader, WireError, Writer


def _ciphertext(config_id=1, enc=b"\x01\x02", payload=b"\x03\x04\x05"):
    return m.HpkeCiphertext(config_id, enc, payload)


def _metadata(report_id=bytes(range(16)), time=17419860):
    return m.ReportMetadata(report_id, time)


# --- Primitives -----------------------------------------------------------

def test_integers_round_trip():
    data = (Writer()
            .uint8(0xFF).uint16(0xBEEF).uint32(0xDEADBEEF).uint64(0x0102030405060708)
            .bytes())
    assert data.hex() == "ffbeefdeadbeef0102030405060708"
    reader = Reader(data)
    assert reader.uint8() == 0xFF
    assert reader.uint16() == 0xBEEF
    assert reader.uint32() == 0xDEADBEEF
    assert reader.uint64() == 0x0102030405060708
    reader.finish()


def test_integer_overflow_is_refused_not_truncated():
    with pytest.raises(WireError):
        Writer().uint8(256)
    with pytest.raises(WireError):
        Writer().uint16(-1)


def test_truncation_and_trailing_bytes_are_errors():
    with pytest.raises(WireError):
        Reader(b"\x00\x01").uint32()
    with pytest.raises(WireError):
        wire.decode(b"\x01\x00", lambda reader: reader.uint8())
    with pytest.raises(WireError):
        Reader(b"\x00\x05abc").var_opaque(2)


def test_vector_length_larger_than_the_message_is_an_error():
    reader = Reader(b"\x00\xff\x01")
    with pytest.raises(WireError):
        reader.vector(lambda r: r.uint8())


def test_variable_opaque_vec_lengths():
    assert Writer().var_opaque(b"abc", 1).bytes() == b"\x03abc"
    assert Writer().var_opaque(b"abc", 4).bytes() == b"\x00\x00\x00\x03abc"


# --- Structures -----------------------------------------------------------

def test_report_metadata_layout():
    encoded = _metadata().encode()
    assert len(encoded) == 16 + 8 + 2
    assert encoded[:16] == bytes(range(16))
    assert encoded[16:24] == (17419860).to_bytes(8, "big")
    assert encoded[24:] == b"\x00\x00"
    assert m.ReportMetadata.from_bytes(encoded) == _metadata()


def test_hpke_ciphertext_layout():
    assert _ciphertext().encode().hex() == "01" "0002" "0102" "00000003" "030405"


def test_hpke_config_and_list_round_trip():
    config = m.HpkeConfig(1, 0x0020, 0x0001, 0x0001, bytes(range(32)))
    encoded = config.encode()
    # id, kem, kdf, aead, then a 2-byte length and the key.
    assert encoded[:7] == b"\x01\x00\x20\x00\x01\x00\x01"
    assert encoded[7:9] == b"\x00\x20"
    configs = m.HpkeConfigList((config,))
    assert m.HpkeConfigList.from_bytes(configs.encode()) == configs
    assert len(configs.encode()) == 2 + len(encoded)


def test_report_round_trip():
    report = m.Report(_metadata(), b"public", _ciphertext(1), _ciphertext(2))
    encoded = report.encode()
    assert m.Report.from_bytes(encoded) == report
    # public_share is <0..2^32-1>: a 4-byte prefix.
    offset = 16 + 8 + 2
    assert encoded[offset:offset + 4] == b"\x00\x00\x00\x06"
    assert encoded[offset + 4:offset + 10] == b"public"


def test_upload_request_is_a_bare_concatenation():
    reports = (
        m.Report(_metadata(b"\x00" * 16, 10), b"", _ciphertext(), _ciphertext()),
        m.Report(_metadata(b"\x01" * 16, 11), b"", _ciphertext(), _ciphertext()),
    )
    request = m.UploadRequest(reports)
    encoded = request.encode()
    assert encoded == reports[0].encode() + reports[1].encode()
    assert m.UploadRequest.from_bytes(encoded) == request
    assert m.UploadRequest.from_bytes(b"") == m.UploadRequest(())


def test_upload_errors_round_trip_and_reserved_codes_are_rejected():
    errors = m.UploadErrors((
        m.ReportUploadStatus(b"\x00" * 16, m.ReportError.REPORT_REPLAYED),
        m.ReportUploadStatus(b"\x01" * 16, m.ReportError.VDAF_VERIFY_ERROR),
    ))
    encoded = errors.encode()
    assert len(encoded) == 2 * 17
    assert m.UploadErrors.from_bytes(encoded) == errors
    with pytest.raises(WireError):
        m.UploadErrors.from_bytes(b"\x00" * 16 + b"\x00")
    with pytest.raises(WireError):
        m.UploadErrors.from_bytes(b"\x00" * 16 + b"\x7f")


def test_plaintext_input_share_round_trip():
    share = m.PlaintextInputShare((m.Extension(1, b"x"),), b"payload")
    encoded = share.encode()
    assert encoded[:2] == b"\x00\x05"  # one extension: type + length + 1 byte
    assert m.PlaintextInputShare.from_bytes(encoded) == share


def test_input_share_aad_layout():
    aad = m.InputShareAad(b"\xaa" * 32, b"CONFIG", _metadata(), b"public")
    encoded = aad.encode()
    assert encoded[:32] == b"\xaa" * 32
    assert encoded[32:38] == b"CONFIG"
    assert encoded[38:64] == _metadata().encode()
    assert encoded[64:] == b"\x00\x00\x00\x06public"


def test_task_configuration_round_trip_and_defaults():
    config = m.TaskConfiguration(
        task_info=b"manifest-digest",
        leader_aggregator_endpoint="https://leader.example",
        helper_aggregator_endpoint="https://helper.example",
        time_precision=86400,
        min_batch_size=10,
        batch_mode=m.BatchMode.TIME_INTERVAL,
        batch_config=b"",
        vdaf_type=m.VDAF_TYPE_PRIO3_SUM_VEC,
        vdaf_configuration=m.Prio3SumVecConfig(2401, 65535, 196).encode(),
    )
    encoded = config.encode()
    assert m.TaskConfiguration.from_bytes(encoded) == config
    # task_info is <0..2^8-1>, so a one-byte prefix.
    assert encoded[:1] == b"\x0f"
    # A second encoding is byte-identical: the AAD depends on it.
    assert config.encode() == encoded


def test_task_configuration_refuses_leader_selected_batches():
    config = m.TaskConfiguration(
        b"", "https://leader", "https://helper", 86400, 10,
        m.BatchMode.LEADER_SELECTED, b"", m.VDAF_TYPE_PRIO3_SUM_VEC, b"")
    with pytest.raises(WireError):
        config.encode()


def test_prio3_sumvec_config_layout():
    assert m.Prio3SumVecConfig(2401, 65535, 196).encode().hex() == (
        "00000961" "000000000000ffff" "000000c4")


def test_verify_init_and_init_req_have_no_vector_prefix_for_inits():
    share = m.ReportShare(_metadata(), b"ps", _ciphertext(2))
    init = m.VerifyInit(share, b"leader-message")
    request = m.AggregationJobInitReq(0, b"", (), (init,))
    encoded = request.encode()
    assert encoded[:1] == b"\x00"                 # verification_key_id
    assert encoded[1:5] == b"\x00\x00\x00\x00"    # empty agg_param
    assert encoded[5:7] == b"\x00\x00"            # no extensions
    assert encoded[7:] == init.encode()           # everything else is inits
    assert m.AggregationJobInitReq.from_bytes(encoded) == request


def test_verify_resp_layouts():
    report_id = b"\x11" * 16
    cont = m.VerifyResp(report_id, m.VerifyRespType.CONTINUE, b"opaque")
    assert cont.encode() == report_id + b"\x00" + b"\x00\x00\x00\x06opaque"
    assert m.VerifyResp.from_bytes(cont.encode()) == cont

    fin = m.VerifyResp(report_id, m.VerifyRespType.FINISH)
    assert fin.encode() == report_id + b"\x01"
    assert m.VerifyResp.from_bytes(fin.encode()) == fin

    rej = m.VerifyResp(report_id, m.VerifyRespType.REJECT,
                       report_error=m.ReportError.VDAF_VERIFY_ERROR)
    assert rej.encode() == report_id + b"\x02\x06"
    assert m.VerifyResp.from_bytes(rej.encode()) == rej

    with pytest.raises(WireError):
        m.VerifyResp(report_id, m.VerifyRespType.REJECT).encode()


def test_aggregation_job_resp_round_trip():
    resp = m.AggregationJobResp((
        m.VerifyResp(b"\x00" * 16, m.VerifyRespType.FINISH),
        m.VerifyResp(b"\x01" * 16, m.VerifyRespType.REJECT,
                     report_error=m.ReportError.HPKE_DECRYPT_ERROR),
    ))
    assert m.AggregationJobResp.from_bytes(resp.encode()) == resp


def test_aggregation_job_continue_req_round_trip():
    request = m.AggregationJobContinueReq(1, (
        m.VerifyContinue(b"\x00" * 16, b"next"),
    ))
    assert m.AggregationJobContinueReq.from_bytes(request.encode()) == request


def test_collection_job_req_and_interval():
    interval = m.Interval(19600, 1)
    query = m.Query(m.BatchMode.TIME_INTERVAL,
                    m.TimeIntervalQueryConfig(interval).encode())
    request = m.CollectionJobReq(query, b"", ())
    encoded = request.encode()
    assert m.CollectionJobReq.from_bytes(encoded) == request
    assert request.batch_interval == interval
    assert encoded[:1] == b"\x01"  # time_interval


def test_aggregate_share_req_keeps_the_raw_collection_job_req():
    query = m.Query(m.BatchMode.TIME_INTERVAL,
                    m.TimeIntervalQueryConfig(m.Interval(19600, 1)).encode())
    collection = m.CollectionJobReq(query, b"", ())
    request = m.AggregateShareReq(
        collection.encode(),
        m.BatchSelector(m.BatchMode.TIME_INTERVAL,
                        m.TimeIntervalBatchSelectorConfig(m.Interval(19600, 1)).encode()),
        report_count=10,
        checksum=b"\x77" * 32,
    )
    decoded = m.AggregateShareReq.from_bytes(request.encode())
    assert decoded == request
    assert decoded.collection_job_req == collection.encode()


def test_aggregate_share_aad_is_task_aad_plus_collection_req():
    collection = m.CollectionJobReq(
        m.Query(m.BatchMode.TIME_INTERVAL,
                m.TimeIntervalQueryConfig(m.Interval(19600, 1)).encode()), b"", ())
    aad = m.AggregateShareAad(b"\x00" * 32, b"CONFIG", collection.encode())
    assert aad.encode() == b"\x00" * 32 + b"CONFIG" + collection.encode()


def test_collection_job_resp_round_trip():
    resp = m.CollectionJobResp(1000, m.Interval(19600, 1), _ciphertext(9), _ciphertext(9))
    assert m.CollectionJobResp.from_bytes(resp.encode()) == resp


# --- Extensions -----------------------------------------------------------

def test_extensions_must_be_strictly_increasing():
    with pytest.raises(WireError):
        m.ReportMetadata(b"\x00" * 16, 1, (m.Extension(2, b""), m.Extension(1, b"")))
    with pytest.raises(WireError):
        m.ReportMetadata(b"\x00" * 16, 1, (m.Extension(1, b""), m.Extension(1, b"")))
    with pytest.raises(WireError):
        m.PlaintextInputShare((m.Extension(3, b""), m.Extension(3, b"")), b"x")


def test_task_extension_wire_shape():
    assert m.Extension(1, b"\x00" * 16).encode() == b"\x00\x01\x00\x10" + b"\x00" * 16


# --- Problem details ------------------------------------------------------

def test_problem_document():
    problem = m.DapProblem("unrecognizedTask", "no such task", 404, b"\xab" * 32)
    document = problem.to_json()
    assert document["type"] == "urn:ietf:params:ppm:dap:error:unrecognizedTask"
    assert document["status"] == 404
    assert document["detail"] == "no such task"
    assert document["taskid"] == "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s"
    json.dumps(document)  # must be plain JSON-serialisable
    with pytest.raises(ValueError):
        m.DapProblem("notARealError")


def test_media_types_are_the_draft_values():
    assert m.MEDIA_UPLOAD_REQ == "application/ppm-dap;message=upload-req"
    assert m.MEDIA_COLLECTION_JOB_RESP == (
        "application/ppm-dap;message=collection-job-resp")
    assert m.MEDIA_PROBLEM_JSON == "application/problem+json"

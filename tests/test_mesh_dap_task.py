"""DAP task files: bucket patterns, the counts mapping and key separation."""

import base64
import json
import os

import pytest

from interlock.mesh.dap import task as t
from interlock.mesh.dap import messages as m


LEADER = "http://127.0.0.1:7960"
HELPER = "http://127.0.0.1:7961"
BUCKETS = [
    "rule-a|block|shell|pre|*",
    "rule-a|block|shell|post|*",
    "rule-b|allow|read|pre|0",
    "rule-b|allow|read|post|*",
]


def _create(tmp_path, **kwargs):
    options = dict(leader=LEADER, helper=HELPER, buckets=BUCKETS,
                   batch_hours=24, min_batch_size=10, max_measurement=65535,
                   out_dir=str(tmp_path))
    options.update(kwargs)
    return t.create_task(**options)


def _key(batch_start, offset, *parts):
    return "|".join(list(parts) + [str(batch_start + offset * t.HOUR_SECONDS)])


# --- Patterns -------------------------------------------------------------

def test_patterns_accept_four_or_five_components():
    assert t.parse_pattern("a|b|c|d") == ("a", "b", "c", "d")
    assert t.parse_pattern("a|b|c|d|*") == ("a", "b", "c", "d", "*")
    assert t.parse_pattern("a|b|c|d|7") == ("a", "b", "c", "d", "7")


@pytest.mark.parametrize("text", [
    "a|b|c", "a|b|c|d|1|2", "a||c|d", "*|b|c|d", "a|b|c|*", "a|b|c|d|x",
    "a|b|c|d|-1", 7,
])
def test_bad_patterns_are_refused(text):
    with pytest.raises(t.TaskError):
        t.parse_pattern(text)


def test_overlapping_patterns_are_refused_at_creation(tmp_path):
    with pytest.raises(t.TaskError, match="overlap"):
        _create(tmp_path, buckets=["a|b|c|d|*", "a|b|c|d|3"])
    with pytest.raises(t.TaskError, match="overlap"):
        _create(tmp_path, buckets=["a|b|c|d", "a|b|c|d|*", "x|y|z|w"])


def test_a_fixed_hour_must_fit_the_batch(tmp_path):
    with pytest.raises(t.TaskError, match="hours 0..23"):
        _create(tmp_path, buckets=["a|b|c|d|24"])


# --- Files ----------------------------------------------------------------

def test_create_writes_four_files_with_the_right_modes(tmp_path):
    _create(tmp_path)
    assert sorted(os.listdir(tmp_path)) == [
        "collector.json", "helper.json", "leader.json", "task.json"]
    assert (os.stat(tmp_path / "task.json").st_mode & 0o777) == 0o644
    for name in ("leader.json", "helper.json", "collector.json"):
        assert (os.stat(tmp_path / name).st_mode & 0o777) == 0o600


def test_task_json_is_public_and_carries_no_secret(tmp_path):
    created, leader_keys, helper_keys, collector_keys = _create(tmp_path)
    raw = (tmp_path / "task.json").read_text()
    document = json.loads(raw)

    assert "hpke_secret" not in raw and "verify_key" not in raw
    assert "token" not in raw
    assert document["task_id_hex"] == created.task_id_hex
    assert document["task_id_b64"] == t.b64url(created.task_id)
    assert document["buckets"] == BUCKETS
    assert document["hours_per_batch"] == 24
    assert document["time_precision"] == 24 * 3600
    assert document["vdaf"]["length"] == len(BUCKETS)
    assert document["vdaf"]["codepoint"] == m.VDAF_TYPE_PRIO3_SUM_VEC

    # The private material is on the role files, and only there.
    assert leader_keys.hpke_secret.hex() in (tmp_path / "leader.json").read_text()
    assert helper_keys.hpke_secret.hex() in (tmp_path / "helper.json").read_text()
    assert collector_keys.hpke_secret.hex() in (tmp_path / "collector.json").read_text()


def test_the_two_aggregators_share_the_verify_key_and_tokens(tmp_path):
    _, leader_keys, helper_keys, _ = _create(tmp_path)
    assert leader_keys.verify_key == helper_keys.verify_key
    assert len(leader_keys.verify_key or b"") == 32
    assert leader_keys.token("helper") == helper_keys.token("leader")
    assert leader_keys.token("helper") != leader_keys.token("collector")


def test_create_refuses_to_overwrite(tmp_path):
    _create(tmp_path)
    with pytest.raises(t.TaskError, match="never overwritten"):
        _create(tmp_path)


def test_load_round_trips_the_task(tmp_path):
    created, *_ = _create(tmp_path)
    loaded = t.load_task(str(tmp_path / "task.json"))
    assert loaded == created
    assert loaded.task_configuration == created.task_configuration


def test_load_refuses_a_corrupted_task_configuration(tmp_path):
    _create(tmp_path)
    path = tmp_path / "task.json"
    document = json.loads(path.read_text())
    # Flip a byte of the encoded configuration: the HPKE AAD would change, so
    # either the decoder or the re-encode check must refuse it.
    raw = bytearray(base64.b64decode(document["task_config_b64"]))
    raw[0] ^= 0x01
    document["task_config_b64"] = base64.b64encode(bytes(raw)).decode()
    path.write_text(json.dumps(document))
    with pytest.raises(t.TaskError):
        t.load_task(str(path))


def test_load_refuses_fields_that_disagree_with_the_wire_config(tmp_path):
    _create(tmp_path)
    path = tmp_path / "task.json"
    document = json.loads(path.read_text())
    document["min_batch_size"] = 11
    path.write_text(json.dumps(document))
    with pytest.raises(t.TaskError, match="min_batch_size"):
        t.load_task(str(path))


def test_load_refuses_a_disagreeing_task_id_b64(tmp_path):
    _create(tmp_path)
    path = tmp_path / "task.json"
    document = json.loads(path.read_text())
    document["task_id_b64"] = t.b64url(b"\x00" * 32)
    path.write_text(json.dumps(document))
    with pytest.raises(t.TaskError, match="task_id_b64"):
        t.load_task(str(path))


def test_role_keys_load_and_reject_a_foreign_task(tmp_path):
    created, leader_keys, helper_keys, collector_keys = _create(tmp_path)
    loaded = t.load_role_keys(str(tmp_path / "leader.json"), created)
    assert loaded == leader_keys
    assert t.load_role_keys(str(tmp_path / "helper.json"), created) == helper_keys
    assert t.load_role_keys(str(tmp_path / "collector.json"), created) == collector_keys
    assert collector_keys.verify_key is None

    other, *_ = _create(tmp_path / "other")
    with pytest.raises(t.TaskError, match="belongs to task"):
        t.load_role_keys(str(tmp_path / "leader.json"), other)


def test_aggregator_keys_without_a_verify_key_are_refused(tmp_path):
    created, *_ = _create(tmp_path)
    path = tmp_path / "leader.json"
    document = json.loads(path.read_text())
    document.pop("verify_key_hex")
    path.write_text(json.dumps(document))
    with pytest.raises(t.TaskError, match="verify_key_hex"):
        t.load_role_keys(str(path), created)


# --- Measurement mapping --------------------------------------------------

def test_measurement_orders_buckets_and_sums_wildcards(tmp_path):
    created, *_ = _create(tmp_path)
    batch = 19600
    start = created.batch_start_time(batch)
    counts = {
        _key(start, 0, "rule-a", "block", "shell", "pre"): 1,
        _key(start, 5, "rule-a", "block", "shell", "pre"): 2,
        _key(start, 23, "rule-a", "block", "shell", "pre"): 3,
        _key(start, 5, "rule-a", "block", "shell", "post"): 7,
        _key(start, 0, "rule-b", "allow", "read", "pre"): 4,
        _key(start, 5, "rule-b", "allow", "read", "post"): 6,
    }
    assert created.measurement(counts, batch) == [6, 7, 4, 6]


def test_measurement_refuses_an_unmatched_count(tmp_path):
    created, *_ = _create(tmp_path)
    batch = 19600
    start = created.batch_start_time(batch)
    # rule-b pre has only the hour-0 pattern, so hour 1 matches nothing.
    counts = {_key(start, 1, "rule-b", "allow", "read", "pre"): 1}
    with pytest.raises(t.TaskError, match="matches no bucket"):
        created.measurement(counts, batch)


def test_measurement_refuses_counts_from_another_batch(tmp_path):
    created, *_ = _create(tmp_path)
    start = created.batch_start_time(19600)
    counts = {_key(start - 3600, 0, "rule-a", "block", "shell", "pre"): 1}
    with pytest.raises(t.TaskError, match="outside batch"):
        created.measurement(counts, 19600)


def test_batch_for_counts_finds_the_one_batch(tmp_path):
    created, *_ = _create(tmp_path)
    start = created.batch_start_time(19600)
    counts = {
        _key(start, 0, "rule-a", "block", "shell", "pre"): 1,
        _key(start, 23, "rule-b", "allow", "read", "pre"): 2,
    }
    assert created.batch_for_counts(counts) == 19600


def test_batch_for_counts_refuses_an_empty_mapping(tmp_path):
    created, *_ = _create(tmp_path)
    with pytest.raises(t.TaskError, match="no counts"):
        created.batch_for_counts({})


def test_batch_for_counts_refuses_counts_from_two_batches(tmp_path):
    created, *_ = _create(tmp_path)
    start = created.batch_start_time(19600)
    counts = {
        _key(start, 0, "rule-a", "block", "shell", "pre"): 1,
        _key(start + created.time_precision, 0, "rule-a", "block", "shell", "pre"): 1,
    }
    with pytest.raises(t.TaskError, match="span batches"):
        created.batch_for_counts(counts)


def test_measurement_refuses_a_negative_or_non_integer_count(tmp_path):
    created, *_ = _create(tmp_path)
    start = created.batch_start_time(19600)
    key = _key(start, 0, "rule-a", "block", "shell", "pre")
    with pytest.raises(t.TaskError):
        created.measurement({key: -1}, 19600)
    with pytest.raises(t.TaskError):
        created.measurement({key: 1.5}, 19600)
    with pytest.raises(t.TaskError):
        created.measurement({key: True}, 19600)


def test_measurement_refuses_a_bucket_over_max_measurement(tmp_path):
    created, *_ = _create(tmp_path, buckets=["a|b|c|d|*"], max_measurement=9)
    start = created.batch_start_time(19600)
    with pytest.raises(t.TaskError, match="over max_measurement"):
        created.measurement({_key(start, 0, "a", "b", "c", "d"): 10}, 19600)


def test_measurement_refuses_a_malformed_key(tmp_path):
    created, *_ = _create(tmp_path)
    for key in ("a|b|c", "a|b|c|d|x", "a|b|c|d|1|2"):
        with pytest.raises(t.TaskError):
            created.measurement({key: 1}, 19600)


def test_counts_inverts_measurement(tmp_path):
    created, *_ = _create(tmp_path)
    batch = 19600
    start = created.batch_start_time(batch)
    counts = {
        _key(start, 3, "rule-a", "block", "shell", "pre"): 5,
        _key(start, 0, "rule-b", "allow", "read", "pre"): 2,
        _key(start, 9, "rule-b", "allow", "read", "post"): 1,
    }
    vector = created.measurement(counts, batch)
    result = created.counts(vector, batch)
    assert result == {
        "rule-a|block|shell|pre|*": 5,
        _key(start, 0, "rule-b", "allow", "read", "pre"): 2,
        "rule-b|allow|read|post|*": 1,
    }


def test_counts_labels_are_not_submission_keys(tmp_path):
    created, *_ = _create(tmp_path)
    batch = 19600
    start = created.batch_start_time(batch)
    counts = {_key(start, 3, "rule-a", "block", "shell", "pre"): 5}
    result = created.counts(created.measurement(counts, batch), batch)
    assert result == {"rule-a|block|shell|pre|*": 5}
    # A wildcard label is a collector-side summary; the client must send the
    # concrete hourly keys it actually counted.
    with pytest.raises(t.TaskError):
        created.measurement(result, batch)


def test_counts_omits_empty_buckets_and_checks_length(tmp_path):
    created, *_ = _create(tmp_path)
    assert created.counts([0] * created.length, 19600) == {}
    with pytest.raises(t.TaskError):
        created.counts([0] * (created.length - 1), 19600)


# --- Parameters -----------------------------------------------------------

def test_default_chunk_length_is_the_isqrt_balance(tmp_path):
    created, *_ = _create(tmp_path, buckets=["a|b|c|d|*"], max_measurement=65535)
    # 1 element * 16 bits -> isqrt(16) == 4.
    assert created.chunk_length == 4


def test_the_vdaf_accepts_the_task_configuration(tmp_path):
    created, *_ = _create(tmp_path)
    vdaf = created.vdaf()
    assert vdaf.ROUNDS == 1


def test_vdaf_parameters_round_trip_in_the_wire_config(tmp_path):
    created, *_ = _create(tmp_path, chunk_length=11)
    config = m.Prio3SumVecConfig.from_bytes(
        m.TaskConfiguration.from_bytes(created.task_configuration).vdaf_configuration)
    assert (config.length, config.max_measurement, config.chunk_length) == (
        created.length, 65535, 11)


@pytest.mark.parametrize("kwargs", [
    {"batch_hours": 0},
    {"batch_hours": 1.5},
    {"min_batch_size": 1},
    {"max_measurement": 0},
    {"max_measurement": 1 << 20},
    {"chunk_length": 0},
    {"leader": "leader.example"},
    {"helper": "ftp://helper"},
    {"buckets": []},
])
def test_bad_parameters_are_refused(tmp_path, kwargs):
    with pytest.raises(t.TaskError):
        _create(tmp_path, **kwargs)


def test_batch_helpers_agree(tmp_path):
    created, *_ = _create(tmp_path, batch_hours=6)
    assert created.time_precision == 6 * 3600
    assert created.hours_per_batch == 6
    assert created.batch_start_time(7) == 7 * 6 * 3600
    assert created.batch_interval(7) == m.Interval(7, 1)
    assert created.context() == b"dap-20" + created.task_id

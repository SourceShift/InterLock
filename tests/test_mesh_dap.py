"""DAP end to end: leader, helper and collector over real HTTP on loopback.

The tests cover the properties the protocol exists for: totals come out exact,
an out-of-range or tampered measurement never enters the totals, a batch below
the floor is not released, a replay or a collected batch is refused, and the
node's kill switch refuses before a socket is opened.
"""

import contextlib
import json
import os
import socket
import threading
import time
from types import SimpleNamespace

import pytest

from interlock.mesh import hpke
from interlock.mesh.dap import client, collector, server
from interlock.mesh.dap import messages as m
from interlock.mesh.dap import task as taskmod
from interlock.mesh.dap.aggregator import input_share_info
from interlock.mesh.report import ReportError, post_bytes


BUCKETS = ["rule-a|block|shell|pre|*", "rule-b|allow|read|post|*"]
MIN_BATCH = 3


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@contextlib.contextmanager
def dap_env(tmp_path, *, min_batch=MIN_BATCH):
    leader_port, helper_port = _free_port(), _free_port()
    out = tmp_path / "dap"
    task, leader_keys, helper_keys, collector_keys = taskmod.create_task(
        leader="http://127.0.0.1:{}".format(leader_port),
        helper="http://127.0.0.1:{}".format(helper_port),
        buckets=BUCKETS, batch_hours=24, min_batch_size=min_batch,
        max_measurement=64, out_dir=str(out))
    leader = server.make_dap_server(
        "127.0.0.1:{}".format(leader_port), role="leader", task=task,
        keys=leader_keys, state_path=str(out / "leader.state"))
    helper = server.make_dap_server(
        "127.0.0.1:{}".format(helper_port), role="helper", task=task,
        keys=helper_keys, state_path=str(out / "helper.state"))
    threads = [threading.Thread(target=srv.serve_forever, daemon=True)
               for srv in (leader, helper)]
    for thread in threads:
        thread.start()
    env = SimpleNamespace(
        task=task, leader_keys=leader_keys, helper_keys=helper_keys,
        collector_keys=collector_keys, leader=leader, helper=helper,
        leader_url=task.leader, helper_url=task.helper, out=out,
        batch=int(time.time() // task.time_precision),
        peer_token=helper_keys.token("leader"),
        collector_token=leader_keys.token("collector"),
    )
    try:
        yield env
    finally:
        for srv in (leader, helper):
            srv.shutdown()
            srv.server_close()
        for thread in threads:
            thread.join(timeout=5)


def _key(env, offset, *parts):
    start = env.task.batch_start_time(env.batch)
    return "|".join(list(parts) + [str(start + offset * 3600)])


def _counts(env, offset, pre, post):
    return {_key(env, offset, "rule-a", "block", "shell", "pre"): pre,
            _key(env, offset + 12, "rule-b", "allow", "read", "post"): post}


def _submit(env, counts):
    return client.submit_counts(env.task, counts, batch_index=env.batch)


# --- Happy path -----------------------------------------------------------

def test_three_reports_aggregate_to_the_exact_totals(tmp_path):
    with dap_env(tmp_path) as env:
        for offset, pre, post in ((0, 1, 1), (1, 2, 1), (2, 3, 1)):
            _plan, result = _submit(env, _counts(env, offset, pre, post))
            assert result.accepted == 1 and result.errors == ()
        result = collector.collect(env.task, env.collector_keys, env.batch)
        assert result.report_count == 3
        assert result.measurement == (6, 3)
        assert result.counts == {"rule-a|block|shell|pre|*": 6,
                                 "rule-b|allow|read|post|*": 3}
        assert result.interval == m.Interval(env.batch, 1)


def test_the_state_files_hold_no_counts_and_are_private(tmp_path):
    with dap_env(tmp_path) as env:
        for offset in range(MIN_BATCH):
            _submit(env, _counts(env, offset, 1, 1))
        collector.collect(env.task, env.collector_keys, env.batch)
        for name in ("leader.state", "helper.state"):
            path = env.out / name
            assert (os.stat(path).st_mode & 0o777) == 0o600
            text = path.read_text()
            assert "rule-a" not in text and "shell" not in text
            assert json.loads(text)["task_id_hex"] == env.task.task_id_hex


def test_the_collector_gets_the_same_answer_twice(tmp_path):
    with dap_env(tmp_path) as env:
        for offset in range(3):
            _submit(env, _counts(env, offset, 1, 1))
        first = collector.collect(env.task, env.collector_keys, env.batch)
        second = collector.collect(env.task, env.collector_keys, env.batch)
        assert first == second


# --- Refusals -------------------------------------------------------------

def test_a_batch_below_the_floor_is_not_released(tmp_path):
    with dap_env(tmp_path) as env:
        for offset in range(MIN_BATCH - 1):
            _submit(env, _counts(env, offset, 1, 1))
        with pytest.raises(collector.CollectorError, match="invalidBatchSize"):
            collector.collect(env.task, env.collector_keys, env.batch)


def test_a_replayed_report_is_refused(tmp_path):
    with dap_env(tmp_path) as env:
        plan = client.build_report(env.task, _counts(env, 0, 1, 1),
                                   leader_config=client.fetch_hpke_config(env.task),
                                   batch_index=env.batch)
        first = client.upload_report(env.task, plan.report)
        assert first.accepted == 1
        second = client.upload_report(env.task, plan.report)
        assert second.accepted == 0
        assert second.errors[0].error is m.ReportError.REPORT_REPLAYED


def test_an_upload_into_a_collected_batch_is_refused(tmp_path):
    with dap_env(tmp_path) as env:
        for offset in range(MIN_BATCH):
            _submit(env, _counts(env, offset, 1, 1))
        collector.collect(env.task, env.collector_keys, env.batch)
        late = client.build_report(env.task, _counts(env, 9, 1, 1),
                                   leader_config=client.fetch_hpke_config(env.task),
                                   batch_index=env.batch)
        result = client.upload_report(env.task, late.report)
        assert result.accepted == 0
        assert result.errors[0].error is m.ReportError.BATCH_COLLECTED


def test_a_collection_query_for_more_than_one_batch_is_refused(tmp_path):
    with dap_env(tmp_path) as env:
        body = m.CollectionJobReq(
            m.Query(m.BatchMode.TIME_INTERVAL,
                    m.TimeIntervalQueryConfig(m.Interval(env.batch, 2)).encode()),
            b"", ()).encode()
        status, _, payload = post_bytes(
            env.leader_url + "/tasks/{}/collection_jobs".format(env.task.task_id_b64),
            body, m.MEDIA_COLLECTION_JOB_REQ, token=env.collector_token)
        assert status == 400
        assert json.loads(payload)["type"].endswith(":batchInvalid")


def test_a_second_aggregate_share_request_for_the_batch_is_an_overlap(tmp_path):
    with dap_env(tmp_path) as env:
        for offset in range(MIN_BATCH):
            _submit(env, _counts(env, offset, 1, 1))
        collector.collect(env.task, env.collector_keys, env.batch)
        interval = m.Interval(env.batch, 1)
        body, _ = collector.collection_request(env.task, env.batch)
        selector = m.BatchSelector(
            m.BatchMode.TIME_INTERVAL,
            m.TimeIntervalBatchSelectorConfig(interval).encode())
        # A different request (the count differs) is not an idempotent replay.
        request = m.AggregateShareReq(body, selector, MIN_BATCH + 1, b"\x00" * 32)
        status, _, payload = post_bytes(
            env.helper_url + "/tasks/{}/aggregate_shares".format(
                env.task.task_id_b64),
            request.encode(), m.MEDIA_AGGREGATE_SHARE_REQ, token=env.peer_token)
        assert status == 400
        assert json.loads(payload)["type"].endswith(":batchOverlap")


def test_a_wrong_task_id_is_unrecognized(tmp_path):
    with dap_env(tmp_path) as env:
        wrong = taskmod.b64url(b"\x00" * 32)
        status, _, payload = post_bytes(
            env.leader_url + "/tasks/{}/upload".format(wrong), b"",
            m.MEDIA_UPLOAD_REQ)
        assert status == 404
        assert json.loads(payload)["type"].endswith(":unrecognizedTask")


def test_aggregator_and_collector_tokens_are_required(tmp_path):
    with dap_env(tmp_path) as env:
        status, _, _payload = post_bytes(
            env.helper_url + "/tasks/{}/aggregation_jobs".format(
                env.task.task_id_b64),
            b"", m.MEDIA_AGGREGATION_JOB_INIT_REQ)
        assert status == 401
        status, _, _ = post_bytes(
            env.leader_url + "/tasks/{}/collection_jobs".format(
                env.task.task_id_b64),
            b"", m.MEDIA_COLLECTION_JOB_REQ)
        assert status == 401


def test_a_wrong_hpke_pin_is_refused(tmp_path):
    with dap_env(tmp_path) as env:
        _secret, public = hpke.generate_keypair()
        other = m.HpkeConfig(env.task.leader_hpke.config_id,
                             env.task.leader_hpke.kem_id,
                             env.task.leader_hpke.kdf_id,
                             env.task.leader_hpke.aead_id, public)
        import dataclasses

        pinned = dataclasses.replace(env.task, leader_hpke=other)
        with pytest.raises(client.ClientError, match="pins"):
            client.fetch_hpke_config(pinned)


# --- Tampering ------------------------------------------------------------

def _craft_report(env, measurement, *, report_id=None, tamper=False):
    """Build a report around a measurement of our choosing, bypassing checks.

    ``tamper`` flips a low byte of the helper's first input-share element after
    sharding, keeping the ciphertext and public share structurally valid. That
    is what a client that lies about its own measurement looks like: the proof
    no longer verifies.
    """
    task = env.task
    vdaf = task.vdaf()
    report_id = report_id or os.urandom(16)
    public_share, shares = vdaf.shard(
        task.context(), measurement, report_id, os.urandom(vdaf.RAND_SIZE))
    encoded_public = vdaf.encode_public_share(public_share)
    # DAP Time is the POSIX time divided by time_precision: the batch index.
    metadata = m.ReportMetadata(report_id, env.batch)
    aad = m.InputShareAad(task.task_id, task.task_configuration, metadata,
                          encoded_public).encode()
    ciphertexts = []
    for config, role, share in zip((task.leader_hpke, task.helper_hpke),
                                   (m.Role.LEADER, m.Role.HELPER), shares):
        encoded_share = bytearray(vdaf.encode_input_share(share))
        if tamper and role is m.Role.HELPER:
            encoded_share[1] ^= 0x01
        plaintext = m.PlaintextInputShare((), bytes(encoded_share)).encode()
        enc, payload = hpke.seal_base(config.public_key, input_share_info(role),
                                      plaintext, aad)
        ciphertexts.append(m.HpkeCiphertext(config.config_id, enc, payload))
    return m.Report(metadata, encoded_public, ciphertexts[0], ciphertexts[1])


def test_a_report_whose_proof_does_not_verify_is_dropped(tmp_path):
    with dap_env(tmp_path) as env:
        # max_measurement is 64, so an honest client can never carry a value
        # this large; the client refuses it. A malicious client edits its share
        # after proving, and the proof stops matching the share.
        forged = _craft_report(env, [5] + [0] * (env.task.length - 1), tamper=True)
        accepted = client.upload_report(env.task, forged)
        assert accepted.accepted == 1  # the leader cannot see the measurement yet
        for offset in range(MIN_BATCH):
            _submit(env, _counts(env, offset, 1, 1))
        result = collector.collect(env.task, env.collector_keys, env.batch)
        # The forged report never entered the batch.
        assert result.report_count == MIN_BATCH
        assert result.measurement == (3, 3)


def test_the_client_refuses_an_out_of_range_measurement(tmp_path):
    with dap_env(tmp_path) as env:
        counts = _counts(env, 0, 65, 0)
        with pytest.raises(client.ClientError, match="max_measurement"):
            client.build_report(env.task, counts,
                                leader_config=env.task.leader_hpke,
                                batch_index=env.batch)


def test_the_client_refuses_counts_from_two_batches(tmp_path):
    with dap_env(tmp_path) as env:
        counts = _counts(env, 0, 1, 1)
        other = _counts(env, 0, 1, 1)
        start = env.task.batch_start_time(env.batch + 1)
        other = {key.replace(str(env.task.batch_start_time(env.batch)), str(start)): value
                 for key, value in other.items()}
        counts.update(other)
        with pytest.raises(client.ClientError, match="outside batch"):
            client.build_report(env.task, counts,
                                leader_config=env.task.leader_hpke,
                                batch_index=env.batch)


# --- Consent ---------------------------------------------------------------

def test_the_kill_switch_refuses_before_any_connection(tmp_path, monkeypatch):
    # Nothing listens on this port; a connection attempt would raise OSError,
    # so a ReportError proves the gate fired first.
    task, *_ = taskmod.create_task(
        leader="http://127.0.0.1:1", helper="http://127.0.0.1:2",
        buckets=BUCKETS, batch_hours=24, min_batch_size=3, out_dir=str(tmp_path / "t"))
    monkeypatch.setenv("INTERLOCK_MESH_NO_REPORT", "1")
    with pytest.raises(ReportError, match="INTERLOCK_MESH_NO_REPORT"):
        client.submit_counts(task, {"rule-a|block|shell|pre|0": 1})

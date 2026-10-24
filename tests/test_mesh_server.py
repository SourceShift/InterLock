"""The collector servers on loopback: a reporter submits a signed report to the
consensus role and secret shares to two aggregators; the public routes answer;
auth, size and shape limits hold."""
import json
import threading
import urllib.error
import urllib.request

import pytest

from interlock.mesh import ed25519
from interlock.mesh.aggregate import combine_totals, count_key, encode_counts, reconcile
from interlock.mesh.report import ReporterKey, build_report, sign_report, submit
from interlock.mesh.server import MAX_BODY, make_server
from interlock.receipt import Receipt, digest_args

T0 = 1_800_000_000.0


@pytest.fixture
def servers(tmp_path):
    started = []

    def start(role, **kw):
        server = make_server(role, "127.0.0.1:0", state_path=str(tmp_path / (role + str(len(started)) + ".json")), **kw)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        started.append(server)
        return server

    yield start
    for server in started:
        server.shutdown()
        server.server_close()


def get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read().decode())


def report_for(key, catalog="cat1"):
    receipts = [Receipt(ts=T0 + 1, action="Bash", verdict="BLOCK", policy_id="destructive_command",
                        reason="r", args_digest=digest_args({"command": "rm -rf /"}))]
    return build_report(receipts, since=T0, until=T0 + 3600, catalog_id=catalog, reporter_id=key.keyid)


def test_end_to_end_reports_and_shares(servers):
    consensus = servers("consensus", known_catalogs=("cat1",), config={"min_orgs": 2, "min_trust": 1.0})
    agg_a = servers("aggregator")
    agg_b = servers("aggregator")
    assert get(consensus.url + "/healthz") == {"ok": True, "role": "consensus"}

    keys = [ReporterKey(ed25519.generate_seed()) for _ in range(2)]
    for index, key in enumerate(keys):
        body = report_for(key)
        env = sign_report(body, key)
        reply = submit(consensus.url + "/v1/reports", env)
        assert reply["accepted"] and reply["reporter"] == key.keyid
        counts = {count_key(c["policy_id"], c["verdict"], c["tool_class"], c["phase"], c["bucket"]): c["n"]
                  for c in body["counts"]}
        share_a, share_b = encode_counts(counts, 2)
        report_id = "{}:{}".format(key.keyid[:8], index)
        assert submit(agg_a.url + "/v1/shares", {"report_id": report_id, "shares": share_a})["accepted"]
        assert submit(agg_b.url + "/v1/shares", {"report_id": report_id, "shares": share_b})["accepted"]

    stats = get(consensus.url + "/v1/stats")
    assert stats["reporters"] == 2 and stats["indicators"] == {"active": 1}
    pack = get(consensus.url + "/v1/indicators")
    assert pack["rules"][0]["with"]["indicators"] == [digest_args({"command": "rm -rf /"})]

    ids = reconcile(get(agg_a.url + "/v1/manifest")["ids"], get(agg_b.url + "/v1/manifest")["ids"])
    assert len(ids) == 2
    totals = combine_totals(submit(agg_a.url + "/v1/totals", {"ids": ids})["totals"],
                            submit(agg_b.url + "/v1/totals", {"ids": ids})["totals"])
    (key,) = totals
    assert key.startswith("destructive_command|BLOCK|shell|call|") and totals[key] == 2
    # State was persisted and restores into a fresh server.
    restored = make_server("consensus", "127.0.0.1:0", state_path=consensus.state_path)
    assert restored.engine.export_stats()["reporters"] == 2
    restored.server_close()


def test_cli_report_build_and_submit_round_trip(servers, tmp_path, monkeypatch):
    """The command line path: `report init`, `build`, `submit` against live collectors."""
    from interlock.cli import main
    from interlock.mesh.catalog import catalog_id
    from interlock.sink import FileSink

    mesh_dir = tmp_path / "mesh"
    monkeypatch.setenv("INTERLOCK_MESH_DIR", str(mesh_dir))
    consensus = servers("consensus", known_catalogs=(catalog_id(),), config={"min_orgs": 1, "min_trust": 0.1})
    agg_a, agg_b = servers("aggregator"), servers("aggregator")
    log = tmp_path / "receipts.jsonl"
    sink = FileSink(str(log), key=b"k" * 32)
    import time as _time
    sink.write(Receipt(ts=_time.time() - 10, action="Bash", verdict="BLOCK", policy_id="destructive_command",
                       reason="r", args_digest=digest_args({"command": "rm -rf /"})))
    assert main(["mesh", "report", "init"]) == 0
    out = tmp_path / "report.json"
    assert main(["mesh", "report", "build", "--receipts", str(log), "--since", "24h", "--out", str(out)]) == 0
    assert main(["mesh", "report", "submit", str(out), "--consensus", consensus.url,
                 "--aggregator", agg_a.url, "--aggregator", agg_b.url]) == 0
    stats = get(consensus.url + "/v1/stats")
    assert stats["reporters"] == 1 and stats["indicators"] == {"active": 1}
    assert len(get(agg_a.url + "/v1/manifest")["ids"]) == 1


def test_rejections(servers):
    consensus = servers("consensus", known_catalogs=("cat1",), token="s3cret")
    key = ReporterKey(ed25519.generate_seed())
    env = sign_report(report_for(key), key)
    with pytest.raises(urllib.error.HTTPError) as err:
        submit(consensus.url + "/v1/reports", env)
    assert err.value.code == 401
    assert submit(consensus.url + "/v1/reports", env, token="s3cret")["accepted"]
    with pytest.raises(urllib.error.HTTPError) as err:
        submit(consensus.url + "/v1/reports", sign_report(report_for(key, catalog="nope"), key), token="s3cret")
    assert err.value.code == 422
    with pytest.raises(urllib.error.HTTPError) as err:
        submit(consensus.url + "/v1/nothing", {}, token="s3cret")
    assert err.value.code == 404
    with pytest.raises(urllib.error.HTTPError) as err:
        get(consensus.url + "/v1/manifest")  # an aggregator route on the consensus role
    assert err.value.code == 404
    big = urllib.request.Request(consensus.url + "/v1/reports", data=b"x" * (MAX_BODY + 1),
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer s3cret"},
                                 method="POST")
    with pytest.raises(urllib.error.HTTPError) as err:
        urllib.request.urlopen(big, timeout=5)
    assert err.value.code == 413
    agg = servers("aggregator")
    with pytest.raises(urllib.error.HTTPError) as err:
        submit(agg.url + "/v1/shares", {"report_id": "r", "shares": {"k": -1}})
    assert err.value.code == 422
    with pytest.raises(urllib.error.HTTPError) as err:
        submit(agg.url + "/v1/totals", {"ids": "r"})
    assert err.value.code == 400
    with pytest.raises(ValueError):
        make_server("oracle")

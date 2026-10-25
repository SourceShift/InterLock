"""The collector servers on loopback: a reporter submits a signed report to the
consensus role and secret shares to two aggregators; the consensus role never
sees a count; totals are released only over a batch at the floor; the public
routes answer; auth, size and shape limits hold."""
import json
import os
import stat
import threading
import urllib.error
import urllib.request

import pytest

from interlock.mesh import ed25519
from interlock.mesh.aggregate import combine_totals, count_key, encode_counts, reconcile
from interlock.mesh.report import ReporterKey, build_counts, build_report, sign_report, submit
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


RECEIPTS = [Receipt(ts=T0 + 1, action="Bash", verdict="BLOCK", policy_id="destructive_command",
                    reason="r", args_digest=digest_args({"command": "rm -rf /"}))]


def report_for(key, catalog="cat1"):
    return build_report(RECEIPTS, since=T0, until=T0 + 3600, catalog_id=catalog, reporter_id=key.keyid)


def totals_refusal(url, ids):
    with pytest.raises(urllib.error.HTTPError) as err:
        submit(url + "/v1/totals", {"ids": ids})
    assert err.value.code == 422
    return json.loads(err.value.read().decode())


def test_end_to_end_reports_and_shares(servers):
    consensus = servers("consensus", known_catalogs=("cat1",), config={"min_orgs": 2, "min_trust": 1.0})
    agg_a = servers("aggregator")
    agg_b = servers("aggregator")
    assert get(consensus.url + "/healthz") == {"ok": True, "role": "consensus"}

    keys = [ReporterKey(ed25519.generate_seed()) for _ in range(3)]
    for index, key in enumerate(keys):
        body = report_for(key)
        assert "counts" not in body
        env = sign_report(body, key)
        reply = submit(consensus.url + "/v1/reports", env)
        assert reply["accepted"] and reply["reporter"] == key.keyid
        share_a, share_b = encode_counts(build_counts(RECEIPTS, T0, T0 + 3600), 2)
        report_id = "{}:{}".format(key.keyid[:8], index)
        assert submit(agg_a.url + "/v1/shares", {"report_id": report_id, "shares": share_a})["accepted"]
        assert submit(agg_b.url + "/v1/shares", {"report_id": report_id, "shares": share_b})["accepted"]
        if index == 1:
            # Two reports: either reporter could subtract its own count and read the other's.
            manifest = get(agg_a.url + "/v1/manifest")
            assert manifest["min_batch"] == 3 and len(manifest["ids"]) == 2
            refused = totals_refusal(agg_a.url, manifest["ids"])
            assert "at least 3" in refused["reason"] and refused["min_batch"] == 3 and "totals" not in refused
            # Repeating an id does not make a batch.
            assert "totals" not in totals_refusal(agg_b.url, manifest["ids"] * 3)

    stats = get(consensus.url + "/v1/stats")
    assert stats["reporters"] == 3 and stats["indicators"] == {"active": 1}
    assert stats["rules"]["destructive_command"] == dict(stats["rules"]["destructive_command"], orgs=3, verdicts=None)
    pack = get(consensus.url + "/v1/indicators")
    assert pack["rules"][0]["with"]["indicators"] == [digest_args({"command": "rm -rf /"})]

    ids = reconcile(get(agg_a.url + "/v1/manifest")["ids"], get(agg_b.url + "/v1/manifest")["ids"])
    assert len(ids) == 3
    totals = combine_totals(submit(agg_a.url + "/v1/totals", {"ids": ids})["totals"],
                            submit(agg_b.url + "/v1/totals", {"ids": ids})["totals"], ids=ids)
    (key,) = totals
    assert key.startswith("destructive_command|BLOCK|shell|call|") and totals[key] == 3
    # State was persisted and restores into a fresh server, floor included.
    restored = make_server("consensus", "127.0.0.1:0", state_path=consensus.state_path)
    assert restored.engine.export_stats()["reporters"] == 3
    restored.server_close()
    restored = make_server("aggregator", "127.0.0.1:0", state_path=agg_a.state_path, config={"min_batch": 4})
    assert restored.aggregator.min_batch == 4 and len(restored.aggregator.report_ids()) == 3
    restored.server_close()
    with pytest.raises(ValueError):
        make_server("aggregator", "127.0.0.1:0", config={"min_batch": 1})


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
    # The envelope carries no counts; they sit beside it, readable by this user only.
    assert "counts" not in json.loads(out.read_text())["report"]
    counts_file = tmp_path / "report.json.counts.json"
    assert stat.S_IMODE(os.stat(counts_file).st_mode) == 0o600
    (key,) = json.loads(counts_file.read_text())["counts"]
    assert key.startswith("destructive_command|BLOCK|shell|call|")
    assert main(["mesh", "report", "submit", str(out), "--consensus", consensus.url,
                 "--aggregator", agg_a.url, "--aggregator", agg_b.url]) == 0
    stats = get(consensus.url + "/v1/stats")
    assert stats["reporters"] == 1 and stats["indicators"] == {"active": 1}
    assert stats["rules"]["destructive_command"]["verdicts"] is None
    assert len(get(agg_a.url + "/v1/manifest")["ids"]) == 1


def _walk(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _walk(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk(v)
    else:
        yield obj


def test_consensus_never_sees_a_count(servers, tmp_path, monkeypatch, capsys):
    """Through the command line: build, submit, then look at what the consensus
    server received, what it answered and what it stored. Fire counts come only
    from the aggregators' combined totals, and only over a batch at the floor."""
    from interlock.cli import main
    from interlock.mesh.catalog import catalog_id
    from interlock.sink import FileSink
    import time as _time

    consensus = servers("consensus", known_catalogs=(catalog_id(),), config={"min_orgs": 1, "min_trust": 0.1})
    agg_a, agg_b = servers("aggregator"), servers("aggregator")
    received = []
    ingest = consensus.engine.ingest

    def spy(envelope):
        result = ingest(envelope)
        received.append((json.loads(json.dumps(envelope)), json.loads(json.dumps(result))))
        return result

    consensus.engine.ingest = spy
    fired = (7, 1, 1)  # reporter 0's guard blocked seven times
    for index, n in enumerate(fired):
        monkeypatch.setenv("INTERLOCK_MESH_DIR", str(tmp_path / "mesh{}".format(index)))
        log = tmp_path / "receipts{}.jsonl".format(index)
        sink = FileSink(str(log), key=b"k" * 32)
        for i in range(n):
            sink.write(Receipt(ts=_time.time() - 10 - i, action="Bash", verdict="BLOCK",
                               policy_id="destructive_command", reason="r",
                               args_digest=digest_args({"command": "rm -rf /"})))
        assert main(["mesh", "report", "init"]) == 0
        out = tmp_path / "report{}.json".format(index)
        assert main(["mesh", "report", "build", "--receipts", str(log), "--since", "24h", "--out", str(out)]) == 0
        assert sum(json.loads((tmp_path / "report{}.json.counts.json".format(index)).read_text())["counts"]
                   .values()) == n
        assert main(["mesh", "report", "submit", str(out), "--consensus", consensus.url,
                     "--aggregator", agg_a.url, "--aggregator", agg_b.url]) == 0
        if index == 1:
            # Two reports reconciled: below the floor, so no fire counts are released.
            capsys.readouterr()
            assert main(["mesh", "consensus", "export", "--state", consensus.state_path, "--stats",
                         "--aggregator", agg_a.url, "--aggregator", agg_b.url]) == 2
            assert "at least 3" in capsys.readouterr().err

    # What the consensus server was sent, what it answered, and what it kept.
    assert len(received) == 3
    for envelope, result in received:
        assert set(envelope) <= {"report", "public", "signature", "credential"}
        assert "counts" not in envelope["report"]
        assert result["accepted"] and "counts" not in result and 7 not in result.values()
    with open(consensus.state_path, "r", encoding="utf-8") as fh:
        state = json.load(fh)
    stored = list(_walk(state))
    assert "counts" not in stored and "verdicts" not in stored and 7 not in stored
    assert not any(isinstance(x, str) and "|BLOCK|shell|" in x for x in stored)
    assert state["rules"]["destructive_command"].keys() == {"orgs", "last"}
    stats = get(consensus.url + "/v1/stats")
    assert stats["rules"]["destructive_command"]["verdicts"] is None and stats["rules"]["destructive_command"]["orgs"] == 3

    # Fire counts from the aggregators: three reconciled reports meet the floor.
    out = tmp_path / "stats.json"
    assert main(["mesh", "consensus", "export", "--state", consensus.state_path, "--stats",
                 "--aggregator", agg_a.url, "--aggregator", agg_b.url, "--out", str(out)]) == 0
    exported = json.loads(out.read_text())
    assert exported["rules"]["destructive_command"]["verdicts"] == {"BLOCK": 9}
    assert exported["rules"]["destructive_command"]["orgs"] == 3
    assert exported["fire_counts"] == {"aggregators": [agg_a.url, agg_b.url], "reports": 3, "min_batch": 3}
    # Without aggregators the stats carry none; one aggregator or no --stats is a usage error.
    capsys.readouterr()
    assert main(["mesh", "consensus", "export", "--state", consensus.state_path, "--stats"]) == 0
    assert json.loads(capsys.readouterr().out)["rules"]["destructive_command"]["verdicts"] is None
    assert main(["mesh", "consensus", "export", "--state", consensus.state_path, "--stats",
                 "--aggregator", agg_a.url]) == 64
    assert main(["mesh", "consensus", "export", "--state", consensus.state_path,
                 "--aggregator", agg_a.url, "--aggregator", agg_b.url]) == 64

    # Fewer than two aggregators: nothing is shared, and the command says so.
    before = len(get(agg_a.url + "/v1/manifest")["ids"])
    capsys.readouterr()
    assert main(["mesh", "report", "submit", str(tmp_path / "report0.json"), "--consensus", consensus.url,
                 "--aggregator", agg_a.url]) == 0
    assert "counts not shared" in capsys.readouterr().out
    assert len(get(agg_a.url + "/v1/manifest")["ids"]) == before


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

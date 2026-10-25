"""The collector servers on loopback: a reporter submits a signed report to the
consensus role and secret shares to two aggregators; the consensus role never
sees a count; totals are released only over a batch at the floor; the public
routes answer; auth, size and shape limits hold. Nothing is sent before the
operator enables reporting, nothing from before the enable is ever sent, a layer
that is not enabled is refused, and INTERLOCK_MESH_NO_REPORT refuses it all."""
import json
import os
import stat
import threading
import urllib.error
import urllib.request

import pytest

import time

from interlock.mesh import ed25519, subscriber
from interlock.mesh.aggregate import combine_totals, count_key, encode_counts, reconcile
from interlock.mesh.report import ReportError, ReporterKey, build_counts, build_report, sign_report, submit
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


def enabled_a_minute_ago(monkeypatch):
    """`report enable` stamps the subscriber clock: put the enable 60 s back, so
    receipts written just now are after it and receipts an hour old are before."""
    start = time.time()
    monkeypatch.setattr(subscriber, "_CLOCK", lambda: start - 60)
    return start - 60


def write_block(log, ts, command="rm -rf /"):
    from interlock.sink import FileSink

    FileSink(str(log), key=b"k" * 32).write(Receipt(ts=ts, action="Bash", verdict="BLOCK",
                                                    policy_id="destructive_command", reason="r",
                                                    args_digest=digest_args({"command": command})))


def test_cli_report_build_and_submit_round_trip(servers, tmp_path, monkeypatch, capsys):
    """The command line path against live collectors: `report init` and `build`
    work with nothing enabled and `submit` refuses; after `enable --digests` a
    report holds only what was observed since the enable, and goes through."""
    from interlock.cli import main
    from interlock.mesh.catalog import catalog_id

    mesh_dir = tmp_path / "mesh"
    monkeypatch.setenv("INTERLOCK_MESH_DIR", str(mesh_dir))
    consensus = servers("consensus", known_catalogs=(catalog_id(),), config={"min_orgs": 1, "min_trust": 0.1})
    agg_a, agg_b = servers("aggregator"), servers("aggregator")
    collectors = ["--consensus", consensus.url, "--aggregator", agg_a.url, "--aggregator", agg_b.url]
    log = tmp_path / "receipts.jsonl"
    enabled_at = enabled_a_minute_ago(monkeypatch)
    write_block(log, enabled_at - 3600, "rm -rf /before")       # observed before the enable
    assert main(["mesh", "report", "init"]) == 0

    # Nothing enabled: the local build is the full preview, and submit sends nothing.
    out = tmp_path / "report.json"
    assert main(["mesh", "report", "build", "--receipts", str(log), "--since", "24h", "--out", str(out)]) == 0
    assert len(json.loads(out.read_text())["report"]["digests"]) == 1
    capsys.readouterr()
    assert main(["mesh", "report", "submit", str(out)] + collectors) == 2
    assert "reporting is off" in capsys.readouterr().err
    assert get(consensus.url + "/v1/stats")["reporters"] == 0
    assert get(agg_a.url + "/v1/manifest")["ids"] == [] and get(agg_b.url + "/v1/manifest")["ids"] == []

    assert main(["mesh", "report", "enable", "--digests"]) == 0
    # The preview built before the enable covers time before it: refused, rebuild.
    capsys.readouterr()
    assert main(["mesh", "report", "submit", str(out)] + collectors) == 2
    assert "before reporting was enabled" in capsys.readouterr().err
    assert get(consensus.url + "/v1/stats")["reporters"] == 0

    write_block(log, time.time() - 10, "rm -rf /after")           # observed after the enable
    assert main(["mesh", "report", "build", "--receipts", str(log), "--since", "24h", "--out", str(out)]) == 0
    body = json.loads(out.read_text())["report"]
    # The envelope carries no counts; they sit beside it, readable by this user only.
    assert "counts" not in body and body["period"]["since"] == enabled_at
    assert [d["args_digest"] for d in body["digests"]] == [digest_args({"command": "rm -rf /after"})]
    counts_file = tmp_path / "report.json.counts.json"
    assert stat.S_IMODE(os.stat(counts_file).st_mode) == 0o600
    ((key, n),) = json.loads(counts_file.read_text())["counts"].items()
    assert key.startswith("destructive_command|BLOCK|shell|call|") and n == 1    # the old receipt is not counted
    assert main(["mesh", "report", "submit", str(out)] + collectors) == 0
    stats = get(consensus.url + "/v1/stats")
    assert stats["reporters"] == 1 and stats["indicators"] == {"active": 1}
    assert stats["rules"]["destructive_command"]["verdicts"] is None
    assert get(consensus.url + "/v1/indicators")["rules"][0]["with"]["indicators"] == [
        digest_args({"command": "rm -rf /after"})]
    assert len(get(agg_a.url + "/v1/manifest")["ids"]) == 1


def test_submit_refuses_a_layer_that_is_not_enabled(servers, tmp_path, monkeypatch, capsys):
    """Narrowing the consent after a build: the envelope still holds digests, so
    submit refuses it and names the flag. The same for fingerprints and for a
    sample from a rule that was not opted in."""
    from interlock.cli import main
    from interlock.cli.mesh import _consent_refusal
    from interlock.mesh.catalog import catalog_id

    monkeypatch.setenv("INTERLOCK_MESH_DIR", str(tmp_path / "mesh"))
    consensus = servers("consensus", known_catalogs=(catalog_id(),), config={"min_orgs": 1, "min_trust": 0.1})
    log = tmp_path / "receipts.jsonl"
    enabled_at = enabled_a_minute_ago(monkeypatch)
    write_block(log, time.time() - 10)
    assert main(["mesh", "report", "init"]) == 0
    assert main(["mesh", "report", "enable", "--digests"]) == 0
    out = tmp_path / "report.json"
    assert main(["mesh", "report", "build", "--receipts", str(log), "--out", str(out)]) == 0
    assert json.loads(out.read_text())["report"]["digests"]
    assert main(["mesh", "report", "enable"]) == 0                # counts and sightings only now
    capsys.readouterr()
    assert main(["mesh", "report", "submit", str(out), "--consensus", consensus.url]) == 2
    assert "digests are not enabled: run `interlock mesh report enable --digests`" in capsys.readouterr().err
    assert get(consensus.url + "/v1/stats")["reporters"] == 0
    # Narrowing kept the enable date; widening again moves it to now.
    from interlock.mesh.subscriber import Subscriber
    node = Subscriber(str(tmp_path / "mesh"))
    assert node.report_consent()["enabled_at"] == enabled_at
    monkeypatch.setattr(subscriber, "_CLOCK", lambda: enabled_at + 30)
    assert node.set_report_consent(["counts", "sightings", "digests"])["enabled_at"] == enabled_at + 30

    period = {"since": enabled_at, "until": enabled_at + 60}
    base = {"enabled_at": enabled_at, "layers": ["counts", "sightings"], "alpha": 1.5, "sample_rules": []}
    fps = {"period": period, "fingerprints": [{"policy_id": "r", "fp": "ab" * 96, "alpha": 1.5}]}
    assert _consent_refusal(fps, base, share_counts=False) == (
        "fingerprints are not enabled: run `interlock mesh report enable --fingerprints`")
    samples = {"period": period, "samples": [{"policy_id": "other_rule", "text": "x"}]}
    with_samples = dict(base, layers=["counts", "sightings", "samples"], sample_rules=["prompt_injection"])
    assert _consent_refusal(samples, with_samples, share_counts=False) == (
        "samples for other_rule are not enabled: run `interlock mesh report enable --sample other_rule "
        "--sample prompt_injection --i-warrant-samples`")
    assert "counts are not enabled" in _consent_refusal({"period": period}, dict(base, layers=["sightings"]),
                                                        share_counts=True)
    assert _consent_refusal({"period": period, "digests": []}, base, share_counts=True) is None


def test_the_kill_switch_refuses_every_upload(servers, tmp_path, monkeypatch, capsys):
    """INTERLOCK_MESH_NO_REPORT=1: `submit` raises before connecting, and the
    command line explains why, whatever the node enabled."""
    from interlock.cli import main
    from interlock.mesh import reporting_killed
    from interlock.mesh.catalog import catalog_id
    from interlock.mesh.subscriber import Subscriber, SubscriberError

    monkeypatch.setenv("INTERLOCK_MESH_DIR", str(tmp_path / "mesh"))
    consensus = servers("consensus", known_catalogs=(catalog_id(),), config={"min_orgs": 1, "min_trust": 0.1})
    agg_a, agg_b = servers("aggregator"), servers("aggregator")
    log = tmp_path / "receipts.jsonl"
    enabled_a_minute_ago(monkeypatch)
    write_block(log, time.time() - 10)
    assert main(["mesh", "report", "init"]) == 0
    assert main(["mesh", "report", "enable", "--digests"]) == 0
    out = tmp_path / "report.json"
    assert main(["mesh", "report", "build", "--receipts", str(log), "--out", str(out)]) == 0
    env = json.loads(out.read_text())
    submit_args = ["mesh", "report", "submit", str(out), "--consensus", consensus.url,
                   "--aggregator", agg_a.url, "--aggregator", agg_b.url]

    monkeypatch.setenv("INTERLOCK_MESH_NO_REPORT", "1")
    assert reporting_killed()
    for url, payload in ((consensus.url + "/v1/reports", env),
                         (agg_a.url + "/v1/shares", {"report_id": "r", "shares": {}}),
                         (agg_a.url + "/v1/totals", {"ids": []})):
        with pytest.raises(ReportError, match="INTERLOCK_MESH_NO_REPORT"):
            submit(url, payload)
    capsys.readouterr()
    assert main(submit_args) == 2
    assert "INTERLOCK_MESH_NO_REPORT is set" in capsys.readouterr().err
    consensus.engine.save(consensus.state_path)
    assert main(["mesh", "consensus", "export", "--state", consensus.state_path, "--stats",
                 "--aggregator", agg_a.url, "--aggregator", agg_b.url]) == 2   # the totals query is an upload too
    assert "INTERLOCK_MESH_NO_REPORT" in capsys.readouterr().err
    checkpoint = tmp_path / "mesh" / "log" / "checkpoint.json"
    checkpoint.parent.mkdir(parents=True)
    checkpoint.write_text(json.dumps({"checkpoint": {"size": 0}}))
    with pytest.raises(SubscriberError, match="INTERLOCK_MESH_NO_REPORT"):
        Subscriber(str(tmp_path / "mesh")).gossip(consensus.url)
    assert main(["mesh", "report", "status"]) == 0
    assert "every upload is refused" in capsys.readouterr().out
    # Nothing reached a collector.
    assert get(consensus.url + "/v1/stats")["reporters"] == 0
    assert get(agg_a.url + "/v1/manifest")["ids"] == [] and get(agg_b.url + "/v1/manifest")["ids"] == []

    monkeypatch.setenv("INTERLOCK_MESH_NO_REPORT", "0")
    assert not reporting_killed()
    monkeypatch.delenv("INTERLOCK_MESH_NO_REPORT")
    assert main(submit_args) == 0
    assert get(consensus.url + "/v1/stats")["reporters"] == 1


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
    enabled_a_minute_ago(monkeypatch)
    for index, n in enumerate(fired):
        monkeypatch.setenv("INTERLOCK_MESH_DIR", str(tmp_path / "mesh{}".format(index)))
        log = tmp_path / "receipts{}.jsonl".format(index)
        sink = FileSink(str(log), key=b"k" * 32)
        for i in range(n):
            sink.write(Receipt(ts=time.time() - 10 - i, action="Bash", verdict="BLOCK",
                               policy_id="destructive_command", reason="r",
                               args_digest=digest_args({"command": "rm -rf /"})))
        assert main(["mesh", "report", "init"]) == 0
        assert main(["mesh", "report", "enable", "--digests"]) == 0
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
                 "--aggregator", agg_a.url, "--dir", str(tmp_path / "mesh0")]) == 0
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


def test_enable_needs_no_commons_and_status_and_doctor_show_it(tmp_path, monkeypatch, capsys):
    """The consent lives in state.json: `report enable` works on a node that
    never ran `mesh init`, and `report status`, `mesh status` and `doctor` show
    it, with a preview of what a report would hold now."""
    from interlock.cli import main
    from interlock.cli.doctor import _mesh_checks
    from interlock.mesh.subscriber import Subscriber

    mesh_dir = tmp_path / "mesh"
    monkeypatch.setenv("INTERLOCK_MESH_DIR", str(mesh_dir))
    monkeypatch.setenv("HOME", str(tmp_path))                   # the preview reads ~/.interlock/receipts.jsonl
    node = Subscriber(str(mesh_dir))
    assert node.report_consent()["enabled_at"] is None
    assert {c.id: c for c in _mesh_checks()}["mesh.report"].summary == "mesh reporting: off"
    capsys.readouterr()
    assert main(["mesh", "status"]) == 1                        # still "not configured"
    out = capsys.readouterr().out
    assert "mesh reporting: off" in out and "report preview: no receipt log at" in out

    (tmp_path / ".interlock").mkdir()
    write_block(tmp_path / ".interlock" / "receipts.jsonl", time.time() - 10)
    assert main(["mesh", "report", "status"]) == 0
    out = capsys.readouterr().out
    assert "mesh reporting: off" in out
    assert "1 count row(s), 1 digest(s), 0 fingerprint(s), 0 sample(s); reporting is off, so none of it is sent" in out

    # Usage errors write nothing.
    for argv in (["--alpha", "2"], ["--off", "--digests"], ["--fingerprints", "--alpha", "0"]):
        assert main(["mesh", "report", "enable"] + argv) == 64
    assert not os.path.exists(node.state_path)

    enabled_at = enabled_a_minute_ago(monkeypatch)
    assert main(["mesh", "report", "enable", "--digests", "--fingerprints", "--alpha", "2",
                 "--sample", "prompt_injection", "--i-warrant-samples"]) == 0
    consent = node.report_consent()
    attestation = consent.pop("attestation")  # the sample warranty recorded by --i-warrant-samples (M5)
    assert attestation["warranty"] == "lawful,no-personal-data,no-confidential"
    assert consent == {"enabled_at": enabled_at, "alpha": 2.0, "sample_rules": ["prompt_injection"],
                       "layers": ["counts", "sightings", "digests", "fingerprints", "samples"]}
    assert stat.S_IMODE(os.stat(node.state_path).st_mode) == 0o600
    from interlock.mesh._util import iso
    line = ("mesh reporting: on since {}: layers counts, sightings, digests, fingerprints (alpha 2), "
            "samples (prompt_injection)".format(iso(enabled_at)))
    check = {c.id: c for c in _mesh_checks()}["mesh.report"]
    assert check.summary == line and check.status == "info"
    capsys.readouterr()
    assert main(["mesh", "status"]) == 1
    out = capsys.readouterr().out
    assert line in out and "report preview, last 24h since the enable: 1 count row(s), 1 digest(s)" in out
    assert main(["mesh", "report", "status", "--json"]) == 0
    shown = json.loads(capsys.readouterr().out)
    shown_consent = {k: v for k, v in shown["report"].items() if k != "attestation"}
    assert shown_consent == consent and shown["preview"]["digests"] == 1 and shown["kill_switch"] is False

    assert main(["mesh", "report", "enable", "--off"]) == 0
    assert node.report_consent() == {"enabled_at": None, "layers": [], "alpha": 1.5, "sample_rules": [],
                                     "attestation": None}
    assert {c.id: c for c in _mesh_checks()}["mesh.report"].summary == "mesh reporting: off"
    # A hand-edited or damaged record never reads as consent.
    for bad in ({"enabled_at": "yesterday", "layers": ["digests"]}, {"enabled_at": 1.0, "layers": "digests"},
                {"enabled_at": True, "layers": ["digests"]}, {"enabled_at": 1.0, "layers": ["telemetry"]}, []):
        state = node._load_state()
        state["report"] = bad
        node._save_state(state)
        assert node.report_consent()["enabled_at"] is None

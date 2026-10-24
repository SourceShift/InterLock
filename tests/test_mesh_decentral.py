"""Phase 3 end to end: a commons with a transparency log, a subscriber that
refuses unlogged or rewritten metadata, a node mirroring its verified cache to
a peer, gossip that catches a split view, and consensus that requires a
membership credential."""
import json
import os
import threading
import time

import pytest

from interlock.mesh import ed25519, metadata
from interlock.mesh.credential import Issuer
from interlock.mesh.consensus import ConsensusEngine
from interlock.mesh.log import MerkleLog, sign_checkpoint
from interlock.mesh.report import ReporterKey, build_report, sign_report
from interlock.mesh.repository import init_keys, publish, verify_site
from interlock.mesh.server import make_server
from interlock.mesh.subscriber import Subscriber, SubscriberError
from interlock.receipt import Receipt, digest_args

PACK = {"version": 1, "name": "p", "rules": [{"id": "r", "verdict": "block", "status": "stable",
                                               "when": {"arg": "x", "eq": 1}}]}


@pytest.fixture
def commons(tmp_path):
    source = tmp_path / "commons"
    (source / "packs").mkdir(parents=True)
    (source / "packs" / "p.json").write_text(json.dumps(PACK))
    keys = tmp_path / "keys"
    init_keys(str(keys))
    site = tmp_path / "site"
    result = publish(str(source), str(site), str(keys))
    return {"source": source, "keys": keys, "site": site, "publish": result, "tmp": tmp_path}


def node_for(tmp, name, site_url, ring="stable"):
    mesh_dir = tmp / name
    sub = Subscriber(str(mesh_dir))
    root = (tmp / "site" / "metadata" / "1.root.json").read_bytes()
    sub.init(root, [site_url], ring=ring, monitor_days=0)
    return sub


def test_publish_logs_everything_and_subscriber_verifies_inclusion(commons):
    result = commons["publish"]
    assert result["log"]["size"] == 5 and result["log"]["added"] == 5  # root, targets, snapshot, timestamp, 1 pack
    walked = verify_site(str(commons["site"]))
    assert walked["log"]["size"] == 5
    node = node_for(commons["tmp"], "node-a", "file://" + str(commons["site"]))
    synced = node.sync()
    assert synced["log"]["size"] == 5
    assert os.path.exists(os.path.join(node.dir, "log", "checkpoint.json"))
    status = node.status()
    assert status["log"]["size"] == 5 and status["split_views"] == []
    # A second publish grows the log; the subscriber sees consistent growth.
    publish(str(commons["source"]), str(commons["site"]), str(commons["keys"]))
    assert node.sync()["log"]["size"] == 8  # new targets, snapshot, timestamp (root and pack unchanged)


def test_unlogged_metadata_is_refused(commons):
    node = node_for(commons["tmp"], "node-b", "file://" + str(commons["site"]))
    node.sync()
    # The maintainers' timestamp key signs a fresh timestamp but nobody logs it.
    from interlock.mesh.repository import load_signers
    signers, _ = load_signers(str(commons["keys"]))
    ts_path = commons["site"] / "metadata" / "timestamp.json"
    env = metadata.loads(ts_path.read_bytes(), 1 << 20)
    signed = dict(env["signed"], version=env["signed"]["version"] + 1)
    ts_path.write_bytes(metadata.dumps(metadata.envelope(signed, signers["timestamp"])))
    with pytest.raises(SubscriberError) as err:
        node.sync()
    assert "not in the log" in str(err.value)
    with pytest.raises(metadata.MetadataError):
        verify_site(str(commons["site"]))


def test_rewritten_log_is_a_split_view(commons):
    node = node_for(commons["tmp"], "node-c", "file://" + str(commons["site"]))
    node.sync()
    # Rewrite history: drop the first entry and re-sign a checkpoint of the same size minus one.
    from interlock.mesh.repository import load_signers
    signers, _ = load_signers(str(commons["keys"]))
    log_dir = commons["site"] / "log"
    log = MerkleLog(str(log_dir / "entries.jsonl"))
    log.entries = log.entries[1:]
    log.append([])
    cp = sign_checkpoint(json.loads((log_dir / "checkpoint.json").read_text())["checkpoint"]["origin"],
                         log.size, log.root(), signers["log"][0].seed)
    (log_dir / "checkpoint.json").write_text(json.dumps(cp))
    with pytest.raises(SubscriberError) as err:
        node.sync()
    assert "shrank" in str(err.value) or "split view" in str(err.value) or "rewritten" in str(err.value)


@pytest.fixture
def mirror(commons):
    node_a = node_for(commons["tmp"], "node-a", "file://" + str(commons["site"]))
    node_a.sync()
    server = make_server("mirror", "127.0.0.1:0", directory=node_a.dir)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield node_a, server
    server.shutdown()
    server.server_close()


def test_peer_syncs_from_a_mirrored_cache_and_gossips(commons, mirror):
    node_a, server = mirror
    node_b = node_for(commons["tmp"], "node-b", server.url)
    synced = node_b.sync()
    assert synced["packs"] == ["packs/p.json"] and synced["log"]["size"] == 5
    doc, _, _ = node_b.resolve("p", "stable")
    assert doc["rules"][0]["id"] == "r"
    result = node_b.gossip(server.url)
    assert result["conflict"] is None and result["theirs"]["size"] == 5
    assert node_b.status()["split_views"] == []
    # The mirror refuses traversal and unknown paths.
    import urllib.error
    import urllib.request
    for bad in ("/metadata/../config.json", "/config.json", "/state.json", "/log/.hidden"):
        with pytest.raises(urllib.error.HTTPError) as err:
            urllib.request.urlopen(server.url + bad, timeout=5)
        assert err.value.code == 404


def test_gossip_detects_a_split_view(commons, mirror):
    node_a, server = mirror
    node_b = node_for(commons["tmp"], "node-b", "file://" + str(commons["site"]))
    node_b.sync()
    # The peer now shows a different root for the same size: forge it with the real log key.
    from interlock.mesh.repository import load_signers
    signers, _ = load_signers(str(commons["keys"]))
    ours = json.loads(open(os.path.join(node_b.dir, "log", "checkpoint.json")).read())["checkpoint"]
    evil = sign_checkpoint(ours["origin"], ours["size"], b"\x99" * 32, signers["log"][0].seed)
    with open(os.path.join(node_a.dir, "log", "checkpoint.json"), "w") as fh:
        json.dump(evil, fh)
    result = node_b.gossip(server.url)
    assert result["conflict"] and "different roots" in result["conflict"]
    status = node_b.status()
    assert status["split_views"] and status["split_views"][-1]["source"] == server.url
    # doctor turns it into a failing check.
    from interlock.cli.doctor import _mesh_checks
    os.environ["INTERLOCK_MESH_DIR"] = node_b.dir
    try:
        checks = {c.id: c for c in _mesh_checks()}
    finally:
        del os.environ["INTERLOCK_MESH_DIR"]
    assert checks["mesh.log"].status == "fail"


def test_consensus_requires_a_credential_when_configured(tmp_path):
    issuer = Issuer.load_or_create(str(tmp_path / "issuer.json"), str(tmp_path / "ledger.json"))
    engine = ConsensusEngine({"require_credential": True, "issuers": [issuer.public.hex()],
                              "credential_scope": "early", "min_orgs": 1, "min_trust": 0.5})
    engine.register_catalog("cat1")
    key = ReporterKey(ed25519.generate_seed())
    receipts = [Receipt(ts=time.time(), action="Bash", verdict="BLOCK", policy_id="destructive_command",
                        reason="r", args_digest=digest_args({"command": "rm -rf /"}))]
    body = build_report(receipts, since=0, until=time.time() + 1, catalog_id="cat1", reporter_id=key.keyid)
    result = engine.ingest(sign_report(body, key))
    assert not result["accepted"] and "credential" in result["reason"]
    cert = issuer.issue("acme", key.public, scope="early")
    result = engine.ingest(sign_report(body, key, credential=cert))
    assert result["accepted"] and result["trust"] >= 1.0  # a credentialed reporter is trusted like an enrolled one
    other = ReporterKey(ed25519.generate_seed())
    body2 = build_report(receipts, since=0, until=time.time() + 1, catalog_id="cat1", reporter_id=other.keyid)
    result = engine.ingest(sign_report(body2, other, credential=cert))  # someone else's certificate
    assert not result["accepted"] and "different key" in result["reason"]
    engine.config["revoked"] = [cert["id"]]
    result = engine.ingest(sign_report(body, key, credential=cert))
    assert not result["accepted"] and "revoked" in result["reason"]

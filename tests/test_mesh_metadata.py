"""The TUF-shaped metadata: thresholds, expiry, versions that never go backwards,
root rotation, and the hash and length checks that pin each document to the one
above it."""
import pytest

from interlock.mesh import ed25519, metadata
from interlock.mesh._util import from_iso, iso
from interlock.mesh.metadata import MetadataError, Signer, TrustedMetadata

NOW = 1_800_000_000.0


def signers(n=1):
    return [Signer(ed25519.generate_seed()) for _ in range(n)]


class Repo:
    """A tiny in-memory repository that signs whatever we ask, so each test can
    tamper with exactly one thing."""

    def __init__(self, root_threshold=1, root_count=1):
        self.keys = {role: signers(root_count if role == "root" else 1) for role in metadata.ROLES}
        self.thresholds = {role: (root_threshold if role == "root" else 1) for role in metadata.ROLES}
        self.root_version = 1
        self.versions = {"targets": 1, "snapshot": 1, "timestamp": 1}
        self.targets = {"packs/a.json": b'{"version":1,"rules":[{"id":"r","verdict":"block","when":{"action":"x"}}]}'}

    def root(self, now=NOW, version=None, extra_signers=()):
        signed = metadata.build_root({r: [s.key for s in ks] for r, ks in self.keys.items()}, self.thresholds,
                                     version=version or self.root_version, expires=iso(now + 365 * 86400))
        return metadata.dumps(metadata.envelope(signed, list(self.keys["root"]) + list(extra_signers)))

    def chain(self, now=NOW, targets_expiry=90 * 86400, snapshot_expiry=7 * 86400, timestamp_expiry=86400):
        targets = {}
        for path, blob in self.targets.items():
            targets[path] = {"length": len(blob), "sha256": metadata.sha256_hex(blob), "custom": {"pack": path}}
        t_signed = metadata.build_targets(targets, version=self.versions["targets"], expires=iso(now + targets_expiry))
        t_raw = metadata.dumps(metadata.envelope(t_signed, self.keys["targets"]))
        s_signed = metadata.build_snapshot(t_raw, self.versions["targets"], version=self.versions["snapshot"],
                                           expires=iso(now + snapshot_expiry))
        s_raw = metadata.dumps(metadata.envelope(s_signed, self.keys["snapshot"]))
        ts_signed = metadata.build_timestamp(s_raw, self.versions["snapshot"], version=self.versions["timestamp"],
                                             expires=iso(now + timestamp_expiry))
        ts_raw = metadata.dumps(metadata.envelope(ts_signed, self.keys["timestamp"]))
        return ts_raw, s_raw, t_raw

    def bump(self):
        for k in self.versions:
            self.versions[k] += 1


def trusted(repo, now=NOW):
    return TrustedMetadata(repo.root(), now=lambda: now)


def walk(client, repo, **kw):
    ts, snap, tgt = repo.chain(**kw)
    client.update_timestamp(ts)
    client.update_snapshot(snap)
    client.update_targets(tgt)
    return ts, snap, tgt


def test_full_walk_and_target_verification():
    repo = Repo()
    client = trusted(repo)
    walk(client, repo)
    info = client.verify_target("packs/a.json", repo.targets["packs/a.json"])
    assert info.consistent_name == "packs/{}.a.json".format(info.sha256)
    with pytest.raises(MetadataError) as err:
        client.verify_target("packs/a.json", repo.targets["packs/a.json"] + b" ")
    assert err.value.code == "length"
    with pytest.raises(MetadataError) as err:
        client.verify_target("packs/a.json", b"x" * len(repo.targets["packs/a.json"]))
    assert err.value.code == "hash"
    with pytest.raises(MetadataError) as err:
        client.verify_target("packs/nope.json", b"")
    assert err.value.code == "unknown"


def test_wrong_key_and_threshold():
    repo = Repo(root_threshold=2, root_count=3)
    client = trusted(repo)
    ts, _, _ = repo.chain()
    # Sign the timestamp with the snapshot key instead: outside the role.
    forged = metadata.loads(ts, 1 << 20)
    forged = metadata.envelope(forged["signed"], repo.keys["snapshot"])
    with pytest.raises(MetadataError) as err:
        client.update_timestamp(metadata.dumps(forged))
    assert err.value.code == "signatures"
    # A root rotation signed by only one of the three root keys misses the threshold.
    repo.root_version = 2
    one = metadata.loads(repo.root(), 1 << 20)
    one["signatures"] = one["signatures"][:1]
    with pytest.raises(MetadataError) as err:
        client.update_root(metadata.dumps(one))
    assert err.value.code == "signatures"


def test_expiry_is_enforced_per_role():
    repo = Repo()
    client = trusted(repo)
    ts, _, _ = repo.chain(timestamp_expiry=-1)
    with pytest.raises(MetadataError) as err:
        client.update_timestamp(ts)
    assert err.value.code == "expired"
    client = trusted(repo)
    ts, snap, _ = repo.chain(snapshot_expiry=-1)
    client.update_timestamp(ts)
    with pytest.raises(MetadataError) as err:
        client.update_snapshot(snap)
    assert err.value.code == "expired"
    assert not client.root_expired()
    assert TrustedMetadata(repo.root(), now=lambda: NOW + 400 * 86400).root_expired()


def test_rollback_and_replay_are_refused():
    repo = Repo()
    client = trusted(repo)
    repo.bump()
    walk(client, repo)
    older = Repo()
    older.keys = repo.keys
    older.thresholds = repo.thresholds
    older.targets = repo.targets
    ts_old, snap_old, _ = older.chain()  # versions 1 < 2
    with pytest.raises(MetadataError) as err:
        client.update_timestamp(ts_old)
    assert err.value.code == "rollback"
    # Same version, different content: a re-signed timestamp is also refused.
    ts_same = metadata.loads(repo.chain()[0], 1 << 20)
    ts_same["signed"]["meta"]["snapshot.json"]["hashes"]["sha256"] = "0" * 64
    ts_same = metadata.dumps(metadata.envelope(ts_same["signed"], repo.keys["timestamp"]))
    with pytest.raises(MetadataError) as err:
        client.update_timestamp(ts_same)
    assert err.value.code == "rollback"


def test_snapshot_must_match_the_timestamp_and_targets_the_snapshot():
    repo = Repo()
    client = trusted(repo)
    ts, snap, tgt = repo.chain()
    client.update_timestamp(ts)
    tampered = metadata.loads(snap, 1 << 20)
    tampered["signed"]["meta"]["targets.json"]["version"] = 99
    tampered = metadata.dumps(metadata.envelope(tampered["signed"], repo.keys["snapshot"]))
    with pytest.raises(MetadataError) as err:
        client.update_snapshot(tampered)
    assert err.value.code in ("hash", "length")  # the timestamp pins the snapshot bytes
    client.update_snapshot(snap)
    with pytest.raises(MetadataError) as err:
        client.update_targets(tgt + b" ")
    assert err.value.code == "length"
    client.update_targets(tgt)
    assert client.target("packs/a.json").custom == {"pack": "packs/a.json"}


def test_snapshot_may_not_drop_or_regress_a_targets_file():
    repo = Repo()
    client = trusted(repo)
    repo.versions["targets"] = 5
    walk(client, repo)
    repo.versions["targets"] = 4
    repo.versions["snapshot"] += 1
    repo.versions["timestamp"] += 1
    ts, snap, _ = repo.chain()
    client.update_timestamp(ts)
    with pytest.raises(MetadataError) as err:
        client.update_snapshot(snap)
    assert err.value.code == "rollback"


def test_root_rotation_needs_old_and_new_signatures_and_consecutive_versions():
    repo = Repo()
    client = trusted(repo)
    old_root_signers = list(repo.keys["root"])
    repo.keys["root"] = signers(1)  # rotate the root key
    repo.root_version = 2
    # Signed by the new key only: the old root never approved it.
    with pytest.raises(MetadataError) as err:
        client.update_root(repo.root())
    assert err.value.code == "signatures"
    # Signed by both: accepted, and the version must be exactly 2.
    client.update_root(repo.root(extra_signers=old_root_signers))
    assert client.root.version == 2
    repo.root_version = 4
    with pytest.raises(MetadataError) as err:
        client.update_root(repo.root(extra_signers=repo.keys["root"]))
    assert err.value.code == "version"


def test_malformed_and_oversized_documents():
    repo = Repo()
    client = trusted(repo)
    with pytest.raises(MetadataError) as err:
        client.update_timestamp(b"not json")
    assert err.value.code == "format"
    with pytest.raises(MetadataError) as err:
        client.update_timestamp(b"[]")
    assert err.value.code == "format"
    with pytest.raises(MetadataError) as err:
        client.update_timestamp(b"{" + b" " * metadata.MAX_LENGTH["timestamp"] + b"}")
    assert err.value.code == "length"
    with pytest.raises(MetadataError) as err:
        client.update_snapshot(b"{}")
    assert err.value.code == "order"
    # A targets path that escapes the repository is refused even when signed.
    repo.targets = {"../etc/passwd": b"x"}
    ts, snap, tgt = repo.chain()
    client.update_timestamp(ts)
    client.update_snapshot(snap)
    with pytest.raises(MetadataError) as err:
        client.update_targets(tgt)
    assert err.value.code == "format"


def test_pinned_root_must_be_self_consistent():
    repo = Repo()
    env = metadata.loads(repo.root(), 1 << 20)
    env["signatures"] = []
    with pytest.raises(MetadataError):
        TrustedMetadata(metadata.dumps(env))
    env = metadata.loads(repo.root(), 1 << 20)
    env["signed"]["roles"]["timestamp"]["threshold"] = 5
    with pytest.raises(MetadataError) as err:
        TrustedMetadata(metadata.dumps(env))
    assert err.value.code == "format"


# --- the root ceremony: expiry, keyholder records, detached signatures --------------


def test_root_expiry_and_its_signing_period():
    assert metadata.DEFAULT_EXPIRY["root"] == 197 * 86400
    assert metadata.ROOT_SIGNING_PERIOD == 46 * 86400


def test_build_root_records_key_owners_and_they_round_trip():
    repo = Repo(root_count=2)
    alice, bob = (s.keyid for s in repo.keys["root"])
    role_keys = {r: [s.key for s in ks] for r, ks in repo.keys.items()}
    signed = metadata.build_root(role_keys, repo.thresholds, version=1, expires=iso(NOW + 86400),
                                 key_owners={alice: {"owner": "Alice", "term_start": "2026-11-01"},
                                             bob: {"owner": "Bob"}})
    raw = metadata.dumps(metadata.envelope(signed, repo.keys["root"]))
    client = TrustedMetadata(raw, now=lambda: NOW)  # signed with the rest, and a subscriber still accepts it
    keys = metadata.loads(client.root_raw, 1 << 20)["signed"]["keys"]
    assert keys[alice][metadata.KEYOWNER_FIELD] == "Alice"
    assert keys[alice][metadata.TERM_START_FIELD] == "2026-11-01"
    assert keys[bob][metadata.KEYOWNER_FIELD] == "Bob" and metadata.TERM_START_FIELD not in keys[bob]
    timestamp_key = repo.keys["timestamp"][0].keyid
    assert metadata.KEYOWNER_FIELD not in keys[timestamp_key]
    for owners in ({alice: {"owner": 7}}, {alice: {"owner": ""}}, {alice: {"employer": "x"}},
                   {timestamp_key: {"owner": "Tim"}}):
        with pytest.raises(ValueError):
            metadata.build_root(role_keys, repo.thresholds, version=1, expires=iso(NOW), key_owners=owners)


PACK = {"version": 1, "rules": [{"id": "r", "verdict": "block", "status": "stable", "when": {"arg": "x", "eq": 1}}]}


def keyholder(tmp_path, name):
    """A keyholder's own machine: one root key file, nothing else."""
    from interlock.mesh.repository import init_keys

    machine = tmp_path / ("machine-" + name)
    init_keys(str(machine))
    return machine / "root.1.json"


@pytest.fixture
def ceremony(tmp_path):
    """A commons published under a 2-of-3 root whose three keys then go offline,
    to Alice's, Bob's and Carol's machines, and a node subscribed to it."""
    import json
    import os

    from interlock.mesh.repository import init_keys, publish
    from interlock.mesh.subscriber import Subscriber

    source = tmp_path / "commons"
    (source / "packs").mkdir(parents=True)
    (source / "packs" / "p.json").write_text(json.dumps(PACK))
    keys = tmp_path / "keys"
    init_keys(str(keys), counts={"root": 3}, thresholds={"root": 2})
    site = tmp_path / "site"
    publish(str(source), str(site), str(keys))
    holders = {}
    for index, name in enumerate(("alice", "bob", "carol"), 1):
        machine = tmp_path / ("machine-" + name)
        machine.mkdir()
        (keys / "root.{}.json".format(index)).rename(machine / "root.json")
        holders[name] = machine / "root.json"
    node = Subscriber(str(tmp_path / "mesh"))
    node.init((site / "metadata" / "1.root.json").read_bytes(), ["file://" + str(site)], monitor_days=0)
    node.sync()
    # Carol steps down; Dave takes her seat.
    holders["dave"] = keyholder(tmp_path, "dave")
    manifest = {"version": 1, "keys": [
        {"public": json.loads(holders[n].read_text())["public"], "owner": n.title(), "term_start": "2026-11-01"}
        for n in ("alice", "bob", "dave")]}
    (keys / "root-keys.json").write_text(json.dumps(manifest))
    assert sorted(os.listdir(keys)) == ["log.1.json", "roles.json", "root-keys.json", "snapshot.1.json",
                                        "targets.1.json", "timestamp.1.json"]
    return {"source": source, "keys": keys, "site": site, "node": node, "holders": holders, "tmp": tmp_path,
            "draft": tmp_path / "ceremony" / "root-2.json"}


def mesh(*argv):
    from interlock.cli import main

    return main(["mesh", *map(str, argv)])


def draft(c, *extra):
    c["draft"].parent.mkdir(exist_ok=True)
    return mesh("root", "draft", "--site", c["site"], "--keys", c["keys"], "--out", c["draft"], *extra)


def sig_file(c, name):
    import json

    keyid = Signer(bytes.fromhex(json.loads(c["holders"][name].read_text())["seed"])).keyid
    return "{}.sig.{}".format(c["draft"], keyid)


def test_a_root_signed_by_two_of_three_detached_signers_is_followed(ceremony, capsys):
    import json

    from interlock.mesh.repository import publish, verify_site

    c = ceremony
    assert draft(c) == 0
    assert "sha256 of the bytes each keyholder signs" in capsys.readouterr().out
    # Two machines, two separate invocations, two detached signature files.
    assert mesh("root", "sign", c["draft"], "--key", c["holders"]["alice"]) == 0
    assert mesh("root", "sign", c["draft"], "--key", c["holders"]["bob"]) == 0
    sigs = [sig_file(c, "alice"), sig_file(c, "bob")]
    assert mesh("root", "assemble", c["draft"], "--sig", *sigs, "--site", c["site"]) == 0
    root = json.loads((c["site"] / "metadata" / "2.root.json").read_text())
    assert (c["site"] / "metadata" / "root.json").read_text() == (c["site"] / "metadata" / "2.root.json").read_text()
    owners = sorted((k.get(metadata.KEYOWNER_FIELD), k.get(metadata.TERM_START_FIELD))
                    for k in root["signed"]["keys"].values() if metadata.KEYOWNER_FIELD in k)
    assert owners == [("Alice", "2026-11-01"), ("Bob", "2026-11-01"), ("Dave", "2026-11-01")]
    assert publish(str(c["source"]), str(c["site"]), str(c["keys"]))["root_version"] == 2  # still no root key
    synced = c["node"].sync()
    assert synced["root_version"] == 2 and c["node"].status()["root_version"] == 2
    assert verify_site(str(c["site"]))["root_version"] == 2


def test_one_detached_signature_is_refused(ceremony, capsys):
    c = ceremony
    assert draft(c) == 0
    assert mesh("root", "sign", c["draft"], "--key", c["holders"]["alice"]) == 0
    capsys.readouterr()
    # The same signature twice still counts once.
    assert mesh("root", "assemble", c["draft"], "--sig", sig_file(c, "alice"), sig_file(c, "alice"),
                "--site", c["site"]) == 2
    err = capsys.readouterr().err
    assert "root v1 has 1 of the 2" in err and "the new root v2 has 1 of the 2" in err
    assert not (c["site"] / "metadata" / "2.root.json").exists()
    assert c["node"].sync()["root_version"] == 1


def test_the_old_root_must_approve_a_new_one(ceremony, capsys):
    import json

    c = ceremony
    # A root of only new keys: its own threshold is met, the old root never approved it.
    c["holders"]["erin"] = keyholder(c["tmp"], "erin")
    manifest = {"version": 1, "keys": [{"public": json.loads(c["holders"][n].read_text())["public"]}
                                       for n in ("dave", "erin")]}
    (c["keys"] / "root-keys.json").write_text(json.dumps(manifest))
    assert draft(c) == 0
    for name in ("dave", "erin"):
        assert mesh("root", "sign", c["draft"], "--key", c["holders"][name]) == 0
    capsys.readouterr()
    assert mesh("root", "assemble", c["draft"], "--sig", sig_file(c, "dave"), sig_file(c, "erin"),
                "--site", c["site"]) == 2
    assert "root v1 has 0 of the 2" in capsys.readouterr().err
    # Keys only in the old root may sign: the draft names them.
    for name in ("alice", "carol"):
        assert mesh("root", "sign", c["draft"], "--key", c["holders"][name]) == 0
    assert "previous root" in capsys.readouterr().out
    assert mesh("root", "assemble", c["draft"], "--sig", *(sig_file(c, n) for n in ("alice", "carol", "dave", "erin")),
                "--site", c["site"]) == 0
    assert c["node"].sync()["root_version"] == 2


def test_an_external_signer_signs_the_canonical_bytes(ceremony, tmp_path):
    import os
    import shlex
    import sys

    c = ceremony
    assert draft(c) == 0
    helper = tmp_path / "token-sign.py"
    helper.write_text(
        "import json, sys\n"
        "sys.path.insert(0, {root!r})\n"
        "from interlock.mesh import ed25519\n"
        "seed = bytes.fromhex(json.load(open(sys.argv[1]))['seed'])\n"
        "print(ed25519.sign(seed, sys.stdin.buffer.read()).hex())\n".format(
            root=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    command = " ".join(shlex.quote(p) for p in (sys.executable, str(helper), str(c["holders"]["bob"])))
    assert mesh("root", "sign", c["draft"], "--external-signer", command) == 0
    assert os.path.exists(sig_file(c, "bob"))
    assert mesh("root", "sign", c["draft"], "--key", c["holders"]["alice"]) == 0
    assert mesh("root", "assemble", c["draft"], "--sig", sig_file(c, "alice"), sig_file(c, "bob"),
                "--site", c["site"]) == 0
    # A signer that fails, or prints something that is not a signature, writes nothing.
    failing = " ".join(shlex.quote(p) for p in (sys.executable, "-c", "import sys; sys.exit(3)"))
    garbage = " ".join(shlex.quote(p) for p in (sys.executable, "-c", "print('00' * 64)"))
    other = c["tmp"] / "ceremony" / "other.json"
    other.write_bytes(c["draft"].read_bytes())
    for cmd in (failing, garbage):
        assert mesh("root", "sign", other, "--external-signer", cmd) == 2
    assert not [f for f in os.listdir(other.parent) if f.startswith("other.json.sig.")]


def test_a_ceremony_refuses_edited_drafts_strangers_and_reuse(ceremony, capsys):
    import json

    c = ceremony
    assert draft(c) == 0
    assert draft(c) == 2  # a draft is never overwritten
    for name in ("alice", "bob"):
        assert mesh("root", "sign", c["draft"], "--key", c["holders"][name]) == 0
    # A key in neither root cannot sign.
    stranger = keyholder(c["tmp"], "mallory")
    assert mesh("root", "sign", c["draft"], "--key", stranger) == 2
    # A draft edited after signing: the signatures no longer cover it.
    doc = json.loads(c["draft"].read_text())
    doc["signed"]["roles"]["root"]["threshold"] = 1
    edited = c["draft"].with_name("edited.json")
    edited.write_text(json.dumps(doc))
    capsys.readouterr()
    assert mesh("root", "assemble", edited, "--sig", sig_file(c, "alice"), sig_file(c, "bob"),
                "--site", c["site"]) == 2
    assert "does not verify" in capsys.readouterr().err
    assert mesh("root", "assemble", c["draft"], "--sig", sig_file(c, "alice"), sig_file(c, "bob"),
                "--site", c["site"]) == 0
    # Once assembled, the same draft is for a root the site already has.
    assert mesh("root", "assemble", c["draft"], "--sig", sig_file(c, "alice"), sig_file(c, "bob"),
                "--site", c["site"]) == 2
    assert "never reused" in capsys.readouterr().err
    assert mesh("root", "draft", "--site", c["site"], "--keys", c["keys"], "--out", c["tmp"] / "x.json",
                "--expires-days", "30") == 2  # shorter than its own signing period
    assert mesh("root") == 64


def test_the_first_root_can_come_from_a_ceremony_too(tmp_path):
    import json

    from interlock.mesh.repository import (PublishError, assemble_root, draft_root, init_keys, publish,
                                           sign_root, verify_site)

    source = tmp_path / "commons"
    (source / "packs").mkdir(parents=True)
    (source / "packs" / "p.json").write_text(json.dumps(PACK))
    keys = tmp_path / "keys"
    init_keys(str(keys))
    (keys / "root.1.json").unlink()  # this machine never holds a root key
    roles = json.loads((keys / "roles.json").read_text())
    roles["thresholds"]["root"] = 2
    (keys / "roles.json").write_text(json.dumps(roles))
    holders = [keyholder(tmp_path, n) for n in ("alice", "bob", "carol")]
    (keys / "root-keys.json").write_text(json.dumps(
        {"version": 1, "keys": [{"public": json.loads(h.read_text())["public"]} for h in holders]}))
    site = tmp_path / "site"
    with pytest.raises(PublishError):
        publish(str(source), str(site), str(keys))  # no root yet, and no root key to sign one
    draft = str(tmp_path / "root-1.json")
    doc = draft_root(str(site), str(keys), draft)
    assert doc["signed"]["version"] == 1 and "previous_root" not in doc
    sigs = [sign_root(draft, key_path=str(h))["path"] for h in holders[:2]]
    with pytest.raises(PublishError):
        assemble_root(draft, sigs[:1], str(site))
    assert assemble_root(draft, sigs, str(site))["root_version"] == 1
    result = publish(str(source), str(site), str(keys))
    assert result["root_version"] == 1 and not result["root_changed"]
    assert verify_site(str(site))["root_version"] == 1


def test_a_late_ceremony_recovers_an_expired_root(ceremony):
    from interlock.mesh.repository import PublishError, assemble_root, draft_root, publish, sign_root, verify_site

    c = ceremony
    root = metadata.loads((c["site"] / "metadata" / "root.json").read_bytes(), 1 << 16)
    later = from_iso(root["signed"]["expires"]) + 86400
    with pytest.raises(PublishError) as err:
        publish(str(c["source"]), str(c["site"]), str(c["keys"]), now=later)
    assert "expired" in str(err.value)
    draft = str(c["tmp"] / "late.json")
    draft_root(str(c["site"]), str(c["keys"]), draft, now=later)
    sigs = [sign_root(draft, key_path=str(c["holders"][n]))["path"] for n in ("alice", "bob")]
    assert assemble_root(draft, sigs, str(c["site"]), now=later)["root_version"] == 2
    assert publish(str(c["source"]), str(c["site"]), str(c["keys"]), now=later)["root_version"] == 2
    assert verify_site(str(c["site"]), now=later)["root_version"] == 2

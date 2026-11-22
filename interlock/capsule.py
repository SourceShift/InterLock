"""A portable evidence capsule: one sealed file an auditor can check alone.

A receipt log proves its own integrity only to someone who has the log, the
key, the policy and the anchor - four artefacts kept in four places, in a shape
that has to be explained each time. Regulation (EU AI Act, ISO 42001, NIST AI
RMF) presumes a record an *independent* party can check. This module packages
the four into one file and answers the questions such a party actually asks:

    interlock capsule create audit.jsonl --key-file audit.key --out evidence.zip
    interlock capsule verify evidence.zip --key-file audit.key

The bundle is a zip of ``receipts.jsonl`` (the log verbatim), an optional
``policy.json`` and ``anchor.json``, and ``manifest.json``, which records the
sha256 of every member, the receipt count and head, the key id, a redaction
attestation, and an HMAC over itself. Verification checks the manifest seal,
every member digest, the receipt chain (against the head the manifest names,
so a removed tail is caught), and the anchor if one is inside - then reports
the adequacy answers, naming each question the record cannot answer.

Two claims are deliberately not made. The manifest MAC proves the bundle was
built by a holder of the log's key; it does not prove which person did. And a
capsule without an anchor cannot show that its tail was not cut - the adequacy
report says so instead of implying coverage.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import zipfile
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .receipt import Receipt, hmac_sha256, verify_chain

#: The manifest schema; bumped only on an incompatible change.
CAPSULE_VERSION = 1

MANIFEST = "manifest.json"
RECEIPTS = "receipts.jsonl"
POLICY = "policy.json"
ANCHOR = "anchor.json"

#: A fixed zip timestamp, so bundling the same log twice gives identical bytes.
_FIXED_TIME = (1980, 1, 1, 0, 0, 0)


class CapsuleError(ValueError):
    """A capsule that cannot be built or read: unreadable, edited, wrong key."""


# --- the seal ------------------------------------------------------------------


def key_id(key: bytes) -> str:
    """A stable short name for a key, without exposing it.

    Derived, so two bundles built with the same key name it the same way and an
    auditor can tell "same signer" from "different signer" without the secret.
    """
    return hashlib.sha256(b"interlock-capsule-key-id:" + key).hexdigest()[:16]


def _canonical(doc: Dict[str, Any]) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")


def seal_manifest(key: bytes, manifest: Dict[str, Any]) -> str:
    """The manifest's MAC: HMAC over everything but ``signature``."""
    body = {name: value for name, value in manifest.items() if name != "signature"}
    return hmac.new(key, _canonical(body), hashlib.sha256).hexdigest()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# --- building ------------------------------------------------------------------


def _read_log(path: str) -> List[Receipt]:
    from .report import read_receipts

    receipts, bad = read_receipts(path)
    if bad:
        raise CapsuleError("{}: line {} is not a receipt ({} unreadable line(s))".format(
            path, bad[0], len(bad)))
    if not receipts:
        raise CapsuleError("{} contains no receipts: an empty capsule proves nothing".format(path))
    return receipts


def _read_bytes(path: str, what: str) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as exc:
        raise CapsuleError("cannot read the {} at {}: {}".format(what, path, exc))


def _redactions(receipts: Iterable[Receipt]) -> Dict[str, Any]:
    """The redaction attestation: how many values were masked, by kind.

    Counts only. A receipt's ``masked`` field is ``{kind: count}`` by design, so
    this cannot leak a value even when the masking was of very few entities.
    """
    by_kind: Dict[str, int] = {}
    touched = 0
    for receipt in receipts:
        masked = receipt.masked
        if not isinstance(masked, dict) or not masked:
            continue
        touched += 1
        for kind, count in masked.items():
            if isinstance(count, int) and count > 0:
                by_kind[str(kind)] = by_kind.get(str(kind), 0) + count
    return {"total": sum(by_kind.values()), "by_kind": dict(sorted(by_kind.items())),
            "receipts": touched}


def _anchor_facts(raw: bytes, receipts: List[Receipt], path: str) -> Dict[str, Any]:
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise CapsuleError("{} is not valid JSON; refusing to bundle it".format(path))
    if not isinstance(doc, dict) or not isinstance(doc.get("count"), int) \
            or not (doc.get("head") is None or isinstance(doc.get("head"), str)):
        raise CapsuleError("{} does not look like an anchor".format(path))
    count = int(doc["count"])
    if count > len(receipts):
        raise CapsuleError("{} anchors {} receipt(s) but the log has {}: the log is "
                           "shorter than its anchor".format(path, count, len(receipts)))
    if count and receipts[count - 1].mac != doc["head"]:
        raise CapsuleError("{} names a receipt the log does not contain at that "
                           "position: the log was rewritten or rolled back".format(path))
    return {"file": ANCHOR, "count": count, "head": doc["head"]}


def create_capsule(
    log_path: str,
    *,
    key: bytes,
    out_path: str,
    policy_path: Optional[str] = None,
    anchor_path: Optional[str] = None,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    """Build the bundle at *out_path* and return its manifest.

    The chain is verified first, so a bundle is never sealed over a broken log.
    ``policy_path`` and ``anchor_path`` are optional evidence: the policy that
    decided, and the head recorded outside the log.
    """
    receipts = _read_log(log_path)
    problem = verify_chain(receipts, hmac_sha256, key)
    if problem is not None:
        raise CapsuleError(
            "{} does not verify with this key ({}). Pass the key that signed the log."
            .format(log_path, problem))

    members: Dict[str, bytes] = {
        RECEIPTS: "".join(r.to_json() + "\n" for r in receipts).encode("utf-8"),
    }
    from . import __version__ as tool_version

    manifest: Dict[str, Any] = {
        "version": CAPSULE_VERSION,
        "created": float(now if now is not None else time.time()),
        "tool": {"name": "interlock", "version": tool_version},
        "key_id": key_id(key),
        "log": os.path.basename(log_path),
        "receipts": {
            "file": RECEIPTS,
            "count": len(receipts),
            "head": receipts[-1].mac,
            "first_ts": receipts[0].ts,
            "last_ts": receipts[-1].ts,
        },
        "redactions": _redactions(receipts),
    }
    if policy_path is not None:
        members[POLICY] = _read_bytes(policy_path, "policy")
        manifest["policy"] = {"file": POLICY}
    if anchor_path is not None:
        raw = _read_bytes(anchor_path, "anchor")
        members[ANCHOR] = raw
        manifest["anchor"] = _anchor_facts(raw, receipts, anchor_path)

    manifest["members"] = {name: _sha256(data) for name, data in members.items()}
    manifest["signature"] = seal_manifest(key, manifest)

    _write_bundle(out_path, members, manifest)
    return manifest


def _write_bundle(out_path: str, members: Dict[str, bytes],
                  manifest: Dict[str, Any]) -> None:
    directory = os.path.dirname(os.path.abspath(out_path))
    os.makedirs(directory, exist_ok=True)
    tmp = out_path + ".tmp-{}".format(os.getpid())
    try:
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zf:
            for name in sorted(members):
                zf.writestr(_info(name), members[name])
            zf.writestr(_info(MANIFEST), json.dumps(manifest, sort_keys=True,
                                                    indent=1).encode("utf-8") + b"\n")
        os.replace(tmp, out_path)
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise CapsuleError("cannot write {}: {}".format(out_path, exc))


def _info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=_FIXED_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    return info


# --- verifying -----------------------------------------------------------------


def _load_bundle(path: str) -> Tuple[Dict[str, bytes], Dict[str, Any]]:
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
            if MANIFEST not in names:
                raise CapsuleError("{} has no {}: not an interlock capsule".format(path, MANIFEST))
            try:
                manifest = json.loads(zf.read(MANIFEST).decode("utf-8"))
            except (UnicodeDecodeError, ValueError):
                raise CapsuleError("{}: the manifest is not valid JSON".format(path))
            members = {name: zf.read(name) for name in names if name != MANIFEST}
    except zipfile.BadZipFile:
        raise CapsuleError("{} is not a zip file".format(path))
    except OSError as exc:
        raise CapsuleError("cannot read {}: {}".format(path, exc))
    if not isinstance(manifest, dict):
        raise CapsuleError("{}: the manifest is not an object".format(path))
    return members, manifest


def _manifest_problems(manifest: Dict[str, Any], key: bytes) -> List[str]:
    problems: List[str] = []
    if manifest.get("version") != CAPSULE_VERSION:
        problems.append("manifest version {!r} is not {}".format(
            manifest.get("version"), CAPSULE_VERSION))
    expected = seal_manifest(key, manifest)
    actual = manifest.get("signature")
    if not isinstance(actual, str) or not hmac.compare_digest(actual, expected):
        problems.append("the manifest signature does not verify: it was edited, or "
                        "this is not the key the capsule was sealed with")
    return problems


def _member_problems(members: Dict[str, bytes], manifest: Dict[str, Any]) -> List[str]:
    problems: List[str] = []
    listed = manifest.get("members")
    if not isinstance(listed, dict) or not listed:
        return ["the manifest lists no members"]
    for name in sorted(set(listed) ^ set(members)):
        if name in listed:
            problems.append("member {} is missing from the bundle".format(name))
        else:
            problems.append("member {} is in the bundle but not in the manifest".format(name))
    for name, digest in sorted(listed.items()):
        if name in members and _sha256(members[name]) != digest:
            problems.append("member {} was edited: its sha256 does not match the "
                            "manifest".format(name))
    return problems


def _receipts_from(members: Dict[str, bytes]) -> Tuple[List[Receipt], List[str]]:
    raw = members.get(RECEIPTS)
    if raw is None:
        return [], ["{} is missing from the bundle".format(RECEIPTS)]
    receipts: List[Receipt] = []
    problems: List[str] = []
    for number, line in enumerate(raw.decode("utf-8", "replace").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            receipts.append(Receipt.from_json(line))
        except (TypeError, ValueError):
            problems.append("line {} of {} is not a receipt".format(number, RECEIPTS))
    return receipts, problems


def adequacy(receipts: List[Receipt], manifest: Dict[str, Any],
             problems: List[str]) -> List[Dict[str, Any]]:
    """The evidentiary-adequacy answers: one entry per binary question.

    Each question is answered from what the record contains, never inferred.
    An unanswered entry says why, so a reader does not mistake "not recorded"
    for "nothing happened".
    """
    total = len(receipts)
    answers: List[Dict[str, Any]] = []

    def add(question: str, answered: bool, detail: str) -> None:
        answers.append({"question": question, "answered": bool(answered), "detail": detail})

    principals = sum(1 for r in receipts if r.principal)
    add("who acted?", total > 0 and principals == total,
        "{} of {} receipt(s) name a principal".format(principals, total))

    times = sum(1 for r in receipts if isinstance(r.ts, (int, float)) and r.ts > 0)
    add("when?", total > 0 and times == total,
        "{} of {} receipt(s) carry a timestamp".format(times, total))

    non_allow = [r for r in receipts if r.verdict != "ALLOW"]
    named = sum(1 for r in non_allow if r.policy_id)
    add("which policy decided?", total > 0 and named == len(non_allow),
        "{} of {} non-ALLOW receipt(s) name a policy".format(named, len(non_allow)))

    escalations = [r for r in receipts
                   if r.policy_verdict == "ESCALATE" or r.verdict == "ESCALATE"]
    settled = sum(1 for r in escalations if r.approval)
    # A settlement names the grant that released it; a delegated one also
    # names the chain behind that grant. Counting both keeps the answer
    # honest without making a direct approval look incomplete.
    delegated = sum(1 for r in escalations if r.approval and r.authority)
    add("under which authority was an escalation settled?",
        settled == len(escalations),
        "{} of {} escalation receipt(s) name how they were settled{}".format(
            settled, len(escalations),
            " ({} of them with a delegation chain)".format(delegated) if delegated else ""))

    add("is the record intact?", not problems,
        "the manifest seal, every member digest and the receipt chain verify"
        if not problems else "{} problem(s) found - see above".format(len(problems)))

    anchor = manifest.get("anchor") if isinstance(manifest.get("anchor"), dict) else None
    add("is the whole run covered?", anchor is not None,
        "the bundle carries the anchor recorded outside the log ({} receipt(s))"
        .format(anchor.get("count")) if anchor is not None else
        "the bundle carries no external anchor: a receipt removed from the tail "
        "cannot be detected")

    redactions = (manifest.get("redactions")
                  if isinstance(manifest.get("redactions"), dict) else None)
    add("what was redacted?", redactions is not None and "total" in redactions,
        "{} value(s) masked in {} receipt(s)".format(redactions.get("total"),
                                                     redactions.get("receipts"))
        if redactions is not None and "total" in redactions
        else "the manifest carries no redaction attestation")

    tool = manifest.get("tool") if isinstance(manifest.get("tool"), dict) else {}
    add("which build produced it?",
        bool(tool.get("version")) and bool(manifest.get("key_id")),
        "interlock {} sealed it under key {}".format(tool.get("version"),
                                                     manifest.get("key_id")))
    return answers


def verify_capsule(bundle_path: str, *, key: bytes) -> Dict[str, Any]:
    """Check the bundle and report what it proves and what it cannot.

    Returns ``{"ok", "problems", "adequacy", "count", "key_id", "created"}``.
    ``ok`` is False on any structural or cryptographic problem; the adequacy
    entries are reported either way, because "intact but incomplete" is a real
    and useful answer.
    """
    members, manifest = _load_bundle(bundle_path)
    problems = _manifest_problems(manifest, key)
    problems.extend(_member_problems(members, manifest))
    receipts, receipt_problems = _receipts_from(members)
    problems.extend(receipt_problems)
    claimed = manifest.get("receipts") if isinstance(manifest.get("receipts"), dict) else {}
    if receipts and claimed.get("count") not in (None, len(receipts)):
        problems.append("the manifest names {} receipt(s); the bundle carries {}".format(
            claimed.get("count"), len(receipts)))
    if receipts:
        head = claimed.get("head") if isinstance(claimed.get("head"), str) else None
        problem = verify_chain(receipts, hmac_sha256, key, head=head)
        if problem is not None:
            problems.append(problem)
        anchor = manifest.get("anchor")
        if isinstance(anchor, dict):
            count = anchor.get("count")
            if isinstance(count, int) and count > len(receipts):
                problems.append("the anchor names {} receipt(s); the bundle carries {}"
                                .format(count, len(receipts)))
            elif isinstance(count, int) and count and receipts[count - 1].mac != anchor.get("head"):
                problems.append("receipt {} does not match the anchor's head".format(count))
    return {
        "ok": not problems,
        "problems": problems,
        "adequacy": adequacy(receipts, manifest, problems),
        "count": len(receipts),
        "key_id": manifest.get("key_id"),
        "created": manifest.get("created"),
    }

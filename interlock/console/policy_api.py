"""The policy editor's API: read, check and save the declarative policy, and
list the project overlays with their trust status.

Everything is computed by the real loader (:mod:`interlock.policy.declarative`)
- the console never re-implements validation. ``check`` compiles a draft the
way the guard will compile the file: same ``extends`` resolution (relative to
the policy file), same quarantine messages with their "did you mean", same
locked-rule rules, same epoch. A draft that does not parse is reported, never
saved.

Saving (``PUT /api/policy``) needs an unlocked tab, refuses a draft that does
not compile, and refuses to overwrite a file that changed on disk since the
page read it (``base_sha``). The write is atomic and keeps the file private
(``0600``). A new epoch voids every approval made under the old one - a
retry's binding no longer matches - so the approved reviews still awaiting a
retry are revoked in the queue rather than left looking usable.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from .server import ROUTES
from .session import ApiError, handles_errors, read_json_body, require_unlocked, setting, whoami

DEFAULT_TEXT = json.dumps({"version": 1, "extends": "builtin:coding-agent"}, indent=2) + "\n"


# --- describing rules -----------------------------------------------------------


def _fmt(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def condition_text(when: Any) -> str:
    """A one-line reading of a ``when`` condition."""
    if not isinstance(when, dict):
        return _fmt(when)
    if "all" in when and isinstance(when["all"], list):
        return " · ".join(condition_text(c) for c in when["all"])
    if "any" in when and isinstance(when["any"], list):
        return " or ".join(condition_text(c) for c in when["any"])
    if "not" in when:
        return "not ({})".format(condition_text(when["not"]))
    if "intent" in when:
        tail = " in args.{}".format(when["arg"]) if "arg" in when else ""
        intent = when["intent"]
        names = " or ".join(map(str, intent)) if isinstance(intent, list) else str(intent)
        return "intent {}{}".format(names, tail)
    if "action" in when and len(when) == 1:
        target = when["action"]
        if isinstance(target, dict):
            return "action " + " ".join("{} {}".format(k, v) for k, v in target.items())
        if isinstance(target, list):
            return "action in " + ", ".join(map(str, target))
        return "action eq {}".format(target)
    subject = "args.{}".format(when["arg"]) if "arg" in when else when.get("field", "?")
    ops = ["{} {}".format(k, _fmt(v)) for k, v in when.items() if k not in ("arg", "field")]
    return "{} {}".format(subject, " ".join(ops)).strip()


def _on_text(on: Any) -> str:
    if on is None:
        return ""
    if isinstance(on, dict):
        return "on " + " ".join("{} {}".format(k, v) for k, v in on.items()) + " · "
    if isinstance(on, list):
        return "on " + ", ".join(map(str, on)) + " · "
    return "on {} · ".format(on)


_CATALOG: Optional[Dict[str, Dict[str, Any]]] = None


def _detector_info(name: str) -> Tuple[Optional[str], List[str]]:
    """(catalog module, verdicts) for a detector rule's ``detector`` name."""
    global _CATALOG
    if _CATALOG is None:
        from .catalog import build_catalog
        _CATALOG = {d["module"]: d for d in build_catalog()["detectors"]}
    head = name.split(".")[0]
    if head in _CATALOG:
        return head, list(_CATALOG[head]["verdicts"])
    for module, det in _CATALOG.items():
        if any(f["name"] == name or f["name"] == name.split(".")[-1] for f in det["factories"]):
            return module, list(det["verdicts"])
    return None, []


def describe(raw: Dict[str, Any]) -> Dict[str, Any]:
    """id, verdict, reason and a readable condition for one rule document."""
    if "detector" in raw:
        module, verdicts = _detector_info(str(raw["detector"]))
        verdict = next((v for v in ("BLOCK", "MODIFY", "ESCALATE") if v in verdicts), "BLOCK")
        args = raw.get("with") or {}
        cond = "detector {}".format(raw["detector"])
        if args:
            cond += " " + ", ".join("{}={}".format(k, _fmt(v)) for k, v in args.items())
        return {"id": raw.get("id"), "verdict": verdict, "reason": raw.get("reason") or
                raw.get("description") or "", "cond": _on_text(raw.get("on")) + cond,
                "detector": module, "phase": raw.get("phase", "call")}
    verdict = str(raw.get("verdict") or "").upper() or "BLOCK"
    return {"id": raw.get("id"), "verdict": verdict, "reason": raw.get("reason") or "",
            "cond": _on_text(raw.get("on")) + condition_text(raw.get("when")),
            "detector": None, "phase": raw.get("phase", "call")}


# --- analysing a policy text -------------------------------------------------------


def analyse(text: str, path: str) -> Dict[str, Any]:
    """Compile ``text`` as the policy at ``path``; describe what the guard would run."""
    from ..policy import declarative as d

    try:
        doc = d.parse_policy_text(text, source=path)
    except d.PolicyError as exc:
        cause = exc.__cause__ or exc.__context__
        line = getattr(cause, "lineno", None)
        return {"ok": False, "parse_error": str(exc).replace(path + ": ", "", 1), "line": line}
    base_dir = os.path.dirname(path)
    try:
        documents, compiled, quarantined, locked = d._compile_with_extends(doc, path, base_dir, 0)
        parent: List[Any] = []
        if doc.get("extends") is not None:
            parent_doc, parent_source, parent_dir = d._resolve_extends(doc["extends"], path, base_dir)
            _, parent, _, _ = d._compile_with_extends(parent_doc, parent_source, parent_dir, 1)
    except d.PolicyError as exc:
        return {"ok": False, "parse_error": str(exc).replace(path + ": ", "", 1), "line": None}

    # "<path> rules[0] (cap-rows) when: ..." reads better without the location.
    where = re.compile(r"(?:{}\s+)?(?:rules\[\d+\]\s+)?(?:\([^)]*\)\s+)?".format(re.escape(path)))
    quarantined = [q.split(": ", 1)[0] + ": " + where.sub("", q.split(": ", 1)[1], count=1)
                   if ": " in q else q for q in quarantined]
    final_ids = {c.id for c in compiled}
    parent_ids = [c.id for c in parent]
    disabled = [x for x in (doc.get("disable") or []) if isinstance(x, str)]
    q_by_id: Dict[str, str] = {}
    for item in quarantined:
        q_by_id.setdefault(item.split(":", 1)[0], item)

    rules: List[Dict[str, Any]] = []
    for raw in doc.get("rules") or []:
        if not isinstance(raw, dict):
            continue
        info = describe(raw)
        rid = info["id"] or "?"
        info.update(source="own", locked=bool(raw.get("locked")), disabled=False,
                    quarantined=q_by_id.get(rid) if rid not in final_ids or rid in parent_ids else None)
        rules.append(info)
    pack: List[Dict[str, Any]] = []
    for c in parent:
        info = describe(dict(c.doc))
        info.update(source="inherited", locked=c.locked, quarantined=None,
                    disabled=c.id in disabled and not c.locked and c.id not in final_ids)
        pack.append(info)
    return {
        "ok": True,
        "extends": doc.get("extends"),
        "rules": rules + pack,
        "pack": [dict(r, disabled=False) for r in pack],
        "quarantined": quarantined,
        "locked": sorted(set(locked)),
        "disabled": disabled,
        "effective": len(compiled),
        "epoch": d._content_epoch(documents),
    }


def _policy_path(handler: Any) -> str:
    path = setting(handler, "policy_path")
    if path is None:
        from ..adapters.config import policy_path
        path = policy_path()
    return path


def _read(path: str) -> Tuple[bool, str, Optional[str]]:
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except FileNotFoundError:
        return False, DEFAULT_TEXT, None
    except OSError as exc:
        raise ApiError(500, "unreadable", "cannot read {}: {}".format(path, exc.strerror or exc))
    return True, raw.decode("utf-8", errors="replace"), hashlib.sha256(raw).hexdigest()


# --- routes -------------------------------------------------------------------------


@handles_errors
def _get_policy(handler: Any) -> Tuple[int, dict]:
    path = _policy_path(handler)
    exists, text, sha = _read(path)
    return 200, {"path": path, "exists": exists, "text": text, "sha": sha,
                 "analysis": analyse(text, path)}


@handles_errors
def _check_policy(handler: Any) -> Tuple[int, dict]:
    body = read_json_body(handler)
    text = body.get("text")
    if not isinstance(text, str):
        raise ApiError(400, "bad_request", "'text' must be the policy as a string")
    return 200, {"analysis": analyse(text, _policy_path(handler))}


def _write_atomic(path: str, text: str) -> None:
    directory = os.path.dirname(path)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".policy.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _void_approvals(handler: Any) -> List[str]:
    """Revoke approvals bound to the previous epoch; they can no longer match."""
    from .reviews_api import _queue

    queue = _queue(handler)
    if queue is None:
        return []
    voided = []
    for review in queue.list(status="approved", limit=500):
        try:
            queue.revoke(review.id, "epoch change")
            voided.append(review.id)
        except Exception:  # already claimed or expired: nothing to void
            continue
    return voided


@handles_errors
def _put_policy(handler: Any) -> Tuple[int, dict]:
    body = read_json_body(handler)
    require_unlocked(handler)
    text = body.get("text")
    if not isinstance(text, str):
        raise ApiError(400, "bad_request", "'text' must be the policy as a string")
    path = _policy_path(handler)
    analysis = analyse(text, path)
    if not analysis["ok"]:
        raise ApiError(400, "does_not_load",
                       "Fix the parse error first. The guard keeps the last good policy.")
    _, current_text, sha = _read(path)
    if body.get("base_sha") != sha:
        raise ApiError(409, "conflict", "The file changed on disk since you opened it. "
                                        "Reload to see the new version before saving.")
    before = analyse(current_text, path).get("epoch")
    _write_atomic(path, text if text.endswith("\n") else text + "\n")
    voided = _void_approvals(handler) if before != analysis["epoch"] else []
    _, saved_text, new_sha = _read(path)
    return 200, {"path": path, "exists": True, "text": saved_text, "sha": new_sha,
                 "analysis": analysis, "voided": voided, "by": whoami()}


@handles_errors
def _get_trust(handler: Any) -> Tuple[int, dict]:
    """Every overlay the trust list knows, plus the project overlay for the
    console's working directory, each with what the guard does with it."""
    from ..policy import declarative as d
    from ..policy.trust import TrustStore, file_digest, find_overlay

    store = TrustStore(setting(handler, "trust_path"))
    entries = dict(store.entries())
    raw = store._load()
    found = find_overlay(setting(handler, "project_cwd") or os.getcwd())
    paths = list(entries)
    if found and os.path.abspath(found) not in entries:
        paths.append(os.path.abspath(found))
    base_path = _policy_path(handler)
    _, base_text, _ = _read(base_path)
    overlays = []
    for path in paths:
        status = store.status(path)
        line, cmd = "", ""
        trusted_at = (raw.get(path) or {}).get("trusted_at")
        if status == "ok":
            added = 0
            try:
                overlay_doc, _ = d.read_policy_file(path)
                added = len(overlay_doc.get("rules") or [])
                engine = d.load_policy(d.parse_policy_text(base_text, source=base_path),
                                       source=base_path, overlays=[(path, overlay_doc)],
                                       base_dir=os.path.dirname(base_path))
                note = dict(engine.overlays).get(path, "applied")
            except d.PolicyError as exc:
                note = "ignored: {}".format(exc)
            if note.startswith("ignored"):
                status = "loosens"
                line = "Ignored whole: {}. Overlays can only tighten.".format(
                    note.split(": ", 1)[-1].replace(path + ": ", ""))
            else:
                line = "Adds {} rule{} on top of the base.".format(added, "" if added == 1 else "s")
        elif status == "untrusted":
            line = "Ignored until you trust this exact content."
            cmd = "interlock trust add {}".format(path)
        elif status == "changed":
            line = "Edited since you trusted it, so it is ignored until you trust it again."
            cmd = "interlock trust add {}".format(path)
        elif status == "missing":
            line = "Trusted before, but the file is gone. Remove the trust entry to tidy up."
            cmd = "interlock trust remove {}".format(path)
        overlays.append({"path": path, "status": status, "line": line, "cmd": cmd,
                         "trusted_at": trusted_at,
                         "sha": file_digest(path) if os.path.exists(path) else None})
    return 200, {"overlays": overlays, "trust_path": store.path}


ROUTES["/api/policy"] = {"GET": _get_policy, "PUT": _put_policy}
ROUTES["/api/policy/check"] = {"POST": _check_policy}
ROUTES["/api/trust"] = {"GET": _get_trust}

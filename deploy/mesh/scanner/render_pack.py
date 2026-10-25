#!/usr/bin/env python3
"""Render a reviewed advisory set into a mesh policy pack.

Nothing here decides that a skill is unsafe. The review file is the decision:
it names each skill that gets a rule, the verdict, and why. This script only
turns that decision into a declarative pack with stable rule ids and bounded
regular expressions, and records the scanner evidence alongside the rules.

The generated rules match **install-shaped shell commands** for the reviewed
skill. They do not match the skill's name in ordinary prose, and they do not
match a bare mention of its repository. A rule needs an install verb, the
repository, and the skill name.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

MAX_PATTERN = 512


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return cleaned or "skill"


def _install_pattern(source: str, skill_path: str, skill_name: str) -> str:
    """A bounded regex: install verb + repository + skill name, in any order."""
    repo = re.escape(source)
    name = re.escape(skill_name)
    # The verb set covers the common installers and copy/download flows. The
    # lookaheads let the tokens appear in any order (`repo --skill name` or
    # `cp repo/skills/name`). `[^\n]` keeps the whole match on one command line:
    # a repository named in prose on one line must not combine with a `cp` on
    # another line into a false positive.
    verb = (r"(?:^|[\s;&|])(?:npx\s+skills\s+(?:add|use)|skills\s+add|"
            r"git\s+clone|cp|install|curl|wget|download)\b")
    pattern = (
        "(?i)(?=[^\\n]*" + repo + ")"
        "(?=[^\\n]*\\b" + name + "\\b)"
        + verb
    )
    if len(pattern) > MAX_PATTERN:
        raise SystemExit("install pattern for {}/{} is {} chars (max {})".format(
            source, skill_path, len(pattern), MAX_PATTERN))
    return pattern


def _load(path: Path):
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--advisories", required=True)
    ap.add_argument("--review", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    advisories = _load(Path(args.advisories))
    review = _load(Path(args.review))
    by_id = {row["id"]: row for row in advisories.get("skills", [])}
    pack_name = review.get("pack") or "skill-safety"
    rules = []
    published = []
    for entry in review.get("rules", []):
        verdict = entry.get("verdict", "escalate")
        if verdict not in ("block", "escalate"):
            raise SystemExit("{}: verdict must be block or escalate".format(entry.get("id")))
        status = entry.get("status", "experimental")
        if status not in ("experimental", "test", "stable"):
            raise SystemExit("{}: status must be experimental, test or stable".format(entry.get("id")))
        if entry.get("generic"):
            # A pack-wide rule about the install surface itself, not a claim
            # about one skill. It still needs an explicit id and either a
            # ready ``when`` block or a Bash command pattern.
            if not entry.get("id"):
                raise SystemExit("a generic rule needs 'id'")
            when = entry.get("when")
            if when is None:
                if not entry.get("matches"):
                    raise SystemExit("generic rule {}: needs 'when' or 'matches'".format(entry["id"]))
                when = {
                    "all": [
                        {"action": "Bash"},
                        {"arg": "command", "matches": entry["matches"]},
                    ]
                }
            rules.append({
                "id": entry["id"],
                "verdict": verdict,
                "status": status,
                "reason": entry.get("reason") or "a reviewed install-surface advisory applies",
                "description": entry.get("description") or "Generic skill-install advisory.",
                "license": "Apache-2.0",
                "when": when,
            })
            continue
        skill_id = entry.get("skill")
        row = by_id.get(skill_id)
        if row is None:
            raise SystemExit("review names unknown skill {!r}".format(skill_id))
        tier = row["triage"].get("tier")
        if tier not in ("review_block", "review_escalate"):
            # A rule asserts something the scanner did not put in front of a
            # reviewer. An unscanned or clean row is not evidence for one.
            raise SystemExit("{}: tier {!r} is not a review candidate".format(skill_id, tier))
        if not row.get("digest") or not row["digest"].get("manifest_sha256"):
            raise SystemExit("{}: no manifest digest; the advisory cannot be bound to bytes".format(skill_id))
        source = row["source"]
        skill_path = row["path"]
        skill_name = Path(skill_path).name if skill_path != "." else Path(source).name
        pattern = entry.get("matches") or _install_pattern(source, skill_path, skill_name)
        rule_id = entry.get("id") or "skill-" + _slug(skill_id)
        material = row["triage"].get("material") or []
        evidence = ", ".join(
            "{} {} {}:{}".format(f.get("id"), f.get("severity"),
                                 f.get("file"), f.get("line"))
            for f in material[:4]
        ) or "no executable high-confidence finding"
        rules.append({
            "id": rule_id,
            "verdict": verdict,
            "status": status,
            "reason": entry.get("reason") or "a reviewed skill advisory applies",
            "description": (
                "{} at {} ({}). SkillSpector static score {}/100, recommendation {}. "
                "Review evidence: {}. Reviewed: {}."
            ).format(source, skill_path, row.get("commit", "unknown commit"),
                     row.get("raw", {}).get("score"), row.get("raw", {}).get("recommendation"),
                     evidence, entry.get("reviewed", "not recorded")),
            "license": "Apache-2.0",
            "when": {
                "all": [
                    {"action": "Bash"},
                    {"arg": "command", "matches": pattern},
                ]
            },
        })
        published.append({
            "skill": skill_id,
            "source": source,
            "path": skill_path,
            "commit": row.get("commit"),
            "scanned_at": row.get("scanned_at"),
            "scanner": row.get("scanner"),
            "digest": row.get("digest"),
            "raw": row.get("raw"),
            "triage": row.get("triage", {}).get("tier"),
            "material": material,
        })
    if not rules:
        raise SystemExit("review produced no rules; a pack needs at least one")
    pack = {
        "version": 1,
        "name": pack_name,
        "channel": review.get("channel") or "skill-safety",
        "description": review.get("description") or (
            "Reviewed skill-install advisories derived from static SkillSpector scans. "
            "Rules match install-shaped commands only; each rule names its source commit "
            "and the findings a human reviewed."
        ),
        "license": "Apache-2.0",
        "provenance": dict({
            "schema": advisories.get("schema"),
            "generated_at": advisories.get("generated_at"),
            "method": advisories.get("method"),
            "corpora": advisories.get("corpora"),
            "published": published,
        }, **(review.get("provenance") or {})),
        "rules": rules,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(pack, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, out)
    print("wrote {}: {} rule(s) across {} advisory(ies)".format(out, len(rules), len(published)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

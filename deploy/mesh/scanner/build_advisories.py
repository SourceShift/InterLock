#!/usr/bin/env python3
"""Turn raw SkillSpector reports into a reviewable advisory set.

This step does not publish policy. It applies a conservative triage so a human
can review the small set of skills whose *executable* code carries a
high-confidence security finding, instead of reading every raw issue.

Why the triage exists: SkillSpector's own score is useful for a single skill,
but it counts coverage findings (``AE1``, "a referenced file was not fully
inspected") and documentation matches at the same weight as executable code.
On a curated skill library that can turn a documentation example into
``DO_NOT_INSTALL``. A mesh policy must not repeat that mistake.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

#: Extensions whose findings describe code the skill can execute. Everything
#: else (Markdown, JSON fixtures, images) is documentation or data: relevant
#: for review, never enough on its own for a block.
EXECUTABLE_SUFFIXES = {
    ".py", ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd",
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".rb", ".pl", ".php",
    ".go", ".rs", ".java", ".kt", ".swift", ".scala", ".lua", ".r",
    ".exe", ".bin", ".so", ".dylib",
}

#: ``SKILL.md`` is prompt code: the agent follows it. A high-confidence
#: instruction-override finding there is material even though the file has no
#: executable suffix. Reference Markdown stays documentation.
MANIFEST_NAMES = {"skill.md"}

#: Findings that describe scan coverage, not skill behaviour. They still belong
#: in the advisory as a coverage caveat, but they must never become a verdict.
COVERAGE_FINDING_IDS = {"AE1"}

#: Confidence below this is a lead, not a finding worth a policy rule.
MIN_CONFIDENCE = 0.8

#: Evidence binding. An advisory is about the exact bytes that were scanned, so
#: the manifest and every file it references get a digest. A changed digest
#: invalidates the advisory: the reviewer approved those bytes, not the name.
MAX_REF_BYTES = 512 * 1024
MAX_REFS = 64
_REF_RE = re.compile(r"`([^`\n]+)`|\]\(([^)\n]+)\)")


def _git_commit(root: Path):
    try:
        proc = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10)
        return proc.stdout.strip() if proc.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def digest_skill(skill_dir: Path):
    """Hash ``SKILL.md`` and the files it references, bounded to its own tree.

    Resolution is deliberately narrow: only backticked paths and Markdown links
    that land inside the skill directory count. A URL, an absolute path, a
    ``..`` escape, a missing file and a file over ``MAX_REF_BYTES`` are all
    excluded — and any of the last three marks the digest incomplete, so a
    consumer can tell a partial record from a full one.
    """
    manifest = skill_dir / "SKILL.md"
    if not manifest.is_file():
        return {"algorithm": "sha256", "complete": False, "manifest_sha256": None,
                "manifest_bytes": None, "files": []}
    try:
        text = manifest.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {"algorithm": "sha256", "complete": False, "manifest_sha256": None,
                "manifest_bytes": None, "files": []}
    root = skill_dir.resolve()
    seen = set()
    files = []
    complete = True
    for match in _REF_RE.finditer(text):
        raw = (match.group(1) or match.group(2) or "").strip()
        if not raw or "://" in raw or raw.startswith(("#", "/", "mailto:")):
            continue
        raw = raw.split("#", 1)[0]
        # Backticks in a manifest usually quote prose, not a path. Only a
        # path-shaped token is a candidate: one line, no whitespace or shell
        # metacharacters, and either a directory component or a file suffix.
        if (not raw or len(raw) > 200 or re.search(r"[\s\"'<>|*?]", raw)
                or ("/" not in raw and "." not in raw.rsplit("/", 1)[-1])):
            continue
        candidate = (root / raw).resolve()
        try:
            candidate.relative_to(root)
        except ValueError:
            continue
        try:
            if not candidate.is_file():
                continue
        except OSError:
            continue
        if candidate in seen:
            continue
        seen.add(candidate)
        if len(files) >= MAX_REFS or candidate.stat().st_size > MAX_REF_BYTES:
            complete = False
            continue
        files.append({
            "path": candidate.relative_to(root).as_posix(),
            "sha256": _sha256(candidate),
            "bytes": candidate.stat().st_size,
        })
    files.sort(key=lambda item: item["path"])
    return {
        "algorithm": "sha256",
        "complete": complete,
        "manifest_sha256": _sha256(manifest),
        "manifest_bytes": manifest.stat().st_size,
        "files": files,
    }


def _suffix(path: str) -> str:
    name = (path or "").lower()
    for suffix in sorted(EXECUTABLE_SUFFIXES, key=len, reverse=True):
        if name.endswith(suffix):
            return suffix
    return ""


def _is_material_file(path: str) -> bool:
    name = (path or "").lower()
    return bool(_suffix(name)) or name.rsplit("/", 1)[-1] in MANIFEST_NAMES


def _compact(finding):
    location = finding.get("location") or {}
    return {
        "id": finding.get("id"),
        "category": finding.get("category"),
        "pattern": finding.get("pattern"),
        "severity": finding.get("severity"),
        "confidence": finding.get("confidence"),
        "file": location.get("file"),
        "line": location.get("start_line"),
        "explanation": (finding.get("explanation") or "")[:400],
        "executable": _is_material_file(location.get("file") or ""),
    }


def triage(report):
    """Return the review tier for one report and the findings behind it."""
    issues = report.get("issues") or []
    compact = [_compact(issue) for issue in issues]
    material = []
    for finding in compact:
        if finding["id"] in COVERAGE_FINDING_IDS:
            continue
        confidence = finding.get("confidence")
        if not isinstance(confidence, (int, float)) or confidence < MIN_CONFIDENCE:
            continue
        if not finding["executable"]:
            continue
        if finding.get("severity") in ("HIGH", "CRITICAL"):
            material.append(dict(finding, tier="block_candidate"))
        elif finding.get("severity") == "MEDIUM":
            material.append(dict(finding, tier="escalate_candidate"))
    completeness = report.get("analysis_completeness") or {}
    coverage_complete = bool(completeness.get("is_complete"))
    if any(f["tier"] == "block_candidate" for f in material):
        tier = "review_block"
    elif any(f["tier"] == "escalate_candidate" for f in material):
        tier = "review_escalate"
    elif issues or not coverage_complete:
        tier = "watch"
    else:
        tier = "clear"
    return {
        "tier": tier,
        "material": material,
        "coverage_complete": coverage_complete,
        "coverage_percent": completeness.get("coverage_percent"),
        "coverage_findings": sum(1 for finding in compact
                                 if finding["id"] in COVERAGE_FINDING_IDS),
    }


def _load_index(reports_dir: Path):
    path = reports_dir / "index.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SystemExit("{}: {}".format(path, exc))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", action="append", required=True,
                    help="a scan output directory (contains index.json); repeatable")
    ap.add_argument("--out", required=True)
    ap.add_argument("--corpus-map",
                    help="JSON object mapping a report directory name to a source label")
    args = ap.parse_args()
    names = {}
    if args.corpus_map:
        with open(args.corpus_map, "r", encoding="utf-8") as fh:
            names = json.load(fh)
    skills = []
    corpora = []
    for value in args.reports:
        reports_dir = Path(value)
        index = _load_index(reports_dir)
        if index is None:
            print("skip {}: no index.json".format(reports_dir), file=sys.stderr)
            continue
        label = names.get(reports_dir.name, reports_dir.name)
        commit = index.get("commit")
        if not commit and index.get("root"):
            commit = _git_commit(Path(index["root"]))
        scanned_at = index.get("scanned_at")
        corpora.append({
            "source": label,
            "commit": commit,
            "skills": index.get("total"),
            "scanned": sum(1 for result in index.get("results", [])
                           if result.get("path") and os.path.exists(result["path"])),
            "scanned_at": scanned_at,
        })
        for result in index.get("results", []):
            report_path = result.get("path")
            skill_dir = result.get("source") or (
                str(Path(index["root"]) / result.get("repo", "") / result["skill"])
                if index.get("root") and result.get("repo") not in (None, ".") else None)
            digest = digest_skill(Path(skill_dir)) if skill_dir and Path(skill_dir).is_dir() else None
            if not report_path or not os.path.exists(report_path):
                skills.append({
                    "id": "{}/{}".format(label, result["skill"]).replace("/", "--"),
                    "source": label,
                    "repo": result.get("repo"),
                    "path": result["skill"],
                    "commit": commit,
                    "scanned_at": scanned_at,
                    "digest": digest,
                    "scanner": {"name": "SkillSpector", "llm": False},
                    "raw": {"score": None, "severity": None, "recommendation": None},
                    "triage": {
                        "tier": "not_scanned",
                        "material": [],
                        "coverage_complete": False,
                        "coverage_percent": None,
                        "coverage_findings": 0,
                        "status": result.get("status"),
                    },
                })
                continue
            try:
                report = json.loads(Path(report_path).read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            finding = triage(report)
            raw = report.get("risk_assessment") or {}
            skills.append({
                "id": "{}/{}".format(label, result["skill"]).replace("/", "--"),
                "source": label,
                "repo": result.get("repo"),
                "path": result["skill"],
                "commit": commit,
                "scanned_at": scanned_at,
                "digest": digest,
                "scanner": {
                    "name": "SkillSpector",
                    "version": (report.get("metadata") or {}).get("skillspector_version"),
                    "llm": False,
                },
                "raw": {
                    "score": raw.get("score"),
                    "severity": raw.get("severity"),
                    "recommendation": raw.get("recommendation"),
                },
                "triage": finding,
            })
    skills.sort(key=lambda row: (row["triage"]["tier"] != "review_block",
                                 row["triage"]["tier"] != "review_escalate",
                                 row["source"], row["path"]))
    payload = {
        "schema": 1,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "method": {
            "scanner": "SkillSpector",
            "llm": False,
            "min_confidence": MIN_CONFIDENCE,
            "executable_only_for_material": True,
            "coverage_finding_ids_ignored_for_verdict": sorted(COVERAGE_FINDING_IDS),
            "digest": "sha256 over SKILL.md and the files it references inside the skill directory",
            "incomplete_scan_never_clear": True,
        },
        "corpora": corpora,
        "skills": skills,
    }
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_suffix(out.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, out)
    counts = {}
    for skill in skills:
        tier = skill["triage"]["tier"]
        counts[tier] = counts.get(tier, 0) + 1
    print("advisories: {} skill(s) {}".format(len(skills), counts))
    return 0


if __name__ == "__main__":
    sys.exit(main())

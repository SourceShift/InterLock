#!/usr/bin/env python3
"""Scan every ``SKILL.md`` under a corpus root with SkillSpector, statically.

One subprocess per skill, bounded by ``--timeout``. A scanner exit of 1 means
"the scanner's own risk gate fired", which is still a complete scan; only a
missing or malformed report is an error for this driver.

The output is deliberately the scanner's own JSON, unmodified, plus an index.
Building policy from it is a separate, reviewable step (``build_advisories.py``
and ``render_pack.py``); keeping the raw evidence lets a reviewer see exactly
what the scanner said even after the derived pack changes.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def discover(root: Path):
    """Return ``(repo, skill, directory)`` for every skill in the corpus."""
    found = []
    for path in sorted(root.rglob("SKILL.md")):
        if not path.is_file():
            continue
        rel = path.parent.relative_to(root)
        parts = rel.parts
        if len(parts) < 2:
            # A SKILL.md at the corpus root is a single skill, not a repository
            # of skills; name it so the report path stays valid.
            found.append((root.name, ".", path.parent))
            continue
        found.append((parts[0], "/".join(parts[1:]), path.parent))
    return found


def _git_commit(root: Path):
    try:
        proc = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=10)
        return proc.stdout.strip() if proc.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def one(repo, skill, directory, out_root, scanner, timeout, force):
    safe_skill = skill.replace("/", "__")
    dest = out_root / repo / (safe_skill + ".json")
    meta = dest.with_suffix(".meta.json")
    if dest.exists() and meta.exists() and not force:
        try:
            data = json.loads(dest.read_text(encoding="utf-8"))
            return {"repo": repo, "skill": skill, "status": "cached",
                    "risk": data.get("risk_assessment"), "path": str(dest),
                    "source": data.get("skill", {}).get("source")}
        except (OSError, ValueError):
            pass
    dest.parent.mkdir(parents=True, exist_ok=True)
    started = time.time()
    cmd = [scanner, "scan", str(directory), "--no-llm", "--format", "json",
           "--output", str(dest)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        elapsed = round(time.time() - started, 1)
        if not dest.exists():
            return {"repo": repo, "skill": skill, "status": "error",
                    "error": (proc.stderr or proc.stdout)[-2000:], "seconds": elapsed}
        data = json.loads(dest.read_text(encoding="utf-8"))
        result = {
            "repo": repo,
            "skill": skill,
            "status": "ok" if proc.returncode in (0, 1) else "warn",
            "returncode": proc.returncode,
            "seconds": elapsed,
            "risk": data.get("risk_assessment"),
            "issues": len(data.get("issues", [])),
            "path": str(dest),
            "source": data.get("skill", {}).get("source"),
        }
        meta.write_text(json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        return result
    except subprocess.TimeoutExpired:
        return {"repo": repo, "skill": skill, "status": "timeout", "seconds": timeout}
    except Exception as exc:  # noqa: BLE001 - one skill must not kill the batch
        return {"repo": repo, "skill": skill, "status": "error", "error": repr(exc),
                "seconds": round(time.time() - started, 1)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", required=True, help="a checkout holding skills")
    ap.add_argument("--out", required=True, help="where reports and index.json go")
    ap.add_argument("--scanner", default="skillspector")
    ap.add_argument("--workers", type=int, default=3)
    ap.add_argument("--timeout", type=float, default=300)
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    root = Path(args.root)
    out_root = Path(args.out)
    out_root.mkdir(parents=True, exist_ok=True)
    skills = discover(root)
    print("discovered {} skill(s) under {}".format(len(skills), root), flush=True)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        futures = {
            pool.submit(one, r, s, d, out_root, args.scanner, args.timeout, args.force): (r, s)
            for r, s, d in skills
        }
        for done, future in enumerate(concurrent.futures.as_completed(futures), 1):
            result = future.result()
            results.append(result)
            risk = result.get("risk") or {}
            print("[{}/{}] {} {} -> {} {} {:.0f}s".format(
                done, len(skills), result["repo"], result["skill"],
                risk.get("score", "-"), risk.get("severity", "-"),
                result.get("seconds", 0)), flush=True)
    results.sort(key=lambda r: (r["repo"], r["skill"]))
    index = {
        "root": str(root.resolve()),
        "commit": _git_commit(root),
        "scanner": args.scanner,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total": len(results),
        "results": results,
    }
    tmp = out_root / "index.json.tmp"
    tmp.write_text(json.dumps(index, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, out_root / "index.json")
    counts = {}
    for result in results:
        counts[result["status"]] = counts.get(result["status"], 0) + 1
    print("done: {}".format(counts))
    return 0 if results else 2


if __name__ == "__main__":
    sys.exit(main())

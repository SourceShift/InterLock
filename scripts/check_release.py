#!/usr/bin/env python3
"""Check that a release tag agrees with the tree before anything is published.

A release is the one build nobody can retract: PyPI and npm keep the version
number permanently, and a mistaken tag publishes a package whose metadata,
changelog and code disagree. So the tag is checked against every place the
version is written — ``pyproject.toml``, ``js/package.json`` and
``web/package.json`` (the console's version travels with the Python package) —
and against a ``CHANGELOG.md`` entry, before any publish step runs.

Usage::

    python3 scripts/check_release.py v0.0.2
    python3 scripts/check_release.py --print-version v0.0.2   # for workflow $GITHUB_OUTPUT
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import List, Optional, Sequence

ROOT = Path(__file__).resolve().parent.parent

#: ``0.0.1``, ``1.2.3rc1``, ``2.0.0+build.7`` — PEP 440 is broader, but a
#: release tag should be boring: three numbers and at most one suffix.
_VERSION = re.compile(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?")
_PROJECT_SECTION = re.compile(r"^\[project\]\s*$", re.MULTILINE)
_NEXT_SECTION = re.compile(r"^\[", re.MULTILINE)
_VERSION_LINE = re.compile(r'^version\s*=\s*"([^"]+)"\s*$', re.MULTILINE)


def tag_version(tag: str) -> Optional[str]:
    """The version a tag names, or None when the tag is not a release tag.

    Both ``v0.0.1`` and ``0.0.1`` are accepted: the workflow triggers on
    ``v*``, but a local dry run should not need the prefix to be repeated.
    """
    version = tag[1:] if tag.startswith("v") else tag
    return version if _VERSION.fullmatch(version) else None


def pyproject_version(text: str) -> Optional[str]:
    """Read ``[project] version`` without requiring a TOML parser (3.9 has none)."""
    section = _PROJECT_SECTION.search(text)
    if section is None:
        return None
    rest = text[section.end():]
    following = _NEXT_SECTION.search(rest)
    body = rest[: following.start()] if following else rest
    match = _VERSION_LINE.search(body)
    return match.group(1) if match else None


def changelog_has_version(text: str, version: str) -> bool:
    """Whether the changelog has a ``## [<version>]`` heading for this release."""
    escaped = re.escape(version)
    return re.search(r"^## \[{0}\](?:\s|$)".format(escaped), text, re.MULTILINE) is not None


def _read(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def check(tag: str, root: Path = ROOT) -> List[str]:
    """Every inconsistency between *tag* and the tree, as human-readable lines."""
    version = tag_version(tag)
    if version is None:
        return ["tag '{}' is not vMAJOR.MINOR.PATCH".format(tag)]

    problems = []
    pyproject = _read(root / "pyproject.toml")
    declared = pyproject_version(pyproject) if pyproject is not None else None
    if declared != version:
        problems.append("pyproject.toml says '{}', tag says '{}'".format(declared, version))

    for relative in ("js/package.json", "web/package.json"):
        package = _read(root / relative)
        try:
            manifest = json.loads(package) if package is not None else None
        except ValueError as exc:
            problems.append("cannot read {}: {}".format(relative, exc))
            continue
        if not isinstance(manifest, dict):
            problems.append("cannot read {}: not an object".format(relative))
        elif manifest.get("version") != version:
            problems.append("{} says '{}', tag says '{}'".format(
                relative, manifest.get("version"), version))

    changelog = _read(root / "CHANGELOG.md")
    if changelog is None:
        problems.append("cannot read CHANGELOG.md")
    elif not changelog_has_version(changelog, version):
        problems.append("CHANGELOG.md has no '## [{}]' section".format(version))
    return problems


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="check a release tag against pyproject.toml, js/package.json "
                    "and CHANGELOG.md")
    parser.add_argument("tag", help="the release tag, e.g. v0.0.1")
    parser.add_argument("--root", type=Path, default=ROOT, help="checkout to inspect")
    parser.add_argument(
        "--print-version", action="store_true",
        help="on success, print the bare version (for $GITHUB_OUTPUT)",
    )
    args = parser.parse_args(argv)

    problems = check(args.tag, args.root)
    if problems:
        for problem in problems:
            print("release check: " + problem, file=sys.stderr)
        return 1
    if args.print_version:
        print(tag_version(args.tag))
    else:
        print("release check: {} agrees with pyproject.toml, js/package.json, "
              "web/package.json and CHANGELOG.md".format(args.tag))
    return 0


if __name__ == "__main__":
    sys.exit(main())

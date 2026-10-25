#!/usr/bin/env python3
"""Checks for the docs site that neither of its two Zensical builds can make.

The site is two builds -- the landing page at / from zensical.landing.toml and
the manual at /docs/ from zensical.toml -- and each build only sees its own
half. This script checks what falls between them:

* the landing config mirrors the manual's where the comments say it does
  (palette, Markdown extensions, fonts, favicon), so the prose renders the
  same on both halves and nobody has to keep the two files in sync by eye;
* the two favicon copies are the same drawing;
* the landing page's links into the manual resolve against the built tree.
  They are written as served URLs (``docs/foo/``), because the landing build
  cannot see the manual's files to check a ``foo.md``; this is that check;
* the built tree has the shape the deploy relies on: the landing owns site/
  (its index, 404, _redirects and robots.txt), the manual owns site/docs/.

Run it after both builds (``make docs`` does). ``--config-only`` runs just the
checks that need no build, which is what the test suite calls.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import List

try:                                       # Python 3.11+
    import tomllib
except ModuleNotFoundError:                # 3.9 and 3.10, via the dev extra
    import tomli as tomllib

ROOT = Path(__file__).resolve().parent.parent
MANUAL_CONFIG = ROOT / "zensical.toml"
LANDING_CONFIG = ROOT / "zensical.landing.toml"
SITE = ROOT / "site"

#: ``[project.theme]`` keys the landing config must mirror from the manual's.
MIRRORED_THEME_KEYS = ("favicon", "font", "palette", "language", "custom_dir")

#: Pages whose internal links are checked against the built tree, as
#: ``(path under site/, URL path the page is served at)``.
LINKED_PAGES = (
    ("index.html", "/"),
    ("404.html", "/"),
    ("docs/404.html", "/docs/"),
)

#: Files the deploy relies on, under site/.
TREE_FILES = (
    "index.html",
    "404.html",
    "_redirects",
    "robots.txt",
    "docs/index.html",
    "docs/404.html",
)


def _load(path: Path) -> dict:
    with path.open("rb") as fh:
        return tomllib.load(fh)["project"]


def check_config_mirror() -> List[str]:
    """The landing config mirrors the manual's where it claims to."""
    manual, landing = _load(MANUAL_CONFIG), _load(LANDING_CONFIG)
    problems: List[str] = []

    for key in ("site_name", "site_description", "site_author", "copyright",
                "repo_url", "repo_name", "markdown_extensions"):
        if manual.get(key) != landing.get(key):
            problems.append(f"{key} differs between zensical.toml and zensical.landing.toml")
    for key in MIRRORED_THEME_KEYS:
        if manual["theme"].get(key) != landing["theme"].get(key):
            problems.append(f"theme.{key} differs between zensical.toml and zensical.landing.toml")

    # The shape the two builds rely on, spelled out so a drift in either file
    # fails here rather than as a missing page on the host.
    if landing.get("site_url", "") + "docs/" != manual.get("site_url"):
        problems.append("the manual's site_url must be the landing's site_url + 'docs/'")
    if landing.get("site_dir") != "site" or manual.get("site_dir") != "site/docs":
        problems.append("site_dir must be 'site' (landing) and 'site/docs' (manual)")
    if landing.get("docs_dir") != "landing" or manual.get("docs_dir", "docs") != "docs":
        problems.append("docs_dir must be 'landing' (landing) and 'docs' (manual)")
    if landing.get("extra", {}).get("landing") is not True:
        problems.append("zensical.landing.toml must set [project.extra] landing = true")
    if "landing" in manual.get("extra", {}):
        problems.append("zensical.toml must not set extra.landing: that flag is the landing build's")
    if landing.get("extra_javascript"):
        problems.append("the landing build must not list extra_javascript: the diagram script ships with the manual")
    return problems


def check_favicon() -> List[str]:
    """Both builds ship the favicon; they must be the same file."""
    manual = ROOT / "docs" / "assets" / "images" / "favicon.svg"
    landing = ROOT / "landing" / "assets" / "images" / "favicon.svg"
    if not (manual.exists() and landing.exists()):
        return ["a favicon.svg is missing under docs/assets/images or landing/assets/images"]
    if manual.read_bytes() != landing.read_bytes():
        return ["docs/assets/images/favicon.svg and landing/assets/images/favicon.svg differ; copy one over the other"]
    return []


def check_tree(site: Path = SITE) -> List[str]:
    """The built tree has the shape the deploy relies on."""
    missing = [f for f in TREE_FILES if not (site / f).is_file()]
    return [f"site/{f} is missing; run both builds, landing first" for f in missing]


_LINK = re.compile(r'\b(?:href|src)="([^"]+)"')


def _targets(html: str):
    for url in _LINK.findall(html):
        if url.startswith(("http://", "https://", "mailto:", "data:", "#", "//")):
            continue
        yield url.split("#", 1)[0].split("?", 1)[0]


def check_links(site: Path = SITE) -> List[str]:
    """Every internal link on the landing page and the 404 pages resolves."""
    problems: List[str] = []
    for rel, served_at in LINKED_PAGES:
        page = site / rel
        if not page.is_file():
            continue  # check_tree reports it
        for url in _targets(page.read_text(encoding="utf-8")):
            if not url:
                continue
            base = "/" if url.startswith("/") else served_at
            path = (base + url.lstrip("/")) if url.startswith("/") else (base + url)
            parts = [p for p in path.split("/") if p not in ("", ".")]
            # Zensical writes ../ for links up the tree; resolve them the way a
            # browser would, from the page's own directory.
            resolved: List[str] = []
            for p in parts:
                if p == "..":
                    if resolved:
                        resolved.pop()
                else:
                    resolved.append(p)
            target = site.joinpath(*resolved) if resolved else site
            if path.endswith("/") or not resolved:
                target = target / "index.html"
            if not target.is_file():
                problems.append(f"{rel} links to {url}, which is not in the built site")
    return problems


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--config-only", action="store_true",
                        help="only the checks that need no build")
    args = parser.parse_args(argv)

    problems = check_config_mirror() + check_favicon()
    if not args.config_only:
        problems += check_tree() + check_links()
    for problem in problems:
        print(f"check_site: {problem}", file=sys.stderr)
    if problems:
        return 1
    print("check_site: ok" + (" (config only)" if args.config_only else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())

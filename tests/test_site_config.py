"""The two Zensical configs stay in step.

The docs site is two builds, and zensical.landing.toml mirrors zensical.toml
where the theme needs it. ``scripts/check_site.py`` is what makes "mirrors"
true; this runs its build-free half so a drift fails the suite, not just the
docs workflow.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

try:                                       # Python 3.11+
    import tomllib
except ModuleNotFoundError:                # 3.9 and 3.10, via the dev extra
    import tomli as tomllib

ROOT = Path(__file__).resolve().parent.parent

#: The C7 operations pages. Each must be both a file under docs/ and an entry
#: in the manual's nav: Zensical has no exclude list, so a page that exists but
#: is absent from `nav` is built and served but unreachable.
CLOUD_PAGES = (
    "guides/cloud.md",
    "guides/cloud-rollout.md",
    "reference/cloud-artifact.md",
    "reference/cloud-runbook.md",
)


def _nav_page_paths(nav):
    for item in nav:
        for _label, value in item.items():
            if isinstance(value, str):
                yield value
            else:
                yield from _nav_page_paths(value)


def _check_site():
    spec = importlib.util.spec_from_file_location("check_site", ROOT / "scripts" / "check_site.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_landing_config_mirrors_the_manual():
    check_site = _check_site()
    assert check_site.check_config_mirror() == []


def test_both_favicons_are_the_same_drawing():
    check_site = _check_site()
    assert check_site.check_favicon() == []


def test_cloud_pages_are_built_and_in_the_manual_nav():
    """The four C7 pages exist and every one is reachable from the nav."""
    config = tomllib.loads((ROOT / "zensical.toml").read_text(encoding="utf-8"))
    nav_paths = set(_nav_page_paths(config["project"]["nav"]))
    missing_from_nav = [page for page in CLOUD_PAGES if page not in nav_paths]
    assert not missing_from_nav, (
        "these cloud pages are not in zensical.toml nav: {}".format(
            ", ".join(missing_from_nav)
        )
    )
    missing_files = [page for page in CLOUD_PAGES if not (ROOT / "docs" / page).is_file()]
    assert not missing_files, (
        "nav names cloud pages that do not exist: {}".format(", ".join(missing_files))
    )


def test_nothing_scratch_under_docs():
    """Everything under docs/ is published at interlock.sourceshift.ai/docs/.

    Zensical has no exclude list, so the only way to keep scratch off the site
    is to keep it out of docs/. Todos, audits and notes go in todos/.
    """
    assert not (ROOT / "docs" / "todos").exists(), (
        "docs/todos/ exists; move it to todos/ -- every file under docs/ is published"
    )

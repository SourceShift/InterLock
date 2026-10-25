"""The two Zensical configs stay in step.

The docs site is two builds, and zensical.landing.toml mirrors zensical.toml
where the theme needs it. ``scripts/check_site.py`` is what makes "mirrors"
true; this runs its build-free half so a drift fails the suite, not just the
docs workflow.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


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


def test_nothing_scratch_under_docs():
    """Everything under docs/ is published at interlock.sourceshift.ai/docs/.

    Zensical has no exclude list, so the only way to keep scratch off the site
    is to keep it out of docs/. Todos, audits and notes go in todos/.
    """
    assert not (ROOT / "docs" / "todos").exists(), (
        "docs/todos/ exists; move it to todos/ -- every file under docs/ is published"
    )

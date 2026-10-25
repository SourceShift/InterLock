"""The release gate: a tag must agree with every place a version is written (R22)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import check_release  # noqa: E402  (after the path insert above)

PYPROJECT = '''\
[build-system]
requires = ["setuptools>=61"]

[project]
name = "example"
version = "1.2.3"
description = "x"

[tool.other]
version = "9.9.9"
'''


def _tree(tmp_path: Path, *, py: str = PYPROJECT, npm: str = "1.2.3",
          web: str = "1.2.3",
          changelog: str = "## [Unreleased]\n\n## [1.2.3] — 2026-10-25\n") -> Path:
    (tmp_path / "pyproject.toml").write_text(py, encoding="utf-8")
    for directory, version in (("js", npm), ("web", web)):
        (tmp_path / directory).mkdir()
        (tmp_path / directory / "package.json").write_text(
            '{"name": "example", "version": "%s"}' % version, encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
    return tmp_path


def test_a_matching_tag_passes(tmp_path):
    assert check_release.check("v1.2.3", _tree(tmp_path)) == []


def test_the_version_is_read_from_the_project_section_only(tmp_path):
    # [tool.other] also says 9.9.9; the release version is [project]'s.
    assert check_release.pyproject_version(PYPROJECT) == "1.2.3"
    assert check_release.check("v1.2.3", _tree(tmp_path)) == []


def test_a_tag_that_is_not_a_version_is_rejected(tmp_path):
    problems = check_release.check("release-1.2.3", _tree(tmp_path))

    assert problems and "not vMAJOR.MINOR.PATCH" in problems[0]


def test_every_disagreement_is_named(tmp_path):
    root = _tree(tmp_path, py=PYPROJECT.replace("1.2.3", "1.2.2"), npm="1.2.4",
                 web="1.2.5", changelog="## [Unreleased]\n")

    problems = check_release.check("v1.2.3", root)

    joined = "\n".join(problems)
    assert "pyproject.toml says '1.2.2'" in joined
    assert "js/package.json says '1.2.4'" in joined
    assert "web/package.json says '1.2.5'" in joined
    assert "no '## [1.2.3]'" in joined


def test_the_matching_changelog_heading_must_be_exact():
    text = "## [1.2.30] — 2026-10-25\n## [1.2.3-rc1]\n"

    assert not check_release.changelog_has_version(text, "1.2.3")


def test_a_missing_file_is_a_failed_check_not_a_traceback(tmp_path):
    (tmp_path / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
    (tmp_path / "js").mkdir()
    (tmp_path / "js" / "package.json").write_text("not json", encoding="utf-8")
    (tmp_path / "CHANGELOG.md").write_text("## [1.2.3]\n", encoding="utf-8")

    problems = check_release.check("v1.2.3", tmp_path)

    assert any("cannot read js/package.json" in problem for problem in problems)


def test_the_cli_prints_the_bare_version_on_success(tmp_path, capsys):
    root = _tree(tmp_path)

    assert check_release.main(["v1.2.3", "--root", str(root), "--print-version"]) == 0
    assert capsys.readouterr().out.strip() == "1.2.3"

    assert check_release.main(["v0.0.9", "--root", str(root)]) == 1
    assert "pyproject.toml says '1.2.3'" in capsys.readouterr().err

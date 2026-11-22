"""The skill digest and pin file: stable, byte-sensitive, bounded, atomic.

These tests pin the properties a pin relies on. The digest must not change when
files are created in a different order (the pin would churn), must change when a
file's bytes change (that is the whole point), must ignore symlinks (their
targets are not part of the reviewed directory), and must refuse a directory
that exceeds the work bounds. Names must never escape a root, and the pin file
must round-trip with mode ``0600`` through an atomic replace.
"""
import json
import os
import stat

import pytest

from interlock import skills


# --- the digest -------------------------------------------------------------


def _write(directory, name, content):
    path = os.path.join(str(directory), name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


def test_digest_is_stable_across_creation_order(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    for directory in (first, second):
        directory.mkdir()
    _write(first, "a.md", "alpha")
    _write(first, "nested/b.md", "beta")
    _write(second, "nested/b.md", "beta")
    _write(second, "a.md", "alpha")
    assert skills.skill_digest(str(first)) == skills.skill_digest(str(second))


def test_digest_changes_when_a_file_changes(tmp_path):
    directory = tmp_path / "skill"
    directory.mkdir()
    _write(directory, "SKILL.md", "original")
    before = skills.skill_digest(str(directory))
    _write(directory, "SKILL.md", "tampered")
    assert skills.skill_digest(str(directory)) != before


def test_digest_changes_when_a_file_is_added(tmp_path):
    directory = tmp_path / "skill"
    directory.mkdir()
    _write(directory, "SKILL.md", "original")
    before = skills.skill_digest(str(directory))
    _write(directory, "extra.md", "more")
    assert skills.skill_digest(str(directory)) != before


def test_digest_ignores_symlinks(tmp_path):
    directory = tmp_path / "skill"
    directory.mkdir()
    _write(directory, "SKILL.md", "original")
    clean = skills.skill_digest(str(directory))
    outside = tmp_path / "outside.md"
    outside.write_text("not part of the skill", encoding="utf-8")
    os.symlink(str(outside), str(directory / "link.md"))
    os.symlink(str(tmp_path), str(directory / "linkdir"))
    assert skills.skill_digest(str(directory)) == clean


def test_digest_of_an_empty_directory_is_the_empty_hash(tmp_path):
    directory = tmp_path / "empty"
    directory.mkdir()
    assert skills.skill_digest(str(directory)) == (
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    )


def test_digest_refuses_a_non_directory(tmp_path):
    path = tmp_path / "file"
    path.write_text("x", encoding="utf-8")
    with pytest.raises(ValueError):
        skills.skill_digest(str(path))


def test_file_count_bound_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(skills, "MAX_FILES", 2)
    directory = tmp_path / "skill"
    directory.mkdir()
    for index in range(3):
        _write(directory, "f{}.md".format(index), "x")
    with pytest.raises(ValueError):
        skills.skill_digest(str(directory))


def test_byte_bound_raises_without_leaking_content(tmp_path, monkeypatch):
    monkeypatch.setattr(skills, "MAX_BYTES", 4)
    directory = tmp_path / "skill"
    directory.mkdir()
    _write(directory, "secret.md", "TOPSECRET-CONTENT")
    with pytest.raises(ValueError) as excinfo:
        skills.skill_digest(str(directory))
    assert "TOPSECRET" not in str(excinfo.value)


def test_digest_raises_when_a_directory_cannot_be_listed(tmp_path, monkeypatch):
    # os.walk swallows an unlistable directory by default. Hashing only the
    # readable part would produce a digest that silently ignores files, so the
    # walk must be handed an onerror that re-raises instead.
    directory = tmp_path / "skill"
    _write(directory, "SKILL.md", "reviewed")

    def walk_that_cannot_list(top, *args, onerror=None, **kwargs):
        assert onerror is not None, "skill_digest must pass onerror to os.walk"
        onerror(OSError("cannot list a subdirectory"))
        return iter(())

    monkeypatch.setattr(skills.os, "walk", walk_that_cannot_list)
    with pytest.raises(OSError):
        skills.skill_digest(str(directory))


# --- finding a skill --------------------------------------------------------


def test_find_skill_returns_the_directory(tmp_path):
    root = tmp_path / "skills"
    directory = root / "reviewed"
    directory.mkdir(parents=True)
    assert skills.find_skill("reviewed", [str(root)]) == str(directory)


def test_find_skill_rejects_unsafe_names(tmp_path):
    root = tmp_path / "skills"
    root.mkdir()
    for name in ("..", ".", "../outside", "/etc", "a/b", "a\\b", "", None, 3):
        assert skills.find_skill(name, [str(root)]) is None


def test_find_skill_does_not_escape_the_root(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "skills"
    root.mkdir()
    # A traversal that would name a real sibling directory is still refused.
    assert skills.find_skill("../outside", [str(root)]) is None


def test_find_skill_resolves_plugin_skills(tmp_path):
    root = tmp_path / "skills"
    directory = root / "my-plugin" / "skills" / "reviewed"
    directory.mkdir(parents=True)
    assert skills.find_skill("my-plugin:reviewed", [str(root)]) == str(directory)


def test_find_skill_falls_back_to_a_plain_plugin_skill(tmp_path):
    root = tmp_path / "skills"
    directory = root / "reviewed"
    directory.mkdir(parents=True)
    assert skills.find_skill("my-plugin:reviewed", [str(root)]) == str(directory)


def test_find_skill_resolves_the_flat_plugin_layout(tmp_path):
    # Claude Code installs a marketplace plugin as <root>/<plugin>/<skill>;
    # caveman:caveman-compress must resolve to <root>/caveman/caveman-compress.
    root = tmp_path / "marketplaces"
    directory = root / "caveman" / "caveman-compress"
    directory.mkdir(parents=True)
    assert skills.find_skill("caveman:caveman-compress", [str(root)]) == str(
        directory)


def test_find_skill_prefers_the_skills_layout_over_the_flat_one(tmp_path):
    root = tmp_path / "marketplaces"
    preferred = root / "my-plugin" / "skills" / "reviewed"
    preferred.mkdir(parents=True)
    flat = root / "my-plugin" / "reviewed"
    flat.mkdir()
    assert skills.find_skill("my-plugin:reviewed", [str(root)]) == str(preferred)


def test_find_skill_resolves_the_root_level_plugin_fallback(tmp_path):
    # A plugin checkout that is itself one skill is activated as
    # kubernetes-skill:kubernetes-skill and lives at <root>/kubernetes-skill.
    root = tmp_path / "marketplaces"
    directory = root / "kubernetes-skill"
    directory.mkdir(parents=True)
    assert skills.find_skill(
        "kubernetes-skill:kubernetes-skill", [str(root)]) == str(directory)


def test_find_skill_returns_none_for_a_missing_flat_plugin_skill(tmp_path):
    root = tmp_path / "marketplaces"
    (root / "caveman").mkdir(parents=True)
    assert skills.find_skill("caveman:absent", [str(root)]) is None


def test_find_skill_expands_the_home_default_at_call_time(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    directory = tmp_path / ".claude" / "skills" / "reviewed"
    directory.mkdir(parents=True)
    assert skills.find_skill("reviewed") == str(directory)


# --- discovering every skill ------------------------------------------------


def test_discover_skills_finds_a_plain_skill_only_with_skill_md(tmp_path):
    root = tmp_path / "skills"
    found = root / "reviewed"
    found.mkdir(parents=True)
    _write(found, "SKILL.md", "reviewed\n")
    # A directory without SKILL.md, and one whose name the component rule
    # rejects, are both skipped.
    (root / "helper").mkdir()
    _write(root / "helper", "README.md", "not a skill\n")
    spaced = root / "bad name"
    spaced.mkdir()
    _write(spaced, "SKILL.md", "unsafe name\n")
    assert skills.discover_skills([str(root)]) == [
        ("reviewed", str(found))]


def test_discover_skills_finds_the_plugin_layout(tmp_path):
    root = tmp_path / "skills"
    directory = root / "my-plugin" / "skills" / "reviewed"
    directory.mkdir(parents=True)
    _write(directory, "SKILL.md", "reviewed\n")
    assert skills.discover_skills([str(root)]) == [
        ("my-plugin:reviewed", str(directory))]


def test_discover_skills_finds_the_flat_plugin_layout(tmp_path):
    root = tmp_path / "marketplaces"
    directory = root / "caveman" / "caveman-compress"
    directory.mkdir(parents=True)
    _write(directory, "SKILL.md", "compressed instructions\n")
    assert skills.discover_skills([str(root)]) == [
        ("caveman:caveman-compress", str(directory))]


def test_discover_skills_does_not_promote_a_skills_subdirectory(tmp_path):
    # A directory that is itself a skill is a plain skill; its subdirectories
    # are not a plugin's skills and must not be named plugin:skill.
    root = tmp_path / "marketplaces"
    outer = root / "kubernetes-skill"
    outer.mkdir(parents=True)
    _write(outer, "SKILL.md", "the skill itself\n")
    nested = outer / "references"
    nested.mkdir()
    _write(nested, "SKILL.md", "not a plugin skill\n")
    assert skills.discover_skills([str(root)]) == [
        ("kubernetes-skill", str(outer))]


def test_discover_skills_does_not_follow_a_symlinked_directory(tmp_path):
    root = tmp_path / "skills"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    _write(outside, "SKILL.md", "not reviewed here\n")
    os.symlink(str(outside), str(root / "linked"))
    assert skills.discover_skills([str(root)]) == []


# --- the pin file -----------------------------------------------------------


def test_save_pins_round_trips_and_is_0600(tmp_path):
    path = tmp_path / "nested" / "skills.json"
    skills.save_pins(str(path), {"reviewed": "a" * 64})
    assert skills.load_pins(str(path)) == {"reviewed": "a" * 64}
    assert stat.S_IMODE(os.stat(str(path)).st_mode) == 0o600


def test_save_pins_leaves_no_temporary_file(tmp_path):
    path = tmp_path / "skills.json"
    skills.save_pins(str(path), {"reviewed": "a" * 64})
    assert sorted(os.listdir(str(tmp_path))) == ["skills.json"]


def test_load_pins_tolerates_a_missing_file(tmp_path):
    assert skills.load_pins(str(tmp_path / "absent.json")) == {}


@pytest.mark.parametrize("body", [
    "{not json",
    "{}",
    '{"version": 1}',
    '{"version": 2, "skills": {}}',
    '{"version": 1, "skills": []}',
    '{"version": 1, "skills": {"name": 3}}',
])
def test_load_pins_raises_on_a_malformed_file(tmp_path, body):
    path = tmp_path / "skills.json"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ValueError):
        skills.load_pins(str(path))


def test_pin_skill_records_the_digest(tmp_path):
    root = tmp_path / "skills"
    directory = root / "reviewed"
    directory.mkdir(parents=True)
    _write(directory, "SKILL.md", "original")
    pins = tmp_path / "pins" / "skills.json"
    digest = skills.pin_skill("reviewed", roots=[str(root)], pins_path=str(pins))
    assert digest == skills.skill_digest(str(directory))
    assert skills.load_pins(str(pins)) == {"reviewed": digest}


def test_pin_skill_root_argument_targets_one_directory(tmp_path):
    root = tmp_path / "skills"
    directory = root / "reviewed"
    directory.mkdir(parents=True)
    _write(directory, "SKILL.md", "original")
    pins = tmp_path / "skills.json"
    digest = skills.pin_skill("reviewed", root=str(root), pins_path=str(pins))
    assert skills.load_pins(str(pins)) == {"reviewed": digest}


def test_pin_skill_merges_with_existing_pins(tmp_path):
    root = tmp_path / "skills"
    for name in ("one", "two"):
        directory = root / name
        directory.mkdir(parents=True)
        _write(directory, "SKILL.md", name)
    pins = tmp_path / "skills.json"
    skills.pin_skill("one", roots=[str(root)], pins_path=str(pins))
    skills.pin_skill("two", roots=[str(root)], pins_path=str(pins))
    assert set(skills.load_pins(str(pins))) == {"one", "two"}


def test_pin_skill_refuses_an_unknown_skill(tmp_path):
    with pytest.raises(ValueError):
        skills.pin_skill("absent", roots=[str(tmp_path)], pins_path=str(tmp_path / "p.json"))


# --- the CLI ----------------------------------------------------------------


def _home_skill(tmp_path, name="reviewed"):
    skills_root = tmp_path / ".claude" / "skills"
    directory = skills_root / name
    directory.mkdir(parents=True)
    _write(directory, "SKILL.md", "reviewed instructions\n")
    return skills_root


def test_cli_list_uses_the_default_pin_file(tmp_path, monkeypatch, capsys):
    from interlock.cli import main

    monkeypatch.setenv("HOME", str(tmp_path))
    assert main(["skills", "list"]) == 0
    assert "no skills pinned in" in capsys.readouterr().out


def test_cli_check_uses_the_default_pin_file_and_exit_codes(
        tmp_path, monkeypatch, capsys):
    from interlock.cli import main

    monkeypatch.setenv("HOME", str(tmp_path))
    root = _home_skill(tmp_path)
    assert main(["skills", "pin", "reviewed"]) == 0
    capsys.readouterr()

    assert main(["skills", "check", "reviewed"]) == 0
    assert capsys.readouterr().out.startswith("ok reviewed ")

    _write(root / "reviewed", "SKILL.md", "tampered instructions\n")
    assert main(["skills", "check", "reviewed"]) == 2
    assert "changed since it was pinned" in capsys.readouterr().err

    assert main(["skills", "check", "absent"]) == 2
    assert "is not pinned" in capsys.readouterr().err


def _audit_tree(tmp_path):
    """A skills root with one pinned-and-matching skill and one unpinned one."""
    root = tmp_path / "skills"
    matched = root / "matched"
    matched.mkdir(parents=True)
    _write(matched, "SKILL.md", "matched instructions\n")
    fresh = root / "fresh"
    fresh.mkdir()
    _write(fresh, "SKILL.md", "brand new instructions\n")
    pins = tmp_path / "skills.json"
    skills.save_pins(
        str(pins), {"matched": skills.skill_digest(str(matched))})
    return root, pins


def _audit_args(root, pins, *extra):
    return ["skills", "check", "--all", "--roots", str(root),
            "--pins", str(pins), *extra]


def test_cli_check_all_reports_ok_and_unpinned_and_exits_0(tmp_path, capsys):
    from interlock.cli import main

    root, pins = _audit_tree(tmp_path)
    assert main(_audit_args(root, pins)) == 0
    statuses = {
        line.split()[0]: line.split()[1]
        for line in capsys.readouterr().out.splitlines()
    }
    assert statuses == {"fresh": "unpinned", "matched": "ok"}


def test_cli_check_all_json_lists_each_status(tmp_path, capsys):
    from interlock.cli import main

    root, pins = _audit_tree(tmp_path)
    assert main(_audit_args(root, pins, "--json")) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["pins"] == str(pins)
    assert {entry["name"]: entry["status"] for entry in payload["skills"]} == {
        "fresh": "unpinned", "matched": "ok"}


def test_cli_check_all_exits_2_on_drift(tmp_path, capsys):
    from interlock.cli import main

    root, pins = _audit_tree(tmp_path)
    _write(root / "matched", "SKILL.md", "changed after pinning\n")
    assert main(_audit_args(root, pins)) == 2
    out = capsys.readouterr().out
    line = next(line for line in out.splitlines() if line.startswith("matched"))
    assert line.split()[1] == "drift"


def test_cli_check_all_exits_2_when_a_skill_cannot_be_hashed(
        tmp_path, monkeypatch, capsys):
    from interlock.cli import main

    root, pins = _audit_tree(tmp_path)

    def boom(_path):
        raise OSError("cannot read")

    monkeypatch.setattr(skills, "skill_digest", boom)
    assert main(_audit_args(root, pins)) == 2
    statuses = {
        line.split()[0]: line.split()[1]
        for line in capsys.readouterr().out.splitlines()
    }
    assert statuses == {"fresh": "error", "matched": "error"}


def test_cli_check_requires_exactly_one_of_name_or_all(tmp_path, capsys):
    from interlock.cli import main

    root, pins = _audit_tree(tmp_path)
    assert main(["skills", "check", "matched", "--all",
                 "--roots", str(root), "--pins", str(pins)]) == 64
    assert "NAME or --all" in capsys.readouterr().err
    assert main(["skills", "check"]) == 64
    assert "NAME or --all" in capsys.readouterr().err

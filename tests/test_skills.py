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
import shutil
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


def test_load_pin_roots_is_none_for_version_1_and_a_missing_file(tmp_path):
    path = tmp_path / "skills.json"
    skills.save_pins(str(path), {"reviewed": "a" * 64})
    assert skills.load_pin_roots(str(path)) is None
    assert skills.load_pin_roots(str(tmp_path / "absent.json")) is None


def test_save_pins_records_roots_as_version_2(tmp_path):
    path = tmp_path / "skills.json"
    skills.save_pins(str(path), {"reviewed": "a" * 64},
                     roots=["~/.claude/skills", "~/work/skills"])
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document == {
        "version": 2,
        "roots": ["~/.claude/skills", "~/work/skills"],
        "skills": {"reviewed": "a" * 64},
    }
    # Stored as given: ``~`` is expanded at call time, not at pin time.
    assert skills.load_pin_roots(str(path)) == ["~/.claude/skills", "~/work/skills"]
    assert skills.load_pins(str(path)) == {"reviewed": "a" * 64}


@pytest.mark.parametrize("body", [
    "{not json",
    "{}",
    '{"version": 1}',
    '{"version": 3, "skills": {}}',
    '{"version": 1, "skills": []}',
    '{"version": 1, "skills": {"name": 3}}',
    # roots belong to version 2; a version-1 file that carries them is wrong.
    '{"version": 1, "skills": {}, "roots": ["~/x"]}',
])
def test_load_pins_raises_on_a_malformed_file(tmp_path, body):
    path = tmp_path / "skills.json"
    path.write_text(body, encoding="utf-8")
    with pytest.raises(ValueError):
        skills.load_pins(str(path))


@pytest.mark.parametrize("roots", ['"not-a-list"', '["ok", 3]', '[""]', '[null]'])
def test_load_pin_roots_rejects_a_malformed_roots_list(tmp_path, roots):
    path = tmp_path / "skills.json"
    path.write_text('{"version": 2, "skills": {}, "roots": %s}' % roots,
                    encoding="utf-8")
    with pytest.raises(ValueError):
        skills.load_pin_roots(str(path))


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


def test_pin_skill_records_the_roots_it_used(tmp_path):
    # The operator's roots are recorded as written, so a later check and the
    # guard can resolve the same skill without being told twice.
    root = tmp_path / "share"
    directory = root / "reviewed"
    directory.mkdir(parents=True)
    _write(directory, "SKILL.md", "reviewed")
    pins = tmp_path / "skills.json"
    skills.pin_skill("reviewed", roots=[str(root)], pins_path=str(pins))
    assert skills.load_pin_roots(str(pins)) == [str(root)]


def test_pin_skill_reuses_recorded_roots_when_none_are_passed(tmp_path):
    root = tmp_path / "share"
    directory = root / "reviewed"
    directory.mkdir(parents=True)
    _write(directory, "SKILL.md", "reviewed")
    pins = tmp_path / "skills.json"
    skills.pin_skill("reviewed", roots=[str(root)], pins_path=str(pins))
    # A re-pin with no --roots still finds the skill through the file.
    digest = skills.pin_skill("reviewed", pins_path=str(pins))
    assert digest == skills.skill_digest(str(directory))
    assert skills.load_pin_roots(str(pins)) == [str(root)]


def test_unpin_skill_removes_only_the_named_pin(tmp_path):
    pins = tmp_path / "skills.json"
    skills.save_pins(str(pins), {"one": "a" * 64, "two": "b" * 64})
    removed = skills.unpin_skill("one", pins_path=str(pins))
    assert removed == "a" * 64
    assert skills.load_pins(str(pins)) == {"two": "b" * 64}


def test_unpin_skill_leaves_the_file_identical_for_an_unknown_name(tmp_path):
    pins = tmp_path / "skills.json"
    skills.save_pins(str(pins), {"reviewed": "a" * 64})
    before = pins.read_bytes()
    with pytest.raises(ValueError, match="skill not pinned: absent"):
        skills.unpin_skill("absent", pins_path=str(pins))
    assert pins.read_bytes() == before


def test_unpin_skill_raises_for_a_missing_pin_file(tmp_path):
    pins = tmp_path / "absent.json"
    with pytest.raises(ValueError, match="skill not pinned: reviewed"):
        skills.unpin_skill("reviewed", pins_path=str(pins))
    assert not pins.exists()


def test_unpin_skill_preserves_the_recorded_roots(tmp_path):
    pins = tmp_path / "skills.json"
    skills.save_pins(str(pins), {"one": "a" * 64, "two": "b" * 64},
                     roots=["~/work/skills"])
    skills.unpin_skill("one", pins_path=str(pins))
    assert skills.load_pin_roots(str(pins)) == ["~/work/skills"]
    document = json.loads(pins.read_text(encoding="utf-8"))
    assert document["version"] == 2


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


def test_cli_pin_records_roots_and_a_later_check_uses_them(
        tmp_path, monkeypatch, capsys):
    from interlock.cli import main

    monkeypatch.setenv("HOME", str(tmp_path))
    root = tmp_path / "share" / "skills"
    directory = root / "reviewed"
    directory.mkdir(parents=True)
    _write(directory, "SKILL.md", "reviewed instructions\n")
    pins = tmp_path / "skills.json"

    assert main(["skills", "pin", "reviewed", "--roots", str(root),
                 "--pins", str(pins)]) == 0
    capsys.readouterr()
    assert skills.load_pin_roots(str(pins)) == [str(root)]

    # No --roots: the check resolves through the roots recorded at pin time.
    assert main(["skills", "check", "reviewed", "--pins", str(pins)]) == 0
    assert capsys.readouterr().out.startswith("ok reviewed ")


def test_cli_check_explicit_roots_override_the_file(tmp_path, monkeypatch, capsys):
    from interlock.cli import main

    monkeypatch.setenv("HOME", str(tmp_path))
    pinned_root = tmp_path / "share" / "skills"
    directory = pinned_root / "reviewed"
    directory.mkdir(parents=True)
    _write(directory, "SKILL.md", "reviewed instructions\n")
    pins = tmp_path / "skills.json"
    assert main(["skills", "pin", "reviewed", "--roots", str(pinned_root),
                 "--pins", str(pins)]) == 0
    capsys.readouterr()

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    assert main(["skills", "check", "reviewed", "--roots", str(elsewhere),
                 "--pins", str(pins)]) == 2
    assert "not found" in capsys.readouterr().err


def test_cli_list_shows_the_roots_the_pin_file_records(tmp_path, capsys):
    from interlock.cli import main

    pins = tmp_path / "skills.json"
    skills.save_pins(str(pins), {"reviewed": "a" * 64}, roots=["~/work/skills"])
    assert main(["skills", "list", "--pins", str(pins)]) == 0
    assert "roots: ~/work/skills" in capsys.readouterr().out


def test_cli_list_json_carries_the_recorded_roots(tmp_path, capsys):
    from interlock.cli import main

    pins = tmp_path / "skills.json"
    skills.save_pins(str(pins), {"reviewed": "a" * 64}, roots=["~/work/skills"])
    assert main(["skills", "list", "--pins", str(pins), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["roots"] == ["~/work/skills"]
    assert payload["skills"] == {"reviewed": "a" * 64}


def test_cli_list_reports_no_roots_for_a_version_1_file(tmp_path, capsys):
    from interlock.cli import main

    pins = tmp_path / "skills.json"
    skills.save_pins(str(pins), {"reviewed": "a" * 64})
    assert main(["skills", "list", "--pins", str(pins), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["roots"] is None
    assert main(["skills", "list", "--pins", str(pins)]) == 0
    assert "roots:" not in capsys.readouterr().out


def test_cli_check_not_found_names_the_recorded_roots(tmp_path, capsys):
    from interlock.cli import main

    share = tmp_path / "share"
    root = share / "skills"
    directory = root / "reviewed"
    directory.mkdir(parents=True)
    _write(directory, "SKILL.md", "reviewed instructions\n")
    pins = tmp_path / "skills.json"
    assert main(["skills", "pin", "reviewed", "--roots", str(root),
                 "--pins", str(pins)]) == 0
    capsys.readouterr()
    root.rename(share / "moved")

    assert main(["skills", "check", "reviewed", "--pins", str(pins)]) == 2
    assert str(root) in capsys.readouterr().err


def test_cli_check_not_found_names_the_default_roots(tmp_path, capsys):
    from interlock.cli import main

    pins = tmp_path / "skills.json"
    skills.save_pins(str(pins), {"reviewed": "a" * 64})
    assert main(["skills", "check", "reviewed", "--pins", str(pins)]) == 2
    assert "~/.claude/skills" in capsys.readouterr().err


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


def test_cli_check_all_reports_a_pinned_skill_whose_directory_is_gone(
        tmp_path, capsys):
    from interlock.cli import main

    root, pins = _audit_tree(tmp_path)
    skills.save_pins(str(pins), skills.load_pins(str(pins)) | {"removed": "a" * 64})

    assert main(_audit_args(root, pins)) == 2
    out = capsys.readouterr().out
    line = next(line for line in out.splitlines() if line.startswith("removed"))
    assert line.split()[1] == "missing"
    assert "a" * 64 in line


def test_cli_check_all_lists_a_missing_pin_in_json(tmp_path, capsys):
    from interlock.cli import main

    root, pins = _audit_tree(tmp_path)
    skills.save_pins(str(pins), skills.load_pins(str(pins)) | {"removed": "a" * 64})

    assert main(_audit_args(root, pins, "--json")) == 2
    payload = json.loads(capsys.readouterr().out)
    entries = {entry["name"]: entry for entry in payload["skills"]}
    assert entries["removed"]["status"] == "missing"
    assert entries["removed"]["digest"] is None
    assert entries["removed"]["pinned"] == "a" * 64
    assert entries["matched"]["status"] == "ok"


def test_cli_check_all_stays_0_when_every_pin_resolves(tmp_path, capsys):
    from interlock.cli import main

    root, pins = _audit_tree(tmp_path)
    assert main(_audit_args(root, pins)) == 0
    assert "missing" not in capsys.readouterr().out


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


def test_cli_unpin_removes_one_pin_and_prints_the_digest(tmp_path, capsys):
    from interlock.cli import main

    pins = tmp_path / "skills.json"
    skills.save_pins(str(pins), {"one": "a" * 64, "two": "b" * 64})
    assert main(["skills", "unpin", "one", "--pins", str(pins)]) == 0
    assert capsys.readouterr().out == "unpinned one {}\n".format("a" * 64)
    assert skills.load_pins(str(pins)) == {"two": "b" * 64}


def test_cli_unpin_json_reports_name_pinned_and_pins(tmp_path, capsys):
    from interlock.cli import main

    pins = tmp_path / "skills.json"
    skills.save_pins(str(pins), {"one": "a" * 64})
    assert main(["skills", "unpin", "one", "--pins", str(pins), "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {
        "name": "one", "pinned": "a" * 64, "pins": str(pins)}


def test_cli_unpin_a_second_time_exits_2_with_not_pinned(tmp_path, capsys):
    from interlock.cli import main

    pins = tmp_path / "skills.json"
    skills.save_pins(str(pins), {"one": "a" * 64})
    assert main(["skills", "unpin", "one", "--pins", str(pins)]) == 0
    capsys.readouterr()
    assert main(["skills", "unpin", "one", "--pins", str(pins)]) == 2
    assert "not pinned" in capsys.readouterr().err


def test_cli_bare_skills_lists_every_action(capsys):
    from interlock.cli import main

    assert main(["skills"]) == 64
    assert ("choose an action: pin, unpin, list, check"
            in capsys.readouterr().err)


# --- the doctor check -------------------------------------------------------


def test_doctor_reports_no_pins_as_info(tmp_path, monkeypatch):
    # An empty pin set is not protection: it is INFO, never OK, because no
    # skill activation is bound to a review yet.
    from interlock.cli.doctor import _skills_checks

    monkeypatch.setenv("HOME", str(tmp_path))
    rows = {check.id: check for check in _skills_checks()}
    assert set(rows) == {"skills.pins"}
    assert rows["skills.pins"].status == "info"
    assert rows["skills.pins"].summary == (
        "skill pins: none - every skill activation is allowed")


def test_doctor_reports_an_unchanged_pin_as_ok(tmp_path, monkeypatch):
    from interlock.cli.doctor import _skills_checks

    monkeypatch.setenv("HOME", str(tmp_path))
    _home_skill(tmp_path)
    skills.pin_skill("reviewed")
    row = _skills_checks()[0]
    assert (row.id, row.status) == ("skills.pins", "ok")
    assert row.summary == "skill pins: 1 pinned, all unchanged"
    assert row.fix == ""


def test_doctor_reports_drift_by_name_only(tmp_path, monkeypatch):
    from interlock.cli.doctor import _skills_checks

    monkeypatch.setenv("HOME", str(tmp_path))
    root = _home_skill(tmp_path)
    pinned = skills.pin_skill("reviewed")
    _write(root / "reviewed", "SKILL.md", "tampered instructions\n")

    row = _skills_checks()[0]
    assert row.status == "warn"
    assert row.summary == "skill pins: 1 of 1 changed since pinning"
    assert row.fix == "interlock skills check --all"
    # Doctor output lands in bug reports: no digest and no path may appear.
    for secret in (pinned, str(root / "reviewed")):
        assert secret not in row.summary + row.fix


def test_doctor_reports_a_missing_directory_as_warn(tmp_path, monkeypatch):
    from interlock.cli.doctor import _skills_checks

    monkeypatch.setenv("HOME", str(tmp_path))
    root = _home_skill(tmp_path)
    skills.pin_skill("reviewed")
    shutil.rmtree(str(root / "reviewed"))

    row = _skills_checks()[0]
    assert row.status == "warn"
    assert row.summary == "skill pins: 1 of 1 no longer found"
    assert row.fix == "interlock skills unpin NAME"


def test_doctor_reports_a_malformed_pin_file_as_warn(tmp_path, monkeypatch):
    from interlock.cli.doctor import _skills_checks

    monkeypatch.setenv("HOME", str(tmp_path))
    pins = tmp_path / ".interlock" / "skills.json"
    pins.parent.mkdir(parents=True)
    pins.write_text('{"skills": "not-a-map"}', encoding="utf-8")

    row = _skills_checks()[0]
    assert row.status == "warn"
    assert row.summary == "skill pins: cannot be read"
    assert row.fix == "interlock skills list"


def test_doctor_reports_drift_before_missing(tmp_path, monkeypatch):
    # A pin set can hold both states at once. One row, and drift wins: the
    # missing-directory roll-up is named only when nothing drifted.
    from interlock.cli.doctor import _skills_checks

    monkeypatch.setenv("HOME", str(tmp_path))
    kept = _home_skill(tmp_path, "kept")
    gone = _home_skill(tmp_path, "gone")
    skills.pin_skill("kept")
    skills.pin_skill("gone")
    _write(kept / "kept", "SKILL.md", "changed after pinning\n")
    shutil.rmtree(str(gone / "gone"))

    rows = _skills_checks()
    assert len(rows) == 1
    assert rows[0].status == "warn"
    assert rows[0].summary == "skill pins: 1 of 2 changed since pinning"
    assert "no longer found" not in rows[0].summary


def test_doctor_skills_check_never_raises_or_leaks_an_exception(
        tmp_path, monkeypatch):
    from interlock.cli.doctor import _skills_checks

    monkeypatch.setenv("HOME", str(tmp_path))

    def boom(_path):
        raise RuntimeError("SECRET pin detail")

    monkeypatch.setattr(skills, "load_pins", boom)
    row = _skills_checks()[0]
    assert row.status == "warn"
    assert "RuntimeError" in row.summary
    assert "SECRET" not in row.summary + row.fix


def test_doctor_cli_reports_the_skills_pins_row(tmp_path, monkeypatch, capsys):
    from interlock.cli import main

    monkeypatch.setenv("HOME", str(tmp_path))
    assert main(["doctor", "--json"]) in (0, 1)
    payload = json.loads(capsys.readouterr().out)
    assert "skills.pins" in {check["id"] for check in payload["checks"]}


def test_doctor_resolves_a_pin_under_its_recorded_root(tmp_path, monkeypatch):
    # A skill pinned under a second root lives in the file's roots; doctor must
    # not report it "no longer found" just because it is not in ~/.claude/skills.
    from interlock.cli.doctor import _skills_checks

    monkeypatch.setenv("HOME", str(tmp_path))
    root = tmp_path / "share" / "skills"
    directory = root / "reviewed"
    directory.mkdir(parents=True)
    _write(directory, "SKILL.md", "reviewed instructions\n")
    pins = tmp_path / ".interlock" / "skills.json"
    skills.pin_skill("reviewed", roots=[str(root)], pins_path=str(pins))

    row = _skills_checks()[0]
    assert (row.id, row.status) == ("skills.pins", "ok")
    assert row.summary == "skill pins: 1 pinned, all unchanged"

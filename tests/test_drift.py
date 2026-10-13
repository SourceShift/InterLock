"""`interlock drift` and interlock.drift (R30)."""
import hashlib
import json
import sys

import pytest

from interlock.cli import main
from interlock.drift import (ADDITION, CHANGE, REMOVAL, build_corpus, diff,
                             dumps, load_corpus, parse_live, write_corpus)

DEMO = [{"name": "demo", "tools": ["read", "write"]}]


def _corpus(tmp_path, surfaces=DEMO, name="corpus.json"):
    path = tmp_path / name
    write_corpus(str(path), surfaces)
    return path


def _live(script, *args):
    """A shell command running `python -c script` (args unused; kept simple)."""
    return "{} -c {}".format(sys.executable, json.dumps(script))


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --- corpus format --------------------------------------------------------

def test_corpus_round_trip(tmp_path):
    path = _corpus(tmp_path)
    assert load_corpus(str(path)) == build_corpus(DEMO)


def test_write_corpus_is_canonical_and_newline_terminated(tmp_path):
    path = _corpus(tmp_path)
    text = path.read_text()
    assert text.endswith("\n")
    assert text == dumps(build_corpus(DEMO)) + "\n"


def test_write_corpus_makes_parent_directories(tmp_path):
    path = tmp_path / "nested" / "deeper" / "corpus.json"
    write_corpus(str(path), DEMO)
    assert load_corpus(str(path)) == build_corpus(DEMO)


def test_load_accepts_bare_string_tools(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"surfaces": [{"name": "demo", "tools": ["read"]}]}))
    surf = load_corpus(str(path))["surfaces"][0]
    assert surf["tools"] == [{"name": "read"}]


@pytest.mark.parametrize("raw", [
    ["not", "an", "object"],
    {"no_surfaces": True},
    {"surfaces": "not-a-list"},
    {"surfaces": [{"name": "", "tools": []}]},
    {"surfaces": [{"name": "demo"}]},
    {"surfaces": [{"name": "demo", "tools": [123]}]},
])
def test_load_rejects_bad_shape(tmp_path, raw):
    from interlock.drift import CorpusError
    path = tmp_path / "c.json"
    path.write_text(json.dumps(raw))
    with pytest.raises(CorpusError):
        load_corpus(str(path))


def test_corpus_version_defaults_when_absent(tmp_path):
    path = tmp_path / "c.json"
    path.write_text(json.dumps({"surfaces": DEMO}))
    assert load_corpus(str(path))["corpus_version"] == 1


# --- the diff engine ------------------------------------------------------

def test_diff_addition():
    report = diff(DEMO[0], ["read", "write", "exec"])
    assert report["drift"] is True
    assert report["counts"] == {ADDITION: 1, REMOVAL: 0, CHANGE: 0, "total": 1}
    assert report["findings"] == [{
        "kind": ADDITION, "tool": "exec", "severity": "high",
        "detail": "present live, not recorded in the corpus"}]


def test_diff_removal():
    report = diff(DEMO[0], ["read"])
    assert report["drift"] is True
    assert report["counts"][REMOVAL] == 1
    assert report["findings"][0]["tool"] == "write"
    assert report["findings"][0]["severity"] == "medium"


def test_diff_changed_schema_shape():
    recorded = {"name": "demo",
                "tools": [{"name": "read", "input_schema": {"type": "object"}}]}
    report = diff(recorded, [{"name": "read", "input_schema": {"type": "string"}}])
    assert report["counts"][CHANGE] == 1
    assert report["findings"][0]["kind"] == CHANGE
    assert "input_schema" in report["findings"][0]["detail"]


def test_diff_unchanged_shape_is_not_drift():
    recorded = {"name": "demo",
                "tools": [{"name": "read", "input_schema": {"type": "object"}}]}
    same = [{"name": "read", "input_schema": {"type": "object"}}]
    report = diff(recorded, same)
    assert report["drift"] is False
    assert report["findings"] == []


def test_diff_does_not_compare_a_shape_only_one_side_states():
    """A schema in the corpus and a bare name live must not be a false change."""
    recorded = {"name": "demo",
                "tools": [{"name": "read", "input_schema": {"type": "object"}}]}
    report = diff(recorded, ["read"])
    assert report["drift"] is False


def test_diff_is_order_independent():
    assert diff(DEMO[0], ["write", "read"])["drift"] is False


def test_diff_reports_fingerprints():
    report = diff(DEMO[0], ["read", "write"])
    assert report["corpus_fingerprint"] == report["live_fingerprint"]
    assert len(report["corpus_fingerprint"]) == 64


def test_diff_does_not_mutate_the_corpus():
    surface = {"name": "demo", "tools": ["read", "write"]}
    before = json.dumps(surface, sort_keys=True)
    diff(surface, ["read", "write", "exec"])
    assert json.dumps(surface, sort_keys=True) == before


# --- live output parsing --------------------------------------------------

def test_parse_live_bare_names():
    assert parse_live("read\n\n  write  \nexec\n") == ["read", "write", "exec"]


def test_parse_live_json_object_lines():
    text = '{"name": "read", "input_schema": {"type": "object"}}'
    assert parse_live(text) == [{"name": "read", "input_schema": {"type": "object"}}]


def test_parse_live_rejects_malformed_json_line():
    from interlock.drift import LiveOutputError
    with pytest.raises(LiveOutputError):
        parse_live('{"name": ')


# --- the CLI --------------------------------------------------------------

def test_cli_unchanged_exits_zero(tmp_path, capsys):
    corpus = _corpus(tmp_path)
    rc = main(["drift", "--corpus", str(corpus),
               "--live", _live("print('read\\nwrite')")])
    assert rc == 0
    assert "matches the corpus" in capsys.readouterr().out


def test_cli_drift_exits_nonzero_and_names_the_tool(tmp_path, capsys):
    corpus = _corpus(tmp_path)
    rc = main(["drift", "--corpus", str(corpus),
               "--live", _live("print('read\\nwrite\\nexec')")])
    assert rc == 1
    out = capsys.readouterr().out
    assert "exec" in out and ADDITION in out


def test_cli_missing_arguments_is_a_usage_error(tmp_path):
    assert main(["drift"]) == 64
    assert main(["drift", "--corpus", str(_corpus(tmp_path))]) == 64


def test_cli_unknown_surface_is_a_usage_error(tmp_path):
    corpus = _corpus(tmp_path)
    assert main(["drift", "--corpus", str(corpus), "--surface", "nope",
                 "--live", _live("print('read')")]) == 64


def test_cli_ambiguous_surface_is_a_usage_error(tmp_path):
    corpus = _corpus(tmp_path, surfaces=[{"name": "a", "tools": []},
                                         {"name": "b", "tools": []}])
    assert main(["drift", "--corpus", str(corpus),
                 "--live", _live("print('read')")]) == 64


def test_cli_named_surface_selects_it(tmp_path):
    corpus = _corpus(tmp_path, surfaces=[{"name": "a", "tools": ["read"]},
                                         {"name": "b", "tools": ["write"]}])
    rc = main(["drift", "--corpus", str(corpus), "--surface", "b",
               "--live", _live("print('write')")])
    assert rc == 0


def test_cli_unreadable_corpus_exits_3(tmp_path):
    assert main(["drift", "--corpus", str(tmp_path / "nope.json"),
                 "--live", _live("print('read')")]) == 3


def test_cli_malformed_corpus_exits_3(tmp_path):
    path = tmp_path / "c.json"
    path.write_text("{not json")
    assert main(["drift", "--corpus", str(path),
                 "--live", _live("print('read')")]) == 3


def test_cli_failed_live_command_exits_3(tmp_path):
    corpus = _corpus(tmp_path)
    assert main(["drift", "--corpus", str(corpus), "--live", "exit 7"]) == 3


def test_cli_json_output(tmp_path, capsys):
    corpus = _corpus(tmp_path)
    rc = main(["drift", "--corpus", str(corpus), "--json",
               "--live", _live("print('read\\nwrite\\nexec')")])
    assert rc == 1
    report = json.loads(capsys.readouterr().out)
    assert report["surface"] == "demo"
    assert report["counts"]["total"] == 1
    assert report["drift"] is True


def test_cli_shell_string_live_command(tmp_path, capsys):
    """The kickoff form: --live is one shell string, `$PY $WORK/server.py`."""
    server = tmp_path / "server.py"
    server.write_text("import sys\nsys.stdout.write('\\n'.join(['read', 'write', 'exec']))\n")
    corpus = _corpus(tmp_path)
    live = "{} {}".format(sys.executable, server)
    assert main(["drift", "--corpus", str(corpus), "--live", live]) == 1
    assert "exec" in capsys.readouterr().out


def test_cli_leaves_the_corpus_byte_identical(tmp_path):
    corpus = _corpus(tmp_path)
    before = _digest(corpus)
    main(["drift", "--corpus", str(corpus),
          "--live", _live("print('read\\nwrite\\nexec')")])
    main(["drift", "--corpus", str(corpus), "--live", _live("print('read\\nwrite')")])
    assert _digest(corpus) == before

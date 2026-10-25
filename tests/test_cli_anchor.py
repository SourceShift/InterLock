"""`interlock anchor`: a recorded head catches a log with its tail cut off.

A chain verifies perfectly after its last receipts are deleted. These tests
anchor a log, then truncate, rewrite and replace it behind the anchor's back,
and expect `--check` (and a re-`record`) to refuse rather than bless it.
"""
from __future__ import annotations

import json
import os
import stat

import pytest

from interlock.cli import main
from interlock.receipt import Receipt
from interlock.sink import FileSink

KEY = b"a" * 32


@pytest.fixture
def log(tmp_path):
    path = tmp_path / "audit.jsonl"
    key = tmp_path / "audit.key"
    key.write_text(KEY.hex())
    return {"log": str(path), "key": str(key), "anchor": str(path) + ".anchor"}


def write(path, count, reason=""):
    sink = FileSink(path, key=KEY)
    for i in range(count):
        sink.write(Receipt(ts=1000.0 + i, action="run", verdict="ALLOW", reason=reason))


def quoted(lines):
    return [line for line in lines if line.strip()]


def run(log, *extra):
    return main(["anchor", log["log"], "--key-file", log["key"]] + list(extra))


def test_record_then_check_is_intact(log, capsys):
    write(log["log"], 3)

    assert run(log) == 0
    assert "anchored 3 receipt(s)" in capsys.readouterr().out
    doc = json.loads(open(log["anchor"]).read())
    assert doc["count"] == 3 and doc["log"] == os.path.abspath(log["log"])
    assert stat.S_IMODE(os.stat(log["anchor"]).st_mode) == 0o600

    assert run(log, "--check") == 0
    assert "intact: 3 receipt(s)" in capsys.readouterr().out


def test_a_grown_log_still_reaches_its_anchor(log, capsys):
    write(log["log"], 3)
    assert run(log) == 0
    capsys.readouterr()

    write(log["log"], 2)
    assert run(log, "--check") == 0
    assert "2 receipt(s) since the anchor" in capsys.readouterr().out


def test_a_truncated_log_is_refused(log, capsys):
    write(log["log"], 5)
    assert run(log) == 0
    capsys.readouterr()

    lines = quoted(open(log["log"]).readlines())
    open(log["log"], "w").writelines(lines[:3])

    assert run(log, "--check") == 2
    assert "shorter than its anchor" in capsys.readouterr().err
    assert run(log) == 2                           # re-anchoring must not bless it


def test_a_rewritten_log_at_the_same_length_is_refused(log, capsys):
    write(log["log"], 4)
    assert run(log) == 0
    capsys.readouterr()

    # A different, internally valid chain of the same length: rebuild from
    # scratch with different timestamps, then pad to four receipts.
    write(log["log"] + ".other", 4, reason="a different history")
    open(log["log"], "w").writelines(quoted(open(log["log"] + ".other").readlines()))

    assert run(log, "--check") == 2
    assert "not the one the anchor records" in capsys.readouterr().err


def test_an_edited_anchor_is_refused(log, capsys):
    write(log["log"], 2)
    assert run(log) == 0
    capsys.readouterr()

    doc = json.loads(open(log["anchor"]).read())
    doc["count"] = 0
    open(log["anchor"], "w").write(json.dumps(doc))

    assert run(log, "--check") == 2
    assert "does not match its signature" in capsys.readouterr().err
    assert run(log) == 2


def test_an_unreadable_anchor_is_refused(log, capsys):
    write(log["log"], 1)
    open(log["anchor"], "w").write("not json")

    assert run(log) == 2
    assert "not valid JSON" in capsys.readouterr().err


def test_an_anchor_for_another_log_is_refused(log, tmp_path, capsys):
    write(log["log"], 2)
    assert run(log) == 0
    capsys.readouterr()

    other = str(tmp_path / "other.jsonl")
    write(other, 2)
    assert main(["anchor", other, "--key-file", log["key"], "--out", log["anchor"]]) == 2
    assert "belongs to" in capsys.readouterr().err


def test_check_without_an_anchor_fails(log, capsys):
    write(log["log"], 1)
    assert run(log, "--check") == 2
    assert "no anchor at" in capsys.readouterr().err


def test_a_broken_chain_is_not_anchored(log, capsys):
    write(log["log"], 3)
    lines = quoted(open(log["log"]).readlines())
    open(log["log"], "w").writelines([lines[0], lines[2]])

    assert run(log) == 2
    assert "chain is broken" in capsys.readouterr().err
    assert not os.path.exists(log["anchor"])


def test_json_output(log, capsys):
    write(log["log"], 2)
    assert run(log, "--json") == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["status"] == "anchored" and doc["count"] == 2

    assert run(log, "--check", "--json") == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["status"] == "intact" and doc["anchored"] == 2

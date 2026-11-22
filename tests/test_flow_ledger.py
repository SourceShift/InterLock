"""The durable taint ledger: poisoned fragments outlive the process, by digest.

The flow tracker remembers which result a value came from, but its memory is
per process - and a hook host starts one process per tool call. This file
pins the piece that cannot be recomputed from the next call: the fragments of
a result that carried an injected instruction, stored as digests so the file
cannot be read back into the text of a tool result.
"""
from __future__ import annotations

from interlock.flow_ledger import TaintLedger, digest_of, durable

SECRET_LINE = "the reconciliation key is 9f2c8ab41d7e0f66aa"


def _remembered(ledger, *fragments, scope="run-1", **bounds):
    return ledger.remember(scope, [digest_of(f) for f in fragments], **bounds)


def test_a_digest_is_remembered_and_found(tmp_path):
    ledger = TaintLedger(str(tmp_path / "taint.db"))
    _remembered(ledger, SECRET_LINE)
    assert ledger.digests("run-1") == {digest_of(SECRET_LINE)}


def test_a_second_ledger_over_one_file_sees_the_same_fragments(tmp_path):
    path = str(tmp_path / "taint.db")
    _remembered(TaintLedger(path), SECRET_LINE)
    # Same file, new object: what the next process sees.
    assert digest_of(SECRET_LINE) in TaintLedger(path).digests("run-1")


def test_the_file_holds_no_fragment_text(tmp_path):
    path = tmp_path / "taint.db"
    _remembered(TaintLedger(str(path)), SECRET_LINE)
    raw = path.read_bytes()
    assert b"9f2c8ab41d7e0f66aa" not in raw
    assert digest_of(SECRET_LINE).encode() in raw


def test_at_most_max_rows_per_scope(tmp_path):
    ledger = TaintLedger(str(tmp_path / "taint.db"))
    _remembered(ledger, "first fragment long enough", max_rows=2)
    _remembered(ledger, "second fragment long enough", max_rows=2)
    _remembered(ledger, "third fragment long enough", max_rows=2)
    assert ledger.digests("run-1") == {
        digest_of("second fragment long enough"),
        digest_of("third fragment long enough"),
    }


def test_re_seeing_a_fragment_makes_it_the_newest(tmp_path):
    ledger = TaintLedger(str(tmp_path / "taint.db"))
    _remembered(ledger, "first fragment long enough", max_rows=2)
    _remembered(ledger, "second fragment long enough", max_rows=2)
    _remembered(ledger, "first fragment long enough", max_rows=2)
    _remembered(ledger, "third fragment long enough", max_rows=2)
    # The second was the stalest at the last write, so it is the one evicted.
    assert ledger.digests("run-1") == {
        digest_of("first fragment long enough"),
        digest_of("third fragment long enough"),
    }


def test_at_most_max_scopes_survive(tmp_path):
    path = str(tmp_path / "taint.db")
    for scope in ("run-1", "run-2", "run-3"):
        _remembered(TaintLedger(path), "fragment long enough to keep",
                    scope=scope, max_scopes=2)
    ledger = TaintLedger(path)
    assert ledger.digests("run-1") == set()
    assert ledger.digests("run-3") == {digest_of("fragment long enough to keep")}


def test_a_lazy_keeper_writes_nothing_until_the_first_poisoned_result(tmp_path):
    path = tmp_path / "taint.db"
    keeper = durable(str(path))
    assert not path.exists()   # constructing the keeper is free and silent
    assert keeper.get() is not None
    assert path.exists()


def test_the_ledger_file_is_owner_only(tmp_path):
    path = tmp_path / "taint.db"
    TaintLedger(str(path))
    assert path.stat().st_mode & 0o777 == 0o600

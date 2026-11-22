"""counter_ledger: one durable per-key tally shared by the rate limiters - the
counts survive a restart, keys are independent, the file is bounded and owner
readable, and a storage fault falls back to memory instead of raising."""
import stat

import pytest

from interlock.counter_ledger import DEFAULT_MAX_KEYS, CounterLedger, Counters


def _path(tmp_path):
    return str(tmp_path / "counters" / "limits.db")


# --- the ledger -------------------------------------------------------------


def test_a_counter_starts_at_one_and_adds_up(tmp_path):
    ledger = CounterLedger(_path(tmp_path))
    assert ledger.bump("agent-1", max_keys=DEFAULT_MAX_KEYS) == 1
    assert ledger.bump("agent-1", max_keys=DEFAULT_MAX_KEYS) == 2
    assert ledger.count("agent-1") == 2


def test_keys_are_counted_independently(tmp_path):
    ledger = CounterLedger(_path(tmp_path))
    ledger.bump("agent-1", max_keys=DEFAULT_MAX_KEYS)
    ledger.bump("agent-1", max_keys=DEFAULT_MAX_KEYS)
    assert ledger.bump("agent-2", max_keys=DEFAULT_MAX_KEYS) == 1


def test_an_unknown_key_reads_zero(tmp_path):
    assert CounterLedger(_path(tmp_path)).count("never-seen") == 0


def test_a_second_ledger_over_the_same_file_sees_the_first_tally(tmp_path):
    # This is what "the next process" means: a fresh object over the same file.
    CounterLedger(_path(tmp_path)).bump("agent-1", max_keys=DEFAULT_MAX_KEYS)
    assert CounterLedger(_path(tmp_path)).bump("agent-1", max_keys=DEFAULT_MAX_KEYS) == 2


def test_the_oldest_key_is_evicted_at_the_bound(tmp_path):
    path = _path(tmp_path)
    ledger = CounterLedger(path)
    ledger.bump("agent-1", max_keys=2)
    ledger.bump("agent-2", max_keys=2)
    ledger.bump("agent-3", max_keys=2)  # evicts agent-1, whose count restarts
    assert ledger.count("agent-1") == 0
    assert ledger.count("agent-3") == 1
    assert ledger.bump("agent-1", max_keys=2) == 1


# --- the facade the detectors use -------------------------------------------


def test_without_a_state_path_the_counts_stay_in_memory(tmp_path):
    counters = Counters("test counter")
    assert counters.bump("agent-1") == 1
    assert counters.bump("agent-1") == 2
    assert not list(tmp_path.iterdir())


def test_a_state_path_carries_the_count_to_the_next_rule(tmp_path):
    path = _path(tmp_path)
    assert Counters("test counter", path).bump("agent-1") == 1
    assert Counters("test counter", path).bump("agent-1") == 2


def test_the_file_is_not_written_until_a_count_arrives(tmp_path):
    path = tmp_path / "counters" / "limits.db"
    counters = Counters("test counter", str(path))
    assert not path.exists()          # `interlock policy check` must not write
    counters.bump("agent-1")
    assert path.exists()


def test_the_state_file_is_readable_only_by_its_owner(tmp_path):
    path = tmp_path / "counters" / "limits.db"
    Counters("test counter", str(path)).bump("agent-1")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@pytest.mark.parametrize("state", ["relative.db", "", "   "])
def test_a_state_path_it_cannot_trust_is_refused(state):
    with pytest.raises(ValueError):
        Counters("test counter", state)


def test_a_corrupt_state_file_falls_back_instead_of_raising(tmp_path):
    path = tmp_path / "counters" / "limits.db"
    path.parent.mkdir()
    path.write_bytes(b"this is not a sqlite database\n" * 64)
    counters = Counters("test counter", str(path))
    assert counters.bump("agent-1") == 1   # warned, then counted in memory
    assert counters.bump("agent-1") == 2

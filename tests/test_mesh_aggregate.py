"""Additive secret sharing: shares recombine, a lone share is uniform noise, and
only reports both aggregators hold are summed."""
import pytest

from interlock.mesh import aggregate
from interlock.mesh.aggregate import PRIME, Aggregator, combine, combine_totals, count_key, encode_counts, reconcile, share


def test_share_and_combine_round_trip():
    for value in (0, 1, 7, 10 ** 9, PRIME - 1):
        for n in (2, 3, 5):
            shares = share(value, n)
            assert len(shares) == n and all(0 <= s < PRIME for s in shares)
            assert combine(shares) == value


def test_shares_are_random_and_not_the_value():
    a, b = share(5), share(5)
    assert a != b  # fresh randomness every time
    assert 5 not in a or 5 not in b  # a share is not the plaintext (except by chance for both)


def test_share_rejects_bad_values():
    for bad in (-1, PRIME, 1.5, True):
        with pytest.raises(ValueError):
            share(bad)
    with pytest.raises(ValueError):
        share(1, n=1)


def test_two_aggregators_recover_totals_only_for_reconciled_reports():
    key_a = count_key("prompt_injection", "BLOCK", "http", "result", 3600)
    key_b = count_key("destructive_command", "BLOCK", "shell", "call", 3600)
    reports = {"r1": {key_a: 3, key_b: 1}, "r2": {key_a: 2}, "r3": {key_b: 10}}
    agg1, agg2 = Aggregator(), Aggregator()
    for rid, counts in reports.items():
        s1, s2 = encode_counts(counts, 2)
        agg1.add(rid, s1)
        if rid != "r3":  # r3 only reached one aggregator
            agg2.add(rid, s2)
    common = reconcile(agg1.report_ids(), agg2.report_ids())
    assert common == ["r1", "r2"]
    totals = combine_totals(agg1.totals(common), agg2.totals(common))
    assert totals == {key_a: 5, key_b: 1}
    # Each side alone learns nothing: its partial sums are field elements, not counts.
    assert agg1.totals(common) != totals or agg2.totals(common) != totals
    assert agg1.manifest() != agg2.manifest()


def test_aggregator_rejects_duplicates_and_malformed_shares():
    agg = Aggregator()
    agg.add("r1", {"k": 1})
    with pytest.raises(ValueError):
        agg.add("r1", {"k": 2})
    with pytest.raises(ValueError):
        agg.add("r2", {"k": PRIME})
    with pytest.raises(ValueError):
        agg.add("", {"k": 1})
    restored = Aggregator.from_dict(agg.to_dict())
    assert restored.report_ids() == ["r1"] and restored.totals(["r1"]) == {"k": 1}


def test_module_constants():
    assert aggregate.PRIME == 2 ** 61 - 1
    assert reconcile() == []

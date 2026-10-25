"""Additive secret sharing: shares recombine, a lone share is uniform noise, only
reports both aggregators hold are summed, and never fewer than the batch floor."""
import pytest

from interlock.mesh import aggregate
from interlock.mesh.aggregate import (
    MIN_BATCH, PRIME, Aggregator, combine, combine_totals, count_key, encode_counts, fire_totals, reconcile, share,
)


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
    reports = {"r1": {key_a: 3, key_b: 1}, "r2": {key_a: 2}, "r3": {key_b: 10}, "r4": {key_b: 4}}
    agg1, agg2 = Aggregator(), Aggregator()
    for rid, counts in reports.items():
        s1, s2 = encode_counts(counts, 2)
        agg1.add(rid, s1)
        if rid != "r3":  # r3 only reached one aggregator
            agg2.add(rid, s2)
    common = reconcile(agg1.report_ids(), agg2.report_ids())
    assert common == ["r1", "r2", "r4"]
    totals = combine_totals(agg1.totals(common), agg2.totals(common), ids=common)
    assert totals == {key_a: 5, key_b: 5}
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
    agg.add("r2", {"k": 2})
    agg.add("r3", {"k": 3})
    restored = Aggregator.from_dict(agg.to_dict())
    assert restored.report_ids() == ["r1", "r2", "r3"] and restored.totals(["r1", "r2", "r3"]) == {"k": 6}
    assert Aggregator.from_dict(agg.to_dict(), min_batch=4).min_batch == 4


def test_module_constants():
    assert aggregate.PRIME == 2 ** 61 - 1
    assert reconcile() == []


def _pair(n, counts=None):
    a, b = Aggregator(), Aggregator()
    for i in range(n):
        s1, s2 = encode_counts(counts or {"k": 1}, 2)
        a.add("r%d" % i, s1)
        b.add("r%d" % i, s2)
    return a, b


def test_totals_below_the_batch_floor_are_refused_and_at_it_released():
    assert MIN_BATCH == 3
    a, b = _pair(2)
    for agg in (a, b):
        with pytest.raises(ValueError, match="at least 3"):
            agg.totals(["r0", "r1"])
    with pytest.raises(ValueError):
        a.totals([])
    a, b = _pair(3)
    ids = ["r0", "r1", "r2"]
    assert combine_totals(a.totals(ids), b.totals(ids), ids=ids) == {"k": 3}
    # A lower floor is a choice, but never below two: one report is the report.
    assert combine_totals(a.totals(ids[:2], min_batch=2), b.totals(ids[:2], min_batch=2)) == {"k": 2}
    assert combine_totals(*(Aggregator.from_dict(x.to_dict(), min_batch=2).totals(ids[:2]) for x in (a, b))) == {"k": 2}
    for bad in (1, 0, -3, True, 2.5, "3", None):
        with pytest.raises(ValueError):
            Aggregator(min_batch=bad)
        if bad is not None:
            with pytest.raises(ValueError):
                a.totals(ids, min_batch=bad)
            with pytest.raises(ValueError):
                combine_totals({}, min_batch=bad)


def test_repeated_or_unknown_ids_do_not_pad_the_batch():
    a, b = _pair(1, {"k": 5})
    with pytest.raises(ValueError):
        a.totals(["r0", "r0", "r0"])
    with pytest.raises(ValueError):
        a.totals(["r0", "elsewhere-1", "elsewhere-2"])
    a, b = _pair(3, {"k": 5})
    ids = ["r0", "r1", "r2", "r2", "r2"]  # the sum is over distinct reports
    assert combine_totals(a.totals(ids), b.totals(ids)) == {"k": 15}
    with pytest.raises(ValueError):
        combine_totals(a.totals(ids), b.totals(ids), ids=["r0", "r0", "r1"])


def test_fire_totals_from_manifests_and_totals_replies():
    bucket = 3600
    a, b = Aggregator(), Aggregator()
    reports = [
        {count_key("destructive_command", "BLOCK", "shell", "call", bucket): 7,
         count_key("destructive_command", "ESCALATE", "shell", "call", bucket): 1},
        {count_key("destructive_command", "BLOCK", "shell", "result", bucket + 3600): 2,
         count_key("a|b", "BLOCK", "http", "call", bucket): 4},
        {count_key("prompt_injection", "BLOCK", "http", "result", bucket): 3, "not a count key": 9},
    ]
    for i, counts in enumerate(reports):
        s1, s2 = encode_counts(counts, 2)
        a.add("r%d" % i, s1)
        b.add("r%d" % i, s2)
    a.add("lonely", {"x": 1})  # reached one side only

    def manifest(agg):
        return {"ids": agg.report_ids(), "digest": agg.manifest(), "min_batch": agg.min_batch}

    manifests = [manifest(a), manifest(b)]
    ids = reconcile(*[m["ids"] for m in manifests])
    replies = [{"totals": a.totals(ids)}, {"totals": b.totals(ids)}]
    fire = fire_totals(manifests, replies)
    assert fire == {"reports": 3, "min_batch": 3, "rules": {
        "destructive_command": {"BLOCK": 9, "ESCALATE": 1},
        "a|b": {"BLOCK": 4},
        "prompt_injection": {"BLOCK": 3},
    }}
    # An aggregator's own higher floor wins over the caller's.
    with pytest.raises(ValueError, match="at least 4"):
        fire_totals([dict(manifests[0], min_batch=4), manifests[1]], replies)
    with pytest.raises(ValueError):
        fire_totals([dict(manifests[0], min_batch=1), manifests[1]], replies)
    with pytest.raises(ValueError):
        fire_totals(manifests[:1], replies[:1])
    with pytest.raises(ValueError):
        fire_totals(manifests, [{"totals": a.totals(ids)}, {"error": "x"}])


def test_padded_shares_hide_which_rules_fired():
    """The key set of a sparse share vector names the rules that fired; the pad
    makes every published rule a key, and a zero's share looks like any other."""
    from interlock.mesh.aggregate import combine, encode_counts

    counts = {"prompt_injection|BLOCK|shell|call|0": 3}
    pad = ["destructive_command|BLOCK|shell|call|0", "prompt_injection|BLOCK|shell|call|0"]
    shares = encode_counts(counts, 2, pad=pad)
    assert set(shares[0]) == set(shares[1]) == set(pad)
    assert combine([shares[0][pad[0]], shares[1][pad[0]]]) == 0
    assert combine([shares[0][pad[1]], shares[1][pad[1]]]) == 3


def test_pad_keys_cover_every_published_rule_per_hour_and_class():
    from interlock.cli.mesh import pad_keys

    counts = {"prompt_injection|BLOCK|shell|call|3600": 1, "prompt_injection|ESCALATE|http|result|7200": 2}
    assert pad_keys(counts, ["a", "b"]) == sorted([
        "a|BLOCK|shell|call|3600", "b|BLOCK|shell|call|3600",
        "a|ESCALATE|http|result|7200", "b|ESCALATE|http|result|7200"])
    assert pad_keys({}, ["a"]) == []

"""The overhead benchmark: it measures a difference, so it must not crash or lie."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from interlock.mesh.harness import load_corpus
from interlock.policy.packs import builtin_pack

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import bench_overhead  # type: ignore[import-not-found]  # noqa: E402


def test_overhead_is_bounded_and_ordered():
    corpus = load_corpus(str(ROOT / "benchmarks" / "fp" / "benign.jsonl"))[:20]
    measured = bench_overhead.measure(builtin_pack("coding-agent"), corpus, repeats=5)
    assert measured["events"] == len(corpus)
    assert measured["evaluated"] == len(corpus) * 5
    for side in ("floor", "guarded"):
        latency = measured[side]
        assert latency["p50"] <= latency["p95"] <= latency["p99"] <= latency["max"]
    assert measured["guarded"]["p50"] >= measured["floor"]["p50"]
    assert measured["overhead_us"]["p50"] >= 0
    assert set(measured["by_action"]) == {event.action for event in corpus}
    # Generous bounds: this asserts the harness runs, not a runner's speed.
    reasons = bench_overhead.gate(measured, max_p95_us=100_000,
                                  max_overhead_us=100_000, max_ratio=10_000)
    assert reasons == []


def test_gate_names_each_regression():
    measured = {"evaluated": 10, "guarded": {"p95": 9000},
                "overhead_us": {"p95": 8000}, "ratio_p50": 600.0}
    reasons = bench_overhead.gate(measured, max_p95_us=5000,
                                  max_overhead_us=1000, max_ratio=500)
    assert len(reasons) == 3
    assert any("p95" in reason for reason in reasons)
    assert any("added" in reason for reason in reasons)
    assert any("ratio" in reason for reason in reasons)


def test_gate_refuses_an_empty_measurement():
    assert bench_overhead.gate({"evaluated": 0}) == ["no events were timed; overhead needs a corpus"]


def _native_policy():
    with open(ROOT / "benchmarks" / "overhead" / "native-policy.json", encoding="utf-8") as handle:
        return json.load(handle)


def test_native_comparison_is_skipped_without_the_wheel(monkeypatch):
    monkeypatch.setattr(bench_overhead.native, "_plan_class", lambda: None)
    measured = bench_overhead.measure_native(_native_policy(), [], repeats=1)
    assert measured == {"skipped": "interlock_scopes is not installed"}


def test_native_comparison_runs_the_same_policy_twice():
    corpus = load_corpus(str(ROOT / "benchmarks" / "fp" / "benign.jsonl"))[:10]
    measured = bench_overhead.measure_native(_native_policy(), corpus, repeats=2)
    if "skipped" in measured:
        assert measured["skipped"] == "policy is not native-eligible"
        return
    assert measured["events"] == len(corpus)
    assert measured["evaluated"] == len(corpus) * 2
    assert set(measured["by_action"]) == {event.action for event in corpus}
    for side in ("python", "native"):
        latency = measured[side]
        assert latency["p50"] <= latency["p95"] <= latency["p99"] <= latency["max"]
    assert measured["speedup_p50"] is None or measured["speedup_p50"] > 0


def test_native_comparison_ignores_an_ambient_native_flag(monkeypatch):
    """The Python side must be Python even when the shell opted into native."""
    corpus = load_corpus(str(ROOT / "benchmarks" / "fp" / "benign.jsonl"))[:5]
    monkeypatch.setenv(bench_overhead.native.ENV_FLAG, "1")
    measured = bench_overhead.measure_native(_native_policy(), corpus, repeats=1)
    if "skipped" in measured:
        return
    assert measured["python"]["count"] == len(corpus)
    # The flag survives the measurement; it belongs to the caller, not to us.
    import os
    assert os.environ[bench_overhead.native.ENV_FLAG] == "1"


def test_cli_json_reports_native_when_the_wheel_is_present():
    if bench_overhead.native._plan_class() is None:
        import pytest
        pytest.skip("interlock_scopes is not installed")
    output = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "bench_overhead.py"),
         "--repeats", "1", "--json", "--max-p95-us", "100000",
         "--max-overhead-us", "100000", "--max-ratio", "100000"],
        capture_output=True, text=True, check=False)
    assert output.returncode == 0, output.stderr
    native = json.loads(output.stdout)["native"]
    assert "skipped" not in native, native
    assert native["python"]["count"] > 0
    assert set(native["by_action"]) == set(json.loads(output.stdout)["measured"]["by_action"])


def test_cli_json_passes_on_the_committed_corpus():
    output = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "bench_overhead.py"),
         "--repeats", "1", "--json", "--no-native", "--max-p95-us", "100000",
         "--max-overhead-us", "100000", "--max-ratio", "100000"],
        capture_output=True, text=True, check=False)
    assert output.returncode == 0, output.stderr
    payload = json.loads(output.stdout)
    assert payload["passed"] is True
    assert payload["measured"]["events"] > 0
    assert "native" in payload

"""Download-extension guard: block a download/write target naming an executable.

Covers the BLOCK contract (the offending arg is named in the reason), the allow
path (an ordinary document gets no opinion), each declared extension, the
boundary behaviour that keeps ``.shell`` from being read as ``.sh``, non-string
and non-dict input that must be skipped rather than crashed on, and end-to-end
verdicts through the engine.
"""
from interlock import PolicyEngine, SensorEvent, Verdict
from interlock.detectors.download_extension_guard import (
    PATTERN,
    POLICY_ID,
    download_extension_guard,
)


def _event(**args):
    return SensorEvent(action="download", args=args)


# --- the block path ---------------------------------------------------------


def test_shell_script_download_is_blocked():
    event = _event(url="https://example.com/payload.sh")
    decision = download_extension_guard()(event)
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID


def test_block_reason_names_the_offending_argument():
    decision = download_extension_guard()(_event(url="https://example.com/payload.sh"))
    assert decision is not None
    assert decision.reason == "download_extension: url"


def test_reason_names_whichever_argument_matched():
    decision = download_extension_guard()(
        _event(filename="report.pdf", dest="https://evil.test/x.exe")
    )
    assert decision is not None
    assert decision.reason == "download_extension: dest"


def test_extension_before_query_string_is_blocked():
    # A download tool strips the query to derive the filename, so ".sh?" is a
    # shell script even though it is not at the very end of the URL.
    decision = download_extension_guard()(
        _event(url="https://example.com/payload.sh?token=abc123")
    )
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_extension_before_fragment_is_blocked():
    decision = download_extension_guard()(
        _event(url="https://example.com/payload.ps1#install")
    )
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_uppercase_extension_is_blocked():
    decision = download_extension_guard()(_event(url="https://example.com/PAYLOAD.SH"))
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


def test_first_matching_argument_wins():
    decision = download_extension_guard()(
        _event(a="https://x/y.sh", b="https://x/z.exe")
    )
    assert decision is not None
    assert decision.reason == "download_extension: a"


# --- the allow path ---------------------------------------------------------


def test_reported_document_gets_no_opinion():
    assert download_extension_guard()(
        _event(url="https://example.com/report.pdf")
    ) is None


def test_clean_multi_argument_call_gets_no_opinion():
    guard = download_extension_guard()
    assert guard(
        _event(url="https://example.com/data.csv", mode="wb", timeout=30)
    ) is None


def test_empty_args_get_no_opinion():
    assert download_extension_guard()(SensorEvent(action="download", args={})) is None


def test_extension_letters_inside_a_name_are_not_a_match():
    # ``.shell`` is followed by name characters, not a boundary: the trailing
    # anchor keeps the guard from firing on it.
    assert download_extension_guard()(
        _event(url="https://example.com/payload.shell")
    ) is None


# --- every declared extension -----------------------------------------------


def test_each_declared_extension_is_blocked():
    payloads = (
        "https://x/a.sh",
        "https://x/a.exe",
        "https://x/a.bat",
        "https://x/a.cmd",
        "https://x/a.ps1",
        "https://x/a.scr",
        "https://x/a.jar",
        "https://x/a.msi",
        "https://x/a.dll",
        "https://x/a.dylib",
        "https://x/a.so",
    )
    guard = download_extension_guard()
    for payload in payloads:
        decision = guard(_event(url=payload))
        assert decision is not None, payload
        assert decision.verdict is Verdict.BLOCK, payload


# --- robustness: skip what it cannot handle, never raise --------------------


def test_non_str_values_are_skipped_without_crashing():
    guard = download_extension_guard()
    assert guard(_event(url=None, size=42)) is None
    assert guard(_event(payload={"nested": "https://x/a.sh"})) is None
    assert guard(_event(urls=["https://x/a.sh"])) is None


def test_non_dict_args_get_no_opinion():
    assert download_extension_guard()(SensorEvent(action="download", args=None)) is None
    assert download_extension_guard()(
        SensorEvent(action="download", args="https://x/a.sh")
    ) is None


def test_a_non_str_sibling_does_not_mask_a_real_match():
    # The int must be skipped, not abort the scan before "url" is reached.
    decision = download_extension_guard()(
        _event(size=42, url="https://x/a.sh")
    )
    assert decision is not None
    assert decision.verdict is Verdict.BLOCK


# --- constants --------------------------------------------------------------


def test_exposed_constants():
    assert POLICY_ID == "download_extension"
    assert PATTERN.search("https://x/payload.sh") is not None
    assert PATTERN.search("https://x/report.pdf") is None


# --- end to end through the engine ------------------------------------------


def test_engine_blocks_malicious_and_allows_benign():
    engine = PolicyEngine(rules=[download_extension_guard()])

    malicious = SensorEvent(action="download", args={"url": "https://x/payload.sh"})
    decision = engine.evaluate(malicious)
    assert decision.verdict is Verdict.BLOCK
    assert decision.policy_id == POLICY_ID

    benign = SensorEvent(action="download", args={"url": "https://x/report.pdf"})
    assert engine.evaluate(benign).verdict is Verdict.ALLOW

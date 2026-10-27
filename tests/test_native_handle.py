"""The C ABI's load-once plan handle (C6).

`il_plan_load` parses a plan once and returns an opaque token;
`il_eval_plan_handle` evaluates against it and `il_plan_free` releases it.
These tests drive the standalone `rust/ffi` cdylib through ctypes, exactly as
a non-Python host would. Every error must fail closed: a null, unknown or
already-freed handle returns `-1` and writes no verdict.

Skipped when `rust/ffi` has not been built. `scripts/check_native_abi.sh`
builds it and proves the same lifecycle from C; the Rust CI job runs both.
"""
from __future__ import annotations

import ctypes
import os
from pathlib import Path

import pytest

PLAN = (
    '{"version":1,"rules":[{"id":"no-rm","verdict":1,'
    '"reason":"recursive delete","when":{"all":['
    '{"action":"Bash"},{"arg":"command","contains":"rm -rf"}]}}]}'
)
HIT = '{"action":"Bash","args":{"command":"rm -rf /"}}'
MISS = '{"action":"Bash","args":{"command":"ls"}}'


def _library() -> ctypes.CDLL:
    root = Path(__file__).resolve().parent.parent
    candidates = [
        Path(os.environ["INTERLOCK_FFI_LIB"]) if os.environ.get("INTERLOCK_FFI_LIB") else None,
        root / "rust" / "ffi" / "target" / "release" / "libinterlock_engine_ffi.dylib",
        root / "rust" / "ffi" / "target" / "release" / "libinterlock_engine_ffi.so",
        root / "rust" / "ffi" / "target" / "release" / "interlock_engine_ffi.dll",
    ]
    found = [path for path in candidates if path is not None and path.is_file()]
    if not found:
        pytest.skip("rust/ffi not built; scripts/check_native_abi.sh covers the C ABI")
    lib = ctypes.CDLL(str(found[0]))
    lib.il_abi_version.restype = ctypes.c_uint32
    lib.il_plan_load.restype = ctypes.c_void_p
    lib.il_plan_load.argtypes = [
        ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_int),
    ]
    lib.il_eval_plan_handle.restype = ctypes.c_int
    lib.il_eval_plan_handle.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_int), ctypes.c_char_p, ctypes.c_size_t,
        ctypes.c_char_p, ctypes.c_size_t,
    ]
    lib.il_plan_free.restype = None
    lib.il_plan_free.argtypes = [ctypes.c_void_p]
    return lib


def _load(lib, plan: bytes = PLAN.encode()):
    err = ctypes.c_int(42)
    handle = lib.il_plan_load(plan, len(plan), ctypes.byref(err))
    return handle, err


def _eval(lib, handle, event: bytes):
    verdict = ctypes.c_int(9)
    policy = ctypes.create_string_buffer(64)
    reason = ctypes.create_string_buffer(128)
    rc = lib.il_eval_plan_handle(
        handle, event, len(event),
        ctypes.byref(verdict), policy, 64, reason, 128,
    )
    return rc, verdict.value, policy.value, reason.value


def test_abi_version_is_two():
    assert _library().il_abi_version() == 2


def test_load_evaluate_free_lifecycle():
    lib = _library()
    handle, err = _load(lib)
    assert err.value == 0
    assert handle

    rc, verdict, policy, reason = _eval(lib, handle, HIT.encode())
    assert (rc, verdict, policy, reason) == (0, 1, b"no-rm", b"recursive delete")

    rc, verdict, policy, _ = _eval(lib, handle, MISS.encode())
    assert rc == 0 and verdict == 0

    # A plan handle is reusable: the parse happened once, at load.
    rc, verdict, _, _ = _eval(lib, handle, HIT.encode())
    assert rc == 0 and verdict == 1

    lib.il_plan_free(handle)


def test_null_handle_fails_closed():
    lib = _library()
    rc, verdict, _, _ = _eval(lib, None, HIT.encode())
    assert rc == -1
    assert verdict == 9


def test_bad_event_json_fails_closed():
    lib = _library()
    handle, _ = _load(lib)
    try:
        rc, verdict, _, _ = _eval(lib, handle, b"{not json")
        assert rc == -1
        assert verdict == 9
    finally:
        lib.il_plan_free(handle)


def test_bad_plan_json_returns_a_null_handle():
    lib = _library()
    handle, err = _load(lib, b"{not json")
    assert err.value == -1
    assert not handle


def test_double_free_is_safe_and_a_freed_handle_fails_closed():
    lib = _library()
    handle, _ = _load(lib)
    lib.il_plan_free(handle)
    # A stale token is removed from the registry, so a second free and any
    # evaluation are no-ops/refusals rather than use-after-free.
    lib.il_plan_free(handle)
    rc, verdict, _, _ = _eval(lib, handle, HIT.encode())
    assert rc == -1
    assert verdict == 9


def test_free_of_null_is_a_noop():
    lib = _library()
    lib.il_plan_free(None)

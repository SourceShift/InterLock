#!/usr/bin/env bash
# Build and run the non-Python C ABI smoke.
#
#   bash scripts/check_native_abi.sh [path/to/libinterlock_engine_ffi]
#
# Builds `rust/ffi` (a standalone cdylib: no PyO3, no CPython) unless a library
# path is given, then compiles `rust/abi-smoke/smoke.c` against it with the
# system C compiler. Nothing in this path imports Python.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CC="${CC:-cc}"
CARGO="${CARGO:-cargo}"

LIB="${1:-}"
if [[ -z "$LIB" ]]; then
    "$CARGO" build --release --manifest-path "$ROOT/rust/ffi/Cargo.toml"
    for candidate in \
        "$ROOT/rust/ffi/target/release/libinterlock_engine_ffi.so" \
        "$ROOT/rust/ffi/target/release/libinterlock_engine_ffi.dylib" \
        "$ROOT/rust/ffi/target/release/interlock_engine_ffi.dll"; do
        if [[ -f "$candidate" ]]; then
            LIB="$candidate"
            break
        fi
    done
fi
if [[ -z "$LIB" || ! -f "$LIB" ]]; then
    echo "check_native_abi: the FFI library was not built" >&2
    exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
BIN="$WORK/il-eval-smoke"

LIBS=()
case "$(uname -s)" in
    Linux) LIBS+=(-ldl) ;;
esac

"$CC" -O2 -std=c11 -Wall -Wextra -o "$BIN" \
    "$ROOT/rust/abi-smoke/smoke.c" "${LIBS[@]}"
"$BIN" "$LIB"

//! The C ABI over `interlock_engine`, for hosts that are not CPython.
//!
//! This is a standalone `cdylib` with no PyO3 dependency. The Python
//! extension beside it is built with `extension-module`, which deliberately
//! leaves CPython symbols unresolved, so a non-Python `dlopen` of that file
//! fails. This library closes that gap: a Node, Go, Rust or C host loads it,
//! resolves two symbols, and evaluates a plan.
//!
//! The ABI is string-in, buffer-out. A caller passes JSON, gets a verdict, and
//! may ask for the policy id and reason as NUL-terminated strings. `-1` means
//! any error (bad JSON, a plan the engine rejects, an internal panic) and
//! nothing is written, so the caller must fail closed.

use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

use interlock_engine::{write_c_str, Event, Plan};

/// Bump when the C signature or the plan schema changes.
pub const ABI_VERSION: u32 = 1;

/// The ABI version the loaded library implements.
#[no_mangle]
pub extern "C" fn il_abi_version() -> u32 {
    ABI_VERSION
}

/// Evaluate one event against one plan.
///
/// Returns 0 on success and -1 on any error. On success `out_verdict` is 0
/// (allow), 1 (block), 2 (modify, never produced by the planner) or 3
/// (escalate). `out_policy` and `out_reason` are NUL-terminated and truncated
/// on a character boundary to fit; pass a null pointer or capacity 0 to skip
/// either.
///
/// # Safety
/// The two input pointers must be readable for their stated lengths, and the
/// out buffers writable for their capacities.
#[no_mangle]
pub unsafe extern "C" fn il_eval_plan(
    event_json: *const c_char,
    event_len: usize,
    plan_json: *const c_char,
    plan_len: usize,
    out_verdict: *mut i32,
    out_policy: *mut c_char,
    policy_cap: usize,
    out_reason: *mut c_char,
    reason_cap: usize,
) -> i32 {
    if event_json.is_null() || plan_json.is_null() || out_verdict.is_null() {
        return -1;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let event_bytes = std::slice::from_raw_parts(event_json as *const u8, event_len);
        let plan_bytes = std::slice::from_raw_parts(plan_json as *const u8, plan_len);
        let event_text = std::str::from_utf8(event_bytes).map_err(|e| e.to_string())?;
        let plan_text = std::str::from_utf8(plan_bytes).map_err(|e| e.to_string())?;
        let plan = Plan::from_json(plan_text)?;
        let event = Event::from_json(event_text)?;
        Ok::<_, String>(plan.evaluate(&event))
    }));
    match result {
        Ok(Ok(outcome)) => {
            *out_verdict = outcome.verdict;
            write_c_str(out_policy, policy_cap, &outcome.policy_id);
            write_c_str(out_reason, reason_cap, &outcome.reason);
            0
        }
        _ => -1,
    }
}

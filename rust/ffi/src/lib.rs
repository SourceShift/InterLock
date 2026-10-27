//! The C ABI over `interlock_engine`, for hosts that are not CPython.
//!
//! This is a standalone `cdylib` with no PyO3 dependency. The Python
//! extension beside it is built with `extension-module`, which deliberately
//! leaves CPython symbols unresolved, so a non-Python `dlopen` of that file
//! fails. This library closes that gap: a Node, Go, Rust or C host loads it,
//! resolves the symbols it needs, and evaluates a plan.
//!
//! Two calling styles share the same `interlock_engine::Plan`:
//!
//! * `il_eval_plan` takes plan JSON on every call. It is what R31 shipped and
//!   stays byte-for-byte compatible, so an existing host keeps working.
//! * `il_plan_load` parses the plan once and returns an opaque handle;
//!   `il_eval_plan_handle` evaluates events against that handle and
//!   `il_plan_free` releases it. This is the load-once path the cloud fast
//!   path uses.
//!
//! Handles live in a process-global registry keyed by the pointer value, so a
//! null, unknown or already-freed handle is a clean `-1` rather than a
//! use-after-free. The pointer is an opaque token, never dereferenced.
//!
//! The ABI is JSON-in, out-parameters-out. A caller passes JSON, gets a
//! verdict, and may ask for the policy id and reason as NUL-terminated
//! strings. `-1` means any error (bad JSON, a plan the engine rejects, an
//! internal panic) and nothing is written, so the caller must fail closed.

use std::collections::HashMap;
use std::ffi::c_void;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, Mutex, OnceLock};

use interlock_engine::{write_c_str, Event, Plan};

/// Bump when the C signature or the plan schema changes. Version 2 adds the
/// opaque handle (`il_plan_load` / `il_eval_plan_handle` / `il_plan_free`);
/// `il_eval_plan` is unchanged.
pub const ABI_VERSION: u32 = 2;

/// The ABI version the loaded library implements.
#[no_mangle]
pub extern "C" fn il_abi_version() -> u32 {
    ABI_VERSION
}

struct Registry {
    next: usize,
    plans: HashMap<usize, Arc<Plan>>,
}

static REGISTRY: OnceLock<Mutex<Registry>> = OnceLock::new();

fn registry() -> &'static Mutex<Registry> {
    REGISTRY.get_or_init(|| {
        Mutex::new(Registry {
            next: 1,
            plans: HashMap::new(),
        })
    })
}

/// Evaluate one event against one plan.
///
/// Returns 0 on success and -1 on any error. On success `out_verdict` is 0
/// (allow), 1 (block), 2 (modify, never produced by the planner) or 3
/// (escalate). `out_policy` and `out_reason` are NUL-terminated and truncated
/// on a character boundary to fit; pass a null pointer or capacity 0 to skip
/// either.
///
/// This is the stateless R31 entry point: the plan JSON is parsed on every
/// call. Prefer `il_plan_load`/`il_eval_plan_handle` on a hot path.
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

/// Parse a plan once and return an opaque handle, or null on error.
///
/// `err`, when non-null, is set to 0 on success and -1 on failure. The handle
/// is a token, not a pointer into Rust memory: it is valid until
/// `il_plan_free`, and every use after that returns `-1` instead of touching
/// freed memory.
///
/// # Safety
/// `plan_json` must be readable for `plan_len` bytes, and `err` writable when
/// non-null.
#[no_mangle]
pub unsafe extern "C" fn il_plan_load(
    plan_json: *const c_char,
    plan_len: usize,
    err: *mut i32,
) -> *mut c_void {
    if !err.is_null() {
        *err = -1;
    }
    if plan_json.is_null() {
        return std::ptr::null_mut();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let plan_bytes = std::slice::from_raw_parts(plan_json as *const u8, plan_len);
        let plan_text = std::str::from_utf8(plan_bytes).map_err(|e| e.to_string())?;
        Plan::from_json(plan_text)
    }));
    let plan = match result {
        Ok(Ok(plan)) => plan,
        _ => return std::ptr::null_mut(),
    };
    let mut guard = match registry().lock() {
        Ok(guard) => guard,
        Err(_) => return std::ptr::null_mut(),
    };
    let mut id = guard.next;
    if id == 0 {
        id = 1;
    }
    guard.next = id.wrapping_add(1);
    guard.plans.insert(id, Arc::new(plan));
    drop(guard);
    if !err.is_null() {
        *err = 0;
    }
    id as *mut c_void
}

/// Evaluate one event against a loaded plan handle.
///
/// Same return and out-parameter contract as `il_eval_plan`. A null, unknown
/// or already-freed handle returns `-1` and writes nothing.
///
/// # Safety
/// `event_json` must be readable for `event_len` bytes, `handle` must be a
/// value returned by `il_plan_load` (or null), and the out buffers writable
/// for their capacities.
#[no_mangle]
pub unsafe extern "C" fn il_eval_plan_handle(
    handle: *mut c_void,
    event_json: *const c_char,
    event_len: usize,
    out_verdict: *mut i32,
    out_policy: *mut c_char,
    policy_cap: usize,
    out_reason: *mut c_char,
    reason_cap: usize,
) -> i32 {
    if handle.is_null() || event_json.is_null() || out_verdict.is_null() {
        return -1;
    }
    let plan = {
        let guard = match registry().lock() {
            Ok(guard) => guard,
            Err(_) => return -1,
        };
        match guard.plans.get(&(handle as usize)) {
            Some(plan) => Arc::clone(plan),
            None => return -1,
        }
    };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let event_bytes = std::slice::from_raw_parts(event_json as *const u8, event_len);
        let event_text = std::str::from_utf8(event_bytes).map_err(|e| e.to_string())?;
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

/// Release a handle returned by `il_plan_load`.
///
/// A null, unknown or already-freed handle is a no-op, so a double free is
/// safe by construction rather than by convention.
///
/// # Safety
/// `handle` must be a value returned by `il_plan_load` (or null). It is never
/// dereferenced.
#[no_mangle]
pub unsafe extern "C" fn il_plan_free(handle: *mut c_void) {
    if handle.is_null() {
        return;
    }
    if let Ok(mut guard) = registry().lock() {
        guard.plans.remove(&(handle as usize));
    }
}

//! The two front ends over `interlock_engine`: PyO3 for CPython, and a C ABI
//! for anything else that can load a shared library.
//!
//! Both call the same `Plan::evaluate`. The Python path is what the policy
//! engine uses when a policy is expressible; the C ABI exists so a Node or Go
//! process can ask the same question without embedding CPython, which is the
//! whole point of keeping the engine free of Python in the first place.
//!
//! The C ABI is deliberately string-in, buffer-out: no allocation crosses the
//! boundary, and a caller that does not want to pass a plan on every call can
//! cache nothing - it pays the parse. That is fine for a language other than
//! Python, where the plan is a few hundred bytes and the call is a tool use,
//! not a hot loop.

use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

use interlock_engine::{Event, Plan};

/// A compiled plan, held by CPython and reused across calls.
#[pyclass]
struct NativePlan {
    plan: Plan,
}

#[pymethods]
impl NativePlan {
    #[new]
    fn new(plan_json: &str) -> PyResult<Self> {
        let plan = Plan::from_json(plan_json).map_err(PyValueError::new_err)?;
        Ok(NativePlan { plan })
    }

    /// `(verdict, policy_id, reason, attributed_to)` for one event.
    ///
    /// 0 allow, 1 block, 2 modify (never returned; the planner refuses plans
    /// with rewrites), 3 escalate.
    fn evaluate(&self, event_json: &str) -> PyResult<(i32, String, String, Option<String>)> {
        let event = Event::from_json(event_json).map_err(PyValueError::new_err)?;
        let outcome = self.plan.evaluate(&event);
        Ok((
            outcome.verdict,
            outcome.policy_id,
            outcome.reason,
            outcome.attributed_to,
        ))
    }

    /// The compiled rule count, for the planner's size gate and for tests.
    #[getter]
    fn rule_count(&self) -> usize {
        self.plan.rules.len()
    }
}

/// ABI version for a caller that loads the library by path and needs to know
/// what it got. Bump when the C signature or the plan schema changes.
pub(crate) const ABI_VERSION: u32 = 1;

#[no_mangle]
pub extern "C" fn il_abi_version() -> u32 {
    ABI_VERSION
}

/// Evaluate one event against one plan.
///
/// Returns 0 on success and -1 on any error (bad JSON, uncompilable plan,
/// internal panic). On error nothing is written: a caller must fail closed,
/// which is what every enforcement site in interlock already does.
///
/// `out_policy` and `out_reason` are NUL-terminated, truncated on a character
/// boundary to fit. Pass a null pointer (or capacity 0) to skip either.
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
            interlock_engine::write_c_str(out_policy, policy_cap, &outcome.policy_id);
            interlock_engine::write_c_str(out_reason, reason_cap, &outcome.reason);
            0
        }
        _ => -1,
    }
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<NativePlan>()?;
    Ok(())
}

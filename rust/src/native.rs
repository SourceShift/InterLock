//! The PyO3 front end over `interlock_engine`.
//!
//! This is what the Python policy engine uses when a policy is expressible.
//! The C ABI for non-Python hosts lives in `rust/ffi`, a separate cdylib: this
//! extension is built with PyO3's `extension-module`, so it cannot be loaded
//! by a process that is not CPython. Both call the same `Plan::evaluate`.

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

/// Plan schema version, exposed on the module as `ENGINE_ABI`. The C ABI has
/// its own `il_abi_version` in `rust/ffi`; both bump together.
pub(crate) const ABI_VERSION: u32 = 1;

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<NativePlan>()?;
    Ok(())
}

//! Native storage backend for interlock's hierarchical policy scopes.
//!
//! This crate reimplements exactly one Python class, `ScopeTree`, the sparse
//! store of policy bindings keyed by scope path. That class is the only place
//! memory scales with subject count: a pure-Python tree of a million bound
//! nodes is a million Python tuples, dicts, and `Binding` instances, each
//! paying Python's per-object header tax. Here the same tree is:
//!
//!   * interned segment / template / key / string-value ids (`u32`), so the
//!     tree stores integers, not repeated Python `str` objects, and shared
//!     path prefixes cost nothing;
//!   * packed nodes holding a compact `Value` enum for params, so common
//!     values (host allowlists, integer limits, keyword lists) hold no Python
//!     object at all;
//!   * a resolver that materializes Python objects only for the single
//!     resolved leaf, only on a cache miss.
//!
//! Everything above the tree is unchanged. The Python `ScopeRegistry` still
//! caches compiled `PolicyEngine`s and `ScopedEngine` still dispatches behind
//! the `evaluate(event) -> Decision` seam. This tree satisfies the same
//! `bind` / `path_versions` / `resolve` / `bindings_at` surface the pure-Python
//! `PyScopeTree` does, so it is a drop-in swap with no change upstream.

use std::collections::{HashMap, HashSet};

use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};

/// Interns strings to compact `u32` ids. Segments, template ids, param keys,
/// and string param values all share this table, so any repeated string in the
/// whole tree is stored once.
#[derive(Default)]
struct Symbols {
    map: HashMap<String, u32>,
    vec: Vec<String>,
}

impl Symbols {
    fn intern(&mut self, s: &str) -> u32 {
        if let Some(&id) = self.map.get(s) {
            return id;
        }
        let id = self.vec.len() as u32;
        self.vec.push(s.to_owned());
        self.map.insert(s.to_owned(), id);
        id
    }

    /// Read-only lookup used on the hot path: never grows the table, so
    /// resolving an unknown scope segment costs nothing and cannot match a node.
    fn get(&self, s: &str) -> Option<u32> {
        self.map.get(s).copied()
    }

    fn name(&self, id: u32) -> &str {
        &self.vec[id as usize]
    }
}

/// A param value in compact native form. Everything but `Other` avoids holding
/// a Python object.
enum Value {
    Str(u32),
    Int(i64),
    Float(f64),
    Bool(bool),
    List(Vec<Value>),
    Other(Py<PyAny>),
}

impl Value {
    fn clone_val(&self, py: Python<'_>) -> Value {
        match self {
            Value::Str(s) => Value::Str(*s),
            Value::Int(i) => Value::Int(*i),
            Value::Float(f) => Value::Float(*f),
            Value::Bool(b) => Value::Bool(*b),
            Value::List(xs) => Value::List(xs.iter().map(|v| v.clone_val(py)).collect()),
            Value::Other(o) => Value::Other(o.clone_ref(py)),
        }
    }
}

struct RBinding {
    template_id: u32,
    enabled: bool,
    params: Vec<(u32, Value)>,
    delegated_from: Option<Vec<u32>>,
}

#[derive(Default)]
struct Node {
    version: u64,
    bindings: Vec<RBinding>,
}

/// Accumulator state while resolving a leaf. `Tomb` is a tombstone: an inherited
/// binding removed at this level, which a deeper node may rebind to `Params`.
enum Slot {
    Tomb,
    Params(Vec<(u32, Value)>),
}

#[pyclass]
struct ScopeTree {
    symbols: Symbols,
    nodes: HashMap<Vec<u32>, Node>,
}

#[pymethods]
impl ScopeTree {
    #[new]
    fn new() -> Self {
        ScopeTree {
            symbols: Symbols::default(),
            nodes: HashMap::new(),
        }
    }

    /// Set (replace) the bindings on `path` and bump its version. Mirrors
    /// `PyScopeTree.bind`: a version bump is what lazily invalidates every
    /// descendant leaf that inherits from this node.
    fn bind(&mut self, path: Vec<String>, bindings: Vec<Bound<'_, PyAny>>) -> PyResult<()> {
        let key: Vec<u32> = path.iter().map(|s| self.symbols.intern(s)).collect();

        let mut rbindings = Vec::with_capacity(bindings.len());
        for b in &bindings {
            let template_id: String = b.getattr("template_id")?.extract()?;
            let enabled: bool = b.getattr("enabled")?.extract()?;
            let params_obj = b.getattr("params")?;
            let delegated_from_obj = b.getattr("delegated_from")?;
            let tid = self.symbols.intern(&template_id);

            let pd = params_obj.downcast::<PyDict>()?;
            let mut params: Vec<(u32, Value)> = Vec::with_capacity(pd.len());
            for (k, v) in pd.iter() {
                let ks: String = k.extract()?;
                let ksym = self.symbols.intern(&ks);
                let val = py_to_value(&mut self.symbols, &v)?;
                params.push((ksym, val));
            }
            // `delegated_from` is Optional[Scope]; Scope is Tuple[str, ...].
            // Extract as Option<Vec<String>> so None round-trips, then intern.
            let delegated_from_py: Option<Vec<String>> = delegated_from_obj.extract()?;
            let delegated_from = delegated_from_py.map(|segs| {
                segs.iter().map(|s| self.symbols.intern(s)).collect()
            });
            rbindings.push(RBinding {
                template_id: tid,
                enabled,
                params,
                delegated_from,
            });
        }

        let node = self.nodes.entry(key).or_default();
        node.version += 1;
        node.bindings = rbindings;
        Ok(())
    }

    /// Version of every node on the root->leaf path (0 for unbound nodes). This
    /// tuple is the cache key's freshness stamp used by `ScopeRegistry`.
    fn path_versions<'py>(
        &self,
        py: Python<'py>,
        leaf: Vec<String>,
    ) -> PyResult<Bound<'py, PyTuple>> {
        let syms: Vec<Option<u32>> = leaf.iter().map(|s| self.symbols.get(s)).collect();
        let mut versions: Vec<u64> = Vec::with_capacity(leaf.len());
        for i in 1..=leaf.len() {
            let prefix = &syms[..i];
            if prefix.iter().any(|s| s.is_none()) {
                versions.push(0);
                continue;
            }
            let k: Vec<u32> = prefix.iter().map(|s| s.unwrap()).collect();
            versions.push(self.nodes.get(&k).map(|n| n.version).unwrap_or(0));
        }
        PyTuple::new(py, versions)
    }

    /// Walk root->leaf, merge per template_id, return effective params as a
    /// `dict[str, dict[str, Any]]`. `union_lookup(template_id)` supplies which
    /// param keys accumulate as set-union instead of override; it is called at
    /// most once per template on the path.
    fn resolve<'py>(
        &self,
        py: Python<'py>,
        leaf: Vec<String>,
        union_lookup: Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyDict>> {
        let syms: Vec<Option<u32>> = leaf.iter().map(|s| self.symbols.get(s)).collect();

        let mut eff: Vec<(u32, Slot)> = Vec::new();
        let mut union_cache: HashMap<u32, HashSet<u32>> = HashMap::new();

        for i in 1..=leaf.len() {
            let prefix = &syms[..i];
            if prefix.iter().any(|s| s.is_none()) {
                continue;
            }
            let k: Vec<u32> = prefix.iter().map(|s| s.unwrap()).collect();
            let node = match self.nodes.get(&k) {
                Some(n) => n,
                None => continue,
            };
            for b in &node.bindings {
                if !b.enabled {
                    set_slot(&mut eff, b.template_id, Slot::Tomb);
                    continue;
                }
                match find_slot(&eff, b.template_id) {
                    None => eff.push((b.template_id, Slot::Params(clone_params(py, &b.params)))),
                    Some(pos) => {
                        let is_params = matches!(eff[pos].1, Slot::Params(_));
                        if !is_params {
                            // was a tombstone: a deeper enabled binding rebinds it
                            eff[pos].1 = Slot::Params(clone_params(py, &b.params));
                        } else {
                            let uk = union_keys(
                                &union_lookup,
                                &mut union_cache,
                                &self.symbols,
                                b.template_id,
                            )?;
                            if let Slot::Params(cur) = &mut eff[pos].1 {
                                for (key, v) in &b.params {
                                    if uk.contains(key) {
                                        let merged = union_merge(py, param_get(cur, *key), v);
                                        param_set(cur, *key, merged);
                                    } else {
                                        param_set(cur, *key, v.clone_val(py));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let out = PyDict::new(py);
        for (tsym, slot) in &eff {
            if let Slot::Params(params) = slot {
                let d = PyDict::new(py);
                for (k, v) in params {
                    d.set_item(self.symbols.name(*k), value_to_py(py, &self.symbols, v)?)?;
                }
                out.set_item(self.symbols.name(*tsym), d)?;
            }
        }
        Ok(out)
    }

    /// Reconstruct the Python `Binding` objects bound directly at `path`. Not on
    /// the hot path; provided for API parity with the pure-Python tree.
    fn bindings_at<'py>(
        &self,
        py: Python<'py>,
        path: Vec<String>,
    ) -> PyResult<Bound<'py, PyTuple>> {
        let mut syms: Vec<u32> = Vec::with_capacity(path.len());
        for seg in &path {
            match self.symbols.get(seg) {
                Some(s) => syms.push(s),
                None => return Ok(PyTuple::empty(py)),
            }
        }
        let node = match self.nodes.get(&syms) {
            Some(n) => n,
            None => return Ok(PyTuple::empty(py)),
        };
        let binding_cls = py.import("interlock.policy.scopes")?.getattr("Binding")?;
        let mut items: Vec<Bound<PyAny>> = Vec::with_capacity(node.bindings.len());
        for b in &node.bindings {
            let params = PyDict::new(py);
            for (k, v) in &b.params {
                params.set_item(self.symbols.name(*k), value_to_py(py, &self.symbols, v)?)?;
            }
            let kwargs = PyDict::new(py);
            kwargs.set_item("enabled", b.enabled)?;
            if let Some(delegated_from) = &b.delegated_from {
                let segs: Vec<String> = delegated_from
                    .iter()
                    .map(|s| self.symbols.name(*s).to_owned())
                    .collect();
                kwargs.set_item("delegated_from", PyTuple::new(py, segs)?)?;
            }
            let obj = binding_cls.call(
                (self.symbols.name(b.template_id), params),
                Some(&kwargs),
            )?;
            items.push(obj);
        }
        PyTuple::new(py, items)
    }
}

/// Convert a Python param value into compact native form. `bool` is checked
/// before `int` because in Python `bool` is a subclass of `int`.
fn py_to_value(symbols: &mut Symbols, v: &Bound<'_, PyAny>) -> PyResult<Value> {
    if v.is_instance_of::<PyBool>() {
        return Ok(Value::Bool(v.extract::<bool>()?));
    }
    if v.is_instance_of::<PyInt>() {
        return Ok(Value::Int(v.extract::<i64>()?));
    }
    if v.is_instance_of::<PyFloat>() {
        return Ok(Value::Float(v.extract::<f64>()?));
    }
    if v.is_instance_of::<PyString>() {
        return Ok(Value::Str(symbols.intern(&v.extract::<String>()?)));
    }
    if v.is_instance_of::<PyList>() || v.is_instance_of::<PyTuple>() {
        let mut out: Vec<Value> = Vec::new();
        for item in v.try_iter()? {
            out.push(py_to_value(symbols, &item?)?);
        }
        return Ok(Value::List(out));
    }
    // exotic type: keep the original Python reference as a fallback
    Ok(Value::Other(v.clone().unbind()))
}

fn value_to_py<'py>(
    py: Python<'py>,
    symbols: &Symbols,
    val: &Value,
) -> PyResult<Bound<'py, PyAny>> {
    Ok(match val {
        Value::Str(s) => PyString::new(py, symbols.name(*s)).into_any(),
        Value::Int(i) => i.into_pyobject(py)?.into_any(),
        Value::Float(f) => f.into_pyobject(py)?.into_any(),
        Value::Bool(b) => b.into_pyobject(py)?.to_owned().into_any(),
        Value::List(xs) => {
            let mut items: Vec<Bound<PyAny>> = Vec::with_capacity(xs.len());
            for x in xs {
                items.push(value_to_py(py, symbols, x)?);
            }
            PyList::new(py, items)?.into_any()
        }
        Value::Other(o) => o.clone_ref(py).into_bound(py),
    })
}

fn clone_params(py: Python<'_>, params: &[(u32, Value)]) -> Vec<(u32, Value)> {
    params.iter().map(|(k, v)| (*k, v.clone_val(py))).collect()
}

fn find_slot(eff: &[(u32, Slot)], tsym: u32) -> Option<usize> {
    eff.iter().position(|(t, _)| *t == tsym)
}

fn set_slot(eff: &mut Vec<(u32, Slot)>, tsym: u32, slot: Slot) {
    match find_slot(eff, tsym) {
        Some(pos) => eff[pos].1 = slot,
        None => eff.push((tsym, slot)),
    }
}

fn param_get(params: &[(u32, Value)], k: u32) -> Option<&Value> {
    params.iter().find(|(kk, _)| *kk == k).map(|(_, v)| v)
}

fn param_set(params: &mut Vec<(u32, Value)>, k: u32, val: Value) {
    match params.iter_mut().find(|(kk, _)| *kk == k) {
        Some(slot) => slot.1 = val,
        None => params.push((k, val)),
    }
}

/// Set-union of two list values, deduped by interned string id (mirrors the
/// Python `set(a) | set(b)` for allowlists and keyword lists). Non-string
/// elements are appended without dedup.
fn union_merge(py: Python<'_>, existing: Option<&Value>, new: &Value) -> Value {
    let mut out: Vec<Value> = Vec::new();
    let mut seen: HashSet<u32> = HashSet::new();

    fn push(v: &Value, out: &mut Vec<Value>, seen: &mut HashSet<u32>, py: Python<'_>) {
        match v {
            Value::List(xs) => {
                for x in xs {
                    if let Value::Str(s) = x {
                        if seen.insert(*s) {
                            out.push(Value::Str(*s));
                        }
                    } else {
                        out.push(x.clone_val(py));
                    }
                }
            }
            other => out.push(other.clone_val(py)),
        }
    }

    if let Some(e) = existing {
        push(e, &mut out, &mut seen, py);
    }
    push(new, &mut out, &mut seen, py);
    Value::List(out)
}

/// Ask the Python `union_lookup(template_id)` which param keys union, translate
/// the returned key names to interned ids, and cache per template so the
/// callback fires at most once per template on a resolve.
fn union_keys(
    union_lookup: &Bound<'_, PyAny>,
    cache: &mut HashMap<u32, HashSet<u32>>,
    symbols: &Symbols,
    tsym: u32,
) -> PyResult<HashSet<u32>> {
    if let Some(s) = cache.get(&tsym) {
        return Ok(s.clone());
    }
    let name = symbols.name(tsym);
    let res = union_lookup.call1((name,))?;
    let mut set: HashSet<u32> = HashSet::new();
    for item in res.try_iter()? {
        let ks: String = item?.extract()?;
        if let Some(id) = symbols.get(&ks) {
            set.insert(id);
        }
    }
    cache.insert(tsym, set.clone());
    Ok(set)
}

#[pymodule]
fn interlock_scopes(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ScopeTree>()?;
    Ok(())
}

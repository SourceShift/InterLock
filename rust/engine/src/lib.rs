//! The native policy evaluator: a compiled plan in, a verdict out.
//!
//! This crate knows nothing about Python. The plan format is written by
//! `interlock.policy.native` from a declarative policy document, and only for
//! documents this evaluator can reproduce exactly; anything else stays on the
//! Python engine. That is why the two engines cannot disagree by accident:
//! there is no partial translation. The Python planner refuses to emit a plan
//! for a policy with a detector, a rewrite, an overlay, a disabled rule, a
//! quarantined rule, a shadow rule or a mesh ceiling.
//!
//! The verdict values are the ones the rest of the package already uses:
//! 0 allow, 1 block, 2 modify (never produced here), 3 escalate.
//!
//! Everything the evaluator needs to mirror is in `interlock/policy/declarative.py`
//! (the condition language) and `interlock/policy/engine.py` (the combining
//! rules). Where Python's equality is looser than JSON's - `true == 1`, `1 ==
//! 1.0` - this crate follows Python, not serde_json.

use glob::{MatchOptions, Pattern};
use regex::Regex;
use serde_json::{Map, Value};

/// Longest regex a `matches` condition may carry, and the longest string it
/// scans. Same numbers as `declarative.MAX_PATTERN` / `MAX_SCAN`.
const MAX_PATTERN: usize = 512;
const MAX_SCAN_CHARS: usize = 64 * 1024;

pub const ALLOW: i32 = 0;
pub const BLOCK: i32 = 1;
pub const MODIFY: i32 = 2;
pub const ESCALATE: i32 = 3;

/// What the evaluator decided, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub verdict: i32,
    pub policy_id: String,
    pub reason: String,
    pub attributed_to: Option<String>,
}

impl Outcome {
    fn allow() -> Self {
        Outcome {
            verdict: ALLOW,
            policy_id: String::new(),
            reason: String::new(),
            attributed_to: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Call,
    Result,
}

impl Phase {
    fn parse(text: &str) -> Result<Phase, String> {
        match text {
            "call" => Ok(Phase::Call),
            "result" => Ok(Phase::Result),
            other => Err(format!("unknown phase {other:?}; use call or result")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Action,
    Principal,
    Phase,
    SpanId,
    ParentPrincipal,
    CallId,
}

impl Field {
    fn parse(text: &str) -> Result<Field, String> {
        match text {
            "action" => Ok(Field::Action),
            "principal" => Ok(Field::Principal),
            "phase" => Ok(Field::Phase),
            "span_id" => Ok(Field::SpanId),
            "parent_principal" => Ok(Field::ParentPrincipal),
            "call_id" => Ok(Field::CallId),
            other => Err(format!("unknown event field {other:?}")),
        }
    }
}

#[derive(Debug, Clone)]
pub enum Subject {
    Field(Field),
    Arg(String),
}

#[derive(Debug, Clone)]
pub enum Op {
    Eq(Value),
    Ne(Value),
    In(Vec<Value>),
    NotIn(Vec<Value>),
    Gt(f64),
    Ge(f64),
    Lt(f64),
    Le(f64),
    Contains(String),
    StartsWith(String),
    EndsWith(String),
    Exists(bool),
    Glob(Pattern),
    Matches(Regex),
}

#[derive(Debug, Clone)]
pub enum ActionMatch {
    Names(Vec<String>),
    Glob(Pattern),
}

#[derive(Debug, Clone)]
pub enum Cond {
    All(Vec<Cond>),
    Any(Vec<Cond>),
    Not(Box<Cond>),
    Action(ActionMatch),
    Test { subject: Subject, op: Op },
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub id: String,
    pub verdict: i32,
    pub reason: String,
    pub phase: Phase,
    pub when: Cond,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub rules: Vec<Rule>,
}

/// One event, as the evaluator sees it. Parsed from the same JSON a front end
/// sends over the C ABI.
#[derive(Debug, Clone)]
pub struct Event {
    action: String,
    args: Value,
    principal: Option<String>,
    span_id: Option<String>,
    parent_principal: Option<String>,
    call_id: Option<String>,
    phase: Phase,
}

fn string_field(obj: &Map<String, Value>, key: &str) -> Option<String> {
    match obj.get(key) {
        Some(Value::String(text)) => Some(text.clone()),
        _ => None,
    }
}

impl Event {
    pub fn from_value(value: &Value) -> Result<Event, String> {
        let obj = value
            .as_object()
            .ok_or_else(|| "an event must be an object".to_string())?;
        let action = match obj.get("action") {
            Some(Value::String(text)) => text.clone(),
            Some(_) => return Err("event action must be a string".to_string()),
            None => String::new(),
        };
        let phase = match obj.get("phase") {
            None | Some(Value::Null) => Phase::Call,
            Some(Value::String(text)) => Phase::parse(text)?,
            Some(_) => return Err("event phase must be a string".to_string()),
        };
        Ok(Event {
            action,
            args: obj.get("args").cloned().unwrap_or(Value::Null),
            principal: string_field(obj, "principal"),
            span_id: string_field(obj, "span_id"),
            parent_principal: string_field(obj, "parent_principal"),
            call_id: string_field(obj, "call_id"),
            phase,
        })
    }

    pub fn from_json(text: &str) -> Result<Event, String> {
        let value: Value =
            serde_json::from_str(text).map_err(|exc| format!("invalid event JSON: {exc}"))?;
        Event::from_value(&value)
    }

    /// The owned value of one top-level field. Cloning is deliberate: field
    /// tests are rare, and returning a borrow would have to keep six separate
    /// `Option<Value>` caches beside the parsed fields for no measurable gain.
    fn field(&self, field: Field) -> Option<Value> {
        match field {
            Field::Action => Some(Value::String(self.action.clone())),
            Field::Principal => self.principal.clone().map(Value::String),
            Field::SpanId => self.span_id.clone().map(Value::String),
            Field::ParentPrincipal => self.parent_principal.clone().map(Value::String),
            Field::CallId => self.call_id.clone().map(Value::String),
            Field::Phase => Some(Value::String(
                match self.phase {
                    Phase::Call => "call",
                    Phase::Result => "result",
                }
                .to_string(),
            )),
        }
    }
}

/// Canonical spelling of an action name, mirroring `interlock.actions`.
///
/// `http.fetch` -> `http_fetch`, `fs.readFile` -> `fs_read_file`,
/// `child_process.execFile` -> `child_process_exec_file`.
pub fn canonical_action(name: &str) -> String {
    if name.is_empty() {
        return String::new();
    }
    let separated: String = name
        .chars()
        .map(|ch| match ch {
            '.' | ':' | '/' => '_',
            other => other,
        })
        .collect();
    // (a) acronym followed by a capitalised word: "HTTPServer" -> "HTTP_Server".
    // (b) lower/digit followed by upper: "readFile" -> "read_File".
    let mut out = String::with_capacity(separated.len() + 4);
    let chars: Vec<char> = separated.chars().collect();
    for (index, ch) in chars.iter().enumerate() {
        if index > 0 {
            let prev = chars[index - 1];
            let acronym = prev.is_ascii_uppercase()
                && ch.is_ascii_uppercase()
                && index + 1 < chars.len()
                && chars[index + 1].is_ascii_lowercase();
            let lower_upper = (prev.is_ascii_lowercase() || prev.is_ascii_digit())
                && ch.is_ascii_uppercase();
            if acronym || lower_upper {
                out.push('_');
            }
        }
        out.push(*ch);
    }
    out.to_ascii_lowercase()
}

fn number_of(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        _ => None,
    }
}

fn truth_value(value: &Value) -> Option<f64> {
    match value {
        Value::Bool(flag) => Some(if *flag { 1.0 } else { 0.0 }),
        other => number_of(other),
    }
}

/// Python's `==` over JSON-shaped values: numbers compare numerically across
/// int/float, and a bool compares as 1/0. Lists and objects compare deeply.
pub fn value_eq(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::String(a), Value::String(b)) => a == b,
        (Value::Number(_), Value::Number(_)) => {
            match (left.as_f64(), right.as_f64()) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            }
        }
        (Value::Bool(_), Value::Number(_)) | (Value::Number(_), Value::Bool(_)) => {
            match (truth_value(left), truth_value(right)) {
                (Some(a), Some(b)) => a == b,
                _ => false,
            }
        }
        (Value::Array(a), Value::Array(b)) => {
            a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| value_eq(x, y))
        }
        (Value::Object(a), Value::Object(b)) => {
            a.len() == b.len()
                && a.iter().all(|(key, val)| {
                    b.get(key).map(|other| value_eq(val, other)).unwrap_or(false)
                })
        }
        _ => false,
    }
}

/// Follow a dotted path through objects and (digit-segment) arrays. `None` is
/// "missing"; a JSON null is `Some(Value::Null)`, which `exists` distinguishes.
fn lookup<'a>(args: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = args;
    for part in path.split('.') {
        current = match current {
            Value::Object(map) => map.get(part)?,
            Value::Array(items) => {
                if part.is_empty() || !part.chars().all(|ch| ch.is_ascii_digit()) {
                    return None;
                }
                let index: usize = part.parse().ok()?;
                items.get(index)?
            }
            _ => return None,
        };
    }
    Some(current)
}

fn always_false() -> MatchOptions {
    MatchOptions {
        case_sensitive: true,
        require_literal_separator: false,
        require_literal_leading_dot: false,
    }
}

impl Op {
    fn parse(raw: &Map<String, Value>, op: &str) -> Result<Op, String> {
        let value = raw
            .get("value")
            .ok_or_else(|| format!("operator {op:?} needs a value"))?;
        match op {
            "eq" => Ok(Op::Eq(value.clone())),
            "ne" => Ok(Op::Ne(value.clone())),
            "in" | "not_in" => {
                let items = value
                    .as_array()
                    .ok_or_else(|| format!("{op:?} takes a list"))?
                    .clone();
                Ok(if op == "in" {
                    Op::In(items)
                } else {
                    Op::NotIn(items)
                })
            }
            "gt" | "ge" | "lt" | "le" => {
                let number = number_of(value)
                    .ok_or_else(|| format!("{op:?} takes a number"))?;
                Ok(match op {
                    "gt" => Op::Gt(number),
                    "ge" => Op::Ge(number),
                    "lt" => Op::Lt(number),
                    _ => Op::Le(number),
                })
            }
            "contains" | "startswith" | "endswith" => {
                let text = value
                    .as_str()
                    .ok_or_else(|| format!("{op:?} takes a string"))?
                    .to_string();
                Ok(match op {
                    "contains" => Op::Contains(text),
                    "startswith" => Op::StartsWith(text),
                    _ => Op::EndsWith(text),
                })
            }
            "exists" => {
                let flag = value
                    .as_bool()
                    .ok_or_else(|| "exists takes true or false".to_string())?;
                Ok(Op::Exists(flag))
            }
            "glob" => {
                let pattern = value
                    .as_str()
                    .ok_or_else(|| "glob takes a string pattern".to_string())?;
                let compiled = Pattern::new(pattern)
                    .map_err(|exc| format!("invalid glob {pattern:?}: {exc}"))?;
                Ok(Op::Glob(compiled))
            }
            "matches" => {
                let pattern = value
                    .as_str()
                    .ok_or_else(|| "matches takes a string pattern".to_string())?;
                if pattern.chars().count() > MAX_PATTERN {
                    return Err(format!(
                        "matches takes a regex of at most {MAX_PATTERN} characters"
                    ));
                }
                let compiled = Regex::new(pattern)
                    .map_err(|exc| format!("invalid regex {pattern:?}: {exc}"))?;
                Ok(Op::Matches(compiled))
            }
            other => Err(format!("unknown operator {other:?}")),
        }
    }

    fn test(&self, value: Option<&Value>) -> bool {
        match self {
            Op::Eq(operand) => value.map(|v| value_eq(v, operand)).unwrap_or(false),
            Op::Ne(operand) => value.map(|v| !value_eq(v, operand)).unwrap_or(true),
            Op::In(items) => value
                .map(|v| items.iter().any(|item| value_eq(v, item)))
                .unwrap_or(false),
            Op::NotIn(items) => value
                .map(|v| !items.iter().any(|item| value_eq(v, item)))
                .unwrap_or(true),
            Op::Gt(limit) => numeric(value).map(|v| v > *limit).unwrap_or(false),
            Op::Ge(limit) => numeric(value).map(|v| v >= *limit).unwrap_or(false),
            Op::Lt(limit) => numeric(value).map(|v| v < *limit).unwrap_or(false),
            Op::Le(limit) => numeric(value).map(|v| v <= *limit).unwrap_or(false),
            Op::Contains(text) => match value {
                Some(Value::String(value)) => value.contains(text),
                Some(Value::Array(items)) => items
                    .iter()
                    .any(|item| item.as_str().map(|s| s == text).unwrap_or(false)),
                _ => false,
            },
            Op::StartsWith(prefix) => value
                .and_then(|v| v.as_str())
                .map(|v| v.starts_with(prefix))
                .unwrap_or(false),
            Op::EndsWith(suffix) => value
                .and_then(|v| v.as_str())
                .map(|v| v.ends_with(suffix))
                .unwrap_or(false),
            Op::Exists(want) => {
                let present = value.map(|v| !v.is_null()).unwrap_or(false);
                present == *want
            }
            Op::Glob(pattern) => value
                .and_then(|v| v.as_str())
                .map(|v| pattern.matches_with(v, always_false()))
                .unwrap_or(false),
            Op::Matches(pattern) => value
                .and_then(|v| v.as_str())
                .map(|v| {
                    let head: String = v.chars().take(MAX_SCAN_CHARS).collect();
                    pattern.is_match(&head)
                })
                .unwrap_or(false),
        }
    }
}

/// A number for ordering comparisons: JSON numbers only, and never a bool -
/// Python's `isinstance(v, (int, float))` is false for `True`, so `True > 0`
/// must not satisfy a `gt` test.
fn numeric(value: Option<&Value>) -> Option<f64> {
    match value {
        Some(Value::Number(number)) => number.as_f64(),
        _ => None,
    }
}

impl Cond {
    /// `Some(Some(attributed))` is a hit that names an argument;
    /// `Some(None)` is a hit with no attribution; `None` is a miss.
    fn eval(&self, event: &Event) -> Option<Option<String>> {
        match self {
            Cond::All(subs) => {
                let mut named: Option<String> = None;
                for sub in subs {
                    let hit = sub.eval(event)?;
                    if named.is_none() {
                        named = hit;
                    }
                }
                Some(named)
            }
            Cond::Any(subs) => subs.iter().find_map(|sub| sub.eval(event)),
            Cond::Not(sub) => {
                if sub.eval(event).is_some() {
                    None
                } else {
                    Some(None)
                }
            }
            Cond::Action(matcher) => {
                let canonical = canonical_action(&event.action);
                let matched = match matcher {
                    ActionMatch::Names(names) => names.iter().any(|name| name == &canonical),
                    ActionMatch::Glob(pattern) => {
                        pattern.matches_with(&event.action, always_false())
                    }
                };
                if matched {
                    Some(None)
                } else {
                    None
                }
            }
            Cond::Test { subject, op } => {
                let hit = match subject {
                    Subject::Field(field) => op.test(event.field(*field).as_ref()),
                    Subject::Arg(path) => op.test(lookup(&event.args, path)),
                };
                if !hit {
                    return None;
                }
                match subject {
                    Subject::Arg(path) => Some(Some(path.clone())),
                    Subject::Field(_) => Some(None),
                }
            }
        }
    }
}

impl Plan {
    pub fn from_value(value: &Value) -> Result<Plan, String> {
        let obj = value
            .as_object()
            .ok_or_else(|| "a plan must be an object".to_string())?;
        match obj.get("version") {
            Some(Value::Number(number)) if number.as_i64() == Some(1) => {}
            _ => return Err("plan version must be 1".to_string()),
        }
        let rules = obj
            .get("rules")
            .and_then(Value::as_array)
            .ok_or_else(|| "plan rules must be a list".to_string())?;
        let mut parsed = Vec::with_capacity(rules.len());
        for (index, raw) in rules.iter().enumerate() {
            parsed.push(parse_rule(raw, index)?);
        }
        Ok(Plan { rules: parsed })
    }

    pub fn from_json(text: &str) -> Result<Plan, String> {
        let value: Value =
            serde_json::from_str(text).map_err(|exc| format!("invalid plan JSON: {exc}"))?;
        Plan::from_value(&value)
    }

    pub fn evaluate(&self, event: &Event) -> Outcome {
        let mut escalation: Option<Outcome> = None;
        for rule in &self.rules {
            if rule.phase != event.phase {
                continue;
            }
            let Some(named) = rule.when.eval(event) else {
                continue;
            };
            let outcome = Outcome {
                verdict: rule.verdict,
                policy_id: rule.id.clone(),
                reason: rule.reason.clone(),
                attributed_to: named,
            };
            if rule.verdict == BLOCK {
                return outcome;
            }
            if rule.verdict == ESCALATE && escalation.is_none() {
                escalation = Some(outcome);
            }
        }
        escalation.unwrap_or_else(Outcome::allow)
    }
}

fn parse_rule(raw: &Value, index: usize) -> Result<Rule, String> {
    let obj = raw
        .as_object()
        .ok_or_else(|| format!("rules[{index}] must be an object"))?;
    let id = obj
        .get("id")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("rules[{index}] needs a string id"))?
        .to_string();
    let verdict = match obj.get("verdict").and_then(Value::as_i64) {
        Some(value) if value == BLOCK as i64 => BLOCK,
        Some(value) if value == ESCALATE as i64 => ESCALATE,
        _ => {
            return Err(format!(
                "rules[{index}] ({id}) verdict must be 1 (block) or 3 (escalate)"
            ))
        }
    };
    let reason = obj
        .get("reason")
        .and_then(Value::as_str)
        .unwrap_or(&id)
        .to_string();
    let phase = match obj.get("phase") {
        None | Some(Value::Null) => Phase::Call,
        Some(Value::String(text)) => Phase::parse(text)?,
        Some(_) => return Err(format!("rules[{index}] ({id}) phase must be a string")),
    };
    let when = obj
        .get("when")
        .ok_or_else(|| format!("rules[{index}] ({id}) needs a when"))?;
    Ok(Rule {
        id,
        verdict,
        reason,
        phase,
        when: parse_cond(when)?,
    })
}

fn parse_cond(raw: &Value) -> Result<Cond, String> {
    let obj = raw
        .as_object()
        .ok_or_else(|| "a condition must be an object".to_string())?;
    if let Some(parts) = obj.get("all") {
        return Ok(Cond::All(parse_list(parts, "all")?));
    }
    if let Some(parts) = obj.get("any") {
        return Ok(Cond::Any(parse_list(parts, "any")?));
    }
    if let Some(inner) = obj.get("not") {
        return Ok(Cond::Not(Box::new(parse_cond(inner)?)));
    }
    if let Some(action) = obj.get("action") {
        return Ok(Cond::Action(parse_action(action)?));
    }
    if let Some(name) = obj.get("field") {
        let name = name
            .as_str()
            .ok_or_else(|| "field must be a string".to_string())?;
        let subject = Subject::Field(Field::parse(name)?);
        return Ok(Cond::Test {
            subject,
            op: parse_operator(obj)?,
        });
    }
    if let Some(name) = obj.get("arg") {
        let name = name
            .as_str()
            .ok_or_else(|| "arg must be a string".to_string())?;
        if name.is_empty() {
            return Err("arg must be a non-empty string".to_string());
        }
        return Ok(Cond::Test {
            subject: Subject::Arg(name.to_string()),
            op: parse_operator(obj)?,
        });
    }
    Err("unknown condition; the native plan accepts all/any/not/action/field/arg".to_string())
}

fn parse_list(raw: &Value, key: &str) -> Result<Vec<Cond>, String> {
    let items = raw
        .as_array()
        .ok_or_else(|| format!("{key} needs a list"))?;
    if items.is_empty() {
        return Err(format!("{key} needs a non-empty list"));
    }
    items.iter().map(parse_cond).collect()
}

fn parse_action(raw: &Value) -> Result<ActionMatch, String> {
    match raw {
        Value::String(name) => Ok(ActionMatch::Names(vec![canonical_action(name)])),
        Value::Array(items) => {
            let mut names = Vec::with_capacity(items.len());
            for item in items {
                let name = item
                    .as_str()
                    .ok_or_else(|| "action list entries must be strings".to_string())?;
                names.push(canonical_action(name));
            }
            if names.is_empty() {
                return Err("action list cannot be empty".to_string());
            }
            Ok(ActionMatch::Names(names))
        }
        Value::Object(map) => {
            let pattern = map
                .get("glob")
                .and_then(Value::as_str)
                .ok_or_else(|| "action object must carry a glob".to_string())?;
            let compiled =
                Pattern::new(pattern).map_err(|exc| format!("invalid glob {pattern:?}: {exc}"))?;
            Ok(ActionMatch::Glob(compiled))
        }
        _ => Err("action must be a name, a list of names, or {\"glob\": ...}".to_string()),
    }
}

fn parse_operator(obj: &Map<String, Value>) -> Result<Op, String> {
    let mut found: Option<(&str, &Value)> = None;
    for key in [
        "eq", "ne", "in", "not_in", "gt", "ge", "lt", "le", "contains", "startswith", "endswith",
        "exists", "glob", "matches",
    ] {
        if let Some(value) = obj.get(key) {
            if found.is_some() {
                return Err("a test takes exactly one operator".to_string());
            }
            found = Some((key, value));
        }
    }
    let (op, value) = found.ok_or_else(|| "a test needs one operator".to_string())?;
    let mut single = Map::new();
    single.insert("value".to_string(), value.clone());
    Op::parse(&single, op)
}

/// Trim a string to fit a fixed C buffer, on a character boundary, and NUL it.
///
/// # Safety
/// `buffer` must point to `capacity` writable bytes.
pub unsafe fn write_c_str(buffer: *mut core::ffi::c_char, capacity: usize, text: &str) {
    if buffer.is_null() || capacity == 0 {
        return;
    }
    let bytes = text.as_bytes();
    let mut len = bytes.len().min(capacity - 1);
    while len > 0 && !text.is_char_boundary(len) {
        len -= 1;
    }
    core::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer as *mut u8, len);
    *buffer.add(len) = 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn plan(rules: Value) -> Plan {
        Plan::from_value(&json!({"version": 1, "rules": rules})).expect("plan parses")
    }

    fn event(value: Value) -> Event {
        Event::from_value(&value).expect("event parses")
    }

    #[test]
    fn block_wins_and_escalate_waits() {
        let plan = plan(json!([
            {"id": "ask", "verdict": 3, "reason": "human", "when": {"action": "Bash"}},
            {"id": "stop", "verdict": 1, "reason": "no", "when": {"arg": "command", "contains": "rm"}}
        ]));
        let hit = plan.evaluate(&event(json!({"action": "bash", "args": {"command": "rm -rf /"}})));
        assert_eq!(hit.verdict, BLOCK);
        assert_eq!(hit.policy_id, "stop");
        assert_eq!(hit.attributed_to.as_deref(), Some("command"));

        let ask = plan.evaluate(&event(json!({"action": "Bash", "args": {"command": "ls"}})));
        assert_eq!(ask.verdict, ESCALATE);
        assert_eq!(ask.policy_id, "ask");
    }

    #[test]
    fn canonical_action_matches_python() {
        assert_eq!(canonical_action("http.fetch"), "http_fetch");
        assert_eq!(canonical_action("fs.readFile"), "fs_read_file");
        assert_eq!(canonical_action("child_process.execFile"), "child_process_exec_file");
        assert_eq!(canonical_action("HTTPServer"), "http_server");
        assert_eq!(canonical_action("read_file"), "read_file");
        assert_eq!(canonical_action(""), "");
    }

    #[test]
    fn missing_is_not_null() {
        let plan = plan(json!([
            {"id": "a", "verdict": 1, "when": {"arg": "x", "exists": false}}
        ]));
        // absent satisfies exists:false ...
        assert_eq!(plan.evaluate(&event(json!({"action": "a", "args": {}}))).verdict, BLOCK);
        // ... and so does an explicit null
        assert_eq!(
            plan.evaluate(&event(json!({"action": "a", "args": {"x": null}}))).verdict,
            BLOCK
        );
        // a value does not
        assert_eq!(
            plan.evaluate(&event(json!({"action": "a", "args": {"x": 0}}))).verdict,
            ALLOW
        );
    }

    #[test]
    fn python_equality_is_looser_than_json() {
        assert!(value_eq(&json!(1), &json!(1.0)));
        assert!(value_eq(&json!(true), &json!(1)));
        assert!(!value_eq(&json!("1"), &json!(1)));
        assert!(value_eq(&json!([1, "a"]), &json!([1.0, "a"])));
    }

    #[test]
    fn ordering_ignores_booleans() {
        let plan = plan(json!([
            {"id": "n", "verdict": 1, "when": {"arg": "limit", "gt": 5}}
        ]));
        assert_eq!(
            plan.evaluate(&event(json!({"action": "q", "args": {"limit": 10}}))).verdict,
            BLOCK
        );
        assert_eq!(
            plan.evaluate(&event(json!({"action": "q", "args": {"limit": true}}))).verdict,
            ALLOW
        );
    }

    #[test]
    fn nested_paths_and_list_indices() {
        let plan = plan(json!([
            {"id": "n", "verdict": 1, "when": {"arg": "items.1.name", "eq": "secret"}}
        ]));
        assert_eq!(
            plan.evaluate(&event(json!({"action": "q", "args": {"items": [{}, {"name": "secret"}]}})))
                .verdict,
            BLOCK
        );
        assert_eq!(
            plan.evaluate(&event(json!({"action": "q", "args": {"items": []}}))).verdict,
            ALLOW
        );
    }

    #[test]
    fn result_phase_rules_only_see_results() {
        let plan = plan(json!([
            {"id": "r", "verdict": 1, "phase": "result", "when": {"arg": "result", "contains": "secret"}}
        ]));
        assert_eq!(
            plan.evaluate(&event(json!({"action": "read", "args": {"result": "secret"}}))).verdict,
            ALLOW
        );
        assert_eq!(
            plan.evaluate(&event(
                json!({"action": "read", "phase": "result", "args": {"result": "secret"}})
            ))
            .verdict,
            BLOCK
        );
    }

    #[test]
    fn glob_and_regex() {
        let plan = plan(json!([
            {"id": "g", "verdict": 1, "when": {"arg": "path", "glob": "*.pem"}},
            {"id": "r", "verdict": 3, "when": {"arg": "cmd", "matches": "^curl\\s"}}
        ]));
        assert_eq!(
            plan.evaluate(&event(json!({"action": "read", "args": {"path": "a/b.pem"}}))).verdict,
            BLOCK
        );
        assert_eq!(
            plan.evaluate(&event(json!({"action": "run", "args": {"cmd": "curl -s x"}}))).verdict,
            ESCALATE
        );
    }

    #[test]
    fn rejects_unsupported_plan() {
        assert!(Plan::from_json(r#"{"version":1,"rules":[{"id":"x","verdict":2,"when":{"action":"a"}}]}"#)
            .is_err());
        assert!(Plan::from_json(r#"{"version":1,"rules":[{"id":"x","verdict":1,"when":{"intent":"git.push"}}]}"#)
            .is_err());
        assert!(Plan::from_json(r#"{"version":2,"rules":[]}"#).is_err());
    }
}

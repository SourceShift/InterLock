# Python API reference

Every public name you can import, with its real signature. Use this page to look
things up. To learn how the pieces fit together, start with
[concepts](../concepts.md) and the guides linked from each section.

Everything in the first six sections is importable straight from `interlock`.
Scopes, receipts, the sandbox, and the testing helpers live in subpackages, and
each section says which one.

- [Setup](#setup): `install`, `get_engine`, `set_engine`
- [Guarding calls](#guarding-calls): `guard`, `monitor`, `guard_mcp_session`,
  `guard_langchain_tools`, `guard_tool_loop`, `guard_litellm_tool_loop`,
  `guard_crewai_tool_loop`, `guard_adk_tool_loop`, `enforce_tool_call`,
  `enforce_tool_result`
- [Rules and engines](#rules-and-engines): `Rule`, `PolicyEngine`, `deny_tool`,
  `deny_when`
- [Decisions](#decisions): `Verdict`, `Decision`, `Blocked`
- [Events](#events): `SensorEvent`
- [Run identity](#run-identity): `span`, `new_span`, `current_span`,
  `current_principal`, `current_parent_principal`, `set_principal`
- [Scopes](#scopes-interlockpolicy): `interlock.policy`
- [Receipts](#receipts-interlocksink-and-interlockreceipt): `interlock.sink`,
  `interlock.receipt`
- [Sandbox](#sandbox-interlockbrace): `interlock.brace`
- [Testing helpers](#testing-helpers-interlocktesting): `interlock.testing`

For the Node.js daemon and its Python client, see the [sidecar reference](sidecar.md).

---

## Setup

Guide: [concepts](../concepts.md), [writing rules](../guides/writing-rules.md).

### `install`

```python
install(engine=None, rules=None, sink=None, approver=None) -> PolicyEngine
```

Sets the process-wide engine that every interceptor consults, and returns it.

| Parameter | Meaning |
|---|---|
| `engine` | The engine to install. If omitted, a new `PolicyEngine(rules=rules)` is built. |
| `rules` | Rules to use. With no `engine`, they become the new engine. With an `engine`, each one is appended to **your** engine via `engine.add_rule`, which changes that object. |
| `sink` | A receipt sink (for example `FileSink("audit.jsonl")`). Installs it with `set_sink`. Omitting it leaves any previously installed sink in place. |
| `approver` | The callable that decides `ESCALATE` verdicts ([approvals](#approvals-interlockapproval)). Without one, escalations are blocked. |

Things to know:

- It is process-global. The last call wins.
- Passing `rules` together with an engine that has no `add_rule` method (a
  `ScopedEngine`, or the sidecar's `RemoteEngine`) raises `TypeError`, saying the
  engine takes no extra rules. Build those engines with their rules first, then
  call `install(engine=...)`. For a `ScopedEngine`, bind extra rules at the root
  scope through a template.
- `install()` never removes a sink. Call `set_sink(None)` to turn receipts off.

```python
import interlock
from interlock import deny_tool

engine = interlock.install(rules=[deny_tool("shell_exec")])
assert interlock.get_engine() is engine
```

### `get_engine`

```python
get_engine() -> PolicyEngine
```

Returns the installed engine. If nothing was ever installed, it creates an empty
`PolicyEngine`, installs it, and returns it. **An empty engine allows every
call**, so a program that forgets `install()` runs unguarded without any error.

### `set_engine`

```python
set_engine(engine) -> None
```

Installs an engine without touching rules or the sink. It accepts any object with
an `evaluate(event) -> Decision` method and does no validation.

### `__version__`

```python
__version__ -> str
```

The installed package version, as a string.

---

## Guarding calls

Guides: [integrations](../guides/integrations.md), [MCP](../guides/mcp.md).

Every function in this section turns a call into a [`SensorEvent`](#sensorevent),
asks the engine for a [`Decision`](#decision), and enforces it. They all share
the same three keyword options:

| Option | Meaning |
|---|---|
| `engine` | Use this engine instead of the installed one. (`guard` and `monitor` always use the installed one.) |
| `enforcement` | `"blocking"` (default) enforces the decision. `"monitor"` records it and never blocks or rewrites. **Any other string enforces**, so a typo like `"monitoring"` blocks rather than silently observing. |
| `principal` | Who is acting. Overrides the principal set by [`span`](#span) for these calls. |

All of them raise [`Blocked`](#blocked) when a call is denied under blocking
enforcement. If a rule itself raises, that exception reaches the caller unchanged
and the tool does not run (see [`PolicyEngine`](#policyengine)). When a receipt
sink is installed, each decision is recorded, including allows. In monitor mode, a
decision that would have blocked or rewritten the call is recorded with
`observed=True`, so the log never reads as enforcement that didn't happen.

### `guard`

```python
guard(policy_id=None, enforcement="blocking", principal=None) -> Callable
```

Decorator for your own functions, sync or async. For each call it:

1. builds an event whose `action` is the function's `__name__` and whose `args`
   are the call's arguments bound to the signature, defaults filled in, with
   every variadic argument exposed by name (see below);
2. evaluates it and raises `Blocked` before the body runs on a block;
3. on a modify, applies `modified_args` wherever each argument was passed:
   positionally, by keyword, or into `**kwargs`;
4. runs the function and passes its return value through
   [`enforce_tool_result`](#enforce_tool_result), so result-phase rules apply too.

Rules see every argument under the name the caller used. Declared parameters
appear by name; each `**kwargs` entry is also flattened to the top level (the
variadic parameter's own key still holds the caller's mapping), so a rule can
look a keyword up directly. A `*args` tuple made only of strings is exposed as
one shell-joined command under the variadic parameter's name; a tuple with any
non-string item is left as the original sequence.

The view is *shallow*-copied: the top-level mapping and a variadic keyword
mapping are new dicts, so replacing an entry in the view never reaches the
caller. A container nested inside a value (a list or dict inside `event.args[...]`)
is still the caller's object; a rule that wants to edit one must copy it first,
because mutating it changes the call.

When a `**kwargs` entry has the same name as a declared parameter — legal for a
positional-only parameter, as in `def upload(path, /, **extra)` — the flattened
name carries the **variadic** value, which is what the callee's
`extra["path"]` reads. The declared value stays addressable as
`__declared__<name>`, a reserved key that is view-only: a caller's own
`__declared__…` keyword stays in the variadic mapping and cannot occupy it.
The variadic parameter's own mapping keeps the caller's entry under its
original name. A rewrite of `path` therefore lands in the variadic mapping,
while a rewrite of `__declared__path` lands in the declared parameter.

`modified_args` is applied in the slot each exposed value came from. A rewrite
of the shell-joined `*args` string is split back into argv with `shlex.split`;
a list or tuple becomes the argv, and any other scalar becomes a one-item
argv. A rewrite that cannot be applied in that shape — a dict aimed at `*args`,
or a shell string that does not split — is refused under blocking enforcement
(`Blocked`, with the argument named) rather than running the call unmodified
under a MODIFY receipt. Monitor mode records the would-be refusal and still
does not intervene. Otherwise the function is called with exactly what the
caller passed.

`policy_id` labels every decision on this tool that doesn't name a policy of its
own, on the call side and the result side, so it shows up in `Blocked`, logs, and
receipts. A rule's own `policy_id` always wins.

```python
import interlock
from interlock import Blocked, Decision, guard

@guard(policy_id="shell.v1")
def run_shell(cmd: str) -> str:
    return cmd

interlock.install(rules=[lambda e: Decision.block("no shells")])
try:
    run_shell("ls")
except Blocked as e:
    assert e.decision.policy_id == "shell.v1"
```

```python
import interlock
from interlock import Decision, guard

@guard()
def transfer(amount: int, to: str) -> str:
    return f"sent {amount} to {to}"

def cap(event):
    if event.args.get("amount", 0) > 100:
        return Decision.modify({"amount": 100}, reason="capped", attributed_to="amount")
    return None

interlock.install(rules=[cap])
assert transfer(5000, "bob") == "sent 100 to bob"
```

### `monitor`

```python
monitor(policy_id=None, principal=None) -> Callable
```

Shorthand for `guard(policy_id, enforcement="monitor", principal)`. Decisions are
logged to the `"interlock"` logger at `DEBUG` and written to the receipt sink if
one is installed, with `observed=True` on any that would have intervened. Nothing
is ever blocked or rewritten.

### `guard_mcp_session`

```python
guard_mcp_session(session, *, engine=None, enforcement="blocking", principal=None,
                  origin=None, schemas=None) -> Any
```

Replaces `session.call_tool` with a guarded version and returns the same session
object. Works whether `call_tool` is sync or async, and never imports the MCP SDK:
any object with a `call_tool(name, arguments)` method works.

Each call is checked with `enforce_tool_call` before it is sent, and the server's
response is checked with `enforce_tool_result` before it is returned. An official
SDK `CallToolResult` has its text joined into `"result"` first (see
[`result_payload`](#result_payload)), so result rules can read it. Extra
positional and keyword arguments to `call_tool` are passed through untouched.

| Parameter | Meaning |
|---|---|
| `origin` | The server this session talks to. Added to every call as the `__origin__` label the MCP trust detectors read (`mcp_trust_registry`, `mcp_capability_lease`, `mcp_server_attestation`). |
| `schemas` | `{tool_name: schema_string}`: the schema the server declared for each tool. Added as the `__schema__` label that `mcp_tool_pinning` checks. |

Labels are facts about a call, so only your code may set them. Before the check,
the wrapper **drops any `TRUST_LABELS` key from the arguments the caller passed**
(those usually come from the model, and a model that wrote `"__origin__": "github"`
could otherwise claim to be a trusted server). It then sets the `origin` and
`schemas` facts on the event's trusted
[`labels`](#sensorevent) channel, and strips every reserved key again before the
call goes to the server. `TRUST_LABELS` is importable from
`interlock.interceptors.mcp`:
`{"__origin__", "__schema__", "__attestation__", "__tools__"}`.

```python
import asyncio
from interlock import PolicyEngine, guard_mcp_session
from interlock.detectors.mcp_trust_registry import mcp_trust_registry

class Server:
    async def call_tool(self, name, arguments=None):
        return {"sent": arguments}

engine = PolicyEngine(rules=[mcp_trust_registry(["github"])])
github = guard_mcp_session(Server(), engine=engine, origin="github")
print(asyncio.run(github.call_tool("create_issue", {"title": "Bug", "__origin__": "evil"})))
# -> {'sent': {'title': 'Bug'}}     the spoofed label was dropped, and so was the real one
```

Only `call_tool` is wrapped. Connecting, listing tools, reading resources, and
sampling are not intercepted. The MCP trust detectors that act on those events
need you to send them yourself (see the [MCP guide](../guides/mcp.md)).
`mcp_capability_lease` never refuses a `tools/list` listing event, so it can share
an engine with `mcp_surface_baseline`.

### `guard_langchain_tools`

```python
guard_langchain_tools(tools, *, engine=None, enforcement="blocking", principal=None) -> List[Any]
```

Returns guarded copies of LangChain tools as `StructuredTool`s with the same
name, description, and argument schema. Each call is checked with
`enforce_tool_call`, the original tool is invoked with the vetted arguments, and
its output is checked with `enforce_tool_result` before it is returned. Result
rules such as `tool_result_injection_guard` therefore apply to LangChain tools
too.

Requires the `[langchain]` extra (`langchain-core`). Importing interlock does not
import LangChain. Calling this function does.

### `guard_tool_loop`

```python
guard_tool_loop(tool, *, engine=None, enforcement="blocking", principal=None) -> Callable
```

Wraps the `(name, args) -> result` dispatcher at the bottom of a framework tool
loop and returns a dispatcher with the same shape. `tool` is that callable, or a
framework tool object exposing `run` / `run_async` (CrewAI's `_run` is also
accepted). On ALLOW the tool's value is returned; on BLOCK `Blocked` is raised
before the tool runs; on MODIFY the tool is called with the rewritten
arguments; and the result is checked on the way back.

The package root exports four entry points. `guard_tool_loop` is the OpenAI SDK
adapter; `guard_litellm_tool_loop`, `guard_crewai_tool_loop` and
`guard_adk_tool_loop` are the LiteLLM, CrewAI and Google ADK adapters' own
`guard_tool_loop`, exposed under distinct names because each module uses the
same symbol. Their signature is identical. The SDK is never imported, so
`import interlock` stays dependency-free. `interlock doctor` reports which of
these adapters it detected and which surfaces remain uncovered.

### `enforce_tool_call`

```python
enforce_tool_call(action, arguments, *, engine=None, enforcement="blocking", principal=None, call_id=None, labels=None) -> Dict[str, Any]
```

The core every adapter uses. Checks one call and returns the arguments to use:

- **allow** or monitor mode: a copy of `arguments` without any reserved trust
  key (`None` becomes `{}`).
- **modify**: that copy with `modified_args` merged in.
- **block**: raises `Blocked`.

The event gets its own copy of the arguments, so a rule that edits `event.args`
in place can't change what the tool receives. Only a modify decision can.

`call_id` ties this event to the rest of one guarded call. Pass the same value
to the matching `enforce_tool_result` call when you drive the phases yourself;
the interceptors mint one with [`new_call_id`](#new_call_id) and use it on the
call, result and outcome events and their receipts.

`labels` carries trust facts out of band - the reserved `__origin__`,
`__schema__`, `__attestation__` and `__tools__` keys the MCP detectors read.
Only the integration that knows the server sets them; they land on the event's
trusted `labels` mapping, never in its `args`. Any reserved key in `arguments`
is stripped first, so a caller forwarding model-produced arguments cannot forge
one.

### `enforce_tool_result`

```python
enforce_tool_result(action, result, *, engine=None, enforcement="blocking", principal=None, call_id=None, labels=None) -> Any
```

Checks what a tool returned, as a `phase="result"` event whose `args` is
[`result_payload(result)`](#result_payload): a copy of `result` if it is a dict,
the joined text of an MCP `CallToolResult`, and `{"result": result}` for anything
else.

- **allow** or monitor mode: returns the original `result`.
- **modify**: returns `decision.modified_result`. If that is `None`, the original
  is returned, so a rule cannot replace a result with `None`.
- **block**: raises `Blocked`. The tool has already run and its side effects
  stand. The caller just never sees the payload.

---

## Rules and engines

Guide: [writing rules](../guides/writing-rules.md).

### `Rule`

```python
Rule = Callable[[SensorEvent], Optional[Decision]]
```

A rule is any function that takes an event and returns a `Decision`, or `None` for
"no opinion". Returning `Decision.allow()` also counts as no opinion: the engine
keeps going.

Rules run on call-phase events by default. To make a rule see results instead,
set an attribute on the function:

```python
from interlock import Decision

def withhold_errors(event):
    if "Traceback" in str(event.args.get("result", "")):
        return Decision.block("internal error text withheld")
    return None

withhold_errors.phase = "result"   # now it only sees phase="result" events
```

A rule runs on exactly one phase. To check both, write two rules.

### `PolicyEngine`

```python
PolicyEngine(rules=None)
```

An ordered list of rules.

| Member | Meaning |
|---|---|
| `add_rule(rule) -> PolicyEngine` | Appends a rule and returns the engine, so calls chain. |
| `evaluate(event) -> Decision` | Runs the rules for the event's phase in order and combines their opinions (see below). If none objects, returns `Decision.allow()`. |
| `len(engine)` | Number of rules. Zero means everything is allowed. |

How opinions combine:

- **A block from any rule wins** and ends evaluation, even if an earlier rule
  rewrote the call.
- **Rewrites compose.** Each one is applied to a working copy of the event, and
  every later rule judges the rewritten call (or result). A later rewrite of the
  same argument wins.
- **The result is one decision.** A single rewrite comes back exactly as the rule
  returned it. Several are combined into one `MODIFY` with every change
  (`modified_args` merged, or the last `modified_result`), the reasons joined with
  `"; "`, and the first rewrite's `policy_id` and `attributed_to`.
- **The caller's event is never changed.**

```python
from interlock import Decision, PolicyEngine, SensorEvent

engine = PolicyEngine(rules=[
    lambda e: Decision.modify({"limit": 100}, reason="capped", policy_id="p.cap"),
    lambda e: Decision.modify({"dry_run": True}, reason="dry run", policy_id="p.dry"),
])
d = engine.evaluate(SensorEvent(action="query", args={"limit": 5000}))
assert d.modified_args == {"limit": 100, "dry_run": True}
assert (d.reason, d.policy_id) == ("capped; dry run", "p.cap")
```

`evaluate` does not catch exceptions. If a rule raises, the exception propagates
through the interceptor and the tool does not run. Only `deny_when` converts a
crashing predicate into a clean block. (The [sidecar](sidecar.md) is different:
it turns a raising rule into a block.)

### `deny_tool`

```python
deny_tool(name, reason="tool not permitted", policy_id=None) -> Rule
```

Blocks every call whose `action` equals `name` exactly. Call phase only.

### `deny_when`

```python
deny_when(predicate, reason, policy_id=None) -> Rule
```

Blocks when `predicate(event)` is truthy. If the predicate raises, the call is
blocked with the reason `"rule error, denied fail-closed: <reason> (<error>)"`
instead of the exception escaping.

---

## Decisions

Guide: [concepts](../concepts.md).

### `Verdict`

An `IntEnum`: `ALLOW = 0`, `BLOCK = 1`, `MODIFY = 2`, `ESCALATE = 3`. The
integers are stable and are what the [wire protocol](sidecar.md#wire-protocol)
sends. Every enforcement site handles each member explicitly; a value it
doesn't know is blocked.

### `Decision`

A dataclass describing what to do with one event.

| Field | Type | Meaning |
|---|---|---|
| `verdict` | `Verdict` | Allow, block, or modify. Default `ALLOW`. |
| `reason` | `str` | Human-readable explanation. Ends up in logs, `Blocked` messages, and receipts. Don't put argument values in it. |
| `policy_id` | `str` or `None` | Which policy made the decision. |
| `modified_args` | `dict` or `None` | For a call-side modify: the arguments to merge into the call. |
| `attributed_to` | `str` or `None` | The **name** of the argument that triggered the decision (`"path"`), never its value. |
| `modified_result` | any or `None` | For a result-side modify: the value that replaces the tool's result. |

Build decisions with the class methods:

| Constructor | Use it to |
|---|---|
| `Decision.allow(reason="", policy_id=None)` | State an explicit allow. Rarely needed: returning `None` does the same. |
| `Decision.block(reason, policy_id=None, attributed_to=None)` | Deny the call. |
| `Decision.modify(modified_args, reason="", policy_id=None, attributed_to=None)` | Let the call continue with some arguments replaced. Only the keys you pass change. |
| `Decision.modify_result(result, reason="", policy_id=None, attributed_to=None)` | Replace a tool's result (use in a result-phase rule). |
| `Decision.escalate(reason, policy_id=None, attributed_to=None)` | Hold the call for a human approver ([approvals](../guides/approvals.md)). A block from any other rule still wins. |

### `Blocked`

```python
Blocked(decision, action)
```

The exception raised when a call or result is denied. It has two attributes,
`decision` (the full `Decision`) and `action` (the tool name). Its message is
`blocked action '<action>': <reason>`.

On the call side, the tool never ran. On the result side, it already ran and only
its output was withheld.

### `NotApproved`

A subclass of `Blocked`, raised for an `ESCALATE` that wasn't approved: no
approver installed, the approver declined or raised, or the policy changed while
it was deciding. Catch it on its own to tell "needs a human" from "refused".

---

## Events

Guide: [concepts](../concepts.md).

### `SensorEvent`

A dataclass describing one action as a rule sees it.

| Field | Type | Meaning |
|---|---|---|
| `action` | `str` | The tool, function, or MCP tool name. |
| `args` | `dict` | On a call: the arguments. On a result: [`result_payload(result)`](#result_payload). |
| `principal` | `str` or `None` | Who is acting, from the `principal=` option or the current [`span`](#span). |
| `span_id` | `str` or `None` | The run this event belongs to. |
| `ts` | `float` | Wall-clock time the event was created. |
| `parent_principal` | `str` or `None` | Who delegated the work, if anyone. |
| `phase` | `str` | `"call"` (default) or `"result"`. |

You only construct events yourself when testing a rule directly:

```python
from interlock import SensorEvent, deny_tool

rule = deny_tool("shell_exec")
assert rule(SensorEvent(action="shell_exec", args={"cmd": "ls"})).reason == "tool not permitted"
assert rule(SensorEvent(action="read_file", args={})) is None
```

### `result_payload`

```python
from interlock.event import result_payload

result_payload(result) -> Dict[str, Any]
```

Shapes a tool's return value into the `args` of a result-phase event. Every
result path uses it.

| The tool returned | `args` |
|---|---|
| a dict | a copy of it. If it has an MCP-style `content` list of text items and no `"result"` key, their joined text is added as `"result"`. |
| an MCP `CallToolResult` (anything with a `content` list of items that have `.text`) | `{"result": <text items joined with newlines>}`, plus each top-level field of its structured content (`structured_content` or `structuredContent`, never replacing `"result"`), plus `"is_error"` (from `is_error` or `isError`) when the result reports it |
| anything else | `{"result": <value>}` |

```python
from dataclasses import dataclass
from interlock.event import result_payload

@dataclass
class Text:
    text: str

@dataclass
class CallToolResult:
    content: list
    structuredContent: dict = None
    isError: bool = False

r = CallToolResult([Text("first"), Text("second")], {"temperature": 21})
assert result_payload(r) == {"result": "first\nsecond", "temperature": 21, "is_error": False}
```

The view is only what rules see. A result rewrite still replaces the whole value
the caller gets, so a rule that rewrites an MCP result hands back whatever it put
in `modified_result`.

---

## Run identity

Guide: [concepts](../concepts.md).

These use `contextvars`, so values follow `await` and are separate per thread and
per asyncio task.

### `span`

```python
span(principal=None, parent_principal=None)   # context manager, yields the span id
```

Starts a new span id for the block and, if given, sets the principal and parent
principal. Everything is restored when the block exits, including on error. Spans
nest.

```python
from interlock import current_principal, span

with span(principal="acme/agent42") as span_id:
    assert current_principal() == "acme/agent42"
assert current_principal() is None
```

### `new_span`

```python
new_span(principal=None, parent_principal=None) -> str
```

Like `span`, but sets the values for the rest of the current context and never
restores them. Returns the new span id.

### `current_span`, `current_principal`, `current_parent_principal`

```python
current_span() -> Optional[str]
current_principal() -> Optional[str]
current_parent_principal() -> Optional[str]
```

Read the current values. `None` when unset.

### `set_principal`

```python
set_principal(principal, parent_principal=None) -> None
```

Sets the principal for the rest of the current context. The parent principal
changes only if you pass one, so `set_principal("x")` keeps an inherited
delegation link. Use `span` when you want the old values restored.

### `new_call_id`

```python
new_call_id() -> str
```

Mints a fresh id for one guarded call. The interceptors use it to tie a call's
call-, result- and outcome-phase events and its receipts together. Pass the same
value to [`enforce_tool_call`](#enforce_tool_call) and
[`enforce_tool_result`](#enforce_tool_result) when you drive the phases yourself.

---

## Scopes (`interlock.policy`)

Guide: [scopes](../guides/scopes.md).

```python
from interlock.policy import Binding, ScopedEngine, ScopeRegistry, ScopeTree, Template
from interlock.policy.scopes import DelegationOverGrant, DelegationDepthExceeded, UnknownTemplate
```

A *scope* is a tuple path such as `("root", "acme", "agent42")`.
`interlock.policy` also re-exports `PolicyEngine`, `Rule`, `deny_tool`, and
`deny_when`.

### `Template`

```python
Template(template_id, factory, union_params=frozenset())
```

A frozen dataclass: a named rule factory. `factory(**params)` must return a
`Rule`. Parameters named in `union_params` accumulate down the tree. All others
are overridden by deeper bindings.

### `Binding`

```python
Binding(template_id, params={}, enabled=True, delegated_from=None)
```

A frozen dataclass attaching a template, with parameters, to one scope node.

| Field | Meaning |
|---|---|
| `template_id` | Which template this configures. |
| `params` | Keyword arguments for the factory. |
| `enabled` | `False` removes an inherited binding for this template at and below this node, until a deeper node binds it again. |
| `delegated_from` | A scope tuple. When set, this binding's resolved params must be a subset of what that scope resolves to, or resolving raises `DelegationOverGrant`. |

### `ScopeTree` and `PyScopeTree`

```python
ScopeTree()
PyScopeTree()
```

The store of bindings. `ScopeTree` is the native Rust tree when the optional
[`rust/`](https://github.com/SourceShift/InterLock/blob/main/rust/README.md) module is installed, and `PyScopeTree` otherwise.
`PyScopeTree` is always available.

| Method | Meaning |
|---|---|
| `bind(path, bindings)` | **Replaces** all bindings at `path` and bumps its version, which invalidates cached engines below it. |
| `bindings_at(path)` | The bindings stored at exactly `path`. |
| `path_versions(leaf)` | The version of every node from root to `leaf`. Used as the cache key. |
| `resolve(leaf, union_lookup)` | Low-level merge. Use `ScopeRegistry.resolve` instead. |

### `SCOPE_BACKEND`

`"rust"` or `"python"`, depending on which tree `ScopeTree` is.

Union parameters always come back as a `set`, whichever tree resolved them. A
non-union parameter keeps whatever type you passed.

### `ScopeRegistry`

```python
ScopeRegistry(tree, templates, *, maxsize=10000, max_delegation_depth=16)
```

Resolves scopes and caches one compiled `PolicyEngine` per scope.

| Parameter | Meaning |
|---|---|
| `tree` | A `ScopeTree` or `PyScopeTree`. |
| `templates` | `{template_id: Template}`. Copied when the registry is built, so adding to your dict later has no effect: use `add_template`. A binding that names an id not registered here raises `UnknownTemplate` when its scope is resolved. |
| `maxsize` | Maximum cached engines (least recently used are dropped). |
| `max_delegation_depth` | How deep `delegated_from` checks may recurse before raising `DelegationDepthExceeded`. |

| Member | Meaning |
|---|---|
| `resolve(leaf) -> dict` | The merged `{template_id: params}` for a scope, after checking every delegated binding on the path. |
| `compile(leaf) -> PolicyEngine` | Builds a fresh engine for a scope, bypassing the cache. |
| `for_scope(leaf) -> PolicyEngine` | The cached engine, rebuilt only if a node on the path changed. |
| `add_template(template)` | Registers a template (or replaces one with the same id) after the registry was built, and drops every cached engine. |
| `invalidate(leaf)` | Drops one cached engine. Rarely needed. |
| `hits`, `misses` | Cache counters. |

### `ScopedEngine`

```python
ScopedEngine(registry, scope_of=None, *, default_scope=(), allow_unscoped=False)
```

An engine that picks a scope for each event and delegates to that scope's
compiled engine. Install it with `interlock.install(engine=ScopedEngine(registry))`.

| Parameter | Meaning |
|---|---|
| `registry` | The `ScopeRegistry` to resolve against. |
| `scope_of` | `event -> scope tuple`. Defaults to [`principal_scope`](#principal_scope). |
| `default_scope` | Used when `scope_of` returns an empty tuple (typically an event with no principal). |
| `allow_unscoped` | `False` (default): an event with no scope is blocked. `True`: it is allowed without running any rule. |

**An event with no scope is blocked by default.** With no principal and no
`default_scope`, `evaluate` returns a block with the reason `no scope for this
event (no principal and no default_scope); denied fail-closed` and the policy id
`scoped_engine.unscoped` (`UNSCOPED_POLICY_ID` in `interlock.policy.scopes`). Set
`default_scope` to a baseline node to give such callers a floor policy instead, or
pass `allow_unscoped=True` if they really should run unchecked.

### `principal_scope`

```python
principal_scope(event) -> Tuple[str, ...]
```

Splits `event.principal` on `/`, dropping empty parts: `"root/acme/agent42"`
becomes `("root", "acme", "agent42")`. No principal gives `()`.

### `delegation_chain`

```python
delegation_chain(event) -> Tuple[Tuple[str, ...], ...]
```

The scopes an event acts through, delegator first: `(parent_scope, own_scope)`
when `parent_principal` is set, otherwise just `(own_scope,)`. Empty scopes are
dropped.

### Delegation errors

Import these from `interlock.policy.scopes`. They are not re-exported from
`interlock.policy`.

| Exception | Raised when |
|---|---|
| `DelegationError` | Base class for the two below. |
| `DelegationOverGrant` | A binding with `delegated_from` grants more than the delegator resolves to. |
| `DelegationDepthExceeded` | Delegation checks recursed past `max_delegation_depth` (a loop or a very deep chain). |

Both are raised from `resolve`, `compile`, and `for_scope`, so a bad grant never
reaches the cache. So is `UnknownTemplate` (a `LookupError`), for a binding whose
template id isn't registered: a binding that silently vanished would be a rule
that never exists. `ScopedEngine.evaluate` catches all three and returns a BLOCK
with policy id `scoped_engine.resolution`, so a call never sees them as raw
exceptions.

---

## Receipts (`interlock.sink` and `interlock.receipt`)

Guide: [audit log](../guides/audit-log.md).

```python
from interlock.sink import FileSink, InMemorySink, OtlpSink, verify_file
from interlock.receipt import set_sink
```

### `FileSink`

```python
FileSink(path, *, signer=hmac_sha256, key=None, shared=False)
```

Appends one JSON line per receipt to `path`, chained and signed. `key` is the
signing key in bytes. Without one, a random per-process key is used and only this
process can verify the file.

`shared=False` (the default) is one writer per file: each write appends using an
append-mode open, which keeps concurrent writers inside one process from
overwriting each other's bytes. `shared=True` is for several processes appending
to one log (each coding-agent hook call is its own process): every write takes an
exclusive file lock and re-reads the chain head from the file, so the writers
extend one chain instead of forking it. It needs `fcntl` (POSIX).

**A reopened file continues its chain.** When `path` already holds receipts (after
a restart, say), the new `FileSink` reads the last one and links the next receipt
to it, so one file can span restarts. Keep the same `key`, or the older receipts
won't verify under the new one. If the file's last line isn't a readable receipt
(a crash mid-write, a foreign file), the constructor raises `ValueError` instead of
appending to damage nobody saw. Move the file aside to start a new log.

Two `FileSink`s in different processes writing the same file **at the same
time** without `shared=True` fork the chain, and verification reports the fork as
`receipt N: chain break (...)`. Either use `shared=True` or keep one writer per
file at a time.

### `InMemorySink`

```python
InMemorySink(*, signer=hmac_sha256, key=None)
```

Keeps receipts in the `receipts` list attribute. Useful in tests.

### `OtlpSink`

```python
OtlpSink(endpoint, headers=None, service_name="interlock", *, signer=hmac_sha256, key=None, timeout=5.0, retry_interval=0.5, max_buffer=4096)
```

A `ChainedSink` that also exports each receipt over OTLP/HTTP. Local behaviour is
exactly `InMemorySink`: every receipt is chained and signed into `receipts`, so
`verify()` and the tamper evidence are unchanged. On top of that, each receipt is
mapped to an OTLP/HTTP JSON log record and handed to a background daemon worker
that POSTs it.

| Parameter | Meaning |
|---|---|
| `endpoint` | The full logs URL, e.g. `http://collector:4318/v1/logs`. POSTed as given — no path is appended. |
| `headers` | Extra HTTP headers, e.g. an auth token. |
| `service_name` | Becomes the `service.name` resource attribute. |
| `signer`, `key` | As for `FileSink`. |
| `timeout` | Per-POST timeout in seconds. |
| `retry_interval` | How long the worker waits before retrying a record the collector did not accept. |
| `max_buffer` | Queue bound. A record enqueued while the queue is full is dropped and counted; a record already retained for retry is never dropped. |

Three guarantees hold by construction, because a receipt is written on the
guarded call's critical path:

- **It never blocks the call.** `write` only appends to an in-memory buffer and
  wakes the worker; the POST happens off-thread with an explicit timeout.
- **It never raises into the call.** Every failure in mapping, buffering,
  serializing and the POST is swallowed and counted in `stats()`.
- **It never carries argument values.** The record is built from an allow-list of
  receipt fields (`action`, `principal`, `policy_id`, `reason`, `span_id`).
  Arguments exist only as the receipt's `args_digest`, which is not exported.

A collector outage changes no verdict: a record that fails to POST stays at the
front of the buffer and is retried until accepted, so the buffer drains in order
once the collector returns. `close(timeout=2.0)` stops the worker; it is
idempotent, a POST already in flight is not interrupted, and records still
buffered when the worker exits are left undelivered and reported by `stats()`.
`stats()` returns `sent`, `failed`, `pending`, `dropped` and `build_failures`.

### `ChainedSink`

```python
ChainedSink(*, signer=hmac_sha256, key=None)
```

The base class. Subclass it and implement `_append(receipt)` and `_read_back()`
to store receipts somewhere else. Any object with a `write(receipt)` method can be
installed as a sink, but only `ChainedSink` subclasses chain and sign.

| Method | Meaning |
|---|---|
| `write(receipt)` | Links the receipt to the previous one, signs it, and appends it. Thread-safe within one instance. |
| `head` | Property: the `mac` of the latest receipt (`GENESIS` before the first). Record it somewhere the log's writer can't reach. |
| `verify(key=None, *, head=None, verifier=None) -> Optional[str]` | Re-checks the whole chain. Returns `None` if intact, or a message naming the first bad index. `key` verifies with a different key. `head` also checks that the chain ends where you recorded it. `verifier` checks signatures without the signing key (see below). |

Deleting receipts from the **end** of a log leaves a valid, shorter chain that the
linkage alone can't catch. Comparing against a recorded `head` does:

```python
import interlock, os, tempfile
from interlock import enforce_tool_call
from interlock.receipt import set_sink
from interlock.sink import FileSink, verify_file

key = b"k" * 32
path = os.path.join(tempfile.mkdtemp(), "audit.jsonl")
sink = FileSink(path, key=key)
interlock.install(rules=[], sink=sink)
for _ in range(3):
    enforce_tool_call("read_rows", {"table": "orders"})
head = sink.head
set_sink(None)

with open(path) as fh:
    lines = fh.readlines()
with open(path, "w") as fh:
    fh.writelines(lines[:2])          # someone deletes the last receipt

print(verify_file(path, key=key))             # -> None: the linkage looks fine
print(verify_file(path, key=key, head=head))
# -> chain ends at receipt 1 but the expected head is ...: receipts were cut from the end, or this is not the log that head came from
```

### `Receipt`

A dataclass. One per enforced decision.

| Field | Meaning |
|---|---|
| `ts` | Time the receipt was written. |
| `action` | Tool name. |
| `verdict` | `"ALLOW"`, `"BLOCK"`, or `"MODIFY"` (the name, as a string). |
| `reason`, `policy_id`, `attributed_to` | Copied from the decision. |
| `principal`, `span_id`, `phase` | Copied from the event. |
| `args_digest` | SHA-256 over the event's arguments, as the caller passed them. The values are never stored. |
| `prev` | The previous receipt's `mac`, or 64 zeros (`GENESIS`) for the first. |
| `mac` | The signer's tag over every other field, hex-encoded. |
| `observed` | `True` when monitor mode recorded a decision without enforcing it. The call went through even though `verdict` may say `BLOCK`. |

`to_json()` and `Receipt.from_json(line)` convert to and from the canonical
one-line form. `fields(include_mac=True)` returns that canonical shape as a dict.
`observed` appears in it (and in the signed bytes) only when it is `True`, so
receipts written before the field existed still verify.

### Functions and the signer seam

| Name | Meaning |
|---|---|
| `set_sink(sink)` | Installs the process-wide sink. `None` turns receipts off. |
| `get_sink()` | The installed sink, or `None`. |
| `Signer` | The type `Callable[[bytes, bytes], bytes]`: `(key, message) -> tag`. |
| `Verifier` | The type `Callable[[bytes, bytes], bool]`: `(message, tag) -> valid`. |
| `hmac_sha256(key, message)` | The default signer. |
| `process_secret()` | This process's random default key. |
| `signing_payload(receipt) -> bytes` | The exact bytes a receipt's `mac` covers (every field but `mac`). |
| `verify_chain(receipts, signer, key, *, verifier=None, head=None)` | Checks a list of receipts directly. Same messages as `verify()`. |
| `verify_file(path, *, key=None, signer=hmac_sha256, verifier=None, head=None)` (in `interlock.sink`) | Checks a log on disk without opening it for writing: the auditor's entry point. Needs `key` or `verifier`, or raises `ValueError`. |
| `digest_args(args)` | The digest used for `args_digest`. |

Without a `verifier`, verification recomputes each tag with `signer` and `key`, so
the verifier needs the signing key. That's the right shape for the default HMAC.
For a public-key scheme, sign with the private key and hand auditors a `verifier`
that checks with the public key. Here it is with Ed25519 from the `cryptography`
package (not an interlock dependency):

```python
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from interlock.sink import FileSink, verify_file

def ed25519_sign(private_bytes, message):            # the writer's Signer
    return Ed25519PrivateKey.from_private_bytes(private_bytes).sign(message)

sink = FileSink("audit.jsonl", signer=ed25519_sign, key=private_bytes)

public_key = Ed25519PublicKey.from_public_bytes(public_bytes)

def ed25519_verify(message, signature):              # the auditor's Verifier
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False

verify_file("audit.jsonl", verifier=ed25519_verify)   # -> None when intact
```

---

## Sandbox (`interlock.brace`)

Guide: [sandbox](../guides/sandbox.md).

```python
from interlock.brace import (
    Sandbox, SandboxProfile, compile_profile, available_backends,
    IsolationUnavailable, LimitUnsupported, KNOWN_TOKENS,
)
```

`Sandbox`, `SandboxProfile`, and `compile_profile` are also importable from
`interlock`.

### `Sandbox`

```python
Sandbox(profile=None, *, backend=None, engine=None, enforcement="blocking",
        principal=None, require=())
```

| Parameter | Meaning |
|---|---|
| `profile` | What the process may reach. Defaults to `SandboxProfile.locked()`: nothing. |
| `backend` | Pin `"bubblewrap"`, `"sandbox-exec"`, or `"soft"`. Default: the strongest one available. |
| `engine`, `enforcement`, `principal` | As for [`enforce_tool_call`](#guarding-calls), applied to the launch check. |
| `require` | `enforced` tokens that must hold, e.g. `("net", "fs-rw")`. `run()` refuses, before starting anything, when the backend can't deliver one. A bare string counts as one token. |

The constructor raises:

- `ValueError("unknown backend: ...")` for a backend name that doesn't exist
  (including `"nftables"`), and `RuntimeError("backend not available on this
  host: ...")` for one this machine can't run;
- `ValueError` for a `require` token that isn't in `KNOWN_TOKENS`, so a typo
  fails here instead of refusing every run;
- [`LimitUnsupported`](#limitunsupported) when the profile asks for a resource
  limit this host can't enforce.

`backend_name` tells you which backend was picked.

| Method | Meaning |
|---|---|
| `run(argv, *, capture_output=True, timeout=None) -> SandboxResult` | Checks the launch with the policy engine, then checks `require` against what the backend would enforce, then runs the command. Creates one private `0700` scratch directory for this run (granted and set as `TMPDIR`/`TMP`/`TEMP`), removes it on every exit path, and on timeout kills the POSIX process group before raising `subprocess.TimeoutExpired`. Raises `Blocked` or [`IsolationUnavailable`](#isolationunavailable) without starting a process and without creating the scratch directory. |
| `plan(argv) -> WrapPlan` | Returns the wrapped command without running it, and **without** the policy check or the `require` check. No scratch directory is created and none appears in the plan: `plan()` describes the profile you passed, not the per-run profile `run()` executes. A `WrapPlan` has `exec_argv`, `popen_kwargs`, `enforced`, `cleanup` (call it if it is not `None`), and `creates_session` (the wrapper calls `setsid()` itself, so the spawner must not also pass `start_new_session`). |

```python
import sys
from interlock.brace import IsolationUnavailable, Sandbox

try:
    Sandbox(backend="soft", require=("net",)).run([sys.executable, "-c", "print('hi')"])
except IsolationUnavailable as e:
    print(e)          # nothing ran
# -> refusing to run: the soft backend cannot enforce ['net'] for this profile (it enforces ['env'])
```

The launch check is an ordinary call event with `action="process_spawn"` and these
`args`: `path` (`argv[0]`), `argv`, `allow_network`, `allowed_hosts`, and
`write_paths`. A rule can block it (`run` raises `Blocked`) or return a modify
with a new `argv` list, which is what runs instead. An empty `argv` raises
`ValueError`. A `timeout` that expires kills the sandbox's process group on
POSIX and raises `subprocess.TimeoutExpired`; a descendant that calls `setsid()`
escapes that group (confinement and rlimits still apply).

### `SandboxProfile`

A frozen dataclass.

| Field | Default | Meaning |
|---|---|---|
| `read_paths` | `()` | Host paths mounted read-only. |
| `write_paths` | `()` | Host paths mounted read-write. `run()` adds one private per-run scratch directory to this set for the executed command; `plan()` and the launch event see the profile as given. |
| `allow_network` | `False` | Whether the process gets any network at all. |
| `allowed_hosts` | `()` | Hosts the grant is meant for. The OS backends can't restrict to these, so they open the network fully and don't report `net`. |
| `env` | `{}` | The child's complete environment. Nothing is inherited from the parent. `run()` overwrites `TMPDIR`, `TMP`, and `TEMP` with the run's scratch directory. |
| `cpu_seconds` | `None` | CPU time limit. Applied on every backend. |
| `memory_mb` | `None` | Address-space limit. Applied on every backend on Linux. **Refused on macOS**, where the kernel won't accept a useful address-space limit (`LimitUnsupported`). |
| `unshare_pid` | `True` | Separate PID namespace where the backend supports it. |
| `workdir` | `None` | Working directory for the command. Honoured by every backend. |

On Windows, any resource limit raises `LimitUnsupported`: there are no POSIX
limits to apply. A requested limit is never dropped silently.

`SandboxProfile.locked()` returns the fully closed default.
`profile.with_paths(read=(), write=())` returns a copy with extra paths added.

### `compile_profile`

```python
compile_profile(resolved, *, workdir=None, base_env=None) -> SandboxProfile
```

Builds a profile from the `{template_id: params}` dict that
`ScopeRegistry.resolve` returns. It reads three bindings and ignores the rest:

| Binding | Params | Effect |
|---|---|---|
| `egress_allowlist` | `allowed_hosts` | A non-empty list turns network on. |
| `sandbox_fs` | `read_paths`, `write_paths` | Filesystem grants. |
| `sandbox_limits` | `cpu_seconds`, `memory_mb` | Resource limits. |

`base_env` becomes the child's environment, and `workdir` its working directory.
`resolved=None` or `{}` gives a locked profile.

### `SandboxResult`

| Field | Meaning |
|---|---|
| `backend` | The backend that ran the command. |
| `argv` | The command as executed (after any policy rewrite), without the wrapper. |
| `returncode` | The exit status. |
| `stdout`, `stderr` | Captured output, or `""` when not captured. |
| `enforced` | The guarantees that actually held, as tokens: `pid`, `net`, `fs-ro`, `fs-rw`, `rlimit`, `env`. Only `soft` reports `rlimit`: bubblewrap and sandbox-exec apply the same limits but don't claim the token, because no escape test pins it for them yet. |
| `ok` | Property: `returncode == 0`. |

### `available_backends` and `select_backend`

```python
available_backends() -> List[str]
select_backend(prefer=None) -> Backend
```

`available_backends()` lists what this machine can run, strongest first. `soft`
is always last and always present. `select_backend` returns a backend instance,
raising the same errors as `Sandbox(backend=...)`. You rarely need it directly.

### `IsolationUnavailable`

A `RuntimeError` raised by `Sandbox.run()` when a `require`d token isn't among the
guarantees the backend would enforce. Nothing was started. Attributes: `backend`
(the backend's name), `missing` (the required tokens it lacks), and `enforced`
(what it does enforce).

### `LimitUnsupported`

A `RuntimeError` raised when a profile asks for a resource limit the host can't
enforce: `memory_mb` on macOS, or any limit on Windows. It's raised when the
`Sandbox` is built and again by `run()` (the profile may have changed). The
message names the limit and the platform.

The check itself is `interlock.brace.limits.check_limits(profile, platform=None)`.
`interlock.brace.limits.rlimit_preexec(cpu_seconds, memory_mb)` builds the
`preexec_fn` every backend uses to apply the limits in the child.

### `KNOWN_TOKENS`

The frozenset of every token a backend can report:
`{"env", "rlimit", "fs-ro", "fs-rw", "pid", "net"}`. `require` is checked against
it.

---

## Testing helpers (`interlock.testing`)

Guide: [Node.js client](https://github.com/SourceShift/InterLock/blob/main/js/README.md).

The package's top level exports nothing. Its modules exist so that clients in
other languages, and your own test suites, can check behaviour against a real
daemon. Most users never import them.

| Import | What it gives you |
|---|---|
| `interlock.testing.harness.serve(engine, path, *, sink=None, timeout=5.0)` | Context manager that runs a sidecar daemon on a background thread for the duration of a `with` block. On exit it closes every open client connection, restores the previous receipt sink, and removes the socket. Put `path` in a private directory, e.g. under `tempfile.mkdtemp()`. |
| `interlock.testing.harness.send_raw(path, line, *, timeout=5.0)` | Sends one raw frame and returns the decoded reply. Use it to test malformed input. |
| `interlock.testing.fixtures.CONFORMANCE_ENGINE` | The fixed 12-rule engine the conformance corpus is written against. `CONFORMANCE_SPEC` is its `module:attr` string for `interlock-sidecar --rules`. |
| `interlock.testing.conformance` | `cases()` (13 events and the decision each must produce), `negatives()` (9 malformed frames and the error each must produce), `build()`, `write_corpus(path)`, `load_corpus(path)`, and `CORPUS_VERSION`. The frozen copy lives at `tests/conformance/events.json`. |

```python
import os, tempfile
from interlock import PolicyEngine, SensorEvent, deny_tool
from interlock.sidecar import RemoteEngine
from interlock.testing.harness import serve

path = os.path.join(tempfile.mkdtemp(), "guard.sock")
with serve(PolicyEngine(rules=[deny_tool("shell_exec")]), path):
    with RemoteEngine(path, timeout=5) as remote:
        decision = remote.evaluate(SensorEvent(action="shell_exec", args={}))
        assert decision.verdict.name == "BLOCK"
```

---

## Added for operations and coding agents

### Call identity and policy epoch

| Name | What it is |
|---|---|
| `SensorEvent.call_id` | One guarded call's id, shared by its call, result and outcome events and receipts. The interceptors mint it with `interlock.new_call_id()`. |
| `enforce_tool_call(..., call_id=None)`, `enforce_tool_result(..., call_id=None)` | Pass the same `call_id` to link a call and its result when you drive them yourself. |
| `PolicyEngine.epoch` | 16 hex characters identifying the installed rule set in this process. Changes when a rule is added. |
| `PolicyEngine.policy_ids` | Each installed rule's `policy_id` or qualified name, in order. |
| `interlock.policy.engine.epoch_of(engine, event=None)` | The epoch an engine decides `event` under (per scope for a `ScopedEngine`), or `None`. |

### Approvals (`interlock.approval`)

Guide: [approvals](../guides/approvals.md).

| Name | What it is |
|---|---|
| `set_approver(fn)` / `get_approver()` | Install or read the process approver. `fn(request) -> True / Approval / False / None`. |
| `approve_once()`, `approve_for_session()`, `approve_for(seconds)` | What an approver returns to approve. |
| `ApprovalRequest` | Frozen: `request_id`, `action`, `phase`, `args_digest`, `reason` (one line, at most 512 bytes), `principal`, `span_id`, `call_id`, `policy_id`, `attributed_to`, `policy_epoch`, `created`, `event` (the full call, for display), and `binding`, the tuple an approval is bound to. |
| `grants()` | The `GrantStore` of session and TTL grants: `active()`, `revoke(action=, principal=, session=)`, `clear()`. |
| `tty_approver(show_args=True)` | Asks at `/dev/tty`; declines without a terminal. |
| `bound_reason(text)` | The one-line, 512-byte form a reason is shown and bound in. |

### Protection posture (`interlock.posture`)

Guide: [production checklist](../guides/production.md).

| Name | What it is |
|---|---|
| `attest(*, engine=None, sink=None, probe_sidecar=False) -> Posture` | Read-only report on the protection in force. |
| `require(min_level="enforced", **kwargs) -> Posture` | Raises `ProtectionError` below `min_level` (`"enforced"` or `"degraded"`). |
| `Posture` | `.level` (`enforced`, `degraded`, `unprotected`), `.checks`, `.check(id)`, `.to_dict()`, `.to_json()`, `.render()`. |
| `Check` | `id`, `status` (`ok`, `info`, `warn`, `fail`), `summary`, `fix`. |
| `WEAKENING_SETTINGS` | Each "settings that weaken protection" row of the security model, mapped to its check id. |

### Receipt reports (`interlock.report`)

| Name | What it is |
|---|---|
| `read_receipts(path) -> (receipts, bad_line_numbers)` | Parse a log. |
| `verification(receipts, *, key=None, verifier=None, head=None)` | `{"status": "verified" / "broken" / "unverified", "detail": ...}`. |
| `summarize(receipts, *, since_seconds=None, now=None, top=10) -> dict` | The report `interlock report --json` prints: verdict counts, block rate, top rules, what monitor mode would have done, escalations, failed outcomes, dropped receipts, latency percentiles. |
| `parse_since("24h")` | `30m` / `24h` / `7d` / `1w` to seconds; `0` or `all` to `None`. |

New receipt fields (`call_id`, `policy_epoch`, `policy_verdict`, `approval`,
`outcome`, `enforcer`, `elapsed_us`) are described in the
[audit log guide](../guides/audit-log.md#what-a-receipt-records).
`interlock.receipt.dropped_receipts()` counts writes that failed and aren't yet
reported. `FileSink(path, *, signer=..., key=None, shared=False)`: `shared=True`
locks the file per write so several processes keep one chain.

### Shell commands (`interlock.shell`)

Guide: [parsed shell commands](../guides/detectors.md#parsed-shell-commands).

| Name | What it is |
|---|---|
| `parse(cmd) -> ParsedCommand` | Never raises. `.invocations` (each an `Invocation`: `binary`, `name` (lowercased), `args`, `via`, `redirects`, `pipeline`, `stage`), `.binaries`, `.partial`. |
| `analyze(cmd_or_parsed) -> tuple[Intent, ...]` | Semantic intents: `kind`, `binary`, `targets`, `detail`, `critical`, and `matches(selector)`. |
| `intents_in(strings)`, `first_match(intents, selectors)` | Helpers for rules. |
| `is_critical_path(path)` | Whether a recursive delete of `path` is host-fatal (`/`, `~`, `$HOME`, system directories). |
| `MAX_DEPTH`, `MAX_INPUT`, `MAX_INVOCATIONS` | The parser's bounds. |

### Declarative policies (`interlock.policy.declarative`, `interlock.policy.trust`)

Guide: [declarative policies](../guides/policies.md).

| Name | What it is |
|---|---|
| `load_policy(doc, *, source="<policy>", overlays=(), base_dir=None)` | Compile a document (and already-trusted overlay documents) into a `DeclarativeEngine`. |
| `load_policy_file(path, *, overlays=(), trust=None, watch=None)` | Load a JSON/YAML file. Overlays apply only if `trust` approves their content; `watch` hot-reloads. |
| `DeclarativeEngine` | A `PolicyEngine` with `.quarantined`, `.locked`, `.overlays`, `.documents`, `.reload()`, `.last_error`, and a content-hash `.epoch`. |
| `check_policy_file(path, *, overlays=(), trust=None) -> dict` | What `interlock policy check` prints. |
| `register_tool_schema(action, arg_names)` | Declare an action's arguments so misspelled `arg` conditions fail at load. |
| `parse_policy_text(text, *, fmt="json")`, `read_policy_file(path)`, `PolicyError` | Lower-level loading. |
| `TrustStore(path=None)` | `status(path)`, `add(path)`, `remove(path)`, `entries()`; default `~/.interlock/trusted.json`. |
| `find_overlay(start)` | The nearest `.interlock/policy.{json,yaml,yml}` up to the git root. |
| `interlock.policy.packs.builtin_pack("coding-agent")` | The built-in pack's document. |

### Credentials (`interlock.credentials`)

Guide: [credentials](../guides/credentials.md).

| Name | What it is |
|---|---|
| `SecretStore().add(id, *, actions, value=/env=/file=/getter=, hosts=(), label="", tags=())` | Register a secret with exactly one source. Chainable. |
| `SecretStore.catalog()` | Ids, labels, tags, actions and hosts, never values. |
| `install_store(store)` / `get_store()` | The process store. Without one, placeholders are left alone. |
| `placeholder(id)` | `"{{secret:<id>}}"`. |
| `substitute_call`, `scrub`, `used_ids` | The boundary steps the interceptors run. |

### Coding-agent adapters (`interlock.adapters`)

Guide: [coding agents](../guides/coding-agents.md).

| Name | What it is |
|---|---|
| `get_adapter("claude-code" / "codex" / "cursor")` | An `Adapter`: `parse(payload)`, `render(call, outcome)`, `install(command, settings=None)`, `uninstall(settings=None)`, `installed_command()`, `settings_path()`. |
| `run_hook(adapter, payload, engine, *, enforcement="blocking") -> (stdout, stderr, exit_code)` | Decide one hook invocation. |
| `interlock.adapters.config.load_engine(...)` / `ensure_home()` | How the hook builds its engine, and `~/.interlock` setup. |

### Sidecar client options

`RemoteEngine(path, *, timeout=5.0, unreachable="deny", fallback=None,
fallback_key=None, fallback_max_age=604800)`: `unreachable` is `"deny"`,
`"degraded"` (needs `fallback_key`) or `"allow"`; `.fallbacks` counts calls
decided without the daemon. `interlock.sidecar.fallback` holds
`write_fallback`, `read_fallback`, `validate_offline` and `fallback_path`
([sidecar reference](sidecar.md#when-the-daemon-is-down)).

### MCP inventory (`interlock.mcp_inventory`)

| Name | What it is |
|---|---|
| `scan(cwd=None) -> (servers, unreadable)` | Every MCP server in known client configs, as `McpServer` (`name`, `client`, `config`, `scope`, `transport`, `command`, `args`, `url`, `env_keys`, `project`, `risks`). |
| `where(servers, name)` | The entries defining one server. |
| `starter_policy(servers)` | A policy blocking `mcp__*` tools from servers not in the list. |

---

## Databases, reviews and operations

### SQL (`interlock.sql`)

Guide: [databases](../guides/databases.md).

| Name | What it is |
|---|---|
| `analyze_sql(text, dialect="generic") -> SqlAnalysis` | Never raises. `operation` (most severe effect), `effects`, `relations` (`Relation(name, access)`), `tables`, flags `unbounded`, `opaque`, `external`, `multi`, `partial`, and `statements` (each a `Statement` with the same fields). `generic` unions the PostgreSQL, MySQL and SQL Server readings |
| `SqlAnalysis.matches(selector)` | Operations, groups (`ddl`, `dml`, `write`, `control`), flags, and `read:`/`write:`/`table:<glob>` |
| `OPERATIONS`, `SEVERITY`, `GROUPS`, `FLAGS`, `DIALECTS` | The vocabularies |

### Masking (`interlock.masking`)

| Name | What it is |
|---|---|
| `Masker(rules=(MaskRule(),), threshold=0.5, allow_list=(), hash_key=None)` | `.mask(value) -> (masked, counts)`, `.mask_text(text)`, `.find(text, entities=None) -> [(entity, start, end)]` |
| `MaskRule(entities=(), columns=(), strategy="redact", keep_last=4, mask_char="*", name="")` | An entity rule, or a column/dotted-path rule. Strategies: `redact`, `mask`, `partial`, `hash` (keyed HMAC) |
| `ENTITIES`, `NOISY`, `STRATEGIES`, `summary(counts)` | The catalog, its noisy entries, and a names-and-counts summary |
| `luhn`, `iban`, `us_ssn`, `aba_routing`, `br_cpf`, `br_cnpj`, `verhoeff`, `de_tax_id`, `jwt`, `ip_address` | The validators |

`Decision.masked` (entity → count) carries what a masking rewrite masked into
the receipt's `masked` field.

### Review queue (`interlock.reviews`)

Guide: [review queue](../guides/reviews.md).

| Name | What it is |
|---|---|
| `ReviewQueue(path=None, *, pending_ttl=3600, approval_ttl=900, min_approvals=1, allow_self_approval=True)` | `lookup_or_file(binding, request)`, `claim(id)`, `approve(id, approver=None)`, `reject(id, reason="", approver=None)`, `revoke(id)`, `get(id)`, `list(status=None, limit=50)`, `wait(id, timeout)` |
| `Review` | A frozen record with `.next` (`wait`, `retry_identical_call`, `stop`) and `.to_dict()` |
| `queue_approver(queue=None, *, wait=0.0, poll=1.0, bind_epoch=True)` | An approver for `set_approver` / `install(approver=...)` |
| `binding_hash(request, *, bind_epoch=True)` | What a review approves |
| `interlock.approval.Declined(reason="", pending=False)` | What an approver returns to decline with a message |
| `interlock.mcp_server.StdioServer`, `Tool` | The dependency-free MCP stdio server `interlock reviews mcp` uses |

### Metrics and the admin endpoint

| Name | What it is |
|---|---|
| `interlock.metrics.snapshot()` | Decisions by verdict, top policies, escalations, masked entities, dropped receipts, latency |
| `interlock.metrics.render_prometheus()` | The same as Prometheus text |
| `interlock.metrics.reset()` | Zero the counters |
| `interlock.sidecar.admin.start(address, config)` | The loopback `/healthz /stats /metrics /config` server behind `interlock-sidecar --admin` |


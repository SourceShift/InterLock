# Give each tenant or agent its own rules

Say you run agents for many customers. Every customer gets the same few kinds of
rule (an egress allowlist, a row limit, a tool ban), but with different
settings, and some agents inside a customer need tighter settings still. Writing
a rule list per agent doesn't scale past a handful, and one shared list can't
tell customers apart.

Scopes solve this by splitting rules into code and data. You write each kind of
rule once, as a **template**. You attach settings to points in a tree, as
**bindings**. Each agent's rules are worked out from its path through that tree.

You'll need: interlock installed and the basics of rules (see
[Writing rules](writing-rules.md)).

## Templates and bindings

A **template** is code: a function that takes settings and returns a rule.

A **binding** is data: "use template X with these settings here". It sits at a
**scope**, which is a path such as `("root", "acme", "agent42")`.

```
root        egress: api.internal         row cap: 1000
└── acme    egress: + api.acme.com       row cap: 100
    └── agent42                          row cap: 10
```

## A worked example

```python
import interlock
from interlock import Blocked, Decision, enforce_tool_call, span
from interlock.policy import Binding, ScopedEngine, ScopeRegistry, ScopeTree, Template


def egress_allowlist(allowed_hosts):
    hosts = frozenset(allowed_hosts)

    def rule(event):
        if event.action == "fetch" and event.args.get("host") not in hosts:
            return Decision.block("egress to {} not allowed".format(event.args.get("host")),
                                  "egress_allowlist")
        return None

    return rule


def row_cap(max_rows):
    def rule(event):
        if event.action == "query" and event.args.get("limit", 0) > max_rows:
            return Decision.modify({"limit": max_rows}, reason="row cap", policy_id="row_cap")
        return None

    return rule


TEMPLATES = {
    # allowed_hosts is a union param: lists add up down the tree instead of replacing
    "egress_allowlist": Template("egress_allowlist", egress_allowlist,
                                 union_params=frozenset({"allowed_hosts"})),
    "row_cap": Template("row_cap", row_cap),
}

tree = ScopeTree()
tree.bind(("root",), [Binding("egress_allowlist", {"allowed_hosts": ["api.internal"]}),
                      Binding("row_cap", {"max_rows": 1000})])
tree.bind(("root", "acme"), [Binding("egress_allowlist", {"allowed_hosts": ["api.acme.com"]}),
                             Binding("row_cap", {"max_rows": 100})])
tree.bind(("root", "acme", "agent42"), [Binding("row_cap", {"max_rows": 10})])

registry = ScopeRegistry(tree, TEMPLATES)
registry.resolve(("root", "acme", "agent42"))
# -> {'egress_allowlist': {'allowed_hosts': {'api.internal', 'api.acme.com'}},
#     'row_cap': {'max_rows': 10}}

interlock.install(engine=ScopedEngine(registry, default_scope=("root",)))
```

The resolved `allowed_hosts` is a set on the pure-Python tree and a list on the
native Rust tree. Don't rely on the order.

`ScopedEngine` picks the scope from each call's principal, split on `/`. Run each
agent inside a `span` with its principal:

```python
with span(principal="root/acme/agent42"):
    enforce_tool_call("fetch", {"host": "api.acme.com"})
    # -> allowed
    enforce_tool_call("fetch", {"host": "evil.example"})
    # -> Blocked: egress to evil.example not allowed
    enforce_tool_call("query", {"sql": "select 1", "limit": 500})
    # -> {'sql': 'select 1', 'limit': 10}

with span(principal="root/globex/bot1"):
    enforce_tool_call("fetch", {"host": "api.acme.com"})
    # -> Blocked: egress to api.acme.com not allowed     (acme's host isn't globex's)
    enforce_tool_call("query", {"sql": "select 1", "limit": 5000})
    # -> {'sql': 'select 1', 'limit': 1000}              (root's cap applies)
```

`globex` has no bindings of its own, so it gets exactly what `root` grants.
`@guard` tools and the MCP and LangChain adapters work the same way, because
`ScopedEngine` has the same `evaluate(event)` method as `PolicyEngine`.

### Calls with no principal

A call made outside any `span(principal=...)` has an empty scope, so there's no
node to take rules from. `ScopedEngine` blocks it rather than letting it skip
policy entirely:

```python
interlock.install(engine=ScopedEngine(registry))
enforce_tool_call("fetch", {"host": "api.internal"})
# -> Blocked: no scope for this event (no principal and no default_scope); denied fail-closed
```

The decision's `policy_id` is `scoped_engine.unscoped`, so these show up clearly
in logs and receipts. Two ways to handle them on purpose:

- `default_scope=("root",)` (as in the example above) gives unlabelled calls your
  floor policy. The same call to `api.internal` is then allowed, and one to
  `evil.example` is blocked by the allowlist.
- `allow_unscoped=True` lets them through with no rules at all. Use it only when
  every call that matters is sure to carry a principal.

### An unknown or typo'd scope is denied too

A non-empty scope that resolves to **no templates** used to compile an empty
engine, which allows everything. It is now a refusal: a typo like
`"acme/payemnts/agent"`, an unknown tenant, or a scope whose every template is
tombstoned blocks with policy id `scoped_engine.unbound` and a reason naming the
scope path. A prefix binding still counts, so `"acme/payments/agent"` inherits
whatever `"acme"` grants and is not unbound.

```python
engine = ScopedEngine(registry)
engine.evaluate(SensorEvent(action="fetch", args={"host": "api.internal"},
                            principal="acme/payemnts/agent"))
# -> Blocked: scope ('acme', 'payemnts', 'agent') resolves to no policy templates,
#    denied fail-closed (pass allow_unbound=True to allow it)
```

`allow_unbound=True` restores the old allow-everything behaviour. It is a
separate opt-out from `allow_unscoped`: that one covers an *empty path*, this one
an unresolved non-empty scope. Both default to `False`, and tightening one does
not loosen the other.

## How settings combine

Walking from the root down to the agent, each template's settings are merged
with three rules.

**Override.** A deeper binding replaces a setting. `agent42`'s `max_rows: 10`
beats `acme`'s `100`, which beats `root`'s `1000`.

**Union.** Settings named in the template's `union_params` add up instead.
`acme`'s `api.acme.com` joins `root`'s `api.internal`, so allowlists grow as you
go down.

**Remove.** `Binding(template_id, enabled=False)` switches a template off for
that node and everything below it, until a deeper node binds it again:

```python
tree.bind(("root", "acme", "sandbox"), [Binding("egress_allowlist", enabled=False)])
tree.bind(("root", "acme", "sandbox", "strict"),
          [Binding("egress_allowlist", {"allowed_hosts": ["api.internal"]})])

sorted(registry.resolve(("root", "acme", "sandbox")))
# -> ['row_cap']                                  no egress template at all
registry.resolve(("root", "acme", "sandbox", "strict"))["egress_allowlist"]
# -> {'allowed_hosts': {'api.internal'}}          re-added, without acme's hosts
```

Note what removing the template does. With no `egress_allowlist` rule, the
`sandbox` scope has **no egress restriction at all**, not an empty allowlist.

`tree.bind(path, bindings)` replaces everything bound at that node. To change one
binding, pass the full list again.

## Rules for every scope

A `ScopedEngine` doesn't take extra rules, and `install` says so instead of
failing somewhere deeper:

```python
from interlock import deny_tool

interlock.install(engine=ScopedEngine(registry), rules=[deny_tool("shell_exec")])
# -> TypeError: ScopedEngine takes no extra rules: pass rules=[...] only with a PolicyEngine.
#    For a ScopedEngine, bind them at the root scope through a template instead.
```

Write the always-on rules as templates with no settings and bind them at the
root. A template added after the registry was built must be registered with
`add_template()`, because the registry copies the templates it was given:

```python
tree.bind(("root",), [Binding("no_shell"),
                      Binding("egress_allowlist", {"allowed_hosts": ["api.internal"]}),
                      Binding("row_cap", {"max_rows": 1000})])
TEMPLATES["no_shell"] = Template("no_shell", lambda: deny_tool("shell_exec"))
registry.add_template(TEMPLATES["no_shell"])   # the registry copied TEMPLATES when built
interlock.install(engine=ScopedEngine(registry, default_scope=("root",)))

with span(principal="root/acme/agent42"):
    enforce_tool_call("shell_exec", {"cmd": "ls"})
    # -> Blocked: blocked action 'shell_exec': tool not permitted
```

`add_template()` also replaces an existing template, and drops every cached
compiled scope so the change takes effect on the next call.

### Unknown templates fail loudly

A binding whose template the registry doesn't know raises `UnknownTemplate`
(from `interlock.policy.scopes`) when that scope is resolved, instead of being
skipped. A typo in a template id, or a template added to your dict but never
registered, can't quietly leave a rule out:

```python
tree.bind(("root", "acme", "typo"), [Binding("no_shel")])
registry.resolve(("root", "acme", "typo"))
# -> UnknownTemplate: scope ('root', 'acme', 'typo') binds unregistered template(s) ['no_shel'];
#    the registry copies its templates when built, so register late ones with
#    ScopeRegistry.add_template()
```

`resolve()` raises it. A call that hits the same scope through `ScopedEngine` is
blocked instead: the caller gets `Blocked` with policy id
`scoped_engine.resolution` and a reason naming the unknown template. Resolve each
scope right after you bind it to catch mistakes before a call does.

## Map calls to scopes your way

By default the scope is the principal split on `/` (`principal_scope`). Pass
`scope_of` to derive it some other way, for example so principals don't have to
spell out `root`:

```python
from interlock import SensorEvent

engine = ScopedEngine(
    registry,
    scope_of=lambda e: ("root",) + tuple(p for p in (e.principal or "").split("/") if p),
)
engine.scope_of(SensorEvent(action="x", principal="acme/agent42"))
# -> ('root', 'acme', 'agent42')
```

This deriver never returns an empty scope, so unlabelled calls land on `root`.
You could also key on a tenant id carried in the arguments, or on the span.

## Sub-agents can't grant themselves more

When an agent hands work to a sub-agent, the sub-agent must not end up with
powers its parent never had. Mark the sub-agent's binding with `delegated_from`,
the scope that granted it. interlock then checks that the binding resolves to a
**subset** of what that scope has:

```python
from interlock.policy.scopes import DelegationOverGrant

tree.bind(("root", "acme", "agent42", "sub7"), [
    Binding("egress_allowlist", {"allowed_hosts": ["api.internal"]},
            delegated_from=("root", "acme", "agent42")),
])
registry.resolve(("root", "acme", "agent42", "sub7"))        # fine: a subset

tree.bind(("root", "acme", "agent42", "sub7"), [
    Binding("egress_allowlist", {"allowed_hosts": ["exfil.example"]},
            delegated_from=("root", "acme", "agent42")),
])
registry.resolve(("root", "acme", "agent42", "sub7"))
# -> DelegationOverGrant: delegation over-grant at ('root', 'acme', 'agent42', 'sub7'):
#    template 'egress_allowlist' binds {...} which is not a subset of delegated_from ...
```

The check runs when rules are resolved, not on every call. `resolve()` raises
`DelegationOverGrant`, so a bad grant never reaches the cache. If the bad binding
is first resolved during a call, that call is blocked with policy id
`scoped_engine.resolution`, like any other refusal. Call
`registry.resolve(scope)` right after binding to catch mistakes early.

### Narrowing a sub-agent

Union settings only grow down the tree, so a delegated `["api.internal"]` still
resolves to everything `agent42` has. To give a sub-agent a *smaller* allowlist,
remove the inherited template and bind the narrow one at the same node:

```python
tree.bind(("root", "acme", "sub7"), [
    Binding("egress_allowlist", enabled=False),
    Binding("egress_allowlist", {"allowed_hosts": ["api.internal"]}, delegated_from=("root", "acme")),
])
registry.resolve(("root", "acme", "sub7"))["egress_allowlist"]
# -> {'allowed_hosts': {'api.internal'}}
```

The subset check still applies: swapping in `["exfil.example"]` here raises
`DelegationOverGrant`.

### Deny-lists narrow in the opposite direction

A parameter can be a **deny-list** - the tools or actions a binding disables -
rather than an allowlist. Declare it in the template's `deny_params`:

```python
templates["denied_tools"] = Template(
    "denied_tools", denied_tools, deny_params=frozenset({"denied"})
)
```

For a deny-list the subset rule is reversed: a delegate must disable **at least
as much** as its delegator did - it may disable more things, never fewer - so
its list must be a **superset** of the delegator's. A delegate that denies only
`["shell"]` while its delegator denies `["shell", "write"]` would regain
`write`, so resolving it raises `DelegationOverGrant`. An equal or larger list
is allowed, and so is omitting the key when the delegator's list is empty; a
delegate that omits a non-empty deny-list denies nothing and is refused.

A parameter cannot appear in both `union_params` and `deny_params`; that is a
`ValueError` at `Template` construction, because the two directions contradict
each other.

### Loops and depth

A chain of delegations is followed up to `ScopeRegistry(max_delegation_depth=...)`
levels (default 16). A loop or a chain that's too deep raises
`DelegationDepthExceeded`:

```python
tree2 = ScopeTree()
tree2.bind(("a",), [Binding("row_cap", {"max_rows": 1}, delegated_from=("b",))])
tree2.bind(("b",), [Binding("row_cap", {"max_rows": 1}, delegated_from=("a",))])
ScopeRegistry(tree2, TEMPLATES, max_delegation_depth=4).resolve(("a",))
# -> DelegationDepthExceeded: delegation chain depth 5 exceeds bound 4 resolving ('b',)
```

Both errors (and their base class `DelegationError`) import from
`interlock.policy.scopes`. Bindings without `delegated_from` are never checked.

### Recording who delegated

`span(principal=..., parent_principal=...)` records the delegator on every
event. `delegation_chain(event)` returns the chain as scopes, delegator first:

```python
from interlock import SensorEvent
from interlock.policy import delegation_chain

ev = SensorEvent(action="fetch", principal="root/acme/agent42/sub7",
                 parent_principal="root/acme/agent42")
delegation_chain(ev)
# -> (('root', 'acme', 'agent42'), ('root', 'acme', 'agent42', 'sub7'))
```

This is information for your rules and logs. The subset check above uses
`delegated_from` on the bindings, not `parent_principal`.

## Caching and scale

`ScopedEngine` asks the registry for each scope's compiled rules. The registry
caches them, and the cache stays correct by itself: each node in the tree has a
version, and editing a node changes it. Only the scopes below an edited node
recompile, on their next call.

```python
reg = ScopeRegistry(tree, TEMPLATES, maxsize=2)
for _ in range(3):
    reg.for_scope(("root", "acme", "agent42"))
reg.hits, reg.misses
# -> (2, 1)
tree.bind(("root", "acme"), [Binding("row_cap", {"max_rows": 50})])
reg.for_scope(("root", "acme", "agent42"))
reg.hits, reg.misses
# -> (2, 2)          the edit to acme forced one recompile
```

- `maxsize` (default 10,000) bounds how many compiled scopes are cached. The
  least recently used one is dropped first.
- Only nodes with bindings use memory. A million agents with no bindings of
  their own cost nothing in the tree.
- A cached lookup costs about the same with ten scopes or a million.
  `python benchmarks/scope_memory.py` measures memory and lookup time on your
  machine.
- `registry.invalidate(scope)` drops one cached entry early. You rarely need it.
- **A delegator change invalidates its delegates.** The freshness stamp covers
  not just the leaf's own path but every `delegated_from` scope reachable from
  its bindings, transitively (bounded by `max_delegation_depth`). A policy change
  - or a revoked grant - at a delegator on another branch recompiles the leaf on
  its next call, even though no node on the leaf's path changed. Without this, an
  already-cached engine could outlive the grant it was built from.

For very large trees, an optional Rust implementation of `ScopeTree` cuts memory
per node by roughly ten times. It's used automatically once built. Check which
one is active with `interlock.policy.SCOPE_BACKEND` (`"python"` or `"rust"`).
See [`rust/README.md`](https://github.com/SourceShift/InterLock/blob/main/rust/README.md).

## Limits

- **Calls with no principal are blocked** unless you set `default_scope` or
  `allow_unscoped=True`. Wrap every agent run in a `span`.
- **An unbound scope is denied, not allowed.** A non-empty scope that resolves to
  no templates blocks with `scoped_engine.unbound`. Bind every principal path you
  expect to use, or opt out deliberately with `allow_unbound=True`.
- **Removing one template removes that restriction.** A tombstoned allowlist
  means no allowlist for that template. If *every* template is tombstoned the
  scope is unbound, so it is blocked rather than left with an empty rule set.
- **A sidecar scope document can express delegation and tombstones.** Binding
  entries accept `"delegated_from": "acme/root"` and `"enabled": false`, the same
  fields as `Binding`; a document without them keeps the old root-grant
  behaviour.
- **Binding mistakes surface at resolve time,** which can be the first call
  from that scope. That call is blocked (`scoped_engine.resolution`). Resolve
  right after binding so you find out before a user does.
- **The sidecar can't serve an exported `ScopedEngine`.** A rules module that
  exports one is refused at start (exit code 2). Serve scopes as data instead:
  export `templates` and a `scope_document`, and start the daemon with
  `--scope-document` ([sidecar reference](../reference/sidecar.md#scoped-engines)).
  A remote client can then pin that document with `scope=`/`scopeFile`.
- **The tree lives in memory.** Persist your bindings yourself and rebuild the
  tree at start-up.

## Next

- [Sandbox subprocesses](sandbox.md): turn a scope's bindings into a sandbox profile
- [Writing rules](writing-rules.md): how to write the rules your templates return
- [Sidecar, scoped engines](../reference/sidecar.md#scoped-engines): serve these scopes over a socket, and pin the document from a client
- [Python API reference](../reference/python-api.md): `ScopeTree`, `ScopeRegistry`, `ScopedEngine`
- [Concepts](../concepts.md): principals and spans

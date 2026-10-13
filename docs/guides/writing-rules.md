# Writing rules

Rules are your policy. This guide starts with one-line rules and builds up to
rules that rewrite calls, check results, keep count, and have their own tests.
Each step adds one idea. If you haven't read [concepts](../concepts.md) yet, its
sections on [verdicts](../concepts.md#verdicts) and
[how rules combine](../concepts.md#how-rules-combine) are worth the two minutes.

All examples call `enforce_tool_call` directly so you can paste them into a REPL.
The same rules work unchanged behind `@guard`, MCP, and LangChain.

## Block a tool outright

`deny_tool` blocks every call to one tool name:

```python
import interlock
from interlock import deny_tool, enforce_tool_call

interlock.install(rules=[
    deny_tool("drop_table", reason="schema changes need a migration", policy_id="db.v1"),
])

enforce_tool_call("drop_table", {"name": "orders"})
# -> Blocked: schema changes need a migration
```

To allow *only* certain tools, use the `tool_allowlist` detector instead:
`from interlock.detectors import tool_allowlist`.

## Block on a condition

`deny_when` takes a test. Calls that pass it are blocked:

```python
from interlock import deny_when

interlock.install(rules=[
    deny_when(
        lambda e: e.action == "send_email" and not str(e.args.get("to", "")).endswith("@acme.com"),
        reason="external email",
        policy_id="email.v1",
    ),
])

enforce_tool_call("send_email", {"to": "bob@gmail.com", "body": "hi"})   # -> Blocked: external email
enforce_tool_call("send_email", {"to": "ann@acme.com", "body": "hi"})    # -> {'to': 'ann@acme.com', 'body': 'hi'}
```

If the test itself crashes, `deny_when` blocks the call rather than letting it
through. That makes it the safest wrapper for any check that might hit a missing
key or a surprising type.

## Write your own rule

When you need more than a yes/no test, write a function. Return a `Decision` to
act, or `None` for "no opinion":

```python
from interlock import Decision

def no_prod_writes(event):
    path = str(event.args.get("path", ""))
    if event.action == "write_file" and path.startswith("/srv/prod/"):
        return Decision.block("prod is read-only", policy_id="fs.prod.v1", attributed_to="path")
    return None

interlock.install(rules=[no_prod_writes])
enforce_tool_call("write_file", {"path": "/srv/prod/app.cfg", "data": "x"})
# -> Blocked: prod is read-only | policy_id: fs.prod.v1 | attributed_to: path
```

Three habits make rules easier to live with:

- **Set `policy_id`.** It's how you find the rule in logs and audits.
- **Set `attributed_to` to the argument's name**, never its value. "Blocked
  because of `path`" is useful; copying the path into a log can leak data.
- **Don't let it raise.** Use `.get()`, check types, and return `None` when the
  input isn't what you expect. A hand-written rule that raises stops the call,
  but the caller gets your exception instead of `Blocked`.
- **Change a call with `Decision.modify(...)`, not by editing `event.args`.**
  The tool never sees an in-place edit (it gets the caller's arguments plus any
  rewrites), and nothing about the edit is recorded.

## Rewrite a call

Return `Decision.modify(...)` with the arguments to change. Everything else
stays as the caller passed it:

```python
from interlock import guard

def force_dry_run(event):
    if event.action == "delete_records" and not event.args.get("dry_run"):
        return Decision.modify({"dry_run": True}, reason="deletes run as dry runs",
                               policy_id="db.v1", attributed_to="dry_run")
    return None

interlock.install(rules=[force_dry_run])

@guard()
def delete_records(table, where, dry_run=False):
    return f"{'would delete' if dry_run else 'DELETED'} rows in {table} where {where}"

delete_records("orders", "status = 'stale'")
# -> "would delete rows in orders where status = 'stale'"
```

The new value lands in the right place however the caller passed the argument:
by position, by keyword, left to its default, or through `**kwargs`.

## Check results

Mark a rule with `.phase = "result"` and it sees what tools return instead of
what they're asked. The return value is in `event.args`: a dict result as itself,
anything else under `"result"`. Use `Decision.modify_result(...)` to replace it:

```python
import re

SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")

def mask_ssns_in_results(event):
    text = event.args.get("result")
    if isinstance(text, str) and SSN.search(text):
        return Decision.modify_result(SSN.sub("[SSN]", text), reason="SSN in tool output", policy_id="pii.v1")
    return None

mask_ssns_in_results.phase = "result"   # without this line, the rule never sees results

interlock.install(rules=[mask_ssns_in_results])

@guard()
def lookup_customer(customer_id):
    return f"Jane Doe, SSN 123-45-6789, id {customer_id}"

lookup_customer(42)
# -> "Jane Doe, SSN [SSN], id 42"
```

`@guard`, `guard_mcp_session`, and `guard_langchain_tools` check results for
you. In your own adapter, call `enforce_tool_result(action, result)` after the
tool returns.

## Apply a rule to some tools only

Some rules make sense for a few tools. `mcp_consent_budget`, for example, counts
**every** tool it sees, so installed on its own it would cap all your tools. Wrap
it:

```python
def only_for(actions, rule):
    names = frozenset(actions)

    def scoped(event):
        return rule(event) if event.action in names else None

    scoped.phase = getattr(rule, "phase", "call")   # keep result rules on the result side
    return scoped


from interlock.detectors.mcp_consent_budget import mcp_consent_budget

interlock.install(rules=[only_for({"wire_money"}, mcp_consent_budget(limit=2))])

enforce_tool_call("wire_money", {"amount": 10})   # ok
enforce_tool_call("wire_money", {"amount": 10})   # ok
enforce_tool_call("wire_money", {"amount": 10})   # -> Blocked: mcp_consent_budget: limit 2 exceeded
enforce_tool_call("read_docs", {})                 # never counted, never blocked
```

Copy `only_for` into your project. It works with any rule or detector.

## Put rules in the right order

A block from any rule wins, wherever it sits, so order can't open a hole. It
still decides what each rule *sees*, because later rules judge the call as
earlier rules rewrote it, and evaluation stops at the first block. A sensible
order:

1. **Hard blocks**: tool deny lists, egress allowlists, destructive-command
   checks. Putting them first means a blocked call never reaches the rules
   below.
2. **Budgets and rate limits.** After the hard blocks, so a call that was going
   to be refused anyway doesn't use up a budget.
3. **Rewrites**: redaction, capping, dry-run forcing.
4. **Checks on rewritten values**, if any (for example, a rule that verifies a
   capped `limit`).
5. **Stamps** (provenance detectors) last, so they stamp the final call.

See [how rules combine](../concepts.md#how-rules-combine).

## Use more than one engine

`install()` sets one engine for the whole process. When different parts of your
app need different policies, build engines yourself and pass them in.
`enforce_tool_call`, `enforce_tool_result`, `guard_mcp_session`, and
`guard_langchain_tools` all accept `engine=`:

```python
from interlock import PolicyEngine

strict = PolicyEngine(rules=[deny_tool("run_shell")])

enforce_tool_call("run_shell", {"cmd": "ls"}, engine=strict)   # -> Blocked: tool not permitted
enforce_tool_call("run_shell", {"cmd": "ls"})                  # process engine: allowed
```

`@guard` always uses the process engine. For per-tenant or per-agent policies at
scale, use [scopes](scopes.md) instead of a pile of engines.

## Test your rules

Rules are code, so test them like code. Keep them in a module and check both
what they block and what they let through:

```python
# policies.py
from interlock import Decision
from interlock.detectors import network_egress_guard, pii_redaction_guard

def no_prod_writes(event):
    if event.action == "write_file" and str(event.args.get("path", "")).startswith("/srv/prod/"):
        return Decision.block("prod is read-only", policy_id="fs.prod.v1", attributed_to="path")
    return None

RULES = [
    no_prod_writes,
    network_egress_guard(allowed_hosts=["api.acme.com"]),
    pii_redaction_guard(),
]
```

```python
# test_policies.py
import pytest
from interlock import Blocked, PolicyEngine, enforce_tool_call
from policies import RULES

engine = PolicyEngine(rules=RULES)

def test_prod_writes_are_blocked():
    with pytest.raises(Blocked) as excinfo:
        enforce_tool_call("write_file", {"path": "/srv/prod/app.cfg"}, engine=engine)
    assert excinfo.value.decision.policy_id == "fs.prod.v1"

def test_ordinary_writes_pass():
    args = {"path": "/tmp/scratch.txt"}
    assert enforce_tool_call("write_file", args, engine=engine) == args

def test_card_numbers_are_masked_on_the_way_out():
    out = enforce_tool_call("http_post", {"url": "https://api.acme.com/notes",
                                          "body": "card 4111 1111 1111 1111"}, engine=engine)
    assert out["body"] == "card [REDACTED CREDIT_CARD]"
```

```text
$ pytest -q test_policies.py
...                                                                      [100%]
```

Passing `engine=` keeps each test independent of the process-wide engine. The
"lets it through" tests matter as much as the "blocks it" tests: they're what
stop a rule from quietly breaking your agent.

The same `RULES` list is what you hand to the Node.js sidecar
(`interlock-sidecar --rules policies:RULES`), so one tested policy covers both
languages.

## Next

- [Detectors](detectors.md): ready-made rules and how to combine them with yours.
- [Scopes](scopes.md): different rules per tenant, agent, or sub-agent.
- [Production checklist](production.md): rolling rules out safely.
- [Python API reference](../reference/python-api.md#rules-and-engines)

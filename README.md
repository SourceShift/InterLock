# interlock

In-process guardrails for AI agents. Intercept an agent's tool and MCP calls
inside its own process, and block or modify a bad action **before it runs**, not
after the damage is done.

Unlike a network proxy, interlock sits inside the process and sees the real call
with real arguments. Unlike prompt filtering, it acts at the point where the
agent actually does something. And for the actions a guard cannot see — a
shell-out, a spawned subprocess — **BRACE** confines the process itself using the
same policy.

```mermaid
flowchart LR
    agent([agent]) --> call["tool / MCP call"]

    subgraph inproc["in-process: what interlock sees"]
        direction LR
        interceptors["interceptors"] --> engine["policy engine"]
        engine -->|"allow"| ok["allow"]
        engine -->|"modify"| ok
        engine -->|"block"| no["block"]
    end

    subgraph outproc["out-of-process: what it cannot see"]
        direction LR
        brace["BRACE sandbox"] --> backends["bubblewrap · Seatbelt · soft"]
    end

    call --> interceptors
    interceptors --> brace
    engine --> brace
```

## Status

**M0 core is shipped and stable**: tri-state verdicts, a fail-closed rule engine,
the `@guard` decorator, and in-process MCP + LangChain interception.

This tree goes well beyond M0. Also shipped: hierarchical policy scopes with
delegation chains (and an optional native accelerator), 105 detectors, signed
execution receipts with an append-only sink, tool-result sanitization, MCP
capability leases with server attestation and tool-surface drift detection, and
the BRACE confinement layer with its escape-resistance matrix. Still open:
declarative YAML/JSON policies, automatic model-SDK hooks, `Verdict.ESCALATE`,
and more — see [`ROADMAP.md`](ROADMAP.md) for the full list, each item with its
reasoning and a falsifiable done criterion.

- **Zero runtime dependencies.** `pip install interlock-guard` pulls nothing. The
  MCP adapter duck-types on `session.call_tool` and never imports the MCP SDK;
  LangChain is imported lazily, only when you call for it.
- **Fail-closed by default.** A rule that raises denies. A confinement profile
  that grants nothing gets no network and no writable paths.
- **Tri-state, not binary.** `allow` / `block` / `modify`. A modify rewrites the
  arguments and proceeds — cap an amount, redact PII — instead of failing shut.

## Install

```bash
pip install interlock-guard                    # core: no dependencies
pip install "interlock-guard[langchain]"       # extra, only if you guard LangChain tools
```

Requires Python 3.9+. The native accelerator in [`rust/`](rust/README.md) is
optional and never required:

```bash
pip install maturin && cd rust && maturin develop --release
python -c "from interlock.policy import SCOPE_BACKEND; print(SCOPE_BACKEND)"  # -> rust
```

## Quickstart

```python
import subprocess

import interlock
from interlock import Blocked, deny_when, guard, span


@guard(policy_id="shell.exec.v1")
def run_shell(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


def looks_destructive(event) -> bool:
    cmd = str(event.args.get("cmd", ""))
    return any(t in cmd for t in ("rm -rf", "mkfs", "dd if=", "> /dev/sd"))


interlock.install(
    rules=[deny_when(looks_destructive, reason="destructive command", policy_id="shell.exec.v1")]
)

with span(principal="my-agent"):
    run_shell("echo hi")            # allowed
    run_shell("rm -rf /important")  # raises Blocked; the command never runs
```

Run the bundled demo: `python examples/block_shell_tool.py`

## Core concepts

**`SensorEvent`** — one observed action as the guard sees it before the effect:
`action` (tool/function/MCP name), `args` (the arguments policy may inspect),
`principal`, `span_id`, `ts`, `parent_principal` (the delegator, when the action
runs on someone else's behalf), and `phase` — `"call"` for an action about to
run, `"result"` for the observation path.

**`Verdict` / `Decision`** — `ALLOW` (0), `BLOCK` (1), `MODIFY` (2). The integer
values match the native engine's out-param contract, so a Rust core can drop in
behind the same enum. A `Decision` carries `reason`, `policy_id`, `attributed_to`
(the argument that triggered the verdict — a name, never the value, so the
decision is explainable without echoing the payload), and a rewrite payload —
`modified_args` for a modified call, `modified_result` for a sanitized result,
each populated only for its own direction.

**`Blocked`** — the exception raised when an enforcing guard denies an action. It
carries the `decision` and the `action`, and is raised *before* the wrapped
function executes, so the side effect never happens.

**Run identity** — `span(principal=...)` scopes a span id (and optional
principal) to a block via `contextvars`, so it survives `await` boundaries and
every decision is attributable to one agent run. `new_span()`,
`current_span()`, `current_principal()`, and `set_principal()` are also public.

**Fail-closed** — `deny_when` treats a predicate that *raises* as a match and
denies, rather than silently allowing.

## Interceptors

Every interceptor funnels into one transport-agnostic core,
`enforce_tool_call(action, arguments)`, so a rule you write once enforces
identically whether the agent speaks MCP, LangChain, or a bespoke callable.

### Custom tools — `@guard`

```python
from interlock import guard, monitor

@guard(policy_id="payments.transfer.v1")          # blocking (default): raises on deny
def transfer(amount: int, to: str) -> str: ...

@monitor()                                        # observe-only: records, never blocks
def risky(x): ...
```

Works on sync and async callables. The decorator binds the call signature
(defaults applied) into the event's `args`.

### MCP sessions — `guard_mcp_session`

Wrap one session once on creation and every outbound `call_tool` is checked
before it reaches the server. No gateway, no proxy, no per-tool decorator.

```python
from interlock import guard_mcp_session

session = guard_mcp_session(await make_client_session())
await session.call_tool("write_file", {"path": "/etc/passwd"})   # Blocked, never sent
```

Dependency-free on purpose: it duck-types on `.call_tool`, so it wraps any client
exposing that method and stays testable with a fake session.

### LangChain tools — `guard_langchain_tools`

```python
from interlock import guard_langchain_tools

safe_tools = guard_langchain_tools(agent_tools, principal="agent-7")
```

Returns drop-in replacements with the same name, description, and argument
schema. The original tool runs untouched once its entry is vetted.

### The transport-agnostic core — `enforce_tool_call`

Use this directly from your own adapter:

```python
from interlock import enforce_tool_call

args = enforce_tool_call("http_post", {"host": "evil.example", "body": "..."})  # raises Blocked
```

Returns the arguments to actually use (rewritten on `MODIFY`), or raises
`Blocked`. Pass `enforcement="monitor"` to record the would-be decision instead.

### Tool results — `enforce_tool_result`

Indirect prompt injection arrives in the tool *result*, not the call — the agent
reads the poison and acts on it. `enforce_tool_result` is the same core pointing
the other way: it takes what a tool returned, and returns the result the agent
should actually see (or raises `Blocked`).

```python
from interlock import enforce_tool_result

result = enforce_tool_result("fetch_url", tool_output)   # sanitized, not raw
```

The pair is deliberately not interchangeable. A result event carries
`phase="result"`, so a rule written for a call never fires on a result and vice
versa — and a rewrite lands in `Decision.modified_result`, not
`modified_args`, so the two directions cannot be confused. `guard_mcp_session`
wraps both halves, so you cannot install only one by accident.

## Policy: rules

A `Rule` is any callable `SensorEvent -> Optional[Decision]`; the first rule
returning a non-`ALLOW` verdict wins, and the default is allow.

```python
from interlock import PolicyEngine, deny_tool, deny_when
import interlock

interlock.install(rules=[
    deny_tool("shell_exec"),
    deny_when(lambda e: "rm -rf" in str(e.args.get("cmd", "")), reason="destructive"),
])

# or build an engine explicitly
engine = PolicyEngine(rules=[...]).add_rule(deny_tool("drop_table"))
interlock.install(engine=engine)
```

`install()` sets the process-global engine the interceptors consult. With no
engine installed, `get_engine()` returns an empty allow-all engine.

## Policy: hierarchical scopes

When one small set of policy *templates* must apply to millions of distinct
subjects (agents, tenants, sessions) with per-subject overrides, `PolicyEngine`
alone is the wrong shape. Scopes split code from data:

- a **template** is code — a factory turning params into a `Rule`, few and fixed;
- a **binding** is data — `(template_id, params, enabled)` on a scope node;
- a **scope** is a path, e.g. `("root", "acme", "agent42")`.

Root→leaf walking merges bindings per template with three rules: **override** (a
more specific binding wins), **union** (`union_params` accumulate — allowlists
grow), and **tombstone** (`enabled=False` removes an inherited binding until a
deeper node re-adds it).

```python
from interlock.policy import Binding, ScopedEngine, ScopeRegistry, ScopeTree, Template
from interlock import Decision, SensorEvent


def egress_allowlist(allowed_hosts):
    hosts = frozenset(allowed_hosts)

    def rule(e: SensorEvent):
        if e.action == "fetch" and (e.args.get("host") or "") not in hosts:
            return Decision.block("egress to " + str(e.args.get("host")), "egress_allowlist")
        return None

    return rule


TEMPLATES = {
    # union_params: allowed_hosts accumulates up the chain instead of overriding
    "egress_allowlist": Template("egress_allowlist", egress_allowlist, frozenset({"allowed_hosts"})),
    "rate_limiter": Template("rate_limiter", lambda limit: ...),
}

tree = ScopeTree()
tree.bind(("root",), [Binding("egress_allowlist", {"allowed_hosts": ["api.internal"]})])
tree.bind(("root", "acme"), [Binding("rate_limiter", {"limit": 5})])
tree.bind(("root", "acme", "agent42"), [Binding("rate_limiter", {"limit": 2})])  # override

registry = ScopeRegistry(tree, TEMPLATES)
registry.resolve(("root", "acme", "agent42"))
# {"egress_allowlist": {"allowed_hosts": {"api.internal"}}, "rate_limiter": {"limit": 2}}

interlock.install(engine=ScopedEngine(registry))   # same evaluate(event) contract
```

**Cost model.** Resolution walks one root→leaf path, compiles a `PolicyEngine`,
and caches it under a per-node version tuple — so warm cost stays flat from ten
scopes to a million, while memory grows only with bound nodes. Editing an
ancestor bumps its version and lazily invalidates only the descendants that
inherit from it. `ScopeRegistry(maxsize=...)` bounds the LRU. The default scope
deriver, `principal_scope`, splits `event.principal` on `/`.

**Delegation chains.** When an agent hands work to a sub-agent, the sub-agent
must not end up with more authority than its delegator. A binding says where its
authority came from, and the check happens at *resolve* time rather than at call
time:

```python
# agent42 itself resolves egress_allowlist to {"api.internal"}, so:
tree.bind(
    ("root", "acme", "agent42", "subagent7"),
    [Binding("egress_allowlist", {"allowed_hosts": ["api.internal"]},
             delegated_from=("root", "acme", "agent42"))],   # resolves — a subset
)

# widening the delegate past its delegator is refused at resolve time:
tree.bind(
    ("root", "acme", "agent42", "subagent7"),
    [Binding("egress_allowlist", {"allowed_hosts": ["api.internal", "exfil.example"]},
             delegated_from=("root", "acme", "agent42"))],   # DelegationOverGrant
)
```

Every binding whose `delegated_from` is set must resolve to a **subset** of what
that scope resolves to, for the same template — so a delegate cannot hand itself
a host, a budget, or a capability its delegator never held. Two escapes are
closed: a delegation loop or unbounded fan-out trips
`ScopeRegistry(max_delegation_depth=...)` (default 16) with
`DelegationDepthExceeded`, and both failures are raised, not logged, so a bad
grant cannot survive into a warm cache. Non-delegated bindings are untouched —
`delegated_from=None` is a no-op, so nothing that never delegates changes shape.
The chain is read from `event.parent_principal`, which the interceptors carry from
the ambient context; `delegation_chain(event)` exposes it as a scope tuple,
delegator first.

`SCOPE_BACKEND` reports which storage layer is live (`"python"` or `"rust"`). The
native crate reimplements exactly one class — the sparse `ScopeTree` — with
interned segment ids and packed values, materializing Python objects only for the
one resolved leaf on a cache miss. Everything above it is unchanged.

## Detectors

105 single-purpose detectors, one rule factory per module, each with a
`POLICY_ID`. Import the eight general ones from the package, or any detector by
its module path:

```python
from interlock.detectors import (
    jailbreak_detector, prompt_injection_detector, execution_guard,
    tool_allowlist, tool_denylist, network_egress_guard,
    sensitive_path_guard, pii_redaction_guard,
)
from interlock.detectors.sql_injection_guard import sql_injection_guard

interlock.install(rules=[sql_injection_guard(), network_egress_guard(allowed_hosts=["api.internal"])])
```

Full catalog, grouped by attack surface (`ls interlock/detectors/` for the live list):

**Injection & jailbreak framing** — `prompt_injection` · `jailbreak` ·
`dan_persona_guard` · `crescendo_guard` · `many_shot_jailbreak_guard` ·
`leetspeak_jailbreak_guard` · `hypothetical_framing_guard` ·
`social_engineering_framing_guard` · `refusal_suppression_guard` ·
`goal_hijack_guard` · `system_prompt_extraction` · `indirect_injection_marker` ·
`translation_evasion_guard` · `delimiter_smuggling` · `homoglyph_injection` ·
`unicode_tag_injection` · `html_comment_injection_guard` ·
`markdown_link_injection_guard` · `payload_splitting_guard` ·
`base64_payload_scan` · `canary_leak_guard` · `pinned_context_guard` ·
`memory_write_injection_guard` · `tool_output_override_guard` ·
`tool_result_injection_guard` · `rag_source_allowlist` ·
`mcp_prompt_arg_injection`

**Classic argument-shaped vulns** — `sql_injection_guard` ·
`nosql_injection_guard` · `shell_injection_guard` · `ldap_injection_guard` ·
`xxe_guard` · `ssti_guard` · `path_traversal_guard` · `prototype_pollution_guard` ·
`open_redirect_guard` · `crlf_header_injection_guard` · `script_tag_output_guard` ·
`ansi_escape_output_guard` · `url_scheme_guard` · `mass_assignment_guard` ·
`pickle_deser_guard` · `download_extension_guard`

**Secret & PII redaction** — `bearer_token_redactor` · `basic_auth_url_redactor` ·
`aws_arn_redactor` · `github_pat_redactor` · `google_api_key_redactor` ·
`jwt_redactor` · `pem_private_key_redactor` · `db_uri_redactor` ·
`stripe_key_redactor` · `slack_webhook_redactor` · `s3_presigned_redactor` ·
`output_secret_redactor` · `secret_entropy_egress_guard` · `env_secret_read_guard` ·
`git_credential_guard` · `email_pii_redactor` · `output_email_redactor` ·
`iban_redactor` · `ssn_redactor` · `us_phone_redactor` · `ipv4_redactor`

**Egress & data movement** — `data_egress` · `egress_rate_limiter` ·
`private_ip_egress_guard` · `raw_ip_egress_guard` · `data_volume_egress_guard` ·
`markdown_image_exfil_guard` · `host_fanout_guard`

**Code execution & host access** — `execution_guard` · `code_eval_exec_guard` ·
`code_dunder_escape_guard` · `code_filesystem_guard` · `code_network_guard` ·
`dynamic_import_guard` · `subprocess_spawn_guard` · `destructive_command_guard` ·
`sensitive_file_write_guard` · `signal_kill_guard` · `memory_bomb_guard`

**MCP trust surface** — `mcp_server_allowlist` · `mcp_tool_pinning` ·
`mcp_tool_description_scan` · `mcp_trust_registry` · `mcp_resource_uri_guard` ·
`mcp_sampling_model_guard` · `mcp_consent_budget` · `mcp_capability_lease` ·
`mcp_server_attestation` · `mcp_surface_baseline`

**Budgets, rate & loops** — `call_rate_limiter` · `cost_budget_guard` ·
`tool_budget_limiter` · `write_action_limiter` · `duplicate_call_loop_guard` ·
`output_length_guard` · `memory_write_size_guard` · `failed_auth_lockout`

**Provenance & integrity stamps** — `event_hmac_stamp` · `content_digest_stamp` ·
`sequence_number_stamp` · `provenance_origin_tag`

**Tool policy** — `tool_policy`

## Confinement: BRACE

BRACE compiles the same policy into a confinement profile and runs the agent's
shell-outs under kernel-enforced isolation. One policy, two enforcement points:
detectors intercept the calls interlock can see, BRACE confines the processes it
cannot.

```python
from interlock.brace import Sandbox, compile_profile

profile = compile_profile(registry.resolve(("root", "acme", "agent42")))
result = Sandbox(profile).run(["python", "worker.py"])

if "net" not in result.enforced:
    raise RuntimeError("refusing to run untrusted code with open network")
```

`Sandbox.run(argv)` checks the launch through the policy engine as a
`process_spawn` event first, so a rule can block or rewrite it before any process
starts, then runs it under the backend. `Sandbox.plan(argv)` returns the wrapped
argv without running anything — useful for inspection and tests.

A `SandboxProfile` describes allowed reach and defaults closed: no network unless
an `egress_allowlist` binding grants hosts, no writable host path unless a
`sandbox_fs` binding grants one, and the child's environment is exactly what you
pass in. `compile_profile(resolved)` reads the `{template_id: params}` dict a
`ScopeRegistry` already produces, recognising `egress_allowlist`,
`sandbox_fs` (`read_paths`/`write_paths`), and `sandbox_limits`
(`cpu_seconds`/`memory_mb`).

**Backends**, strongest first, chosen for the host at runtime — or pinned with
`Sandbox(profile, backend="bubblewrap")`:

| Backend | Host | Enforces | Reports (`enforced`) |
|---|---|---|---|
| `bubblewrap` | Linux | namespaces, ro/rw binds, network unshare | `pid`, `net`, `fs-ro`, `fs-rw`, `env` |
| `sandbox-exec` | macOS | Seatbelt s-expression profile | `net`, `fs-rw`, `env` |
| `soft` | anywhere | rlimits + scrubbed env — **not a security boundary** | `rlimit`, `env` |

`available_backends()` lists what the host offers. `SandboxResult.enforced`
reports the guarantees that actually held as short tokens so a caller that needs
real isolation can fail closed instead of silently accepting a downgrade to
`soft`. Each token in that column is a *tested* claim, not a wish: every row is
an escape run for real plus a relaxed control (the same attack with only that one
confinement lifted, asserted to succeed, so the block is attributable to the
sandbox and not to the kernel refusing the syscall). The guarantee table in
`interlock/brace/__init__.py` is the human-readable form and
`tests/integration/test_brace_token_matrix.py` is the executable one; a drift test
pins each backend's reported set to that table in **both** directions, so a token
cannot be added or dropped without the table moving with it.

**Known limitation — the missing rung.** `nftables` is intentionally absent from
the selectable set: `Sandbox(profile, backend="nftables")` raises
`ValueError: unknown backend: nftables`, and `backends/nftables.py` is reachable
only by a caller who is already root and imports it directly. So there is no
unprivileged host-granular egress backend between bubblewrap's `--unshare-net`
(all network or none) and nftables (per-host, but root/`CAP_NET_ADMIN` and
Linux-only). That is a measured absence rather than an unimplemented TODO:
Seatbelt's network filters accept only `*` or `localhost` as the remote host, so
an allowlist of specific hosts cannot be expressed on macOS at all. When a
profile grants network, `sandbox-exec` and `bubblewrap` therefore open egress
entirely and report **no** `net` token, honestly. Confining that grant to the
listed hosts happens in-process, via the `egress_allowlist` detector on captured
calls; at the host level, only the privileged nftables path does it.

## Receipts: an audit trail you can hand to someone else

Detectors decide; receipts *record* the decision, in a form a third party can
check afterwards without trusting the process that wrote it. It is off by
default — with no sink installed, `emit_receipt` is a no-op and the guard
behaves byte-identically to a build without receipts. Turning it on is explicit:

```python
from interlock import install
from interlock.sink import FileSink

install(sink=FileSink("audit.jsonl"))          # or set_sink(my_sink)
```

Every enforced decision then appends one `Receipt` — `ts`, `action`, `verdict`,
`reason`, `policy_id`, `attributed_to`, `principal`, `span_id`, `phase`,
`args_digest`, `prev`, `mac` — from the enforcement sites only (the decorator's
`_emit` and the MCP interceptor's call and result paths), never from a rule, so a
rule cannot forge a receipt or quietly drop one.

Two properties are worth naming, because they are the whole point:

- **The arguments are digested, not stored.** `args_digest` is a SHA-256 over the
  arguments; the receipt records *that* a payload was seen and *which* one,
  without becoming a second copy of your customer data. An audit log that
  duplicates every payload is a retention liability, not an audit log.
- **The chain is tamper-evident.** `prev` is the previous receipt's `mac`
  (`GENESIS` for the first) and `mac` covers every other field, so editing a
  receipt breaks its own mac, and deleting or reordering one breaks the *next*
  receipt's linkage. `verify()` walks the chain and names the first bad index,
  because "the chain is broken" without an index leaves the auditor hunting:

```python
sink = FileSink("audit.jsonl", key=KEY)
sink.verify()      # None, or "receipt 7: MAC mismatch (edited, or verified with a different key)"
```

**What the default signer claims — and what it does not.** The default is
`hmac_sha256`: a MAC, not a public-key signature. It proves the content has not
changed since signing and that whoever wrote it held the shared secret. It does
**not** prove *which* holder produced it, and it is not verifiable by a party
without the secret. When you need attribution rather than integrity, inject a
signer through the same `Signer` seam (an Ed25519 signer from `cryptography`);
`pyproject.toml` stays dependency-free either way. The default key is random per
process (`process_secret()`), so a durable audit trail passes its own long-lived
key.

**One sink instance, one process, one chain.** Concurrent threads share an
unbroken chain — the read-prev / sign / append step runs under a lock. Writers in
*other* processes are not serialized: two processes appending to one file each
start their own chain at `GENESIS`, and `verify()` reports the junction as a
break rather than silently accepting a spliced history. How you partition the
audit file across processes is a deployment decision, and the sink does not make
it for you.

## Project layout

```
interlock/
  enforce.py             Verdict, Decision, Blocked
  event.py               SensorEvent
  context.py             span / principal via contextvars
  _runtime.py            the process-global engine
  receipt.py             Receipt, compute_mac, verify_chain, emit_receipt
  sink.py                ChainedSink, InMemorySink, FileSink
  interceptors/          decorator.py, mcp.py, langchain.py  (all funnel to enforce_tool_call)
  policy/                engine.py (rules), scopes.py (templates, registry, ScopedEngine)
  detectors/             105 detector modules
  brace/                 profile.py, sandbox.py, result.py, backends/, trace.py
rust/                    optional PyO3 accelerator for the scope store
benchmarks/              scope-store memory and warm-resolve benchmark
tests/                   117 unit-test modules + tests/integration/
examples/                block_shell_tool.py
```

The public repo is the `interlock/` package plus `tests/`. `rsi/` is internal,
git-ignored build apparatus (see below).

## Development

```bash
git clone <repo> && cd interlock
python -m pytest                      # full suite from the repo root (conftest handles sys.path)
python -m pytest tests/test_scopes.py -q
python examples/block_shell_tool.py   # the demo
python benchmarks/scope_memory.py     # scope-store memory / warm-resolve numbers
```

There is no build step and no lint config to satisfy: the package is pure Python
with no dependencies, and `conftest.py` pins the repo root on `sys.path` and
resets the global engine between tests.

### Adding a detector

One module in `interlock/detectors/`, exposing a rule factory and a `POLICY_ID`:

```python
"""What the payload class is, why it is visible at this point, and what is matched."""
POLICY_ID = "my_guard"

def my_guard(*, extra_patterns=None):
    def rule(event):
        # return None for "no opinion"; Decision.block(...) to deny
        return None
    return rule
```

Conventions the suite relies on, and which keep the catalog uniform:

- **Never raise on odd input.** A non-dict `args`, an `int`, or `None` yields no
  opinion. A detector is a guard, not a parser; raising is a fail-closed denial in
  production and a test failure here.
- **Precision over recall.** Each detector matches a shape an ordinary value
  will not contain, and says so in its module docstring — the reasoning is the
  documentation.
- **One rule, one concern, no imports beyond stdlib.** Detectors must stay
  dependency-free, like the core.
- **Add a test module** `tests/test_<name>.py` covering both the match and the
  non-match (the non-match is what stops the detector from being noise).
- Detectors are deliberately *not* auto-registered. Import and `install` the ones
  you want; nothing is enabled behind your back.

### Native accelerator

The Rust crate reimplements only `ScopeTree`. Build it, then confirm the swap:

```bash
cd rust && maturin develop --release
python -c "from interlock.policy import SCOPE_BACKEND; print(SCOPE_BACKEND)"
python -m pytest tests/test_scope_backend.py -q    # checks native/python parity
```

`tests/test_scope_backend.py` uses the pure-Python tree as the parity oracle, so
the two backends must agree on every resolution. `*.so` and `rust/target/` are
git-ignored; the canonical build is `maturin develop`.

### Keeping the docs honest

This README drifted once already: it advertised a milestone roadmap while the
tree had moved well past it, and its detector count was stale by more than a
dozen. Before editing, check the claim against the code:

```bash
ls interlock/detectors/*.py | grep -v __init__ | wc -l   # detector count
git ls-files interlock/ | wc -l                          # tracked package files
python -m pytest -q                                      # suite must be green
```

### RSI pipeline (internal, not shipped)

`rsi/` is a git-ignored recursive-self-improvement loop that grows the detector
catalog by mining recent arXiv guardrail research and adding one verified
technique at a time. The discipline is that every change is judged by what the
code actually did — interlock's own `pytest` — not by a model's opinion of its own
output; a vacuous pass is downgraded to a failure. `rsi/backlog.md` holds the
ranked technique families, `rsi/verify.py` is the reward gate, and the paid
worker lanes spend real money, so run it deliberately:

```bash
PYTHONPATH=. RSI_TARGET=100 python rsi/run_100.py
```

## Roadmap

Shipped in this tree:

- Tri-state verdicts, fail-closed rule engine, `@guard` / `monitor`, and run identity.
- In-process MCP interception (`guard_mcp_session`) and the LangChain adapter —
  explicit wrap, one shared `enforce_tool_call` core.
- Hierarchical policy scopes: override / union / tombstone merge, version-keyed
  cache, `ScopedEngine`, delegation chains with resolve-time attenuation
  (`delegated_from` / `max_delegation_depth`), and the optional native `ScopeTree`.
- 105 detectors across injection, redaction, egress, code execution, MCP trust,
  budgets, and provenance.
- Verdict provenance: every non-ALLOW `Decision` carries `attributed_to`, so a
  block names the input that triggered it, not merely the rule that fired.
- Signed execution receipts and an append-only, tamper-evident sink
  (`interlock/receipt.py`, `interlock/sink.py`) — off by default, opted into with
  `install(sink=...)`.
- Tool-result sanitization: `enforce_tool_result` points the same tri-state
  decision at the observation path, so injection in a tool *result* is remediated
  rather than only observed.
- MCP capability leases, server attestation, and tool-surface drift detection,
  extending the `mcp_*` detectors from static allowlisting to time-boxed grants.
- BRACE confinement: profile IR, `compile_profile` from policy, `Sandbox`, the
  bubblewrap / Seatbelt / soft backends with reported guarantees, and an
  escape-resistance matrix that runs each claimed token's attack for real.
- A scope-store benchmark under `benchmarks/`.

Upcoming, roughly in expected-value order — the first three come from a survey of
445 arXiv papers from 2026
([`research/agent-guardrails-2026.md`](research/agent-guardrails-2026.md)),
the rest are open items from earlier milestones:

- **`Verdict.ESCALATE`** — a fourth outcome: *pause for a human, with the
  evidence attached*, instead of approximating it with a block.
- **Guardrail robustness harness** — false-positive rate on benign traffic and
  resistance to induced blocking. A fail-closed library with an unmeasured FP
  rate is a product risk; forcing blocks is a denial-of-service primitive.
- **Flow-typed policy dimension** — express "output of tool A must not reach
  argument B", so the policy layer does not dead-end as flat rules.
- **Declarative YAML/JSON policies** with a safe condition evaluator and hot reload.
- **Automatic interception** — import hooks for MCP clients and model SDKs, plus
  dependency tamper detection.
- **An overhead benchmark suite** with a stated methodology.
- **A Node.js sensor** reusing the same engine and policies.

Each item above has a full entry — problem, why now, what changes, impact on
callers, a falsifiable acceptance criterion, and its risks — in
[`ROADMAP.md`](ROADMAP.md). Logit / decoding-layer intervention is recorded there
as explicitly out of scope.

## License

Apache-2.0. See [LICENSE](LICENSE).

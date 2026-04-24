# interlock

In-process guardrails for AI agents. Hook an agent's tool, MCP, and model calls
inside its own process, and block or modify a bad action **before it runs**, not
after the damage is done.

Unlike a network proxy, interlock sits inside the process and sees the real call
with real arguments. Unlike prompt filtering, it acts at the point where the
agent actually does something.

Status: **M0** (opt-in decorator + Python-rule policy engine). Automatic import
-hook interception (MCP, model SDKs), declarative YAML policies, signed audit
receipts, and a native Rust fast-path are on the roadmap below.

## Quickstart

```python
import interlock
from interlock import guard, Blocked, deny_when, span

@guard(policy_id="shell.exec.v1")
def run_shell(cmd: str) -> str:
    import subprocess
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

def looks_destructive(event):
    return "rm -rf" in str(event.args.get("cmd", ""))

interlock.install(rules=[deny_when(looks_destructive, reason="destructive command")])

with span(principal="my-agent"):
    run_shell("echo hi")                 # allowed
    run_shell("rm -rf /important")       # raises Blocked, the command never runs
```

Run the demo:

```bash
python examples/block_shell_tool.py
```

## How it works

- **Verdict is tri-state**: allow / block / modify. A block raises `Blocked`
  before the wrapped function executes, so the side effect never happens. A
  modify rewrites the call arguments (for example, cap an amount or redact PII)
  and then proceeds.
- **Policies are data, not code.** M0 rules are Python functions; M2 loads the
  same decisions from declarative YAML/JSON so they survive model and framework
  migrations.
- **Fail-closed by default.** A rule that errors denies rather than silently
  allowing.
- **Run identity** rides along on every event via `contextvars`, so each
  decision is attributable to one agent run.

## Roadmap

- **M1** automatic MCP interception (import hook wraps the MCP client; block
  before the request is sent).
- **M2** declarative YAML/JSON policy engine with a safe condition evaluator and
  hot reload.
- **M3** automatic model-SDK hooks (OpenAI, Anthropic) plus an import monitor
  with dependency tamper detection.
- **M4** Ed25519-signed decision receipts and an append-only audit log.
- **M5** measured overhead benchmarks with an honest methodology.
- **M6** native Rust policy engine over ctypes (the fast path) and a Node.js
  sensor reusing the same engine and policies.

## License

Apache-2.0.

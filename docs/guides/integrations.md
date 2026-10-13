# Integrations

interlock plugs in wherever your agent calls tools. This page shows each way to
connect it, from a single decorated function to a whole MCP session or a Node.js
agent. All of them run the same rules, so you can mix them freely.

| You have | Use | Checks calls | Checks results |
|---|---|---|---|
| Your own Python functions | [`@guard`](#your-own-functions) | yes | yes |
| An MCP client session | [`guard_mcp_session`](#mcp-sessions) | yes | yes |
| LangChain tools | [`guard_langchain_tools`](#langchain-tools) | yes | yes |
| A model SDK's tool loop (OpenAI, Anthropic, others) or any other framework | [`enforce_tool_call` + `enforce_tool_result`](#a-model-sdk-or-any-other-framework) | yes | yes, when you call it |
| A framework tool loop: OpenAI SDK, LiteLLM, CrewAI, Google ADK | [`guard_tool_loop`](#framework-tool-loops) | yes | yes |
| A Node.js agent | [the `interlock-guard` npm package](#nodejs-agents) | yes | yes for MCP and model-SDK tools |
| Subprocesses your agent launches | [BRACE sandbox](sandbox.md) | the launch | OS-level confinement instead |

## Your own functions

Put `@guard()` on any function your agent calls. It works on sync and async
functions:

```python
from interlock import guard, monitor

@guard()
def transfer(amount: int, to: str) -> str: ...

@guard()
async def fetch(url: str) -> str: ...

@monitor()                        # observe only: record decisions, never block
def experimental_tool(x): ...
```

The event's `action` is the function's name, and `args` maps parameter names to
values (defaults included). Pass `principal=` to tag every call from this
function with a fixed identity, for example `@guard(principal="billing-bot")`.
Without it, the principal comes from the surrounding `span()`.

`@guard` always uses the process engine set by `interlock.install()`.

## MCP sessions

Wrap a client session once, and every `call_tool` is checked before it reaches
the server. The result is checked before your agent sees it.

```python
from interlock import guard_mcp_session

session = guard_mcp_session(await make_client_session(), origin="github")
await session.call_tool("write_file", {"path": "/etc/passwd"})   # Blocked, never sent
```

It works with any object that has a `call_tool(name, arguments)` method, sync or
async, so it doesn't import the MCP SDK and is easy to test with a fake. It also
accepts `engine=`, `enforcement=`, and `principal=`.

The official SDK's `CallToolResult` is understood: its text content is what your
result rules read. `origin=` tells the MCP trust detectors which server the
session talks to; a server label the model slips into the arguments is dropped.
Checking *which servers* you connect to and whether their tools changed takes a
few more lines. The [MCP guide](mcp.md) covers that.

## LangChain tools

```python
from interlock import guard_langchain_tools

safe_tools = guard_langchain_tools(agent_tools, principal="agent-7")
agent = create_agent(llm, safe_tools)     # whatever your agent constructor is
```

Requires `pip install "interlock-guard[langchain] @ git+https://github.com/SourceShift/InterLock.git"`.
Each returned tool keeps the original's name, description, and argument schema,
so the model sees no difference. Each call is checked before the tool runs, and
what the tool returns is checked before the agent reads it:

```python
import interlock
from interlock import guard_langchain_tools
from interlock.detectors.tool_result_injection_guard import tool_result_injection_guard

interlock.install(rules=[tool_result_injection_guard()])
safe_fetch, = guard_langchain_tools([fetch])     # fetch: a LangChain @tool

safe_fetch.invoke({"url": "https://docs.python.org"})
# -> '<html>ok</html>'
safe_fetch.invoke({"url": "https://blog.example.com"})    # the page carries an injected instruction
# -> Blocked: tool_result_injection: ignore previous instructions
```

## A model SDK, or any other framework

Most agents end up with a loop that takes the model's tool request, runs the
tool, and sends the result back. Put interlock in that loop:

```python
from interlock import Blocked, enforce_tool_call, enforce_tool_result

TOOLS = {"fetch": fetch, "send_email": send_email}

def run_tool(name: str, arguments: dict):
    try:
        safe_args = enforce_tool_call(name, arguments)
        result = TOOLS[name](**safe_args)
        return enforce_tool_result(name, result)
    except Blocked as e:
        return f"[blocked by policy: {e.decision.reason}]"
```

```text
run_tool("fetch", {"url": "https://evil.example"})
-> [blocked by policy: egress to 'evil.example' is not on the destination allowlist]

run_tool("fetch", {"url": "https://blog.example.com"})
-> [blocked by policy: tool_result_injection: ignore previous instructions]

run_tool("fetch", {"url": "https://docs.python.org"})
-> <html>ok</html>
```

Returning the refusal as the tool's result, rather than crashing the loop, lets
the model see what happened and try something else. Built-in detectors keep
their reasons short, though some name the host or IP address they refused. Make
sure your own rules don't put secrets in `reason`, since the model will read it.

`enforce_tool_call` returns the arguments to actually use, which may have been
rewritten. Always call the tool with its return value, not with the original
arguments.

Both functions accept `engine=`, `enforcement=`, and `principal=`.

## Framework tool loops

The loop above is what every agent framework bottoms out in: a *tool runner*
that takes the model's tool request and returns the tool's result. interlock
ships a thin adapter per framework that guards that runner for you, so you don't
hand-write the `try`/`enforce_tool_call`/`enforce_tool_result` wrapper. Each one
routes through the same two core functions, so the rules you already wrote apply
unchanged.

```python
from interlock.interceptors.openai import guard_tool_loop      # or .litellm,
                                                               # .crewai, .google_adk
dispatch = guard_tool_loop(run_tool)          # run_tool(name, args) -> result

for call in response.choices[0].message.tool_calls:
    result = dispatch(call.function.name, json.loads(call.function.arguments))
```

`guard_tool_loop` is the same symbol in each adapter module:

| Framework | Import | Wraps |
|---|---|---|
| OpenAI SDK | `interlock.interceptors.openai` | the tool loop's dispatcher |
| LiteLLM | `interlock.interceptors.litellm` | the `litellm.completion` tool loop |
| CrewAI | `interlock.interceptors.crewai` | a tool's `run` entrypoint |
| Google ADK | `interlock.interceptors.google_adk` | a tool's `run_async` entrypoint |

Hand it the `(name, args) -> result` dispatcher your loop already calls, or a
native tool object (recognized by duck-typing on `run` / `run_async` - the SDK is
never imported). It hands back a callable of the same `(name, args)` shape, async
when the tool is. A call that the policy blocks raises `Blocked` **before** the
tool runs; a `MODIFY` hands the tool the rewritten arguments; the result is
checked before the model reads it. All of them accept `engine=`, `enforcement=`
(default `"blocking"`; use `"monitor"` to trial), and `principal=`.

None of these adapters import their SDK at module scope, so importing interlock
never pulls in `openai`, `litellm`, `crewai` or `google.adk` - the framework is
only needed when you actually use it.

`interlock doctor` reports one `framework.<name>` row per adapter: **detected**
(the package is importable here, so its surface can be guarded) or **uncovered**
(the package is not importable, so interlock cannot attest that surface is
guarded). An uncovered surface is a warning, not silence - a framework that is
absent is never quietly reported as covered.

## Node.js agents

A Node.js agent uses the same Python engine through a small daemon that runs next
to it. You write the rules once in Python, and the `interlock-guard` npm package
asks the daemon for a verdict before each tool call.

```bash
interlock-sidecar --rules my_service.policies:RULES --socket "$HOME/.interlock/guard.sock"
```

```ts
import { homedir } from "node:os";
import { join } from "node:path";
import { RemoteEngine, guardMcpSession } from "interlock-guard";

const engine = new RemoteEngine(join(homedir(), ".interlock", "guard.sock"), { timeout: 5 });
guardMcpSession(client, { engine });
```

> **Warning**
> If the daemon isn't running, every guarded call is denied, even in monitor
> mode. `RemoteEngine` gives up after 5 seconds by default (and denies the call),
> so a hung daemon can't hang your agent. Don't pass `timeout: null` in
> production.

The package can also guard `fs`, `child_process`, and `fetch` for the whole
process, and the tool map or runner of any model SDK. See
[js/README.md](https://github.com/SourceShift/InterLock/blob/main/js/README.md) for setup and the
[sidecar reference](../reference/sidecar.md) for every daemon flag.

## Subprocesses

When your agent runs a program (`subprocess.run`, a shell tool, generated code),
interlock can't see what that program does. Run it in the
[BRACE sandbox](sandbox.md) instead. The launch is checked against your rules,
then the process runs with OS-level limits on network, files, and environment.

## Next

- [MCP guide](mcp.md): trusting servers, not just checking calls.
- [Writing rules](writing-rules.md)
- [Python API reference](../reference/python-api.md#guarding-calls)

---
hide:
  - navigation
  - toc
---

<!--
  The landing page at https://interlock.sourceshift.ai/

  The hero and the proof block are rendered by overrides/main.html, which is
  gated on `page.is_homepage` and appears above this content. Everything below
  is ordinary Markdown so the words are cheap to edit and render sensibly on
  GitHub as well as on the site.

  `hide: [navigation, toc]` drops both sidebars: this page is a front door, and
  the sidebar is the table of contents for the manual behind it.
-->

## Why interlock

Agents make mistakes, and some get tricked. Sooner or later one runs `rm -rf`,
sends data to a host you have never heard of, or follows an instruction it found
on a web page. Most guardrails watch what the model **says**. interlock watches
what it **does**: at the last moment you can still say no, with the real
arguments in hand.

<div class="grid cards" markdown>

- :material-swap-horizontal:{ .lg .middle } **Three verdicts, not two**

    ---

    A call can be allowed, blocked, or **rewritten** &mdash; mask a card number,
    cap a row limit, force a dry run. Safety does not always have to cost you
    the task.

- :material-import:{ .lg .middle } **It checks what tools send back**

    ---

    Injected instructions arrive in tool output: a web page, an email, a
    document. interlock screens results before your agent ever reads them.

- :material-shield-check:{ .lg .middle } **One policy, every framework**

    ---

    The same rules guard decorated functions, MCP sessions, LangChain tools,
    your own model loop, and Node.js agents.

- :material-text-box-search:{ .lg .middle } **105 detectors, ready-made**

    ---

    Prompt injection, SQL and shell injection, secret and PII redaction, SSRF,
    egress allowlists, MCP server trust, budgets, and runaway loops.

- :material-server-security:{ .lg .middle } **Built for real deployments**

    ---

    Per-tenant policy scopes with safe delegation to sub-agents, a
    tamper-evident audit log, and an OS sandbox for the subprocesses your agent
    launches.

- :material-tune:{ .lg .middle } **Nothing to sign up for**

    ---

    Pure Python, no runtime dependencies, no API keys, no telemetry. It runs
    offline, and it works the same in CI as it does on your laptop.

</div>

## Where interlock fits

There are three places you can put a guard on an agent, and they each see
something different:

| Where | Sees | Misses |
|---|---|---|
| **Prompt / output filter** | what the model is told, and what it says | what the model decides to *do* |
| **Network proxy or gateway** | outbound HTTP, usually encrypted | file writes, shell commands, local tools, and the real arguments |
| **interlock, in-process** | every guarded call with its real arguments, right before it runs | code that runs outside the guarded functions, such as a subprocess |

interlock sits at the last moment you can still refuse, and it is the only
position holding the exact arguments. For the part it cannot see &mdash; a
subprocess the agent launches &mdash; interlock ships
[BRACE](guides/sandbox.md), an OS sandbox built from the same policy.

[How interlock works](concepts.md) covers the mechanics: events, rules, verdicts,
ordering, and what happens when something goes wrong.

## Know the limits

These are the honest ones. A guardrail you over-trust is worse than one you
understand.

<ul class="il-limits" markdown>

<li markdown>

**It does not understand intent.** The detectors match specific patterns, tuned
so ordinary values do not trip them. That keeps false alarms low, and it means a
reworded attack can get through: `tool_result_injection_guard` catches "ignore
previous instructions", but not "ignore *all* previous instructions". Treat
detectors as layers, and pair them with allowlists, which do not depend on
wording.

</li>

<li markdown>

**It only sees the calls you wrap.** A tool without `@guard`, a session you did
not wrap, or a call that never goes through `enforce_tool_call` is invisible to
interlock.

</li>

<li markdown>

**It does not undo actions.** A result is checked after the tool has already
run. Blocking the result hides the output from your agent; the side effects
stand.

</li>

<li markdown>

**It cannot stop malicious code in its own process.** interlock runs inside your
agent. Code sitting next to it could call the unguarded function directly, or
install an empty engine. Run code you do not trust &mdash; model-written scripts,
third-party plugins &mdash; in the [sandbox](guides/sandbox.md), not just behind
a guard.

</li>

<li markdown>

**There is no "ask a human" verdict yet.** A call is allowed, blocked, or
rewritten. A fourth verdict that pauses for human approval is on the
[roadmap](https://github.com/SourceShift/InterLock/blob/main/ROADMAP.md).

</li>

</ul>

The [security model](security-model.md) is the full version, including the
settings that quietly weaken protection and the gaps we have not closed.

## Read the docs

<div class="grid cards" markdown>

- **Start here**

    ---

    [Getting started](getting-started.md) &mdash; about fifteen minutes. Guard a
    tool, block a dangerous call, rewrite a risky one, catch an injected
    instruction, and try a rule without enforcing it. Every snippet was run, and
    the output is what it printed.

- **Understand it**

    ---

    [How interlock works](concepts.md) &mdash; events, rules, verdicts, how they
    combine, and what happens when a rule crashes.

    [Security model](security-model.md) &mdash; what it protects against, what it
    assumes, and where it stops.

- **Pick your defence**

    ---

    [Using detectors](guides/detectors.md) &mdash; choose from 105 built-in
    rules, and make sure they see your tools.

    [Writing rules](guides/writing-rules.md) &mdash; from one-liners to
    result-phase rules and tests.

- **Deploy it**

    ---

    [Production checklist](guides/production.md) &mdash; monitor mode, logging,
    and rollout.

    [Scopes](guides/scopes.md) and [audit log](guides/audit-log.md) &mdash;
    per-tenant policy and a tamper-evident record of every decision.

- **Connect it**

    ---

    [Integrations](guides/integrations.md) &mdash; `@guard`, MCP, LangChain, a
    model SDK loop, or a Node.js agent.

    [MCP](guides/mcp.md) &mdash; guard a session and decide which servers and
    tools to trust.

- **Look it up**

    ---

    [Python API](reference/python-api.md) &mdash; every public class and function,
    with signatures.

    [Detector catalog](reference/detectors.md) &mdash; all 105 detectors: what
    each catches, and which calls it sees.

</div>

<p class="il-flow" markdown>

[Get started :material-arrow-right:](getting-started.md){ .il-btn .il-btn--primary }

</p>

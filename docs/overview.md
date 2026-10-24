# interlock documentation

interlock checks every tool call your AI agent makes, inside the agent's own
process, and allows, blocks, or rewrites it before it runs. These docs take you
from a first guarded function to a production deployment.

**New here?** Do the [getting started](getting-started.md) tutorial (about fifteen
minutes), then read [how interlock works](concepts.md).

## How these docs are organised

| Section | What it's for | Read it when |
|---|---|---|
| [Getting started](getting-started.md) | A guided first run, every step with real output | You've never used interlock |
| [Concepts](concepts.md) | How a decision is made: events, rules, verdicts, order, failures | You want to understand what you're relying on |
| [Security model](security-model.md) | What interlock protects against, what it assumes, where it stops | Before you trust it with anything that matters |
| Guides (below) | Step-by-step instructions for one task each | You know what you want to do |
| Reference (below) | Every function, parameter, detector, and CLI flag | You need an exact name or default |

## Guides

| Guide | You'll learn to |
|---|---|
| [Console](guides/console.md) | Build and launch the local web UI over your running policy engine |
| [Writing rules](guides/writing-rules.md) | Block, rewrite, check results, scope rules to tools, and test your policy |
| [Using detectors](guides/detectors.md) | Pick from the 120 built-in detectors, make sure they see your tools, and start from a tested set |
| [Declarative policies](guides/policies.md) | Write rules as JSON/YAML, lock the ones that must stay on, and accept project overlays safely |
| [Approvals](guides/approvals.md) | Hold a call for a human with `ESCALATE`, and write an approver |
| [Coding agents](guides/coding-agents.md) | Guard Claude Code, Codex and Cursor with one command |
| [Credentials](guides/credentials.md) | Let agents use secrets they never see |
| [Databases and APIs](guides/databases.md) | Judge SQL by what it does, mask what comes back, keep personal data out of queries |
| [Review queue](guides/reviews.md) | Refuse now, let a human approve later, run the identical retry once |
| [Integrations](guides/integrations.md) | Connect `@guard`, MCP, LangChain, a model SDK loop, or a Node.js agent |
| [MCP](guides/mcp.md) | Guard MCP sessions and decide which servers and tools to trust |
| [Scopes](guides/scopes.md) | Give each tenant, agent, and sub-agent its own rules |
| [Audit log](guides/audit-log.md) | Keep a tamper-evident record of every decision |
| [Sandbox](guides/sandbox.md) | Run subprocesses under OS-level confinement built from your policy |
| [Mesh](guides/mesh.md) | Subscribe to community policy packs, verified from a pinned root and applied in monitor mode first; or publish a commons |
| [Production checklist](guides/production.md) | Roll out safely: prove protection is on, monitor mode, refusals, logging, deployment |

## Reference

| Page | Covers |
|---|---|
| [Python API](reference/python-api.md) | Every public class and function, with signatures |
| [Detector catalog](reference/detectors.md) | All 120 detectors: what they catch, which calls they see, how to build them |
| [Command line](reference/cli.md) | `interlock doctor`, `report`, `hook`, `install-hook`, `policy`, `learn`, `trust`, `mcp`, `reviews`, `drift` |
| [Sidecar](reference/sidecar.md) | The `interlock-sidecar` daemon for Node.js agents, and its wire protocol |
| [Node.js client](https://github.com/SourceShift/InterLock/blob/main/js/README.md) | The `interlock-guard` npm package |
| [Native scope store](https://github.com/SourceShift/InterLock/blob/main/rust/README.md) | The optional Rust backend for very large scope trees |

## More

- [Roadmap](https://github.com/SourceShift/InterLock/blob/main/ROADMAP.md): what's planned and why.
- [Contributing](https://github.com/SourceShift/InterLock/blob/main/CONTRIBUTING.md): development setup, adding a detector,
  keeping these docs accurate.
- [How other projects document themselves](https://github.com/SourceShift/InterLock/blob/main/research/readme-docs-benchmark.md):
  the research behind this layout.

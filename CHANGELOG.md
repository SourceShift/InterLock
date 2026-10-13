# Changelog

All notable changes to interlock are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0. While the version is `0.x`, the minor number is where
breaking changes land.

## [Unreleased]

Nothing yet.

## [0.0.1] — 2026-10-13

The first tagged release. interlock is alpha: the core API is stable and covered
by tests, but expect the surface to move before 1.0.

### Added

- **Guardrails for agent actions.** `@guard()` decides on every tool call before
  it runs, with three verdicts rather than two: allow, block, or **rewrite**
  (mask a secret, cap a value, force a dry run).
- **Result checking.** `@guard()` also inspects what a tool *returns*, so
  instructions injected through a web page, an email, or a document can be
  stopped before the agent reads them.
- **105 detectors** covering prompt injection, SQL and shell injection, secret
  and PII redaction, SSRF, network egress, MCP server trust, budgets, and loops.
  See the [detector catalog](docs/reference/detectors.md).
- **MCP trust.** Allowlist servers, pin tool schemas, catch a changed tool
  listing, and issue time-limited capability grants.
- **Scopes.** Per-tenant and per-agent policy trees, with an optional native
  accelerator (`interlock_scopes`, Rust) that resolves identically to the
  pure-Python fallback.
- **Audit log.** Chained, signed receipts for every decision. Arguments are
  hashed, not stored.
- **BRACE sandbox.** Runs subprocesses under bubblewrap on Linux or Seatbelt on
  macOS, generated from the same policy that guards the calls.
- **Node.js client.** The `interlock-guard` npm package and `interlock-sidecar`
  daemon apply the same Python policy to JS agents.
- **Integrations.** MCP client sessions, LangChain tools, and generic OpenAI /
  Anthropic tool loops via `enforce_tool_call` / `enforce_tool_result`.

### Notes

- Pure Python, no runtime dependencies, works offline. The `mcp` and `langchain`
  extras are optional.
- Not yet published to PyPI or npm; install from GitHub and pin a commit.
- Known limits are documented in the [security model](docs/security-model.md) —
  in particular, no rules installed means everything is allowed.

[Unreleased]: https://github.com/SourceShift/InterLock/compare/v0.0.1...HEAD
[0.0.1]: https://github.com/SourceShift/InterLock/releases/tag/v0.0.1

# Changelog

All notable changes to interlock are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0. While the version is `0.x`, the minor number is where
breaking changes land.

## [Unreleased]

### Added

- The mesh, phase 0 (`interlock mesh`, `interlock.mesh`): subscribe to
  community policy packs with `"extends": "mesh:<pack>@<ring>"`. A node pins a
  root and syncs a commons through TUF-shaped metadata (root, targets,
  snapshot, timestamp: thresholds, expiry, rollback and hash checks) over any
  HTTP or `file://` mirror, with pure-Python Ed25519. Rules carry a `status`;
  the node's ring decides which it installs and caps their verdict (`ceiling`),
  and every rule new to the node spends a monitor window in `"mode": "shadow"`,
  recorded but not enforced, then reloads into enforcement. Policy loads read
  the verified cache only and fail closed. `interlock mesh keys|publish|verify`
  run a commons; `interlock doctor` reports a stale subscription. Receipts gain
  an optional `catalog` field (the installed detector set's hash) once
  `interlock.receipt.set_catalog_id` is called.

- The console (`python -m interlock.console`, `interlock-console`): a local
  web app on loopback for the person running the agent - activity, the review
  queue, the audit log with a live tail, the policy editor with overlays and
  trust, the playground, the detector catalog, the scopes and sandbox
  inspector, and ops (doctor, hooks, MCP servers, sidecar). Writes need a tab
  unlocked with a one-off code the console prints to its own terminal, so an
  agent on the same machine can't approve itself through it.
- `interlock.tamper` also flags an HTTP client calling the console's unlock or
  write routes; `metrics.snapshot()` reports histogram p50/p99 latency.
- `Verdict.ESCALATE`: hold a call for a human approver, bound to the exact
  call (one-use by default; session and TTL scopes; a block always wins; no
  approver means blocked). `NotApproved` is raised when it isn't approved.
- A durable review queue (`interlock.reviews`, `interlock reviews ...`): refuse
  now with a review id, release the identical retry exactly once after a human
  approves; quorum, two expiry clocks, a read-only MCP status server.
- Coding-agent hook adapters for Claude Code, Codex and Cursor
  (`interlock install-hook`), with the `builtin:coding-agent` policy pack.
- Declarative JSON/YAML policies with load-time typo checks, quarantine,
  locked rules, hot reload and trust-gated project overlays
  (`interlock policy`, `interlock trust`).
- Shell commands judged by what they do (`interlock.shell`,
  `command_intent_guard`); SQL judged by its effects and tables
  (`interlock.sql`, `sql_statement_guard`).
- A masking engine with checksum-validated entities, column rules and
  redact/mask/partial/keyed-hash strategies (`data_masking_guard`,
  `pii_argument_guard`); masked counts in receipts and reports.
- `runbook_guard`, `http_request_guard`, `http_status_guard`,
  `mcp_elicitation_guard`, `result_size_guard`, `tool_output_secret_redactor`.
- Receipt provenance (`call_id`, `policy_epoch`, `policy_verdict`,
  `approval`, `outcome`/`enforcer`, `elapsed_us`, `masked`), fail-closed sink
  writes, and `FileSink(shared=True)` for several writers.
- `interlock doctor`, `interlock report`, `interlock mcp scan`, and
  `interlock.posture.attest()` / `require()`.
- `interlock.metrics` (Prometheus text) and `interlock-sidecar --admin`.
- Sidecar clients choose what an unreachable daemon means
  (`unreachable="deny" | "degraded" | "allow"`), with a signed offline
  fallback policy (`interlock-sidecar --fallback-policy`).
- Placeholder credentials (`interlock.credentials`): `{{secret:id}}` filled
  after the decision, only where allowed, and scrubbed from results.
- Conformance suites: every rule of the coding-agent pack through the Claude
  Code, Codex and Cursor hooks, and every catalog detector against actions that
  must end in each of its verdicts and look-alikes that must not
  (`tests/conformance/`, `python3 tests/conformance/runner.py`).

### Changed

- Every enforcement site dispatches through one exhaustive function, so a
  verdict it doesn't know is blocked rather than allowed (Python and Node.js).
- `destructive_command_guard` and `git_credential_guard` also parse commands;
  the parsed check only adds findings (`parse=False` keeps the old behaviour).
- A failed receipt write raises `Blocked` (policy `audit_sink`) instead of the
  sink's own exception.
- `token_budget_guard` lets a window reach its `limit` and blocks the call that
  goes over it, like the other budget rules (it used to block on reaching it).
- `destructive_command_guard`'s raw-text check blocks `dd` only when `of=` is a
  block device; `dd ... of=scratch.img` makes a file and is allowed.

### Fixed

- Claude Code results are checked where the text actually is: a `Read` result's
  file content is now scanned for injected instructions and masked in place, and
  an `Edit`/`Write` result no longer blocks on the agent's own content echoed back.
- Coding-agent hooks spell a path in its on-disk case on case-insensitive
  volumes, so `~/.SSH/id_rsa` still matches the pack's secret-file rules.
- `private_ip_egress_guard` and `raw_ip_egress_guard` read every IPv4 spelling a
  client dials (`http://2130706433/`, `0x7f.1`, `0177.0.0.1`, IPv4-mapped IPv6),
  not just dotted quads.
- `markdown_link_injection_guard` and `markdown_image_exfil_guard` match
  regardless of letter case.
- `output_secret_redactor` masks scoped `sk-proj-` / `sk-ant-` keys.
- `tool_output_secret_redactor` no longer masks snake_case identifiers as values.

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

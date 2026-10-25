# Changelog

All notable changes to interlock are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project aims to follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
once it reaches 1.0. While the version is `0.x`, the minor number is where
breaking changes land.

## [Unreleased]

### Added

- `interlock.attach()` / `detach()` / `uncovered()`: the opt-in import hook
  (ROADMAP R11). `attach()` patches
  `mcp.client.session.ClientSession.call_tool` at the class - immediately when
  the SDK is already imported, through a `sys.meta_path` finder when it is
  imported later - so every session created afterwards is guarded on its first
  call with no per-session wiring. It is idempotent (the class is never wrapped
  twice), `detach()` restores the original method, and a failing hook never
  breaks the user's import. `uncovered()` reports the surfaces this process has
  not guarded, with the explicit adapter that guards each; the model SDKs stay
  adapter-guarded because they return tool-call requests rather than executing
  tools.
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
- The mesh, phase 1: reporting and consensus. `interlock mesh report
  init|build|submit` projects a receipt log into a signed report of rule
  counts (per verdict, tool class, phase and hour), argument digests of what
  was blocked or escalated (never from redacting rules, rewrites or monitor
  mode), and operator false-positive sightings; counts leave the node as
  additive secret shares to two or more aggregators (`interlock.mesh.aggregate`).
  `interlock mesh serve --role consensus|aggregator` is a standard-library
  reference implementation of the collectors; the consensus engine
  (`interlock.mesh.consensus`) requires a known detector catalog, weights
  reporters by tenure and canary agreement, needs distinct organisations
  before an indicator is active, demotes rules on multi-organisation
  false-positive sightings, expires stale indicators, and exports a public
  stats document and an indicator pack. The `mesh_indicator_guard` detector
  blocks (or escalates) a call whose argument digest is a published indicator.
- The mesh, phase 2: similarity and the forge. `interlock mesh report enable`
  installs a decision observer (`interlock.receipt.add_decision_observer`, a
  new hook that sees event, decision and receipt and can never change a
  decision) that records private fingerprints of what the guard blocked:
  redact, SimHash-embed, quantise to 768 bits, randomised response with budget
  `alpha` (local differential privacy), plus opt-in redacted samples per rule.
  The consensus engine clusters fingerprints into campaigns and exports a pack
  for the new `mesh_similarity_guard` detector, which escalates a live call
  within Hamming distance of a published fingerprint. `interlock mesh harness`
  measures a policy's false-positive rate, latency percentiles and recall over
  a benign corpus and attack samples (the roadmap's R5 gate); `interlock mesh
  forge` drafts gated, reviewable proposals (indicators, campaigns, and shared
  fragments from multi-organisation samples; an optional drafter hook) and
  writes them as pull-request-shaped directories, never publishing.
- The mesh, phase 3: decentralise. A commons with a `log` key keeps an
  RFC 6962/9162 Merkle transparency log of every published document and pack
  (`interlock.mesh.log`, with inclusion and consistency proofs) and signs a
  checkpoint per publish; a subscriber refuses unlogged, rewritten or
  shrunken history at sync, `interlock mesh log` walks a site's log, and
  `interlock mesh gossip --peer URL` compares checkpoints to catch split
  views (`status` shows them, `doctor` fails on them). `interlock mesh serve
  --role mirror` seeds a node's verified cache to peers read-only and answers
  gossip. `interlock mesh credential init|issue|revoke|verify`
  (`interlock.mesh.credential`) issues one pseudonymous membership certificate
  per member per weekly epoch, unlinkable to verifiers and accountable to the
  issuer; collectors started with `--require-credential` refuse reports
  without one, and `report build --credential FILE` attaches it.
- Mesh root ceremonies: `interlock mesh root draft|sign|assemble`
  (`interlock.mesh.repository.draft_root`, `sign_root`, `assemble_root`) sign
  a new commons root with keys on separate machines. `draft` writes the
  unsigned next root from the online keys and the root public keys in
  `keys/root-keys.json`; each keyholder's `sign` writes a detached
  `FILE.sig.<keyid>`, from a key file or `--external-signer CMD` (stdin: the
  bytes, stdout: the hex signature, for a hardware token); `assemble` checks
  the previous root's threshold and the new root's own before it writes
  `metadata/<N>.root.json` and logs it. `build_root` records each root key's
  `x-interlock-keyowner` and `x-interlock-term-start`. New `GOVERNANCE.md`
  (who holds the commons' keys) and
  [root ceremony guide](docs/guides/mesh-root-ceremony.md).
- A data licence and a data warranty for the mesh commons (decision R4). New
  top-level `LICENSE-DATA`: indicators, fingerprints and redacted samples,
  wherever they appear, are CC0-1.0, while code and packs stay Apache-2.0
  under `LICENSE`. `CONTRIBUTING.md` adds a three-clause data warranty under
  the DCO sign-off (lawfully obtained, no personal data, no third party's
  confidential data) and says there is no CLA. `GOVERNANCE.md` adds the intake
  floor for upstream packs (the licence must permit ingest, modification and
  redistribution) and the erasure procedure (a sample with personal data
  leaves the tree and the next release within 30 days). A pack names its
  licence as an SPDX id in `license` (`normalize_pack` defaults it to
  `Apache-2.0`, and `pack_summary` publishes it in the targets `custom`
  field); a rule may carry its own `license`, metadata only and outside
  `rule_digest`; the policy loader also accepts a document's `provenance`.
  `ConsensusEngine.export_indicators` and `export_similarity` stamp
  `"license": "CC0-1.0"`, and every forge proposal's `pack.json` and
  `PROPOSAL.md` carry its licence and `provenance` (source, organisations, run
  time); an indicator or similarity candidate's `organisations` now counts the
  organisations behind it instead of restating `min_orgs`. `interlock mesh
  consensus forget --state FILE --sample DIGEST`
  (`ConsensusEngine.forget_sample`) erases a sample from a consensus state.
- Full DAP/Prio3 wire compatibility for mesh counts (decision R2 step 3).
  Counts can now be reported as one **Prio3** report over
  `draft-ietf-ppm-dap-20`: `interlock mesh dap task` writes a `task.json` and
  one key file per role; `interlock mesh dap submit` maps a node's counts to an
  ordered bucket vector, refuses an out-of-range or two-batch report, shards it
  with `Prio3SumVec` (VDAF `draft-irtf-cfrg-vdaf-22`, codepoint `3`, validity
  proofs over Field128 with TurboSHAKE128), and HPKE-encrypts one share to each
  aggregator (RFC 9180 base mode, X25519 / HKDF-SHA256 / AES-128-GCM);
  `interlock mesh dap collect` unshards both aggregate shares with the
  collector key. `interlock mesh serve --role dap-leader|dap-helper` runs both
  aggregator roles: binary DAP messages, the `/hpke_config` route, uploads,
  aggregation jobs, collection jobs and aggregate shares, RFC 9457 problem
  documents with the draft's error tokens, and a batch rule that releases only
  a fixed `time_precision` interval, once, over at least `min_batch_size`
  verified reports. A failed proof is dropped, a replay is refused, and a
  second collection of an overlapping interval is refused. The upload path
  reuses the counts consent and `INTERLOCK_MESH_NO_REPORT=1` refuses before a
  socket is opened. Pure-Python X25519/AES-GCM/TurboSHAKE128 are correct but
  not constant-time, as documented for the mesh's Ed25519; there is no live
  interop test against a third-party DAP implementation, so correctness rests
  on the official VDAF and HPKE vectors plus wire and end-to-end tests.

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

- The review queue signs every row with an HMAC-SHA256 key kept beside the
  database (`reviews.key`, mode 0600) and outside it: editing the SQLite file
  alone can no longer approve a call, redirect an approval to another binding,
  edit the preview an approver is shown, or add an approver to satisfy
  `min_approvals` - the queue refuses a row it did not write.
  `ReviewQueue(key=..., key_path=...)` separates the key from the database;
  a pre-signing database is sealed on first open.

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
- Mesh counts leave a node only as secret shares, and no total is released
  below a batch floor. The signed report envelope no longer carries `counts`
  (`interlock.mesh.report.build_counts` projects them separately), and
  `verify_report` refuses one that does, so `interlock mesh report submit`
  sends the consensus service digests and sightings only. `report build --out
  FILE` writes the count vector to `FILE.counts.json` (0600) for `submit` to
  share with two or more aggregators. The consensus engine counts organisations
  per rule from digests and sightings; `/v1/stats` and `export_stats()` keep
  the `rules` shape but `verdicts` is `null`, and a state file written before
  this change is scrubbed on load. `Aggregator.totals` and `combine_totals`
  refuse fewer than `min_batch` reconciled reports (default 3, at least 2;
  `mesh serve --role aggregator --min-batch N`); `POST /v1/totals` answers 422
  below it and `GET /v1/manifest` names it. Fire counts come from
  `interlock mesh consensus export --stats --aggregator URL --aggregator URL`
  (`interlock.mesh.aggregate.fire_totals`). Breaking: reports built before
  this change are refused, and reporters and collectors upgrade together.
- A mesh rule's `block` takes effect only with an operator grant (decision R5).
  The stable status's default ceiling is `modify`, so a community block is
  capped to an escalate on every ring; `interlock mesh grant block --pack P
  [--status S]` or `--rule ID [--pack P]` lifts it to the pack's verdict
  (`grant --list`, `grant revoke ...`; stored as `grants` in the node's
  `config.json`, which a watched policy now reloads on). A pack grant matches
  the subscribed name, not the pack's own `name`. Installed mesh rules carry
  `"origin": "mesh"` (a pack may not set it), `mesh resolve` reports `granted`
  and `capped`, and `mesh status` and `doctor` print "N mesh rules capped at
  escalate; no approver installed: shadow only". With no approver installed, a
  capped mesh rule's escalation (`Decision.mesh_ceiling`) is recorded as a
  shadow finding and the call proceeds (receipt `approval:
  shadow:no-approver`) where interlock settles it in process; every other
  escalation is still `NotApproved`, and a capped mesh escalation never
  replaces a local one. A `config.json` whose `ceilings` are exactly what
  `init` used to write reads as the new defaults. Breaking: a stable
  subscription stops blocking until its operator grants it.
- `interlock mesh publish` no longer needs a root key: `load_signers` requires
  only the targets, snapshot and timestamp keys (and log when present), and
  `publish` re-publishes the current root while the online keys match it and
  it has not expired. It refuses, saying a root ceremony is needed, when a new
  root is needed and the root keys are not there. Root metadata now expires
  after 197 days instead of 365, with a 46-day signing period
  (`metadata.ROOT_SIGNING_PERIOD`): `publish` warns inside it (the summary's
  `warnings`), with root keys present it signs the next root itself, and
  `interlock doctor` reports a subscription's root as due (`mesh.root` WARN) or
  expired (FAIL).
- Mesh reporting is off by default, local by default and never retroactive
  (decision R3). `interlock mesh report enable` is the one consent point: it
  records the enable time and the enabled layers in the node's `state.json`
  (`Subscriber.report_consent()`, `set_report_consent()`) and needs no commons.
  A bare `enable` turns on counts and sightings, `--digests`, `--fingerprints`
  (with `--alpha`) and `--sample RULE` each add their own layer, and `--off`
  turns them all off, the recorder included. Adding a layer moves the enable
  time to now. `build_report` and `build_counts` take keyword-only
  `enabled_since` and `enabled_layers`, which clamp `since` to the enable and
  keep only the enabled layers; `report build` applies them, and with nothing
  enabled it still builds the full report as a local preview. `report submit`
  refuses, before any connection, a report while reporting is off, a report
  built over time before the enable, and any layer (or counts to share) that
  is not enabled, naming the flag; it takes `--dir`. `INTERLOCK_MESH_NO_REPORT=1`
  makes `interlock.mesh.report.submit` refuse every upload (reports, shares,
  totals queries, gossip) with a `ReportError`. The new `interlock mesh report
  status`, `mesh status` and `doctor` (check `mesh.report`) show the consent and
  a preview of what a report would hold now; `Subscriber.status()` carries
  `report` instead of `recorder`. `GOVERNANCE.md` states that early-ring
  credentials go to organisations that report. Breaking: `submit` refuses until
  the operator runs `report enable`; `report enable --alpha` needs
  `--fingerprints`; and the recorder follows the consent, not `config.json`'s
  `recorder`, so a node that recorded before this change records again only
  after `report enable --fingerprints` or `--sample RULE`.
- Mesh samples need the reporter's data warranty. `interlock mesh report
  enable --sample RULE` refuses (exit 64) without `--i-warrant-samples`, which
  records `{"warranty": "lawful,no-personal-data,no-confidential", "at": TIME}`
  as the `attestation` of the reporting consent in `state.json`
  (`Subscriber.set_report_consent(..., attestation=)`, which refuses samples
  without it). A consent record whose samples have no warranty reads as no
  samples, so the recorder keeps none and `report build` leaves them out.
  `build_report(..., attestation=)` puts it in every body that carries samples
  (`interlock.mesh.report.WARRANTY`, `new_attestation`, `check_attestation`),
  `verify_report` refuses samples without it, and the consensus engine stores
  it with each sample and drops unattested samples from an older state on
  load. Breaking: a report with samples built before this change is refused,
  so nodes that share samples upgrade with the consensus service, and a node
  that enabled samples before this change runs `report enable --sample RULE
  --i-warrant-samples` again.

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

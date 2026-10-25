# Security model

This page says what interlock protects against, what it assumes, and where it
stops. Read it before you rely on interlock for anything that matters. A guard
you overestimate is worse than one you know the edges of.

## What interlock is for

interlock defends against an agent that is **confused or manipulated** into
doing harm with the tools you gave it. Typical cases:

| Threat | How interlock helps |
|---|---|
| The agent runs a destructive command (`rm -rf`, `DROP TABLE`) | Call rules and detectors block it before it runs |
| Injected instructions in a web page, email, or document steer the agent | Result rules keep the poisoned output from the agent; call rules limit what a steered agent can do |
| The agent sends data to a host it shouldn't | Egress allowlists block the call |
| Secrets or personal data end up in an outbound message | Redaction detectors mask them and let the message through |
| An MCP server changes its tools after you reviewed them | Pinning, surface baselines, attestation, and leases refuse the changed server |
| A loop or a hijacked agent burns money or calls | Rate, budget, and loop detectors cut it off |
| A sub-agent grants itself more than its parent had | Scope delegation refuses the over-grant when rules are resolved |
| The agent launches a subprocess that escapes in-process checks | BRACE runs it in an OS sandbox built from the same policy |
| Someone edits the record of what the agent was allowed to do | Chained receipts make tampering detectable |
| A coding agent (Claude Code, Codex, Cursor) runs `rm -fr ~`, force-pushes, or reads `~/.ssh` | The [hook adapters](guides/coding-agents.md) apply the same policy to its tool calls, parse shell commands by what they do, and withhold injected or secret-bearing tool output |
| A legal but consequential call (a payment, a publish) happens without anyone deciding | An [ESCALATE](guides/approvals.md) verdict holds it for an approver bound to that exact call |
| A credential in the agent's context leaks into arguments or logs | [Placeholder credentials](guides/credentials.md) keep the value out of the model's reach |
| Protection is silently off (no rules, monitor mode, a dead sidecar) | `interlock.posture.attest()` / `require()` and `interlock doctor` report it |

## What interlock assumes

- **The agent's own code is trusted; its decisions are not.** interlock runs
  inside the agent's process. It reliably checks the calls that go through the
  guarded functions. It can't stop *malicious code* running in the same process,
  which could call the unguarded function directly, patch interlock out, or
  install an empty engine. Run code you don't trust (model-written scripts,
  third-party plugins) in a [sandbox](guides/sandbox.md), not just behind a
  guard.
- **You guarded the paths that matter.** interlock only sees calls that go
  through `@guard`, a wrapped MCP session, wrapped LangChain tools, or your own
  call to `enforce_tool_call`. A tool you didn't wrap is invisible to it.
- **Your rules are right.** interlock enforces your policy faithfully. It can't
  tell you the policy is missing a case.

## What interlock does not do

- **It doesn't understand intent.** The detectors match specific patterns,
  tuned so ordinary values don't trigger them. That keeps false alarms low, and
  it means a reworded attack can get through: `tool_result_injection_guard`
  catches "ignore previous instructions" but not "ignore *all* previous
  instructions". Treat detectors as layers, not as a complete defence, and pair
  them with allowlists, which don't depend on wording.
- **It isn't a content moderator.** There's no model-based classifier for
  toxicity, harmful content, or topic control. Use a dedicated tool for that if
  you need it.
- **It doesn't undo actions.** A result is checked after the tool ran. Blocking
  it hides the output; the side effects stand.
- **It doesn't see network traffic.** It sees the call your code makes, not the
  bytes on the wire. Code that opens its own sockets outside a guarded function
  isn't checked (in Python; the Node.js client can patch `fetch`).

## Settings that weaken protection

Each of these is sometimes the right choice. Make it on purpose.

| Setting | Effect | Reasonable when |
|---|---|---|
| Never calling `install()` | The default engine is empty and **allows every call** | Never in production |
| `enforcement="monitor"` / `@monitor()` | Rules are evaluated and logged, nothing is blocked; receipts are marked `observed` | Trialling new rules |
| `ScopedEngine(..., allow_unscoped=True)` | A call with no principal matches no scope and is **allowed without running any rule** | Every guarded call already runs inside `span(principal=...)`, and you've checked |
| A hand-written rule that can raise | The caller gets the rule's exception, not `Blocked`; code that only catches `Blocked` may mishandle it | Wrap risky tests in `deny_when` |
| `Sandbox(..., backend="soft")`, or a host where only `soft` is available | Resource limits and a clean environment only; **not a security boundary** | Local development. In production, pass `require=` so `run()` refuses a weak backend |
| Granting hosts to a sandbox profile | bubblewrap and Seatbelt can't filter by host, so the child gets **all** network; `net` is left out of `enforced` | The child is trusted with network access, and in-process egress rules cover the rest |
| `FileSink(path)` without `key=` | A random per-process key; after a restart, nobody can verify the old receipts | Tests |
| Several processes appending to one audit file at once | Their receipts fork the chain; `verify()` reports the fork as a break. `FileSink(path, shared=True)` locks the file and keeps one chain | Never without `shared=True` |
| `RemoteEngine(..., timeout=None)` (Python or Node.js) | No timeout: a hung sidecar hangs every guarded call. The default is 5 seconds | Never in production |
| `RemoteEngine(..., unreachable="allow")` (Python or Node.js) | When the sidecar can't be reached, every call is **allowed unchecked** (with a warning each time). A sidecar that answers with an error still blocks | Availability matters more than enforcement, and someone watches the warnings |
| `RemoteEngine(..., unreachable="degraded")` (Python or Node.js) | When the sidecar can't be reached, only its signed offline fallback policy is enforced, which is a subset of the real one. A missing, tampered or stale fallback file still blocks | You keep the fallback to the rules you need standing with the daemon down |

## Cryptography and the mesh

interlock's mesh primitives are pure Python, because the default install has
`dependencies = []`: Ed25519 for signatures, X25519, HKDF-SHA256 and
AES-128-GCM for DAP's HPKE, TurboSHAKE128 for Prio3, and the Prio3 field
arithmetic. Each is checked against its official test vectors (RFC 8032,
RFC 9180 A.1, NIST GCM, RFC 9861, the VDAF `test_vec/` files), and each is
**not constant-time**. A local attacker who can measure cache and branch
timing against a process holding a secret may recover it; the defence is
process isolation and a TLS-terminating proxy, not the arithmetic. An optional
Rust scope store exists, but the DAP path does not depend on it.

What the DAP path does and does not assume:

- **One honest aggregator.** A leader and a helper each see one additive share
  of every report. Either alone learns nothing about a vector; together, or
  with a colluding operator, they learn it. The pair must be distinct legal
  entities ([GOVERNANCE.md](https://github.com/SourceShift/InterLock/blob/main/GOVERNANCE.md)).
- **The collector is the only reader.** Both aggregate shares are encrypted to
  the collector's HPKE key, so a compromised aggregator host cannot decrypt the
  other's share or the result.
- **A client cannot inflate its counts.** The Prio3 validity proof is verified
  by the helper; a report that fails is dropped before it joins a batch. The
  client refuses out-of-range or two-batch counts before it builds a report.
- **Batches are fixed and collected once.** Overlapping collection is refused,
  so a caller who may collect cannot difference two totals to isolate a node
  that way, and a batch below `min_batch_size` is not released.
- **Transport is the proxy's job.** The reference servers speak plain HTTP on
  loopback and expect TLS in front. Bearer tokens between the aggregators and
  from the collector are compared in constant time, but they are secrets like
  any other.
- **A malicious leader can still drop reports.** DAP gives integrity and
  privacy, not guaranteed delivery; dropping is a liveness attack and the
  collector sees a smaller batch (or a floor refusal), not a wrong total.
- **No live third-party interop run has been made.** The wire format follows
  `draft-ietf-ppm-dap-20` and the codecs are tested against the drafts'
  structures, but a deployment against another implementation should run the
  guide's interop checklist first.

## Known gaps

- **Only MCP can be attached at import time.** `attach()` patches
  `mcp.client.session.ClientSession.call_tool` once, so every session created
  afterwards is guarded on its first call; `detach()` removes the hook. The
  model SDKs (OpenAI, Anthropic, LangChain, LiteLLM, CrewAI, Google ADK) do not
  execute tools - they return a call request and your own dispatcher runs it -
  so there is no library method to wrap that would not also wrap your code.
  Guard the dispatcher with the matching `guard_*` adapter, and call
  `uncovered()` to see, per process, which surfaces are still unguarded
  ([Python API](reference/python-api.md)).
- **MCP trust labels come from your adapter, not the model.** Reserved `__*__`
  keys in model-produced arguments (`__origin__`, `__schema__`, `__attestation__`,
  `__tools__`) are stripped at every boundary before an event is built, so a
  model cannot claim a trusted server. Only the integration that knows the fact
  sets a label: `guard_mcp_session(origin=, schemas=)`, or an explicit `labels=`
  when you build an event with `enforce_tool_call`. A hand-built event with no
  labels stays untrusted ([MCP guide](guides/mcp.md)).
- **Approvals default to the agent's process.** An `ESCALATE` waits for the
  installed approver, which runs in-process: code that is already malicious
  there could install its own. The coding-agent hooks avoid this by handing
  escalations to the agent's native prompt, and the durable review queue
  (`interlock reviews approve`, or the opt-in console) lets a human decide from
  another process. Use one of those when the agent must not reach the decision
  ([approvals](guides/approvals.md), [reviews](guides/reviews.md)).
- **Shell commands are parsed best-effort.** The parser decodes ANSI-C quoting
  (`$'\x72\x6d'`) and a base64 payload piped into a shell, follows a script
  fetched in one command and run by a later one when both name the same literal
  path, and sees through respelling, wrappers (`sudo`, `env`, `xargs`),
  `sh -c`, substitutions and inline interpreter code. A payload encoded some
  other way (gzip, a rotated alphabet, an encryptor), and a path assembled at
  run time, still get past it. Parsed intent normally adds to the raw-text
  checks, but the destructive-command guard lets a complete parse clear a raw
  match when the command is a pure print (`echo rm -rf /`), so the union is not
  strictly add-only. Contain untrusted commands with BRACE.
- **SQL analysis and masking are best-effort.** The SQL analyzer is a lexer:
  a function called from a `SELECT` list is invisible to it. Masking detects
  formats and checksums, not meaning: names and places aren't detected, and a
  value transformed before it's returned (base64, say) isn't recognised.
  Database permissions and least-privilege credentials stay the boundary.
  **Accepted:** semantic SQL and PII understanding is out of scope.
- **The review queue is only as strong as its key directory.** Every row is
  signed with an HMAC key kept beside the database (`reviews.key`, 0600), so a
  process that can edit `reviews.db` alone can no longer approve a call,
  redirect an approval to another binding, edit the preview an approver sees,
  or forge an approver name (`tests/test_review_integrity.py`). The key is the
  boundary: a process that can read both files can forge, and one that can
  delete either can deny service, and restoring an older copy of *both* files
  replays decisions until `approval_ttl` expires. Keep `~/.interlock` private;
  put the key on separate storage (`key_path=`) when the database is shared.
- **Coding-agent hooks are cooperative, and agents differ.** Hooks see the tools
  an agent routes through them; they are not an OS boundary. Codex can't ask or
  rewrite at `PreToolUse` (those verdicts are refused) or withhold tool output;
  Cursor has no result hook. Claude Code's rewrite and output-replacement paths
  follow its documentation and are worth confirming on your version
  ([coding agents](guides/coding-agents.md)). **Accepted:** a hook adapter is
  cooperative by construction; only an OS boundary confines an agent.
- **The published false-positive rate covers one pack, on one machine.**
  `benchmarks/fp/benign.jsonl` holds 70 ordinary coding-agent calls, and
  `scripts/fp_baseline.py` measures `builtin:coding-agent` against them:
  **0 false positives, p95 ≈ 2 ms** on 2026-10-25 (`benchmarks/fp/README.md`).
  `tests/test_fp_baseline.py` re-runs it in CI, so a rule that starts firing on
  a routine `git status` breaks the build. That is a regression gate, not a
  guarantee: zero events out of 70 leaves a 95% upper bound near 4%, the corpus
  is one developer's traffic, and no per-detector number ships for other
  policies. `interlock mesh harness` measures yours against your own corpus.
  An attacker who can *trigger* blocks can use a fail-closed guard to stop your
  agent working.
- **OS-level per-host egress needs root.** Between bubblewrap's "all network or
  none" and nftables (per-host, root only, not selectable from `Sandbox`) there's
  no unprivileged middle ground. macOS's Seatbelt can't express a host allowlist
  at all. **Accepted:** use in-process egress rules for the gap, or run the
  sandbox as root with the nftables helper.
- **macOS sandboxing can't confine reads or process visibility,** and can't cap
  memory. `sandbox-exec` never reports `fs-ro` or `pid`, and a profile with
  `memory_mb` raises `LimitUnsupported` on macOS rather than running without the
  limit. **Accepted:** Seatbelt cannot express either; use Linux for a
  read-confined sandbox.
- **A sandbox timeout kills the process group; `setsid()` leaves it.** BRACE
  starts each sandbox in its own session so `timeout=` can kill the child and
  its descendants together, but a descendant that calls `setsid()` itself
  leaves that group. Under bubblewrap the child also gets its own PID namespace
  and `--die-with-parent`, so the kernel reaps the escapee when bwrap dies; the
  escape is live under `sandbox-exec` and `soft`. On Windows the timeout kill
  runs `taskkill /T`, which walks the parent/process-id tree, then kills the
  direct child - a process that has already reparented itself can still escape
  it. Its confinement and per-process rlimits still apply, and the caller's
  wait is bounded.
- **Write confinement differs by backend.** On macOS the Seatbelt profile
  grants writes only to the profile's `write_paths` plus one private per-run
  scratch directory (set as `TMPDIR`/`TMP`/`TEMP` and removed after the run);
  the shared temp roots (`/private/tmp`, `/private/var/folders`) and the rest
  of `/dev` stay unwritable. Under bubblewrap, `/tmp` is a fresh tmpfs and
  `/dev` a fresh private device tree, so writes there outside the run's own
  scratch bind stay inside the sandbox and never reach the host's shared temp
  roots; nothing outside the binds is visible. A scratch tree is left in place
  only when an escaped descendant still holds it open at timeout.
- **A resource ceiling is only as good as the host allows.** All three backends
  apply CPU/memory rlimits and report the `rlimit` token, but macOS rejects any
  address-space limit below ~1 TB (so `memory_mb` is refused there, not
  approximated) and Windows has no POSIX rlimits at all (any ceiling is
  refused). `check_limits` fails the launch rather than running without the
  ceiling the policy asked for. **Accepted:** the platform cannot express it.
- **Cutting the end off an audit log needs an outside record to catch.** The
  chain shows edits, deletions, and reordering inside the log, but a log with its
  last receipts removed is still a valid, shorter chain. Record `sink.head`
  somewhere the writer can't reach and pass it to `verify(head=...)`
  ([audit log](guides/audit-log.md)).
- **Receipts prove integrity, not authorship, by default.** The HMAC signature
  shows a log wasn't changed by someone without the key; it doesn't show which
  key holder wrote it. `interlock.receipt_ed25519` signs with a private seed
  and lets an auditor verify with only the public key (`verifier=`), at a few
  milliseconds per receipt; until you switch, the HMAC default stays
  ([audit log](guides/audit-log.md)).
- **Node.js has holes no JavaScript patch can close.** ESM named imports,
  `*Sync` calls, and handle-returning openers like `fs.createReadStream` aren't
  guarded. `installInterceptors().uncovered` lists them
  ([js/README.md](https://github.com/SourceShift/InterLock/blob/main/js/README.md)).
  **Accepted:** no JavaScript patch can reach those shapes; the sidecar or an OS
  sandbox is the boundary.
- **The Node.js client depends on a sidecar.** By default, if it's down, every
  guarded call is denied. `unreachable="degraded"` falls back to a signed
  offline subset of the policy, and `unreachable="allow"` lets calls through;
  both weaken protection and are listed above ([sidecar](reference/sidecar.md#when-the-daemon-is-down)).

## Reporting a vulnerability

Please don't open a public issue for a security problem. Contact the maintainers
privately through the [repository](https://github.com/SourceShift/InterLock)
owner's GitHub profile, and include a way to reproduce it.

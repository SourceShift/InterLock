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

## Known gaps

- **Python import-time hooks don't exist yet.** You wrap each session, tool list,
  or function explicitly. Automatic interception of MCP clients and model SDKs is
  on the [roadmap](https://github.com/SourceShift/InterLock/blob/main/ROADMAP.md).
- **MCP trust labels are only as good as your adapter.** `guard_mcp_session`
  strips any `__origin__` or `__schema__` the caller passes and adds the ones you
  configure (`origin=`, `schemas=`). If you build MCP events yourself with
  `enforce_tool_call`, never copy those keys from model-generated arguments
  ([MCP guide](guides/mcp.md)).
- **Approvals run in the agent's process.** An `ESCALATE` waits for the
  installed approver, which runs in-process: code that is already malicious
  there could install its own. The coding-agent hooks avoid this by handing
  escalations to the agent's native prompt ([approvals](guides/approvals.md)).
- **Shell commands are parsed best-effort.** The parser sees through respelling,
  wrappers (`sudo`, `env`, `xargs`), `sh -c`, substitutions and inline
  interpreter code, but obfuscation (`$'\x72\x6d'`, base64, a downloaded
  script) gets past it. It can only add findings to the raw-text checks, never
  remove them. Contain untrusted commands with BRACE.
- **SQL analysis and masking are best-effort.** The SQL analyzer is a lexer:
  a function called from a `SELECT` list is invisible to it. Masking detects
  formats and checksums, not meaning: names and places aren't detected, and a
  value transformed before it's returned (base64, say) isn't recognised.
  Database permissions and least-privilege credentials stay the boundary.
- **The review queue trusts its file.** Approvals live in a local SQLite file;
  anyone who can write it can approve anything, under any name. Keep it where
  the agent can't write (`~/.interlock` under the coding-agent policy).
- **Coding-agent hooks are cooperative, and agents differ.** Hooks see the tools
  an agent routes through them; they are not an OS boundary. Codex can't ask or
  rewrite at `PreToolUse` (those verdicts are refused) or withhold tool output;
  Cursor has no result hook. Claude Code's rewrite and output-replacement paths
  follow its documentation and are worth confirming on your version
  ([coding agents](guides/coding-agents.md)).
- **No measured false-positive rate.** The detectors are tested for matches and
  non-matches, but there's no published benchmark of how often they block
  harmless traffic. An attacker who can *trigger* blocks can use a fail-closed
  guard to stop your agent working. A robustness harness is planned.
- **OS-level per-host egress needs root.** Between bubblewrap's "all network or
  none" and nftables (per-host, root only, not selectable from `Sandbox`) there's
  no unprivileged middle ground. macOS's Seatbelt can't express a host allowlist
  at all.
- **macOS sandboxing can't confine reads or process visibility,** and can't cap
  memory. `sandbox-exec` never reports `fs-ro` or `pid`, and a profile with
  `memory_mb` raises `LimitUnsupported` on macOS rather than running without the
  limit.
- **A sandbox timeout kills the process group; `setsid()` leaves it.** BRACE
  starts each sandbox in its own session so `timeout=` can kill the child and
  its descendants together, but a descendant that calls `setsid()` itself
  survives the kill. Its confinement and per-process rlimits still apply, and
  the caller's wait is bounded. On Windows only the direct child is killed.
- **Write confinement differs by backend.** On macOS the Seatbelt profile
  grants writes only to the profile's `write_paths` plus one private per-run
  scratch directory (set as `TMPDIR`/`TMP`/`TEMP` and removed after the run);
  the shared temp roots (`/private/tmp`, `/private/var/folders`) and the rest
  of `/dev` stay unwritable. Under bubblewrap, `/tmp` is a fresh tmpfs and
  `/dev` a fresh private device tree, so writes there outside the run's own
  scratch bind stay inside the sandbox and never reach the host's shared temp
  roots; nothing outside the binds is visible. A scratch tree is left in place
  only when an escaped descendant still holds it open at timeout.
- **CPU and memory limits are reported only by `soft`.** bubblewrap and Seatbelt
  apply them too, but leave `rlimit` out of `enforced` until those rows join the
  tested guarantee matrix.
- **Cutting the end off an audit log needs an outside record to catch.** The
  chain shows edits, deletions, and reordering inside the log, but a log with its
  last receipts removed is still a valid, shorter chain. Record `sink.head`
  somewhere the writer can't reach and pass it to `verify(head=...)`
  ([audit log](guides/audit-log.md)).
- **Receipts prove integrity, not authorship, by default.** The HMAC signature
  shows a log wasn't changed by someone without the key; it doesn't show which
  key holder wrote it. For third-party verification, sign with a public-key
  scheme and verify with `verifier=` ([audit log](guides/audit-log.md)).
- **Node.js has holes no JavaScript patch can close.** ESM named imports,
  `*Sync` calls, and handle-returning openers like `fs.createReadStream` aren't
  guarded. `installInterceptors().uncovered` lists them
  ([js/README.md](https://github.com/SourceShift/InterLock/blob/main/js/README.md)).
- **The Node.js client depends on a sidecar.** By default, if it's down, every
  guarded call is denied. `unreachable="degraded"` falls back to a signed
  offline subset of the policy, and `unreachable="allow"` lets calls through;
  both weaken protection and are listed above ([sidecar](reference/sidecar.md#when-the-daemon-is-down)).

## Reporting a vulnerability

Please don't open a public issue for a security problem. Contact the maintainers
privately through the [repository](https://github.com/SourceShift/InterLock)
owner's GitHub profile, and include a way to reproduce it.

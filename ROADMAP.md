# Roadmap

Where interlock is going, item by item, with the reasoning and the done
criteria.

The short version lives in [`README.md`](README.md#roadmap). This file is the
long version: for each item still open, **what breaks today**, **why it is
worth doing now**, **what would actually change in the tree**, **what it costs
the people using the library**, **how we know it is finished**, and **what
could stop it**.

Everything here is scoped so it can ship on its own. Nothing in this file is a
promise about a date — it is an ordering by expected value, so that if the
project stops after the next item, it stopped in the right place.

---

## How to read this

**Status** is one of:

| Status | Means |
|---|---|
| `not started` | No code in the tree for it. |
| `partial` | Some of it exists; the item names what is missing. |
| `blocked` | Waiting on a decision or an upstream change. Not used for "hard". |
| `shipped` | Done and tested. The reasoning below is kept for the record. |

**"Upcoming" is anything not `shipped`** — the items derived from the 2026
literature survey ([`research/agent-guardrails-2026.md`](research/agent-guardrails-2026.md)),
plus the open items carried over from earlier milestones. Receipts and
flow-typed policies appear as single entries rather than two, because the
literature item and the older TODO describe the same feature; the entry notes
which is which.

**Size** is a rough shape, not a schedule: `S` is a focused change to one or two
modules, `M` is a new module plus tests, `L` is a new subsystem.

**How items move.** An item is promoted by someone being able to write the
**Acceptance** line as something a test can assert. An item is dropped when the
acceptance criterion stops being worth the cost — that is a legitimate outcome,
and it is recorded by deleting the section, not by leaving it to rot. Nothing
here is dropped for being hard.

**Why a separate file.** A README is read linearly by someone deciding whether
to *use* the library; a roadmap is read selectively by someone deciding whether
to *invest* — in time, in a contribution, or in a dependency. Those are
different readers with different questions, and a README that carries both is
worse at both jobs.

### At a glance

| # | Item | Status | Size | Pull |
|---|---|---|---|---|
| R1 | Delegation chains and scope attenuation | `shipped` | M | T1 · 68 papers (top cluster) |
| R2 | `Verdict.ESCALATE` | `not started` | S | T9 · 15 papers |
| R3 | Verdict provenance (`reason`, `attributed_to`) | `shipped` | S | T2, T3 |
| R4 | Signed execution receipts + append-only audit sink | `shipped` | M | T3 · M4 TODO resolved |
| R5 | Guardrail robustness harness (FP rate, DoS) | `not started` | M | T5 · nothing ships today |
| R6 | MCP capability leases + server attestation | `shipped` | L | T4 · 57 papers |
| R7 | Tool-result and observation sanitization | `shipped` | M | T8 |
| R8 | BRACE escape-resistance suite + unprivileged egress | `shipped` | M | T7 |
| R9 | Flow-typed policy dimension | `not started` | L | T6 · a constraint on R10 |
| R10 | Declarative YAML/JSON policies | `not started` | L | carried from M0 → M2 |
| R11 | Automatic interception (import hooks) | `not started` | L | carried from M0 → M1/M3 |
| R12 | Overhead benchmark suite, with methodology | `not started` | S | carried from M0 |
| R13 | Node.js sensor | `not started` | L | carried from M0 |

---

## R1 · Delegation chains and scope attenuation

**Status:** `shipped` — `Binding.delegated_from` carries provenance, a
resolve-time check refuses a delegated binding that over-grants its parent, and
`ScopeRegistry(max_delegation_depth=...)` fails closed on an unbounded chain.
The native `ScopeTree` carries the field too, so the two backends stay in parity
(`tests/test_scope_backend.py` runs the assertion on both).
**Size:** M
**Literature:** T1, the largest cluster in the corpus (68 of 445 papers).

### Problem

interlock knows *who* acted (`SensorEvent.principal`) and can key policy on a
path derived from it (`principal_scope` splits `"acme/payments/agent42"` into
`("acme", "payments", "agent42")`). What it cannot express is that one principal
**acted on behalf of** another. So there is no way to say "the reporting agent
may read the ledger, but only because the auditor it is running under may" —
and, more importantly, no way to *refuse* the opposite: today a delegated agent
can hand itself a scope its delegator never had. The corpus is close to
unanimous that this is the load-bearing property — a delegate must receive
**strictly less** authority than its delegator, and the chain has to be
auditable hop by hop.

### Why now

It extends an abstraction that already exists rather than inventing one:
scopes are already tuples with a parent walk, `ScopeRegistry.resolve` already
merges child-over-parent, and `Binding` is already the unit of grant. The
missing piece is provenance on the grant, which is a data change, not a redesign.

### What changes

- `Binding` gains `delegated_from: Optional[Scope]` (default `None`, meaning
  "granted directly by the root").
- `ScopeRegistry.resolve(leaf)` walks the parent chain and checks that every
  delegated binding at `leaf` is a subset of what `delegated_from` resolves to.
  A violation is a resolve-time error, not a runtime surprise.
- `principal_scope` gains a sibling deriver for the chain, or the chain is read
  off the event (`event.parent_principal`), so `SensorEvent` gains one optional
  field and every existing caller is unaffected.
- A depth bound is configuration on the registry, so a delegation loop or an
  unbounded fan-out fails closed.

The native `ScopeTree` path (`rust/`) has to carry `delegated_from` too, or the
two backends diverge — `tests/test_scope_backend.py` already asserts parity
between them, so that test is the tripwire.

### Impact

API: additive only. `Binding` gains a keyword field with a default; existing
policies resolve identically because a `None` parent means no new check.
Correctness cost: one extra walk per resolve, mitigated by the existing
version-keyed cache. Policy authors get a new failure mode — a delegated binding
that over-grants — which is the point.

### Acceptance

A test constructs a parent binding granting `("acme",)` and a child binding
granting `("acme", "payments", "agent42")` but delegated from a sibling that
holds only `("acme", "payments")`; `resolve` raises. A second test asserts the
non-delegated case is unaffected. Measured over the same fixture, resolve
latency stays within the tolerance `tests/test_scope_backend.py` already uses.

### Risks & dependencies

The concept of a "delegator" has to come from somewhere — either the caller
threads it through, or the interception layer infers it. Inference is where this
gets hard: inferring wrongly is worse than not having the feature, because a
false chain gives false assurance. Phase it: explicit `delegated_from` first,
inference later, behind its own item.

---

## R2 · `Verdict.ESCALATE`

**Status:** `not started` — `Verdict` is exactly `ALLOW / BLOCK / MODIFY`.
**Size:** S
**Literature:** T9 (15 papers converging on approval as a distinct outcome),
plus T3's "verifiable action card".

### Problem

There is no way to say *"this is legal, but a human must decide."* Deployments
approximate it by blocking, which throws the action away and puts the burden on
the wrong person — the caller now has to notice the block, reconstruct the
intent, and re-issue it. Fifteen papers converge on the same fourth outcome:
not allow, not block, but **pause and ask, with the evidence attached**.

### Why now

`Verdict` is an `IntEnum` whose values deliberately mirror the native engine's
out-param contract (`0/1/2`). A fourth value is a small, additive type change
with outsized expressiveness — and the alternative today, encoding escalation as
a BLOCK with a magic reason string, is exactly the kind of thing that becomes
load-bearing and then unmovable.

### What changes

- `Verdict.ESCALATE = 3`, and `Decision.escalate(reason, evidence=None)`.
- **The important part is the enforcement path.** Both enforcers currently fall
  through to "return the args" for any verdict they do not recognise —
  `interlock/interceptors/mcp.py` handles `ALLOW`/monitor, `BLOCK`, `MODIFY`, and
  then returns; `interlock/interceptors/decorator.py:_enforce` does the same. Add
  a fourth enum member without touching those and an escalation **silently
  allows**. So this item is not the enum, it is the two dispatch sites plus an
  escalation hook (a callable `guard(..., on_escalate=...)`) and a defined
  default when no hook is installed — the only safe default is BLOCK.
- `PolicyEngine.evaluate` needs no change: it already returns the first verdict
  that is not `ALLOW`.

### Impact

Users who do nothing see no change (no hook, escalations block, which is the
current behaviour). Users who install a hook gain a pause-and-ask path with
evidence attached. The native engine contract in `rust/` must be updated in the
same change, or a ctypes engine will disagree with the Python enum about value
`3`. Anything that switches exhaustively on `Verdict` is a compile-time or
test-time break, which is the right kind.

### Acceptance

A rule returning `Decision.escalate(...)` against a `@guard`-wrapped function
invokes the escalation hook and does **not** call the wrapped function until the
hook resolves. With no hook installed, the call is blocked. A test asserts the
"unrecognised verdict" fallthrough cannot happen — i.e. that adding a verdict
without handling it is caught.

### Risks & dependencies

Escalation needs somewhere to escalate *to*; a hook is the least opinionated
answer, but it means the library ships the verb and the deployment supplies the
noun. Also couples to R3: an escalation without `attributed_to` gives a human
nothing to decide on, so shipping R2 without R3 produces a prompt with no
evidence.

---

## R3 · Verdict provenance (`reason`, `attributed_to`)

**Status:** `shipped` — `Decision.attributed_to` names the input slot that
triggered the verdict, plumbed to the decision record alongside `reason` and
`policy_id`. The detector sweep is enforced by test, not by convention:
`tests/test_decision_attribution.py` walks `interlock/detectors/*.py` and
requires every module to either attribute a case or be a declared gap.
**Size:** S
**Literature:** T2 (pre-execution gating by causal attribution) and T3.

### Problem

The *timing* is already right: `Decision.block`/`modify` happen before the call
runs. What is missing is the **explanation**. A verdict says what was denied and
which policy denied it, but not *which input caused it* — so a caller cannot act
on attribution, and a reviewer auditing the decision cannot see the reason
without re-deriving it. The 2026 shift in the literature is precisely from "does
this call look bad?" to "*why* was this call produced?", and the answer is
carried as data on the verdict.

### Why now

`Decision` already has `reason: str` and `policy_id: Optional[str]`, so the
shape is proven and the payload is a single additive field plumbed to the event.
This is the cheapest item on the list relative to what it unlocks: R4's receipts
and R2's escalation both consume it.

### What changes

- `Decision.attributed_to: Optional[str]` — the input slot or argument path that
  triggered the verdict (`"args.path"`, `"args.url"`, `"tool_description"`).
  Optional, defaults to `None`; nothing that does not set it changes.
- A rule that returns a decision can name the field cheaply if the engine passes
  it: `Decision.block(reason, policy_id, attributed_to="args.path")`.
- The detectors that already know which argument they matched should populate it.
  That is the bulk of the work: 105 detectors, each already computing the
  offending field inline.
- `SensorEvent` does not change; the field is on the decision, and the event is
  what gets logged. `_emit` at `interlock/interceptors/decorator.py:45` — the
  line that still carries the M4 note — is the natural place to surface it.

### Impact

Additive. Existing rules produce `attributed_to=None`, which reads as "policy
declined to attribute", not as an error. The cost is in the detector sweep: a
detector that sets it wrong is worse than one that leaves it `None`, so the
sweep has to be reviewed in chunks rather than applied mechanically.

### Acceptance

Every non-ALLOW decision produced by the shipped detector suite reports the
argument path that triggered it, or explicitly reports `None` — and a test walks
the detector registry asserting one of those two, so a new detector that forgets
to attribute is caught at test time rather than at audit time.

### Risks & dependencies

Attribution is only as good as the detector's own reasoning. Where a detector
matches across several joined fields, naming one field is a lie of omission. The
honest answer for those is `None`, and the acceptance criterion above is written
to permit it.

---

## R4 · Signed execution receipts + append-only audit sink

**Status:** `shipped` — `interlock/receipt.py` emits a decision-level `Receipt`
binding the four stamps to the verdict: `ts`, `action`, `verdict`, `reason`,
`policy_id`, `attributed_to`, `principal`, `span_id`, `phase`, `args_digest`, a
`prev` link seeded from `GENESIS`, and an HMAC `mac`. `set_sink` installs an
append-only backend (hash-chained append, plus a null default), and
`verify_chain(receipts, signer, key)` catches a byte-flip or a mid-chain
deletion. The M4 note at `interceptors/decorator.py:45` is resolved — `_emit`
now surfaces `attributed_to` on the same path the receipt is taken from.
**Size:** M
**Literature:** T3. This is also the open M4 TODO, re-specified — the tree
already names it at `interlock/interceptors/decorator.py:45`
("M4 replaces this with signed receipts + an audit sink").

### Problem

Events are logged at debug level. That is not an audit trail: it can be turned
off, it is not tamper-evident, and it does not prove anything to a third party.
The literature is specific about the gap here — a receipt must prove the
guardrail **ran**, not merely that a log exists. A log is a claim by the
operator; a receipt is evidence that survives the operator.

### Why now

The stamp detectors already exist and already sign and sequence; what is missing
is a *decision-level* record that binds the four stamps to the verdict. The
pieces are in the tree, just not connected. And the M4 note has been sitting in
the decorator since M0 — an unbuilt milestone marker is worse than no marker,
because it reads as "planned" indefinitely.

### What changes

- A `receipt` module: given a `SensorEvent` + `Decision` (+ whatever R3
  attributed), emit a signed record. Signing reuses whichever stamp detector the
  deployment already configured, so there is one key management story, not two.
- An **append-only sink** interface with at least a file backend (hash-chained
  append, no rotation that breaks the chain) and a null backend. Plugging into
  an external store is the deployment's job; the library's job is that the
  record cannot be quietly rewritten locally.
- Filling in `_emit` so the debug log and the receipt are produced from one
  place.
- **Stating the trust boundary in the docs**: a receipt proves what the guard
  decided, under a key the guard holds. It does not prove the guard was not
  bypassed entirely. That distinction is the difference between an honest
  receipt and a security theatre one, and the literature is explicit about it.

### Impact

Per-decision cost: one hash (cheap) plus one append (the thing to measure —
`benchmarks/` exists precisely so this number is stated rather than assumed).
Off by default, because a sink that cannot be opened must not take down an
agent. Users gain offline verification: a receipt verifies against a published
key with no access to the running system.

### Acceptance

A receipt verifies offline against the published key; a byte-flipped record
fails verification; removing a record from the middle of the chain is detected.
A benchmark reports the added per-decision cost, and the README's claim about
overhead (see R12) is updated to match the measured number.

### Risks & dependencies

Key storage is the hard part and it is not solvable in a library — the honest
scope is "bring your own key, here is the interface". Depends on R3 for the
attribution half of the record; a receipt that says "blocked, reason unknown" is
still useful but much less so.

---

## R5 · Guardrail robustness harness (false positives, induced blocking)

**Status:** `not started`.
**Size:** M
**Literature:** T5 — a cluster that barely existed a year ago, and the area
where interlock has the largest gap relative to its importance.

### Problem

interlock is fail-closed by design, and that is the correct default — but it has
**no measurement of its own false-positive rate, no cost model for a blocked
action, and no resistance to being induced to block.** For a library whose
selling point is blocking, an unmeasured FP rate is a product risk, not merely
an evaluation gap: a detector that fires on benign traffic trains users to widen
their allowlists, and a widened allowlist is a bypass. Worse, "make the guard
block" is a denial-of-service primitive — an attacker who cannot exfiltrate can
often still stall the agent by making it refuse, and the literature now treats
that as a first-class attack.

### Why now

Nothing ships for this today, so the first measurement is the whole value. It is
also the item that de-risks every other item: adding detectors (R6, R7) without
a benign corpus to run them against is how a detector suite accumulates its own
DoS surface.

### What changes

- A benign corpus under `benchmarks/` or a new `evals/` — realistic agent
  traffic that *should* pass: normal tool calls, normal file paths, normal URLs,
  normal documents that merely mention the words a detector looks for.
- A runner that executes every detector over the corpus and reports FP rate per
  detector, not just an aggregate. An aggregate hides the one detector that fires
  on everything.
- A load/abuse fixture: many calls, large arguments, deeply nested structures,
  long strings — measured for latency and for whether the detector can be driven
  to block.
- A regression gate: the FP rate is a number in the repo that a change is not
  allowed to worsen silently.

### Impact

This is the item that changes what interlock can *claim*. Today "fail-closed" is
a design statement; with this, it is a measured one with a published cost. The
immediate user-visible effect is a table in the README — and the very real risk
that the first published number is embarrassing. That is the point: it is
cheaper to find out here than in production.

### Acceptance

Desktop README reports a false-positive rate per detector over a committed
benign corpus, and CI fails when a change worsens it beyond a stated tolerance.
A documented load fixture shows the guard degrades (latency) rather than
silently failing open under adversarial volume.

### Risks & dependencies

The corpus is the whole item, and a bad corpus is worse than none — a corpus of
trivially benign traffic yields a 0% FP rate that means nothing. The corpus needs
to be adversarial *toward the detectors* (near-miss strings, look-alike paths)
while remaining genuinely benign. Also: a published FP rate invites tuning
detectors to the corpus, which is overfitting; the mitigation is a held-out
split, and it should be decided before the first number is published.

---

## R6 · MCP capability leases + server attestation

**Status:** `shipped`, in three parts. **Lease** —
`mcp_capability_lease` + `LeaseRegistry.issue/renew/revoke`: a grant with an
issued-at and an expiry, checked at call time, denying with an attributable
reason once it lapses. **Attestation** — `mcp_server_attestation` binds a
server identity to a digest of the surface it *presents*, behind an injectable
`verifier` seam; the shipped default is a shared-token check and the module says
plainly that this is not a real attestation until a caller supplies a root of
trust. **Runtime drift** — `mcp_surface_baseline` holds the *reviewed* listing
and blocks any later one that differs (added, removed, renamed, or merely
re-described tool), revoking that server's leases on the drift so an old grant
cannot cover the new surface; re-admission is a fresh rule.
**Size:** L
**Literature:** T4 — MCP's trust model is the single hottest concrete surface
(57 papers in that cluster).

### Problem

Existing MCP detectors answer "was this server allowed, and was this tool the
one we pinned?" — at configuration time. They do not answer "**is** this the
server we pinned, right now?" (attestation) and they do not answer "was this
grant still valid when the call happened?" (a lease). There is nothing that
expires, and nothing that detects a tool *surface* that drifts after admission —
a description that changed, a tool whose arguments widened. The literature's
direction here is unambiguous: admission should be proven, and grants should
lapse.

### Why now

It extends existing detectors rather than replacing them: `mcp_tool_pinning`
already holds the expected identity, so attestation is "prove the identity we
already pinned" rather than a new trust model. And leases are how every other
capability system handles revocation without a config reload.

### What changes

- A lease: a grant with an issued-at and an expiry, checked at call time.
  `mcp_*` detectors consult the lease; an expired lease denies, and the denial
  says so (which R3's `reason` makes visible).
- Attestation: verify that the server presenting itself matches the pinned
  identity — at minimum a stable server identity token, ideally a signature over
  the tool listing.
- Runtime drift detection: hash the tool surface at admission, re-check on
  listing change, and treat a silent change as a new admission decision rather
  than a continuation of the old one.
- A renewal path, or leases will be turned off on the first expiry that breaks a
  healthy deployment — which is the failure mode that kills time-boxed systems.

### Impact

The largest single item here. It adds state (leases are stateful in a library
that is currently mostly stateless), which affects the concurrency story and the
"zero runtime dependencies" purity of the core. Renewal UX decides whether it is
adopted at all. All four existing `mcp_*` detectors need to agree on the lease
lookup or the deployment gets a split verdict.

### Acceptance

A lease expires and the next tool call on that server is denied with an
attributable reason. A server whose identity has changed fails admission rather
than being treated as the same server. A tool description that changes after
admission is re-admitted, not silently accepted.

### Risks & dependencies

Attestation needs a root of trust the library does not own; without one, this
degenerates into "compare two strings", which is a real downgrade that must be
documented rather than dressed up. Depends on nothing, but is a prerequisite for
anyone who wants a *provable* MCP posture — which is most of the 57 papers.

---

## R7 · Tool-result and observation sanitization

**Status:** `shipped` — `SensorEvent` gained a `phase` field (`"call"` by
default, `"result"` on the observation path), so a result-level rule cannot fire
on a call event and vice versa. `enforce_tool_result(action, result)` mirrors
`enforce_tool_call` and returns the sanitized result (or raises `Blocked`), and
`Decision.modified_result` is a field of its own rather than an overload of
`modified_args`. `tool_result_injection_guard` is the first detector that
remediates rather than merely flags: a poisoned result is rewritten, not just
reported.
**Size:** M
**Literature:** T8 — the injection channel that matters is the tool *result* and
the tool *description*, not the user prompt.

### Problem

Every interceptor today guards the **call** path: name + arguments, before
effect. The tool *result* comes back unguarded. That is the wrong half to omit,
because indirect prompt injection arrives in the result (or in the tool
description) — the agent reads it and acts on it. interlock correctly identifies
the poison and then does nothing about it, leaving the caller to decide.

### Why now

The remedy already exists as a verb: `Decision.modify` rewrites arguments today.
Pointed at the observation path it would rewrite a poisoned result. The missing
piece is a place to observe results, not a new verdict — which makes this
unusually cheap for its value.

### What changes

- An `enforce_tool_result(action, result)` beside `enforce_tool_call` in
  `interlock/interceptors/mcp.py` — the same core, the other direction.
- `guard_mcp_session` wraps the result as well as the call, so the pair is
  symmetrical and there is no way to install half of it by accident.
- Detectors that currently return `MODIFY` for argument rewriting gain the
  ability to express result rewriting: sanitize the injection marker, strip the
  override instruction, neutralize the smuggled delimiter.
- Policy needs to distinguish the two directions, or a rule written for a call
  fires on a result (the `SensorEvent` model would need a direction field, or
  the event gets an explicit phase).

### Impact

API change with a real-shape question: `MODIFY` currently means "modified_args";
on the result path it means "modified_result". Overloading one field for two
meanings is the kind of thing that looks fine for one release and is painful
forever. The options are a second field or a wrapper type, and that choice
should be made deliberately here rather than accreted.

### Acceptance

A poisoned tool result is rewritten, not merely flagged, and the guarded call
returns the sanitized result to the agent. A test asserts that a result-level
rule does not fire on a call-level event and vice versa, so the two directions
cannot cross-contaminate.

### Risks & dependencies

Sanitization is destructive: a rewrite that removes legitimate content is a
correctness bug in the agent, and a partial rewrite can leave a payload that
still works. The conservative shape is to detect-and-rewrite known markers and
*refuse* (block) on ambiguity rather than attempt a clever paraphrase. Depends on
a decision about the `MODIFY` shape above.

---

## R8 · BRACE escape-resistance suite + unprivileged egress

**Status:** `shipped` — `tests/integration/test_brace_token_matrix.py` turns
every `enforced` token into a tested contract: for each backend and each token it
reports, the escape that token is meant to stop is run for real and asserted
stopped, **plus a relaxed control** proving the block is the sandbox's doing
rather than the kernel refusing a syscall. A drift test pins each backend's
reported token set to the guarantee table in `interlock/brace/__init__.py` in
both directions, so the table and the code cannot part company.

The unprivileged egress rung is **not** delivered, and the item lands saying so:
`nftables` still stays out of `_ORDER` (it is not selectable — pinning it raises
`ValueError`), and Seatbelt rejects literal remote-IP network filters outright
("host must be `*` or `localhost`"), so no unprivileged host-granular egress is
expressible on this host. That is recorded as a measured absence in the brace
docstring and the README's confinement section, not papered over.
**Size:** M
**Literature:** T7 — directly adjacent to BRACE.

### Problem

Two things. First, BRACE backends *claim* containment by returning `enforced`
tokens on `SandboxResult` (`["fs-ro", "fs-rw", "env", "pid", "net"]` for
bubblewrap, `["env"]` + `["rlimit"]` for soft), and the documented usage pattern
is to refuse a downgrade by checking them — but no test asserts that a claimed
token actually holds. A claim is not a proof. Second, the inversion: the
literature's direction is strength *without* privilege, and here the strongest
egress confinement is the one that needs root, so the strongest guarantee is
unavailable in exactly the deployments (containers, CI, unprivileged users) that
need it most.

### Why now

The gap between "reports `enforced: ["net"]`" and "net is actually confined" is
the gap between a security control and a security *feeling*. The integration
suite (`tests/integration/test_brace_confinement.py`) already attempts real
attacks, so the harness exists — this item is making the assertions exhaustive
per backend, and closing the privilege gap.

### What changes

- Per-backend escape tests, driven by the `enforced` tokens the backend reports:
  for each token, an attack that token is supposed to stop, asserted stopped.
  A backend that reports a token it does not deliver fails, and the token list
  becomes a tested contract rather than a docstring.
- The unprivileged egress path: bubblewrap's `--unshare-net` gives a
  no-network namespace without root, but nothing between "no network" and
  "nftables-with-root" exists today — a host-granular egress confinement that
  works as an unprivileged user is the missing rung. The declaration in
  `compile_profile` / `SandboxProfile.allowed_hosts` already anticipates it
  ("enforced host-granular by the nftables backend, and by the in-process
  `egress_allowlist` detector on captured calls"), so the in-process half exists;
  the out-of-process unprivileged half does not.
- Honest reporting when a token is absent: the `Sandbox(sandbox.py)` docstring
  example already refuses to run without `"net"`; that pattern should be the
  documented default for untrusted code, not an example.

### Impact

No API change. The output is a guarantee table per backend that is tested, and
an honest one — including a row that says "not available without root" if that
is where the unprivileged path lands. The `soft` backend is a speed bump and the
docs should say so rather than leaving a reader to infer it from an `enforced`
list of length two.

### Acceptance

For each backend and each `enforced` token it reports, a test performs the
escape that token is meant to prevent and asserts the sandbox stops it. Egress
confinement is demonstrably applied on an unprivileged Linux host, or the
absence is stated in the README's confinement section as a known limitation.

### Risks & dependencies

Escape tests are host- and kernel-sensitive: a test that passes because the
attack needs a syscall the CI kernel refuses, rather than because the sandbox
stopped it, is a false pass. Each test needs to fail-in-the-open when the
sandbox is disabled (a positive control) — otherwise the suite proves nothing.
Depends on `bwrap`/`sandbox-exec` availability, which is why the harness must
skip with a *reported* skip, not a silent one.

---

## R9 · Flow-typed policy dimension (source → sink)

**Status:** `not started` — no dataflow dimension exists.
**Size:** L
**Literature:** T6 — the policy-language literature moved from flat rules to
typed rules and source→sink flow constraints.

### Problem

Rules are Python predicates with a `Template`/`Binding` parameter model:
expressive, untyped, and **flat**. Nothing can express "data that entered via
tool X may not reach argument Y" — the single most useful constraint in an agent
setting, because it is exactly the shape of exfiltration. Today that is
approximated by an argument-matching egress rule, which fires on the *call* and
cannot see where the value came from.

### Why now

This is technically a constraint on R10 rather than an independent item: the
moment declarative policies are designed, the flat-vs-flow decision gets made by
default. Designing the flow dimension *now*, as R10's shape, costs design effort;
discovering it is needed *after* R10 ships costs the schema. That asymmetry is
the entire argument for doing it in this order.

### What changes

- A provenance edge: values carry where they entered (`tool:fetch_url`,
  `principal:acme/agent42`) and a rule constrains source→sink, not just sink.
- The natural home is the `SensorEvent`: an optional per-argument origin map,
  populated at the interception boundary (this is the link back to R1 — the
  delegation chain is one source of provenance, the tool result is another).
- `PolicyEngine.evaluate` stays the seam; flow rules are rules, they just see
  more of the event. No new evaluation model.
- Detectors that already do this in ad-hoc form (`data_egress`,
  `secret_entropy_egress_guard`, `taint`-adjacent guards) become the first
  consumers, and their bespoke logic is the specification for the general one.

### Impact

This is the item that decides whether interlock's policy layer is a real policy
language or a bag of predicates. It is also the largest design risk on the list:
flow typing has a well-known expressiveness/decidability trade, and the wrong
choice is expensive to undo. Impact on users is deferred until R10 ships, which
is why R9 is a *design and prototype* item, not a delivery item.

### Acceptance

A rule expresses and enforces "the output of tool A must not reach argument B",
and the existing `data_egress` detector's hand-written case is expressible in the
general mechanism — that equivalence is the proof the abstraction is real and not
a second way of writing the same special case.

### Risks & dependencies

Untyped Python args mean origins have to be tracked by convention, and a
convention is bypassable — a value laundered through a string operation loses its
origin. The honest scope is to track origins at the boundary (which tool produced
this value) and accept that intra-argument laundering is not modelled; claiming
more would be false assurance. Depends on R10; should not ship before it.

---

## R10 · Declarative YAML/JSON policies

**Status:** `not started` — M0 rules are Python (carried from M0 → M2 in the
engine docstring).
**Size:** L
**Pull:** internal. `interlock/policy/engine.py` names it: "M2 loads declarative
YAML/JSON policies with a safe condition evaluator".

### Problem

A policy written as a Python predicate is a policy that only a Python developer
can read, review, or change — and it is coupled to the internals of whatever
event shape it inspects. That makes the policy layer the least durable part of
the system: the rules survive model migrations and framework migrations only if
the thing expressing them is not code. The stated goal is exactly that: *so rules
survive model and framework migrations*.

### Why now

It is the item the whole policy layer is shaped around — `PolicyEngine.evaluate`
is explicitly the seam that "later milestones replace". Keeping it as Python
indefinitely means every policy carries an import risk, and it means the answer
to "can I change this rule without a deploy" is no. It is also the gate for
everything about the policy layer's future: R9's flow typing is designed against
this schema.

### What changes

- A schema for rules (match → verdict, with bindings), a **safe** condition
  evaluator (no `eval`, no attribute access into arbitrary objects — an
  allowlist of operations over event fields), and hot reload so a changed file
  takes effect without a restart.
- The `Template`/`Binding` model already separates code from data, so the schema
  is largely a serialization of what exists, plus the condition language.
- Loading YAML would add a dependency; the core is deliberately
  `dependencies = []`. Either JSON-only in the core, or an optional extra — which
  is a decision worth making explicitly rather than by accident (note: the
  existing `mcp = ["wrapt>=1.15"]` extra in `pyproject.toml` is declared but
  never imported — dead, and should be removed rather than left as precedent).
- Hot reload needs a failure story: a bad file must not take down a running
  guard. Fail-closed on parse error means the last-good policy stays live, and
  the parse error is loud.

### Impact

The largest user-facing change in the file: policy authoring stops requiring
Python, and rule changes stop requiring a deploy. It also creates the first real
compatibility surface — a schema that others write against — so it deserves the
care that a schema deserves, and it should not ship in the same release as R9's
flow dimension unless that is ready.

### Acceptance

A rule expressed in YAML/JSON enforces identically to the equivalent Python rule
over the same event fixture (a differential test, which is also how the schema
gets meaningfully tested). A malformed policy file leaves the running policy in
place and reports the parse error. A changed valid file takes effect without
restarting the process.

### Risks & dependencies

The condition evaluator is a security-critical component: it evaluates
deployment-supplied expressions, and a hole in it is a hole in the guard.
The acceptance bar is that it cannot reach anything outside an allowlisted set of
event operations, with tests that attack it rather than merely exercise it.
Depends on the R9 design decision; blocks nothing else.

---

## R11 · Automatic interception (import hooks)

**Status:** `not started` — MCP is wrapped explicitly and `@guard` is opt-in
(carried from M0 → M1/M3).
**Size:** L
**Pull:** internal. The decorator docstring: "Automatic interception (import
hooks for MCP and the model SDKs) lands in M1 and M3; this decorator is what
covers bespoke in-house tools the auto-hooks cannot see."

### Problem

Explicit wrapping means coverage is a function of discipline. A developer who
forgets `guard_mcp_session` gets no guard, silently — the failure mode of a
security library that must be remembered is that it is not used. Every
interception point the library cannot reach on its own is an unguarded path, and
the paths that matter (third-party MCP clients, model SDKs) are exactly the ones
the developer does not control.

### Why now

It is the item that converts interlock from "a guard you call" to "a guard that
is there" — and it is the milestone the architecture was explicitly laid out
for: `enforce_tool_call` is already the one transport-agnostic core that MCP and
LangChain both funnel through, so an import hook has a single place to attach
rather than one per framework.

### What changes

- Import hooks that wrap MCP client sessions and model SDKs (OpenAI, Anthropic)
  at import time, routing through the existing `enforce_tool_call` core.
- An import **monitor**: dependency tamper detection, so a wrapped client that
  changes underneath is noticed.
- A compatibility contract, because monkey-patching other people's libraries is
  the most fragile thing in this entire roadmap — a hook that breaks a client
  update is worse than no hook.

### Impact

Adoption cost drops to near zero and coverage stops depending on developer
memory. The cost is coupling: interlock now owns behaviour on top of third-party
APIs it does not control, and each client release is a potential break. That
trade should be made deliberately and with an opt-out that is documented as
first-class, not a hack.

### Acceptance

An agent using an MCP client (or a model SDK) without any code change is
guarded: a blocked tool call is blocked before effect, demonstrated in an
integration test that uses the real client API shape. An opt-out exists and is
tested. A `monitor` mode exists to roll it out without blocking.

### Risks & dependencies

This is the highest-fragility item on the list and should be the last of the
interception work, after R4 gives it a receipt to emit and R2/R3 give it
somewhere to send a decision. Its acceptance test must run against real client
shapes, not only fakes, or the fragility is discovered by users.

---

## R12 · Overhead benchmark suite, with methodology

**Status:** `not started` — only `benchmarks/scope_memory.py` exists.
**Size:** S
**Pull:** internal, carried from M0.

### Problem

The library's central claim to an operator is that it can sit in the request
path. That claim is currently unquantified: there is a scope-store memory
benchmark and nothing else. Without numbers, "adds negligible overhead" is an
assertion, and an operator evaluating interlock has to guess — or measure it
themselves, which they will do by not adopting it.

### Why now

It is small, it is mostly mechanical, and it is a prerequisite for two other
items making honest claims: R4's per-receipt cost and R5's robustness results
both need somewhere to report numbers, and that somewhere should be one harness
with one methodology rather than several ad-hoc scripts.

### What changes

- A benchmark harness with a **stated methodology**: what is measured (per-decision
  latency at p50/p99, throughput, memory per subject), against what baseline (no
  guard installed), on what hardware, with what event mix (allow-heavy is the
  common case; block-heavy is the rare one and must be measured separately).
- Scenarios per interception path (`enforce_tool_call`, `@guard`, BRACE spawn)
  and per backend, so the numbers are comparable across items rather than
  per-feature folklore.
- Machine-readable output, so R5's regression gate and CI can consume the same
  numbers a human reads.

### Impact

Purely additive; no API. The output is a README table with a methodology note and
a hardware line — and the discipline that a claimed overhead must come from the
harness. The anti-goal: a benchmark tuned to produce a flattering number. The
methodology section is what makes it a measurement instead of marketing.

### Acceptance

`python -m benchmarks` (or the documented entry point) produces a table
including a no-guard baseline, and the README cites those numbers with the
hardware they were taken on. Re-running on the same hardware reproduces within a
stated tolerance.

### Risks & dependencies

Micro-benchmarks overstate detector costs in isolation and understate them in
aggregate; the mitigation is measuring the composition (a realistic event mix),
not just individual detectors. No dependencies.

---

## R13 · Node.js sensor

**Status:** `not started` — the native path covers the scope store, not a policy
engine (carried from M0).
**Size:** L
**Pull:** internal.

### Problem

The Python tree guards Python agents. A large share of MCP clients and agent
frameworks are JavaScript, and those integrations are out of reach today: the
policy engine, detectors, and interception core exist only in Python.

### Why now

Not urgent, and listed honestly as such — the ordering above it is the answer to
"why not now". It becomes urgent when a real JS integration appears, and the
sequencing matters: porting the *engine* after the policy schema (R10) stabilizes
is far cheaper than porting it twice, because the schema is the portable
artifact and Python predicates are not.

### What changes

- Reuse the same engine and policies, per the original goal — a JS sensor over
  the same declarative policy (R10) and the same `enforce_tool_call` contract,
  ideally backed by the native core rather than a second implementation.
- The interceptors are the JS-native part (MCP client, model SDKs in JS); the
  engine is the part that should not be reimplemented.
- Language-neutral test fixtures: the event/decision fixtures from the Python
  suite become the conformance suite the JS sensor must pass, so "same policies"
  is verified rather than asserted.

### Impact

Doubles the addressable integrations. Carries a permanent maintenance cost — two
implementations, two release trains — which is the reason this is the last item
and not the fifth.

### Acceptance

A JS agent using an MCP client is guarded by the same policy file as the Python
equivalent, and the shared conformance fixtures pass on both.

### Risks & dependencies

A second implementation of the policy engine is the risk; the mitigation is
making the native core the single engine and JS a binding to it. Depends on R10
(the declarative schema is what makes the policy portable at all) and on R11's
lessons about which interception points are stable.

---

## Explicitly out of scope

**Logit / decoding-layer intervention.** Papers on constrained decoding,
gradient-controlled decoding, and logit-based safety primitives are excluded
deliberately, not overlooked. interlock's premise is that it sits at the process
boundary and sees **real calls with real arguments**; reaching inside the model
would change what the library is, and a half-built version of it would be worse
than none. Recorded here so the boundary is a decision rather than an omission.

---

## Shipped

Landed items keep their entry above, marked `shipped`, so the reasoning behind a
decision stays readable after the decision is taken.

Shipped before this campaign: tri-state verdicts with a fail-closed engine;
`@guard` / `monitor`; run identity; in-process MCP interception and the LangChain
adapter over one `enforce_tool_call` core; hierarchical scopes with
override/union/tombstone merge and the optional native `ScopeTree`; 105 detectors;
BRACE profile IR, `compile_profile`, `Sandbox`, and the unprivileged confinement
backends with reported guarantees; and the scope-store memory benchmark.

Shipped in the `mo/roadmap-partials` campaign — all on `main` as of merge commit
`5d42091`:

- **R1** delegation chains — `Binding.delegated_from`, per-hop attenuation, and
  the `max_delegation_depth` bound (`cc74d5e`).
- **R3** verdict provenance — `Decision.attributed_to`, swept across the detector
  suite with a registry test (`19a6378`).
- **R4** signed execution receipts + append-only sink — `interlock/receipt.py`,
  which also resolves the M4 note at `interceptors/decorator.py:45` (`da42c23`).
- **R6** MCP capability leases (`609a5c4`), server attestation behind an honest
  verifier seam (`12b11ee`), and runtime surface-drift detection (`bb7d0d5`).
- **R7** tool-result sanitization — `SensorEvent.phase`,
  `Decision.modified_result`, `enforce_tool_result` (`9bb51b6`).
- **R8** BRACE escape-resistance suite — the tested token matrix, and the
  unprivileged-egress rung recorded as a measured absence (`de1f971`).

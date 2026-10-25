# The mesh: shared policy from a commons

Every interlock deployment runs its own policy. The mesh lets a deployment
**subscribe** to policy packs a community maintains, verified end to end and
applied in monitor mode first, and (later phases) **report** what its guard
stopped in a form that never carries a prompt or an argument. The design and
the research behind it are in
[`research/mesh-shared-policy-network.md`](https://github.com/SourceShift/InterLock/blob/main/research/mesh-shared-policy-network.md).

This guide covers what ships today: subscribing to a commons, and running one.

## Subscribe to a commons

You need two things from the commons you join: its **root** metadata (a small
signed JSON file, obtained out of band, the way you would obtain a CA
certificate) and one or more **mirror** URLs.

```bash
interlock mesh init --root root.json --mirror https://commons.example.org --ring stable
interlock mesh sync
```

`sync` fetches and verifies the repository and fills a local cache under
`~/.interlock/mesh/`. Nothing is installed yet. In your policy file, extend a
pack the way you extend a built-in one:

```json
{"version": 1, "extends": "mesh:coding-agent@stable",
 "disable": ["some-rule-you-do-not-want"],
 "rules": [{"id": "local", "verdict": "block", "when": {"arg": "env", "eq": "prod"}}]}
```

`interlock policy check policy.json` shows what was installed. The spec is
`mesh:<pack>` with an optional `@<ring>`; without one the node's configured
ring applies.

### What the node does with a pack

A pack is a normal declarative policy whose rules each carry a **status**:
`experimental`, `test`, `stable` or `deprecated`. The node's **ring** decides
which statuses it installs and the strongest verdict each may carry (its
**ceiling**). A decision above the ceiling becomes an `escalate`, so the rule
asks a human instead of acting.

| Ring | Installs | Default ceiling by status | After a grant |
|---|---|---|---|
| `canary` | experimental, test, stable | experimental → escalate, test → modify, stable → modify | the pack's verdict |
| `early` | test, stable | test → modify, stable → modify | the pack's verdict |
| `stable` | stable | stable → modify | the pack's verdict |

A `modify` ceiling leaves a pack's rewrites as they are and turns its blocks
into escalations, so **no community rule blocks on its own**, on any ring. A
rule carries the pack's own verdict only after its monitor window and an
operator grant (see [Grant a block](#grant-a-block)). Deprecated rules are
always dropped. `locked` is stripped from every mesh rule: you can always
`disable` a community rule in your own file.

On top of that, every rule the node has not seen before spends a **monitor
window** (seven days by default, `--monitor-days` at `init`) in **shadow
mode**: it is evaluated, what it would have decided is logged and counted, and
it decides nothing. When the window ends the policy reloads itself and the
rule starts enforcing, under its ceiling. The window restarts if the rule's
logic changes, not when its status is promoted.

```bash
interlock mesh status          # subscriptions, freshness, grants, capped rules, what shadow rules would have done
interlock mesh resolve mesh:coding-agent@early   # the exact document this node would install
interlock doctor               # warns when the timestamp has expired, a sync failed, or the root is due
```

The console's **Mesh** page shows the same state read-only: whether a commons
is configured, the pinned root and ring, the verified packs with their status,
the timestamp's expiry, mirror count and any split view, and which reporting
consent layers are on. It reads `GET /api/mesh` from this node's cache, so
point the console at a non-default directory with
`interlock console --mesh-dir <dir>`.

### Grant a block

A grant is the operator's consent for community blocks to block on this node.
It lives in the node's `config.json` and lifts the ceiling to the pack's own
verdict for the rules it names:

```bash
interlock mesh grant block --pack coding-agent --status stable   # this pack's stable rules
interlock mesh grant block --pack coding-agent --status test     # its test and stable rules
interlock mesh grant block --rule no-curl-pipe-sh                # one rule id, in any pack
interlock mesh grant block --rule no-curl-pipe-sh --pack coding-agent   # that rule in that pack only
interlock mesh grant --list
interlock mesh grant revoke --pack coding-agent --status stable  # the same arguments take it back
```

```json
{"grants": {"block": [{"pack": "coding-agent", "status": "stable"}, {"rule": "no-curl-pipe-sh"}]}}
```

- A pack grant covers rules at **or above** its status (experimental, then
  test, then stable); `--status` defaults to `stable`. `--pack` is the name
  you subscribe to (`mesh:<pack>`), not the `name` inside the pack, which its
  authors chose.
- A rule id is chosen by a pack's authors too, so a bare `--rule` grant
  reaches that id in every pack you subscribe to; add `--pack` to keep it to
  one.
- A grant does not skip the monitor window: a new rule still spends it in
  shadow mode first. Granting or revoking does not restart the window.
- `interlock mesh resolve` lists the rules a grant lifted (`granted`) and the
  ones still capped to an escalate (`capped`). A policy loaded with a watch
  picks a grant up at its next check; any other picks it up at its next load.
- A malformed `grants` entry makes the mesh config unreadable, and the policy
  load fails closed (the last good policy stays in force): a typo never grants
  anything.

**With no approver installed**, a capped community block has no one to ask.
Rather than refusing the call (an `escalate` with no approver is otherwise
`NotApproved`), the node records it as a shadow finding: the call runs, the
receipt says `approval: shadow:no-approver`, and the decision goes to the same
shadow log as monitor-window rules, under `interlock mesh status`. `interlock
mesh status` and `interlock doctor` say how many rules are capped: "3 mesh
rules capped at escalate; no approver installed: shadow only". Every other
escalation with no approver, including a mesh rule whose own verdict is
`escalate`, is still refused. This applies where the policy is loaded and the
escalation settled in the agent's process (`@guard`, `enforce_tool_call`); an
escalation decided by a sidecar is refused as before, and the coding-agent
hook adapters hand every escalation to the agent's own prompt, as before.

### What is verified, and what happens when it fails

The cache is trusted only through a chain that starts at your pinned root:

1. **root**: the keys and thresholds of every role. A new root is accepted
   only if signed by a threshold of the old root's keys and of its own, with
   the next version number.
2. **timestamp**: short-lived (a day by default). Its expiry is the commons'
   kill switch: if the maintainers stop signing, every node notices.
3. **snapshot**: pins the exact version, length and hash of the targets file.
4. **targets**: pins the length and hash of every pack.
5. each **pack**'s bytes against that hash.

A failure at any step, a tampered file, a stale or replayed document, an
oversized download, leaves the cache exactly as it was and is recorded for
`status` and `doctor`. A policy load reads the cache only, never the network,
so a mirror outage cannot stall your agent, and a pack missing from the cache
is a load error, which keeps the last good policy running. Fail closed, never
fail open.

Mirrors and peers are trusted for availability only. Any HTTP server, object
store, or `file://` path that serves the published tree is a valid mirror.

## Run a commons

A commons is a directory of packs under version control:

```text
commons/
  packs/coding-agent.json         a policy document; every rule has a status
  packs/coding-agent.tests.json   optional conformance cases
```

Create keys, publish, verify:

```bash
interlock mesh keys init --out keys/                   # one key per role; see "Keys" for a real root
interlock mesh publish --source commons/ --out site/ --keys keys/
interlock mesh verify site/                            # walk it exactly as a subscriber would
```

`publish` compiles every pack with the same loader a subscriber uses and
refuses a pack with a quarantined rule. It writes a static tree:

```text
site/metadata/1.root.json  root.json  timestamp.json
site/metadata/3.snapshot.json  snapshot.json  3.targets.json  targets.json
site/targets/packs/<sha256>.coding-agent.json
```

Every publish bumps the targets, snapshot and timestamp versions, so a
subscriber sees each one as an update and never as a rollback. Re-run it at
least as often as the timestamp expiry (`--timestamp-days`, default 1): that
is the heartbeat subscribers watch.

**Keys.** `keys init` writes one Ed25519 key per role, mode 0600. The
targets, snapshot, timestamp and log keys are online: `publish` signs with them
every time, and they are cheap to rotate. The root keys are neither. `publish`
reads a root key only to sign a *new* root; while the online keys still match
the current root and it has not expired, it re-publishes that root with no
root key present. A first deployment can publish once with the root key `keys
init` wrote and then move that file offline. A real commons generates each
root key on its keyholder's own machine (or in a hardware token), lists the
public keys in `keys/root-keys.json`, sets the root threshold in
`keys/roles.json`, and signs even its first root in a
[root ceremony](mesh-root-ceremony.md). The commons this project runs uses
2-of-3, held by the people
[`GOVERNANCE.md`](https://github.com/SourceShift/InterLock/blob/main/GOVERNANCE.md)
names.

A root lasts 197 days. Its last 46 are its signing period: `publish` warns, and
`interlock doctor` on every subscribed node reports it, until the keyholders
sign the next one. They do that in a ceremony:
`interlock mesh root draft` writes the unsigned next root, each keyholder runs
`interlock mesh root sign` on their own machine (with a key file or a hardware
token's signing program), and `interlock mesh root assemble` checks that the
old root's threshold and the new root's own both signed before it writes the
new root into the site. Changing an online key works the same way: `publish`
refuses until a ceremony has signed a root that names the new key. Subscribers
follow the rotation on their next sync.

A commons that keeps its root keys beside the others (a first deployment, a
test) still rotates the old way: move the old root key files under
`keys/retired/`, put the new ones in place, and publish. The new root is signed
by both sets.

## Report what your guard stopped

Reporting is off by default: nothing leaves a node until its operator turns
it on, one layer at a time, and an enable never reaches back before its own
date. A report is a projection of the receipts interlock already writes
([audit log](audit-log.md)). It has five kinds of fact, called layers, and they
leave the node by two different routes:

| Layer | Enabled by | Carries | Goes to | Never carries |
|---|---|---|---|---|
| counts | `report enable` | how often each published rule fired, per verdict, tool *class* (shell, http, file.write, mcp, ...), phase and hour | the **aggregators**, only as secret shares; never in the report | tool names, principals, sessions |
| sightings | `report enable` | "rule X is wrong here", an operator's false-positive statement | the **consensus** service, in the signed report | |
| digests | `report enable --digests` | the SHA-256 of the arguments a rule **blocked or escalated**, exactly as the receipt stores it | the **consensus** service, in the signed report | arguments; anything a redacting or masking rule saw; rewrites; monitor-mode decisions |
| fingerprints | `report enable --fingerprints` | a noised fingerprint of what a rule stopped ([below](#find-similar-attacks-without-sharing-text)) | the **consensus** service, in the signed report | the text |
| samples | `report enable --sample RULE --i-warrant-samples` | the redacted text, for the rules you name | the **consensus** service, in the signed report | text from rules you did not name |

```bash
interlock mesh report init                                  # an Ed25519 key: the only identity the mesh sees
interlock mesh report build --receipts ~/.interlock/receipts.jsonl --since 24h --out report.json   # local only
interlock mesh report enable --digests                      # counts, sightings and digests, from now on
interlock mesh report status                                # what is enabled, since when, and a preview
interlock mesh report build --receipts ~/.interlock/receipts.jsonl --since 24h --out report.json
interlock mesh report build --receipts ... --false-positive tool_result_injection --out report.json
interlock mesh report submit report.json --consensus https://consensus.example.org \
    --aggregator https://agg-a.example.org --aggregator https://agg-b.example.org
```

**One consent point.** `report enable` is the node's only consent. It records
the enable time and the enabled layers in the mesh state (`state.json` in the
mesh directory). It needs no commons, so a node can report without
subscribing. A bare `enable` turns on counts and sightings, and `--digests`,
`--fingerprints` (with `--alpha`) and `--sample RULE` (with the data warranty,
`--i-warrant-samples`, [below](#licences-and-the-data-warranty)) each add their
own layer. Each `enable` replaces the one before it, so name every layer you want.
`report enable --off` turns every layer off, the recorder included.

**Never retroactive.** A report never holds anything observed before the
enable. `report build` opens its window no earlier than the enable time,
whatever `--since` asks for, and leaves out every layer that is not enabled.
Adding a layer or a sample rule moves the enable time to now, so a new layer
never covers time before its own enable. Turning reporting off and on again
starts over, and the gap is never sent. Narrowing the layers keeps the enable
time.

**`submit` refuses what is not enabled.** Before it opens a connection,
`submit` refuses:

- any report while reporting is off;
- a report built over time before the enable, such as a preview built before
  you enabled (rebuild it);
- an envelope that carries a layer that is not enabled, or counts to share
  when counts are not enabled. The message names the flag that would enable
  it, for example:
  ``digests are not enabled: run `interlock mesh report enable --digests` ``.

Every refusal exits 2.

**The preview.** `report build` always works locally, with nothing enabled,
so you can see exactly what would be sent. Until you enable reporting, it
shows every layer. It prints what the report contains before anything leaves
the machine, and `--json` shows the exact envelope. `interlock mesh report
status` and `interlock mesh status` print one line saying what a report built
now from the last 24 hours of `~/.interlock/receipts.jsonl` would hold: count
rows, digests, fingerprints and samples. `interlock doctor` adds an INFO check:
`mesh reporting: off`, or `mesh reporting: on since <date>: layers ...`.

| Variable | Effect |
|---|---|
| `INTERLOCK_MESH_DIR` | moves the mesh directory (config, verified cache, `state.json` with the consent, the reporting key) away from `~/.interlock/mesh` |
| `INTERLOCK_MESH_NO_REPORT=1` | the kill switch, whatever is enabled: `interlock.mesh.report.submit` refuses every upload before it connects. That covers reports, count shares, the aggregator totals query and gossip with peers. `report submit` says why and exits 2. Empty or `0` leaves it off |

With `--out report.json`, `build` writes two files: the signed envelope, and the
count vector beside it in `report.json.counts.json` (mode 0600). The envelope
carries no counts, and the consensus service refuses one that does.

`submit` sends the signed envelope (the enabled digests, sightings,
fingerprints and samples) to the **consensus** service. Counts **never reach consensus**: `submit` reads them
from the local counts file and splits them into additive secret shares, one per
**aggregator**. Each aggregator sees a uniformly random number, and only their
combined sums are the real totals. Two aggregators run by organisations that
will not collude are the minimum; with fewer, counts are not sent at all, and
`submit` says so.

Every report also names the node's **catalog id**, a hash of the installed
detector modules and the interlock version. The consensus engine refuses
reports from catalogs it does not know, so only unmodified, published
detectors count, the way only unmodified hub scenarios count in CrowdSec.

## Run the collectors

The package ships a reference implementation of both roles, standard library
only, meant to sit behind a real web server:

```bash
interlock mesh serve --role consensus --bind 127.0.0.1:7949 --state consensus.json \
    --known-catalog <catalog id> --token <shared secret>
interlock mesh serve --role aggregator --bind 127.0.0.1:7950 --state agg.json
```

Flags passed to `serve` win over values persisted in `--state`: a restarted
consensus server picks up the CLI's `--min-orgs`, `--token`, `--issuer`,
`--require-credential` and `--revoked` even when the state file remembers older
ones. That keeps the state file a record of decisions, not a second, hidden
configuration.

The consensus engine turns reports into decisions the way every crowdsourced
defence that works does:

- **Distinct organisations, not events.** An indicator (a rule id plus a
  digest) becomes *active* when at least `min_orgs` (default 3) different
  reporters saw it and their combined trust clears `min_trust`.
- **Trust the reporter, not the report.** Trust starts at a floor, grows with
  tenure and with agreement with **canaries** (known-bad payloads the
  maintainers seed), and drops when a node reports a known-*benign* canary as
  blocked, the signature of misconfiguration or poisoning. Reports are
  rate-limited per reporter.
- **Let receivers push back.** False-positive sightings from `fp_demote_orgs`
  (default 2) organisations demote a rule: its indicators leave the pack and
  the demotion is published in the stats for the maintainers to act on.
- **Expire everything.** An indicator unseen for `indicator_ttl_days` (default
  30) is no longer active.

`GET /v1/stats` is the public dashboard: how many organisations saw each rule
fire (a reporter that sent a digest or a sighting for a rule saw it fire), the
indicator funnel, and demotions. It carries nothing per reporter and **no fire
counts**: each rule's `verdicts` is `null`, because consensus never sees a
count. Fire counts come from the aggregators' combined totals:

```bash
interlock mesh consensus export --state consensus.json --stats \
    --aggregator https://agg-a.example.org --aggregator https://agg-b.example.org
```

reads both aggregators' `GET /v1/manifest`, asks each for its partial sums over
the reports both hold (`POST /v1/totals`), adds them, and fills in each rule's
`verdicts`.

An aggregator releases totals only over a **batch floor** of at least
`min_batch` reconciled reports (default 3; `mesh serve --role aggregator
--min-batch N` raises it, and it cannot be set below 2). Below the floor,
`POST /v1/totals` answers 422 with a reason, and `GET /v1/manifest` names the
floor. The reason is subtraction: a total over one report *is* that report, and
with two, either reporter can subtract its own counts from the total and read
the other's. A repeated or unknown report id does not count toward the batch.
The floor does not stop someone who may call `/v1/totals` from differencing
two overlapping batches (four reports minus three of them is the fourth). The
**DAP path** below closes that with fixed, non-overlapping batches, and adds
validity proofs so a node cannot lie about its own counts.

`GET /v1/indicators` (or
`interlock mesh consensus export --state consensus.json`) is the indicator
**pack**: one rule using the `mesh_indicator_guard` detector with the active
digests, published with status `test`. On a subscriber's canary and early
rings that caps it to an escalate, and the stable ring does not install it
until a maintainer promotes the pack; it blocks only where an operator has
granted it. The commons publishes it like any other
pack, so indicators reach nodes through the same verified path.

## Counts with validity proofs: Prio3 over DAP

The secret-share path above is interlock's own protocol, and it trusts the
shape of a report: a node could claim ten million blocked calls for a rule it
never ran, and the aggregators could not tell. The DAP path replaces it with a
published standard and two upgrades that matter:

- **Validity proofs.** Each count vector is sharded with **Prio3** (VDAF
  `draft-irtf-cfrg-vdaf-22`, `Prio3SumVec`, codepoint `3`). The report carries a
  proof that every bucket sum is inside the task's range; an aggregator that
  verifies it learns nothing about the individual vector, and a report whose
  proof fails is dropped before it reaches a total.
- **Fixed, non-overlapping batches.** A batch is one `time_precision` interval,
  defined by the task, and it is collected once. A second collection of an
  overlapping interval is refused as `batchOverlap`, and reports that arrive
  after their batch was collected are refused as `batchCollected`. Differencing
  two overlapping totals is impossible because overlapping totals do not exist.

The transport is DAP `draft-ietf-ppm-dap-20`: HPKE-encrypted input shares
(RFC 9180 base mode, X25519 / HKDF-SHA256 / AES-128-GCM), binary messages, and
RFC 9457 problem documents. A third-party DAP deployment can host the leader
and the helper; the reference servers here are standard-library only and are
expected to sit behind a TLS-terminating proxy.

### Create a task

A task fixes everything both aggregators and the collector must agree on. One
command writes four files:

```bash
interlock mesh dap task --out /srv/dap \
    --leader-url https://leader.example.org \
    --helper-url https://helper.example.org \
    --bucket 'rule-a|block|shell|pre|*' \
    --bucket 'rule-b|allow|read|post|*' \
    --batch-hours 24 --min-batch 10 --max-measurement 65535
```

| File | Mode | Holds |
|---|---|---|
| `task.json` | 644 | task id, URLs, time precision, minimum batch size, VDAF configuration, the ordered bucket patterns, the collector's **public** HPKE config, and pinned leader/helper public keys |
| `leader.json` | 600 | the leader's HPKE secret, the shared VDAF verify key, the helper bearer token, the collector bearer token |
| `helper.json` | 600 | the helper's HPKE secret, the same verify key, the bearer token |
| `collector.json` | 600 | the collector's HPKE secret and the leader bearer token |

`task.json` is shareable; the other three never are. The command refuses to
overwrite an existing task, because a new task id silently strands every
report queued under the old one. `--json` prints the public task instead of the
summary.

**Buckets.** A pattern has four components, `policy_id|verdict|tool_class|phase`,
or five, with an hour. `*` is allowed only in the hour position and sums the
batch's hours. Every count in a report must match **exactly one** pattern;
unmatched counts and overlapping patterns are refused when the task is created,
never silently dropped. A bucket's sum must stay at or under
`--max-measurement`. Adding a rule or a dimension needs a new task.

**Kinds of nothing else.** One VDAF (`Prio3SumVec`), one batch mode
(`time_interval`), and one query shape: a single fixed batch per collection job.

### Run the two aggregators

```bash
interlock mesh serve --role dap-helper --task /srv/dap/task.json \
    --keys /srv/dap/helper.json --bind 127.0.0.1:7961
interlock mesh serve --role dap-leader --task /srv/dap/task.json \
    --keys /srv/dap/leader.json --bind 127.0.0.1:7960
```

Each role reads its own key file and refuses one that belongs to the other
role. State is an atomic JSON file, mode 0600, defaulting to `<keys>.state`; it
holds report ids, report metadata, committed aggregate shares and collection
responses, **never** a count or a label. `--peer-token` and
`--collector-token` override the tokens from the key files. TLS is the proxy's
job.

### Upload, then collect

`dap submit` reuses the same consent gate as `report submit`: it needs counts
consent, and `INTERLOCK_MESH_NO_REPORT=1` refuses before it opens a socket to
fetch a key.

```bash
interlock mesh report enable                                  # counts consent, once
interlock mesh report build --receipts ~/.interlock/receipts.jsonl \
    --since 24h --out report.json                            # envelope + report.json.counts.json
interlock mesh dap submit --report report.json --task /srv/dap/task.json \
    --keys /srv/dap/leader.json
interlock mesh dap collect --task /srv/dap/task.json \
    --keys /srv/dap/collector.json --start 20743 --json
```

`submit` maps the counts to the bucket vector, refuses a count outside one
batch or over the bucket ceiling, shards it with Prio3, encrypts one share to
each aggregator and posts the report. It prints the report id and whether the
leader accepted it; a refusal exits 2 and names the wire error, including the
collector's own reason when it sends one.

The leader's collector token can come from `--token`, or from the role key file
with `--keys`; the latter reads the `leader` token the task names, so the flow
matches `dap collect`:

`--start` is a DAP **Time**: POSIX seconds divided by the task's
`time_precision`, which is also the batch index. With `--batch-hours 24`, batch
`n` covers `[n × 86400, (n + 1) × 86400)` in POSIX seconds. A collection job
asks for exactly one batch, so its duration is always 1. The command opens both
aggregate shares with the collector key, unshards, and prints the per-bucket
totals; `--out` writes them to a 0600 file.

### What each side refuses, and why

| Refusal | Where | Why |
|---|---|---|
| `invalidBatchSize` | leader, helper | fewer than `min_batch_size` verified reports: a total over one report is that report |
| `vdaf_verify_error`, then a drop | helper | the proof does not match the share; the report never counts |
| `report_replayed` | leader | the same report id twice: one report is one report, however often it arrives |
| `batch_collected`, `batchOverlap` | leader, helper | the batch is closed; a late report or a second overlapping query would allow differencing |
| `unrecognizedTask` | both | the path or `task_id` names a task this aggregator does not serve |
| `invalidMessage` with 401 | both | missing or wrong bearer token between leader and helper, or from the collector |
| `invalidBatchSize`/`batchMismatch` | helper | the leader's count or checksum of committed report ids disagrees with the helper's |
| `stepMismatch` (409) | helper | a continuation poll: Prio3 finishes during initialization, so there is no second round |

The leader commits a report's output share only after the helper's `continue`
response verifies it, and the helper caches responses by the SHA-256 of the
request body, so a retried job after a lost reply is answered idempotently
instead of tripping a replay or overlap rule.

**One inherent limit.** If a report is dropped *after* the helper committed its
share but before the leader counts it, the two aggregators disagree and the
batch cannot be released. That is a liveness loss, not a privacy loss, and it
is the honest cost of committing shares early. Rebuild the task only when you
mean to discard the batch.

### Interop checklist for a third-party deployment

- Give both aggregators the same **byte-identical** `TaskConfiguration`.
  `task.json`'s `task_config_b64` is re-encoded on load and refused if it does
  not round-trip, because the HPKE associated data is derived from those exact
  bytes.
- Pin the deployment's leader and helper HPKE public keys in `task.json`; the
  client refuses a config that differs from the pin.
- Use the DAP suite from the draft: KEM `0x0020`, KDF `0x0001`, AEAD `0x0001`.
- Share the bearer tokens out of band; the reference servers expect
  `Authorization: Bearer …` on aggregator-to-aggregator and collection
  traffic.
- The CLI mints new tasks. To adopt an existing deployment, write `task.json`
  around its `TaskConfiguration`; `load_task` is the check that it is faithful.

**Honest limits.** There is no live interop test against another DAP
implementation in this repository; correctness rests on the official VDAF test
vectors, RFC 9180 HPKE vectors, the wire conformance tests and the local
leader↔helper end-to-end tests. The pure-Python X25519, AES-GCM and
TurboSHAKE128 are correct but **not constant-time**, the same posture as the
mesh's Ed25519 (see the [security model](../security-model.md)). Run them in an
isolated process behind TLS, and keep bucket lists small: a Prio3 proof is tens
of kilobytes per report.

## Find similar attacks without sharing text

An exact digest matches only the identical payload. Attacks arrive re-spelled,
so a node can also record a **fingerprint** of what its guard blocked:

```bash
interlock mesh report enable --fingerprints --alpha 1.5       # fingerprints (with counts and sightings)
interlock mesh report enable --fingerprints --sample tool_result_injection --i-warrant-samples   # plus redacted samples for one rule
interlock mesh report enable --off
```

A fingerprint is made inside the node, at decision time, by a recorder that
sees the arguments and never writes a rule: redact (emails, card-shaped
numbers, tokens, IPs, home directories), embed (a 768-dimensional SimHash of
character and word n-grams by default; a semantic embedder can be plugged in
through the Python API), keep one bit per dimension, then flip every bit with
probability `1 / (1 + e^alpha)`. That last step is local differential privacy
with budget `alpha` per fingerprint: the text cannot be reconstructed, and
`alpha` is the dial between privacy and match quality. Smaller is more private
and misses more variants. Once their layer is enabled, fingerprints and
samples are included by the next `report build` and shown in its summary
before anything leaves. The recorder runs while either layer is on, and starts
or stops when a watched policy next checks the mesh state (otherwise at the
next policy load). What it records stays on the node: `--sample` without
`--fingerprints` uploads no fingerprints.

The consensus engine clusters fingerprints across organisations into
**campaigns** and, once enough distinct reporters are in one, exports a pack
using the `mesh_similarity_guard` detector: a node that installs it
fingerprints each call's arguments the same way (without the noise) and
**escalates** a call within Hamming distance of a published fingerprint.
Similarity is evidence, not proof, so the default is to ask a human.

A match boundary is never a cliff. The detector blocks at or below the
threshold and, up to one review margin beyond it (76 bits by default, a tenth
of the 768 dimensions; `review_margin` on the detector), escalates a near miss
instead of allowing it. A variant one bit outside the line still reaches a
human, and the margin can be widened or set to `0` to restore the hard edge.
The campaign export is available directly:

```bash
interlock mesh consensus export --state consensus.json --similarity
```

writes the similarity pack (fingerprints and campaign metadata) that a
subscriber installs; `--stats` remains the public dashboard export, and asking
for both is refused.

A **sample** is the redacted text itself, kept only for rules you name, capped,
and carrying the argument names it came from. Samples exist for the forge, and
sharing one means giving the data warranty
([Licences and the data warranty](#licences-and-the-data-warranty)).

## Measure a rule before you ship it

```bash
interlock mesh harness --policy pack.json --benign benign.jsonl --samples attacks.jsonl
```

`benign.jsonl` is a corpus of events your deployment considers fine, one JSON
object per line (`{"action": "Bash", "args": {"command": "git status"}}`);
record real tool calls from a trusted session, or start from the actions
`interlock learn` saw allowed. The harness reports the false-positive rate
overall and per rule, p50 and p95 evaluation latency, recall over the attack
samples, and a pass or fail against budgets (`--max-fp-rate`, `--max-p95-us`,
`--min-recall`). The same gates run inside the forge and belong in a commons'
CI, so a human merge cannot skip them.

## The forge

```bash
interlock mesh forge --state consensus.json --benign benign.jsonl --out proposals/
```

The forge never publishes. It reads a consensus state and writes one
**proposal** directory per candidate, shaped like a pull request: `pack.json`
(every rule `experimental`), `tests.json` (the samples it must catch and benign
events it must not), `evidence.json` and a `PROPOSAL.md` with the
organisations behind it, the false-positive rate, recall and cost. Candidates
are the active exact-match indicators, the active campaign fingerprints, and,
for a rule whose redacted samples came from several organisations, the longest
fragment most samples share as an `escalate` rule on the argument names the
samples named. A `drafter` callable (an LLM behind a validation loop) can be
plugged in through the Python API; whatever it returns runs through the same
gates. A human reviews the proposal and opens the pull request.

## Licences and the data warranty

The commons holds two kinds of thing under two licences (decision R4 in
`research/mesh-decisions.md`):

| What | Licence | Where it says so |
|---|---|---|
| code and policy packs | Apache-2.0 ([LICENSE](https://github.com/SourceShift/InterLock/blob/main/LICENSE)) | a pack's `license` field; a pack that names none is `Apache-2.0` |
| indicators, fingerprints and redacted samples, wherever they appear | CC0-1.0 ([LICENSE-DATA](https://github.com/SourceShift/InterLock/blob/main/LICENSE-DATA)) | `"license": "CC0-1.0"` on the indicator and similarity packs the consensus engine exports |

A pack names its licence as an SPDX identifier in `license`, and `publish`
writes it into the targets metadata (each pack's `custom.license`), so a node
sees it before it installs anything. A rule may carry its own `license` when
only that rule came from a project with another licence. Both are metadata:
they never change what a rule decides, and annotating a rule does not restart
its monitor window.

Every forge proposal's `pack.json` carries a `license` and a `provenance`
block: where the candidate came from (`source`), how many organisations stand
behind it (`organisations`) and when the forge ran (`generated`).
`PROPOSAL.md` shows both. The indicator and similarity candidates are
CC0-1.0, and a drafted rule is Apache-2.0, like any other pack. The sample
strings in `tests.json` are CC0-1.0 whatever the pack's licence.

**The data warranty.** A redacted sample is text an attacker wrote and your
guard saw, so sharing one means warranting what you hold, not that you wrote
it. `--sample` therefore needs an explicit flag:

```bash
interlock mesh report enable --sample tool_result_injection --i-warrant-samples
```

With it you warrant that every sample is lawfully obtained, contains no
personal data, and contains no third party's confidential data. These are the
three clauses a contributor's sign-off covers
([CONTRIBUTING.md](https://github.com/SourceShift/InterLock/blob/main/CONTRIBUTING.md)).
Without the flag, `report enable --sample` refuses (exit 64). The warranty is
recorded with the reporting consent in the node's `state.json`, with the time
it was given, and every report that carries samples carries it too, inside the
signed body:

```json
{"attestation": {"warranty": "lawful,no-personal-data,no-confidential", "at": 1800000000.0}}
```

The recorder keeps no samples on a node that has not given the warranty: a
consent record whose samples carry none (one written before this change, or
edited by hand) reads as no samples. `report build` leaves recorded samples
out, saying so, when no warranty is on record (for example, after a `report
enable` without `--sample`, or while reporting is off).

The consensus service refuses a report whose samples arrive without the
attestation, and stores the attestation with each sample it keeps. **This
changes the wire format:** a report with samples, built by a node from before
this change, is refused whole, so nodes that share samples upgrade together
with the consensus service. Reports without samples are unaffected. A
consensus state file written before the change drops its unattested samples
when it is loaded.

**Erasure.** A sample reported to contain personal data leaves a commons'
tree and its next release within 30 days
([GOVERNANCE.md](https://github.com/SourceShift/InterLock/blob/main/GOVERNANCE.md#erasure)). On the consensus side:

```bash
interlock mesh consensus forget --state consensus.json --sample 8e91205596c31285
```

removes every copy of the sample with that digest, under every rule, and
rewrites the state file the engine's own way (mode 0600). The digest is the
one the state holds: the first 16 hex characters of the SHA-256 of the
sample's text. Stop the consensus service first, because it keeps the state in
memory and writes it back after the next report. Exit 2 means no sample has
that digest; exit 3 means the state file could not be read or written back.

## The transparency log

Signed metadata proves a document came from the maintainers. It does not
prove they published the same document to everyone, or that a compromised
signing key did not publish something quietly. A commons whose keys include a
`log` key (`keys init` creates one) therefore also keeps a **transparency
log**: every metadata document and every pack is a leaf in a Merkle tree
(RFC 6962 / RFC 9162 hashing, so an independent monitor written against the
RFC can read it), and each publish signs the tree's root as a **checkpoint**.

A subscriber whose root names a `log` role refuses, at sync, anything the log
cannot vouch for:

- a checkpoint not signed by the log key, or whose root the entries do not
  reproduce;
- a document it just verified that is not in the logged prefix (an *unlogged*
  publish, however well signed);
- a log that shrank or whose earlier entries changed (the previous checkpoint
  must be a prefix of the new tree).

```bash
interlock mesh log site/                     # walk a site's log exactly as a subscriber would
interlock mesh log https://commons.example.org
```

### Gossip and split views

The attack a log cannot catch alone is the **split view**: one tree shown to
you, another to everyone else. Nodes catch it by comparing notes. A node that
serves its verified cache (below) also answers gossip, and any node can ask:

```bash
interlock mesh gossip --peer http://peer.example.org:7949
```

Both sides exchange their newest checkpoints. Two checkpoints of the same
size with different roots, or a peer's checkpoint the local entries cannot
reproduce, is recorded as a split view: `status` shows it, `doctor` fails on
it, and the evidence (both signed checkpoints) stays in the mesh state. That
is the point of a log: the maintainers are accountable to it.

## Seed your cache to peers

Mirrors and peers are trusted for availability only, so any node may be one:

```bash
interlock mesh serve --role mirror --bind 0.0.0.0:7949
```

serves the node's own verified cache (`metadata/`, `targets/`, `log/`)
read-only and answers gossip. Another node adds `http://host:7949` as a
mirror and verifies everything from its own pinned root, exactly as it would
from the maintainers' site. If every maintainer mirror is offline, the
commons keeps flowing between nodes, and nothing a peer serves can be
altered without a signature it does not have.

## Membership credentials

The early ring is a trusted community, and a reporter's weight in consensus
is worth attacking: one organisation pretending to be ten is the Sybil
problem. An **issuer** (the people who run the commons) admits an
organisation once, out of band, then signs one **certificate per epoch** (a
week) for a pseudonymous reporting key the member generated:

```bash
interlock mesh credential init --out issuer/                 # once, offline
interlock mesh credential issue --issuer issuer/ --member acme --pseudonym <hex public> --out acme-week.json
interlock mesh credential revoke --issuer issuer/ <certificate id>
```

The certificate names the pseudonym, the epoch and a scope, never the member.
A collector started with `--require-credential --issuer <hex public>` refuses
reports without one, and a node attaches its certificate with
`report build --credential acme-week.json`. Verifiers learn only that the
issuer admitted whoever holds this key this week; certificates from different
weeks are unlinkable to them; the issuer's private ledger says who got which,
so misbehaviour has an owner and a revocation list. One certificate per
member per epoch is the Sybil bound. The stated upgrade is an anonymous
credential or a zero-knowledge membership proof, which would remove the
issuer's own linkability without changing what verifiers see.

Revocation is enforced, not just recorded. A collector serves the list with
`--revoked revocations.json` (rewritten by `credential revoke`), re-reads it
before every consensus report so a revocation lands without a restart, and
keeps the last good list if a read fails. A verifier checks one certificate
against the same file:

```bash
interlock mesh credential verify acme-week.json --revoked revocations.json
```

An id on that list is refused; without `--revoked` the command checks only the
signature and epoch, which is why a revocation dead-end was possible before
the flag existed.

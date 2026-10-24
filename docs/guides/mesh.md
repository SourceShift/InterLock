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

| Ring | Installs | Default ceiling by status |
|---|---|---|
| `canary` | experimental, test, stable | experimental → escalate, test → modify |
| `early` | test, stable | test → modify |
| `stable` | stable | none: the pack's own verdict |

Deprecated rules are always dropped. `locked` is stripped from every mesh
rule: you can always `disable` a community rule in your own file.

On top of that, every rule the node has not seen before spends a **monitor
window** (seven days by default, `--monitor-days` at `init`) in **shadow
mode**: it is evaluated, what it would have decided is logged and counted, and
it decides nothing. When the window ends the policy reloads itself and the
rule starts enforcing. The window restarts if the rule's logic changes, not
when its status is promoted.

```bash
interlock mesh status          # subscriptions, freshness, what shadow rules would have done
interlock mesh resolve mesh:coding-agent@early   # the exact document this node would install
interlock doctor               # warns when the timestamp has expired or a sync failed
```

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
interlock mesh keys init --out keys/                   # one key per role; see below for a real root
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

**Keys.** `keys init` writes one Ed25519 key per role, mode 0600. A real
commons generates its root keys on offline machines and raises the threshold
(`--root-keys 5 --root-threshold 3`); the targets, snapshot and timestamp keys
are online and cheap to rotate. To rotate the root, move the old root key
files under `keys/retired/`, put the new ones in place, and publish: the new
root is signed by both sets, and subscribers follow the rotation on their next
sync.

## Report what your guard stopped

Reporting is off until you turn it on, and it is a projection of the receipts
interlock already writes ([audit log](audit-log.md)). A report carries three
kinds of fact and nothing else:

| Layer | Carries | Never carries |
|---|---|---|
| counts | how often each published rule fired, per verdict, tool *class* (shell, http, file.write, mcp, ...), phase and hour | tool names, principals, sessions |
| digests | the SHA-256 of the arguments a rule **blocked or escalated**, exactly as the receipt stores it | arguments; anything a redacting or masking rule saw; rewrites; monitor-mode decisions |
| sightings | "rule X is wrong here", an operator's false-positive statement | |

```bash
interlock mesh report init                                  # an Ed25519 key: the only identity the mesh sees
interlock mesh report build --receipts ~/.interlock/receipts.jsonl --since 24h --out report.json
interlock mesh report build --receipts ... --false-positive tool_result_injection --out report.json
interlock mesh report submit report.json --consensus https://consensus.example.org \
    --aggregator https://agg-a.example.org --aggregator https://agg-b.example.org
```

`build` prints what the report contains before anything leaves the machine;
`--json` shows the exact envelope. `submit` sends the signed envelope (digests
and sightings) to the **consensus** service, and splits the counts into
additive secret shares, one per **aggregator**: each aggregator sees a
uniformly random number, and only their combined sums are the real totals. Two
aggregators run by organisations that will not collude are the minimum; with
fewer, counts are not sent at all.

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

`GET /v1/stats` is the public dashboard: per-rule fire counts across the
network, how many organisations saw each rule fire, the indicator funnel, and
demotions. It carries nothing per reporter. `GET /v1/indicators` (or
`interlock mesh consensus export --state consensus.json`) is the indicator
**pack**: one rule using the `mesh_indicator_guard` detector with the active
digests, published with status `test`. On a subscriber's canary and early
rings that caps it to an escalate, and the stable ring does not install it
until a maintainer promotes the pack. The commons publishes it like any other
pack, so indicators reach nodes through the same verified path.

## What is not here yet

Phases 2 and 3 of the design, private fingerprints for paraphrased variants,
the forge that drafts rules from reports, and the transparency log with
monitors and peer seeding, land in their own sections of this guide.

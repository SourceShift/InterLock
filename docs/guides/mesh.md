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

## What is not here yet

Phases 1 to 3 of the design, reporting what the guard stopped (as counts,
digests and private fingerprints), the consensus service, the forge that
drafts rules from reports, and the transparency log, are in the package but
described in their own sections of this guide as they land.

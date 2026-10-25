# A bootstrap mesh commons

This directory is a working, repeatable deployment of one Interlock mesh
commons on a single Linux host. It is deliberately small: a signed static site,
one mirror process, one consensus collector, a test DAP pair, and a Cloudflare
Tunnel that is the only public listener.

It is **not** a production trust root. Read [What is still missing](#what-is-still-missing)
before treating any of it as authoritative.

## What runs

| Process | Loopback bind | Public name (example) | Purpose |
|---|---|---|---|
| `interlock mesh serve --role mirror` | `127.0.0.1:7949` | `mesh.example.com` | Serves `metadata/`, `targets/`, `log/` read-only |
| `interlock mesh serve --role consensus` | `127.0.0.1:7950` | `mesh-consensus.example.com` | Accepts signed reports, exports indicators |
| `interlock mesh serve --role dap-leader` | `127.0.0.1:7960` | `mesh-leader.example.com` | Test DAP leader |
| `interlock mesh serve --role dap-helper` | `127.0.0.1:7961` | `mesh-helper.example.com` | Test DAP helper |
| `interlock-mesh-publish.timer` | — | — | Daily timestamp/snapshot/targets refresh |
| `cloudflared` | — | all of the above | TLS and public ingress |

The mirror and the consensus collector are unrelated trust domains even though
they share a host here. The mirror only serves bytes signed elsewhere; the
consensus collector only ingests signed reports. Neither holds a root key.

## Install

Assumptions: Ubuntu-like host, Python 3.12, `cloudflared` installed at
`/usr/local/bin/cloudflared`, a Cloudflare zone, and a dedicated tunnel.

```bash
# 1. Service account and root
sudo useradd --system --home /srv/interlock-mesh --shell /usr/sbin/nologin interlock-mesh
sudo mkdir -p /srv/interlock-mesh/{bin,keys,secrets,state,logs,commons/packs,site}
sudo chown -R interlock-mesh:interlock-mesh /srv/interlock-mesh

# 2. Code and venv
sudo -u interlock-mesh git clone --depth 1 https://github.com/SourceShift/InterLock.git /srv/interlock-mesh/src
sudo -u interlock-mesh python3.12 -m venv /srv/interlock-mesh/venv
sudo -u interlock-mesh /srv/interlock-mesh/venv/bin/pip install /srv/interlock-mesh/src

# 3. Keys and tokens
#    The first publish is the only one that needs the root key. Keep a copy
#    offline and delete it from the host once the root is stable.
sudo -u interlock-mesh /srv/interlock-mesh/venv/bin/interlock mesh init \
  --keys /srv/interlock-mesh/keys --root-threshold 1
sudo -u interlock-mesh sh -c 'openssl rand -hex 32 > /srv/interlock-mesh/secrets/consensus.token'
sudo -u interlock-mesh sh -c 'openssl rand -hex 32 > /srv/interlock-mesh/secrets/mirror-gossip.token'
sudo chmod 600 /srv/interlock-mesh/secrets/*.token

# 4. Copy bin/ and commons/packs/ from this directory, then publish once
sudo -u interlock-mesh /srv/interlock-mesh/bin/publish.sh

# 5. Tunnel and units
sudo cp cloudflared/interlock-mesh.yml.example /etc/cloudflared/interlock-mesh.yml
sudo cp systemd/interlock-mesh-*.service systemd/interlock-mesh-publish.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now interlock-mesh-mirror interlock-mesh-consensus \
  interlock-mesh-dap-leader interlock-mesh-dap-helper interlock-mesh-tunnel \
  interlock-mesh-publish.timer
```

Create the tunnel and DNS records with the Cloudflare dashboard or `cloudflared
tunnel route dns`. Use **flat** hostnames under the zone apex. Universal SSL
covers `example.com` and `*.example.com`; it does not cover
`*.mesh.example.com`.

## Smoke

```bash
curl -fsS https://mesh.example.com/healthz
curl -fsS https://mesh-consensus.example.com/v1/stats | jq .

# A subscriber must verify the whole chain, not just fetch a file.
INTERLOCK_MESH_DIR=/tmp/mesh-check interlock mesh init \
  --root /tmp/root.json --mirror https://mesh.example.com --ring stable
INTERLOCK_MESH_DIR=/tmp/mesh-check interlock mesh sync
```

`interlock mesh verify https://mesh.example.com` and `interlock mesh log <url>`
currently treat the argument as a local path. Fetch a known-good root over TLS,
then use `mesh init --mirror <url>` and `mesh sync`, which verify over HTTP.

## The skill-safety commons

`scanner/` is a pipeline for **reviewed** skill-install advisories:

```
pinned corpus checkouts
        |
        v
scan_corpus.py       SkillSpector, --no-llm, one subprocess per SKILL.md
        |
        v
build_advisories.py  conservative triage; raw report is never rewritten
        |
        v
review.json          a human names each published rule and its verdict
        |
        v
render_pack.py       commons/packs/skill-safety.json
        |
        v
publish.sh           signed targets, log, timestamp
```

The triage exists because a scanner score is not a policy. SkillSpector counts
scan-coverage findings (`AE1`, "a referenced file was not fully inspected") and
matches in documentation. A documentation example can therefore produce
`DO_NOT_INSTALL` for a curated official skill. The pipeline:

- ignores `AE1` for verdict purposes, and records it as a coverage caveat;
- treats a finding as material only when it is in an executable file, has
  confidence at least 0.8, and is `HIGH` or `CRITICAL`;
- never turns a raw score into a rule by itself;
- requires `review.json` to name every published rule.

A specific rule matches an **install-shaped shell command** containing both the
repository and the skill name, on one line. A prose mention, a URL fetch, or
reading a skill's source does not match.

The first run (2026-10-25, four corpora, 67 of 68 skills scanned statically)
produced 16 review candidates and no confirmed malicious skill. Every candidate
was inspected and recorded in `scanner/review.json`; the published pack carries
two generic `experimental` rules instead of naming a skill:

| Rule | What it asks about |
|---|---|
| `skill-install-requires-review` | an install-shaped command (`npx skills add`, `claude plugin install`, a skills-repo clone) |
| `skill-manifest-write-requires-review` | a `Write`/`Edit` of `SKILL.md` under `.claude/skills`, `.agents/skills`, `.codex/skills`, `.cursor/skills` or `.gemini/skills` |

The second rule exists because writing the manifest is the same act as
installing the skill, without an install command to observe.

Each advisory is bound to the bytes that were scanned: corpus commit, scan
time, scanner version, and a SHA-256 of `SKILL.md` plus the files it references
inside the skill directory. A changed digest invalidates the advisory. An
incomplete scan is never `clear`.

### Which corpora

The first run pins four public, permissively licensed collections. The exact
commits are in each `scan-reports/<name>/index.json` and in the generated
pack's `provenance.corpora`:

| Corpus | Why it is here |
|---|---|
| `anthropics/skills` | Official Agent Skills reference set |
| `addyosmani/agent-skills` | Widely used production-engineering set |
| `vercel-labs/agent-skills` | The `npx skills` reference collection |
| `obra/superpowers` | Large community methodology set |

Scanning a corpus is **not** an endorsement or a claim that every skill in it is
safe. Coverage is stated per corpus, per commit, in the signed pack.

## What is still missing

These are properties of the deployment, not bugs in the mesh:

1. **The root is 1-of-1 and its key is on the host.** Governance requires 2-of-3
   across three people or organisations. This deployment is a bootstrap:
   convenient for a first commons, unacceptable for authority over other
   people's agents. Run the root ceremony before admitting members.
2. **The DAP pair shares one operator and one host.** Leader and helper must be
   independent legal entities and cloud tenancies before any production count
   is uploaded. The pair here is a protocol test only.
3. **`mesh-mirror.example.com` is an alias, not an independent mirror.** It
   points at the same process and host. A second operator, host and network path
   is what makes a mirror useful.
4. **No credential issuer is deployed.** Collectors accept reports without
   credentials. Deploy an offline issuer, publish its public key, and use
   weekly epochs before opening reporting.
5. **No backups, alerting, rate limiting or log rotation.** The JSON state is
   atomically written, which prevents torn files, not data loss.
6. **The commons has no independent review.** A pack is code. Until a second
   maintainer reviews a rule, its status should stay `experimental`.

# SkillSpector → mesh advisories

This pipeline scans public agent-skill repositories with
[NVIDIA SkillSpector](https://github.com/NVIDIA/SkillSpector), then publishes
**reviewed** install advisories as a signed mesh policy pack. It is static
analysis (`--no-llm`) so a published advisory is reproducible from the recorded
scanner version and source commit.

## Run

```bash
export INTERLOCK_MESH_ROOT=/srv/interlock-mesh
export SCANNER=/srv/interlock-mesh/scanner-venv/bin/skillspector

# One-time: clone the pinned corpora under $INTERLOCK_MESH_ROOT/corpus/
# names must match scanner/corpus-map.json
git clone --depth 1 https://github.com/anthropics/skills.git       "$INTERLOCK_MESH_ROOT/corpus/anthropics-skills"
git clone --depth 1 https://github.com/addyosmani/agent-skills.git "$INTERLOCK_MESH_ROOT/corpus/addyosmani-agent-skills"
git clone --depth 1 https://github.com/vercel-labs/agent-skills.git "$INTERLOCK_MESH_ROOT/corpus/vercel-labs-agent-skills"
git clone --depth 1 https://github.com/obra/superpowers.git        "$INTERLOCK_MESH_ROOT/corpus/obra-superpowers"

# Scan every SKILL.md, build the queue, render only what review.json names
bash "$INTERLOCK_MESH_ROOT/bin/scan-skills.sh"
```

The first full run takes roughly 20–40 minutes on 8 vCPUs because SkillSpector
runs a multi-analyzer graph per skill. Later runs reuse reports unless
`--force` is passed. The scanner is a separate Python 3.12 venv:

```bash
python3.12 -m venv "$INTERLOCK_MESH_ROOT/scanner-venv"
"$INTERLOCK_MESH_ROOT/scanner-venv/bin/pip" install \
  "skillspector @ git+https://github.com/NVIDIA/SkillSpector.git"
```

## Review

`build_advisories.py` writes `scan-reports/advisories.json`. Every row carries
the corpus commit, the scan time, the scanner version, and a digest of
`SKILL.md` plus the files it references inside the skill directory. A changed
digest invalidates the advisory: the reviewer approved those bytes, not the
skill's name. An incomplete scan can never produce a `clear` row.

It sorts the interesting skills first:

- `review_block`: executable `HIGH`/`CRITICAL`, confidence ≥ 0.8
- `review_escalate`: executable `MEDIUM`, confidence ≥ 0.8
- `watch`: other findings, or incomplete coverage
- `clear`: no findings and complete coverage

`AE1` coverage findings are recorded but never drive a verdict. A
`review_block` row is a **candidate**, not a conclusion. Open the raw report
(`path` in the row) and decide whether the finding is real, reachable, and the
kind of risk an install command should stop.

Then write `review.json`:

```json
{
  "pack": "skill-safety",
  "channel": "skill-safety",
  "description": "Reviewed install advisories for public agent skills.",
  "rules": [
    {
      "skill": "anthropics/skills--example-skill",
      "verdict": "escalate",
      "status": "experimental",
      "reason": "the install path runs a downloaded shell script",
      "reviewed": "2026-10-25 by <maintainer>, reviewed finding <id>"
    }
  ]
}
```

Every rule starts `experimental`. Promotion is a separate decision, governed by
the normal mesh statuses and the node operator's grant. A `block` rule in the
pack still becomes an `escalate` on every ring until the node's operator grants
it, and every new rule spends the seven-day monitor window first. That is the
mesh's safety property, not a limitation of this pipeline.

A `generic` rule names no skill. It describes the install surface itself:

```json
{
  "id": "skill-install-requires-review",
  "generic": true,
  "verdict": "escalate",
  "status": "experimental",
  "matches": "(?i)(?:^|[\\s;&|])(?:npx\\s+skills\\s+(?:add|use|update)|...)"
}
```

A generic entry may also carry a full `when` block instead of `matches`, which
is how `skill-manifest-write-requires-review` covers an agent writing
`SKILL.md` straight into `~/.claude/skills` without running an installer.
`render_pack.py` refuses to name a specific skill unless the row is a review
candidate **and** carries a manifest digest.

## First published result

The 2026-10-25 run scanned 67 of 68 skills across the four corpora (one
timeout). Sixteen were review candidates: 14 `review_block`, 2
`review_escalate`. All sixteen were inspected line by line and none was a
genuine malicious skill — the causes were security prose quoting an attack,
YARA matches on threat-model vocabulary, `__MACOSX` metadata inside a zip, and
intentional cleanup commands. Each disposition is recorded in
`review.json` under `provenance.reviewed_candidates`.

That outcome is the reason the first pack guards the install surface rather
than naming a skill. A scanner finding is a lead; only a reviewed finding is a
policy.

## Why not publish the raw score

On a curated official skill, SkillSpector can report `CRITICAL` largely because
two referenced Markdown files were only partially inspected and a documentation
example mentions an access token. Those findings are worth reading. They are
not a reason to tell every agent in a network to refuse an install. A policy
pack has the force of code, so this pipeline separates:

1. **what the scanner observed** (raw report, retained);
2. **what a reviewer concluded** (review.json);
3. **what the mesh distributes** (signed pack, with provenance).

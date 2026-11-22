# Skills: pin what you reviewed

A skill is a directory an agent loads by name. The name is what a human
reviewed and trusted; the files under it are what the agent actually reads.
Nothing in the agent loop reads those files on the way to a decision, so a
`SKILL.md` edited or swapped after review runs under a name that was already
trusted. `interlock skills` binds the name to the bytes: `pin` records a
sha256 over the directory's regular files, `check` recomputes it, and the
`skill-digest` rule in the default `coding-agent` pack refuses a `Skill`
activation whose content moved since it was pinned.

## Pin after review

Review the skill as you would review any instruction the agent will follow,
then pin it by name:

```bash
interlock skills pin reviewed-skill
```

```
pinned reviewed-skill bb13efcb75b55a6fe95d4ef0371e8af10daecde43731afda2a45ecbe8da37a37
```

Pinning merges into the pin file; it does not replace the other names. By
default that file is `~/.interlock/skills.json`, created atomically with mode
`0600`:

```json
{
  "skills": {
    "reviewed-skill": "bb13efcb75b55a6fe95d4ef0371e8af10daecde43731afda2a45ecbe8da37a37"
  },
  "version": 1
}
```

```bash
interlock skills list
```

```
reviewed-skill                   bb13efcb75b55a6fe95d4ef0371e8af10daecde43731afda2a45ecbe8da37a37
```

The default roots are `~/.claude/skills`; a plain name resolves to
`<root>/<name>`. A directory is discoverable when it holds a regular
`SKILL.md`.

### Plugin skills

Claude Code activates a skill installed by a plugin as `plugin:skill`, and on
disk that name can live in three layouts under a root. For `plugin:skill`,
`find_skill` tries each in turn and takes the first that exists:

| Layout | Example | Activated as |
|---|---|---|
| `<root>/<plugin>/skills/<skill>` | `marketplaces/fullstack-dev-skills/skills/python-pro` | `fullstack-dev-skills:python-pro` |
| `<root>/<plugin>/<skill>` | `marketplaces/caveman/caveman-compress` | `caveman:caveman-compress` |
| `<root>/<skill>` | `marketplaces/kubernetes-skill` | `kubernetes-skill:kubernetes-skill` |

A directory that is itself a skill - one holding a regular `SKILL.md` - is a
plain skill, not a plugin: its other subdirectories are not promoted to
`plugin:skill`. Only a plugin directory with no `SKILL.md` of its own
contributes flat `<plugin>/<skill>` entries. An explicit `skills/`
subdirectory is still scanned, because that layout is unambiguous whatever
else the directory holds.

`~/.claude/plugins/marketplaces` is **not** a default root. To audit and pin
the plugin skills installed there, pass it explicitly:

```bash
interlock skills check --all --roots ~/.claude/skills ~/.claude/plugins/marketplaces
```

and give the detector the same list, so it resolves the same names:

```json
"with": {"roots": ["~/.claude/skills", "~/.claude/plugins/marketplaces"]}
```

The guard only sees the roots it is given. A plugin tree left out of `roots`
stays invisible to the audit: its skills are never pinned, so an activation
resolves to "unknown" and the default `on_unknown` policy allows it.

The digest covers every regular file's relative POSIX path, byte size and
sha256, folded in sorted path order. That makes it independent of directory
creation order and sensitive to any byte change. Symlinks and other
non-regular entries are skipped - a link's target can change without the skill
directory changing, so hashing through it would make the pin lie. The walk is
bounded at 512 files and 8 MiB; a skill past either bound is an error, not a
digest of the readable part.

`--roots` and `--pins` move those two locations:

```bash
interlock skills pin reviewed-skill --roots ~/.claude/skills ~/work/skills --pins ~/.interlock/skills.json
```

If you move them, the guard must be told the same locations; see
[Wiring and tuning](#wiring-and-tuning).

## Check before trust

Check one skill before you let an agent activate it:

```bash
interlock skills check reviewed-skill
```

```
ok reviewed-skill bb13efcb75b55a6fe95d4ef0371e8af10daecde43731afda2a45ecbe8da37a37
```

A skill whose bytes moved prints nothing to stdout and one line to stderr:

```bash
interlock skills check drifted-skill
```

```
interlock skills: drifted-skill changed since it was pinned
```

`check --all` audits every discoverable skill under the roots. It is
read-only: it never writes the pin file. Run against a tree with one skill in
each state, it prints one line per skill and exits `2`:

```bash
interlock skills check --all
```

```
drifted-skill                    drift     62eb90e40fc6f3d49f32913256185b8fb9fb576fc8212b3d7090c520c6a364e5 (pinned 4b65e2fec4bea7df532e706cabb166a26e662f7e28196cf8117f8f3246163914)
huge-skill                       error     skill exceeds 8388608 bytes
new-skill                        unpinned  c80d0c75f8176e8c132e9200c55ba7b584f41a11e1b12c8da2533d1feade7253
reviewed-skill                   ok        bb13efcb75b55a6fe95d4ef0371e8af10daecde43731afda2a45ecbe8da37a37
```

| Status | Meaning |
|---|---|
| `ok` | the recomputed digest matches the pin |
| `drift` | it does not; the line shows both digests, and the default guard refuses the activation |
| `unpinned` | the skill was found but never pinned; the guard's `on_unknown` policy applies |
| `error` | the directory could not be read or hashed (unreadable file, or a bound exceeded); the line says why |

An audit exits `2` when any skill is `drift` or `error`, and `0` otherwise -
an `unpinned` skill is reported but does not by itself fail the audit, because
pinning is an opt-in decision. `check NAME` is stricter about missing input: an
unpinned name, a name with no directory, and an unreadable directory each exit
`2`. Usage errors - `check` given neither or both of `NAME` and `--all`, or no
action at all - exit `64`; an unrecognized subcommand is rejected by the
argument parser with exit `2`.

Add `--json` to any subcommand for automation. `check --all --json` emits one
entry per skill with `name`, `status`, `digest` and `pinned` (`null` when
unpinned); `check NAME --json` emits `name`, `digest`, `pinned` and `match`.

## What the guard does on activation

Claude Code emits a `Skill` action carrying the skill name in `args["skill"]`
(falling back to `args["name"]`). The default `coding-agent` pack carries this
rule, with no tuning parameters, so the defaults below are what an
`interlock install-hook` install applies:

```json
{"id": "skill-digest", "on": "Skill", "detector": "skill_digest_guard"}
```

The rule reads the pin file on every call, so a re-pin takes effect without
rebuilding the policy.

| Situation | Default | What the agent sees |
|---|---|---|
| pinned, digest matches | allow (no opinion) | the activation proceeds |
| pinned, digest differs | **block** (`on_mismatch`) | the activation is refused |
| no pin, or no directory | allow (`on_unknown`) | the activation proceeds - pinning is the opt-in |
| the skill directory cannot be read or hashed | **escalate** (`on_error`) | a human is asked |

The asymmetry is deliberate. Drift is a stated change to content you trusted,
so it blocks. An unpinned skill is simply outside the contract, so the rule
stays inert until you pin it. A skill whose contents cannot be read is
"cannot be judged", never "matches", so it escalates rather than allowing.

An unreadable or malformed pin file is not an error case: it is treated as
"unknown", so the default `on_unknown` (allow) applies. The distinction
matters - a broken pin file silently leaves skills unprotected rather than
escalating, and `check` exits `2` on the same file so the audit catches it.

Block and escalate decisions carry `policy_id` `skill_digest` and
`attributed_to` `skill`, and the reason names only the skill - never a path and
never file content. The rule never raises into the agent loop; an unexpected
exception lands on `on_error`.

## Wiring and tuning

If your policy extends `builtin:coding-agent`, the rule is already on. Tune it
by disabling the inherited rule and adding your own with the detector's
parameters. This file was checked with `interlock policy check` and loads
cleanly:

```json
{
  "version": 1,
  "extends": "builtin:coding-agent",
  "disable": ["skill-digest"],
  "rules": [
    {
      "id": "skill-digest",
      "on": "Skill",
      "detector": "skill_digest_guard",
      "with": {
        "on_mismatch": "escalate",
        "on_unknown": "block",
        "on_error": "block"
      }
    }
  ]
}
```

`on_mismatch`, `on_unknown` and `on_error` each take `allow`, `block` or
`escalate`. A common rollout keeps drift at `block`, sets `on_unknown` to
`block` once every skill you rely on is pinned, and leaves `on_error` at
`escalate`. Choosing `escalate` for drift files a review instead of refusing
outright; see [Review queue](reviews.md).

Pass `roots` and `pins_path` in the same `with` block when the CLI uses
non-default locations:

```json
"with": {"roots": ["/srv/agent-skills"], "pins_path": "/srv/interlock/skills.json"}
```

Keep the pin file somewhere the agent cannot write. The locked
`self-protect-files` rule already keeps agent file tools out of
`~/.interlock`, so the default path is protected.

For the `extends` / `disable` mechanics and what a project overlay may change,
see [Declarative policies](policies.md). An overlay is a repository control and
may only tighten; it cannot disable a base rule or add a detector rule, so
tuning this guard is an operator decision made in your own policy file, not
something a checked-out repository can do to you.

## The three-command recipe

```bash
# 1. after review: record the bytes you approved
interlock skills pin <name>

# 2. before one activation: prove they have not moved
interlock skills check <name>

# 3. before a rollout: find everything the roots expose
interlock skills check --all
```

Step 1 is the only command that writes. Step 2 is the per-activation gate:
exit `0` means the pinned content is intact, `2` means refuse or re-review.
Step 3 is the audit that catches a skill that appeared after the last pin, or
one you forgot to pin at all; treat any `drift` or `error` as a stop and any
`unpinned` as a decision you have not made yet. After an intentional edit,
re-run `pin` for that name - `check` reports drift, it never heals it.

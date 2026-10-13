# Declarative policies

Write rules as data, in JSON (or YAML, if PyYAML is installed), instead of
Python. A policy file can be reviewed by someone who doesn't write Python,
changed without a deploy, checked before it ships, and reloaded while the
guard runs.

```json
{
  "version": 1,
  "rules": [
    {"id": "no-force-push", "verdict": "block",
     "reason": "force-push to a default branch",
     "when": {"intent": "git.push.force:default"}},
    {"id": "cap-rows", "verdict": "modify", "set": {"limit": 100},
     "reason": "row limit capped",
     "when": {"all": [{"action": "query_db"}, {"arg": "limit", "gt": 100}]}},
    {"id": "big-payments", "verdict": "escalate",
     "reason": "payments over 1,000 need a human",
     "when": {"all": [{"action": {"glob": "pay_*"}}, {"arg": "amount", "gt": 1000}]}},
    {"id": "egress", "detector": "data_egress.network_egress_guard",
     "with": {"allowed_hosts": ["api.acme.com"]}, "widenable": ["allowed_hosts"]}
  ]
}
```

```python
import interlock
from interlock.policy.declarative import load_policy_file

interlock.install(engine=load_policy_file("policy.json", watch=2.0))
```

`watch=2.0` re-checks the file at most every two seconds and reloads it when it
changes. A file that no longer parses leaves the last good policy running and
logs the error (`engine.last_error` says why).

## Rules

| Key | Meaning |
|---|---|
| `id` | Required, unique. Becomes the `policy_id` on decisions and receipts |
| `verdict` | `block`, `escalate` (ask a human; see [approvals](approvals.md)) or `modify` |
| `when` | The condition (below) |
| `reason` | What a blocked caller or an approver is told |
| `set` | For `modify`: the argument values to rewrite |
| `phase` | `call` (default) or `result` |
| `on` | Limit the rule to an action, a list of actions, or `{"glob": ...}` |
| `locked` | `true`: no file that extends this one, and no overlay, can disable it |
| `detector` + `with` | Instead of `when`/`verdict`: any [catalogued detector](../reference/detectors.md), by name, with its keyword arguments |
| `widenable` | For a detector rule: the list parameters an overlay may extend |

There is no `allow` verdict. The engine allows by default, and a block from any
rule always wins.

## Conditions

| Condition | Matches when |
|---|---|
| `{"all": [c, ...]}` / `{"any": [...]}` / `{"not": c}` | all / any / none of the parts match |
| `{"action": "name"}`, `["a", "b"]`, `{"glob": "mcp__github__*"}` | the tool name matches |
| `{"field": F, OP: value}` | an event field passes the test; F is `action`, `principal`, `phase`, `span_id`, `parent_principal` or `call_id` |
| `{"arg": "name", OP: value}` | a tool argument passes the test; `"a.b"` reaches into nested objects, `"items.0"` into lists |
| `{"intent": "selector"}` | a string argument is a shell command that does this (add `"arg": "command"` to look at one argument only) |

| Operator | Test |
|---|---|
| `eq`, `ne` | equal / not equal (a missing argument is `ne` anything) |
| `in`, `not_in` | in / not in a list |
| `gt`, `ge`, `lt`, `le` | numeric comparison (strings and booleans never match) |
| `contains` | substring of a string, or member of a list |
| `startswith`, `endswith` | string prefix / suffix |
| `glob` | shell-style pattern, whole string |
| `matches` | regular expression (at most 512 characters; scans the first 64 KiB) |
| `exists` | `true`: the argument is present and not null |

Shell-intent selectors are listed in [parsed shell commands](detectors.md#parsed-shell-commands):
`git.push.force`, `pkg.publish`, `net.fetch_exec`, `fs.delete.recursive:critical`
and so on. A prefix matches its family (`"git"` covers every `git.*` intent),
and `:detail` or `:critical` narrows it.

## Mistakes fail at load, not in production

A rule that loads cleanly but can never fire is the worst kind. So:

- An unknown key, field or operator is an error that names the valid choices and
  the likely one you meant (`'equals'` → `eq`, `'principle'` → `principal`).
- For actions with a known argument schema, a misspelled argument is an error
  too: `{"on": "Bash", "when": {"arg": "cmd", ...}}` reports
  "Bash has no argument 'cmd' (did you mean 'command'?)". The coding-agent tools
  are known out of the box; declare your own with a `"tools"` section:
  `"tools": {"query_db": ["sql", "limit"]}`.
- An invalid rule is **quarantined**: skipped, logged, and listed in
  `engine.quarantined` with the reason. The rest of the file still loads.

```bash
interlock policy check policy.json
```

prints the rules, the locked ones and anything quarantined, and exits 1 if any
rule was skipped, so you can run it in CI.

## Building on another policy

```json
{"version": 1, "extends": "builtin:coding-agent", "disable": ["privilege"],
 "rules": [...]}
```

`extends` takes a built-in pack (`builtin:coding-agent`) or a path relative to
this file. `disable` removes inherited rules by id. A `locked` rule can't be
disabled; the attempt is listed in `quarantined` and the rule stays.

## Project overlays

An overlay is a policy file a project carries (`.interlock/policy.json`, found
by walking up from the working directory to the git root). It's written by
whoever controls the repository, which may be the agent itself. So:

- **It is ignored until a human trusts it**, by content hash:
  `interlock trust add`. Editing the file revokes trust until it's re-approved.
- **It can only tighten.** An overlay may add rules (`block`, `escalate`,
  `modify`) and extend lists that the base marks `widenable`:

  ```json
  {"widen": {"egress": {"allowed_hosts": ["staging.acme.com"]}},
   "rules": [{"id": "no-prod-env", "verdict": "block",
              "when": {"arg": "env", "eq": "prod"}}]}
  ```

  It can't `disable` anything, replace a base rule's id, lock a rule, or widen a
  list the base didn't mark widenable. An overlay that tries is ignored whole.

```python
from interlock.policy.declarative import load_policy_file
from interlock.policy.trust import TrustStore, find_overlay

overlay = find_overlay(".")
engine = load_policy_file("policy.json", overlays=[overlay] if overlay else [],
                          trust=TrustStore())
```

Applied and ignored overlays are recorded as `policy.overlay` receipts.
`engine.overlays` lists each one with its status. The trust file
(`~/.interlock/trusted.json`) must be somewhere the agent can't write.

## The policy epoch

`engine.epoch` is a hash of the effective policy documents. It is stable across
processes for the same files, it changes when they change, and it's stamped on
every receipt. Approvals are bound to it, so a policy change invalidates them.

## Safety of the evaluator

Policy files are data, and the evaluator treats them as untrusted:

- No `eval`, no imports, no attribute access. `arg` paths index dicts and lists
  only, so `"__class__"` is just a missing key.
- Detectors are looked up in the detector package by name. Nothing else can be
  imported.
- An exception while evaluating a rule blocks the call; it never allows it.
- One compiled policy is safe to evaluate from many threads.

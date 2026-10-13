# Command line

`interlock` (also `python -m interlock`) is installed with the package. Each
command's `--help` shows the same text as below. `--no-color` (before the
command) turns off color; color is also off when output isn't a terminal or
`NO_COLOR` is set.

| Command | Does |
|---|---|
| [`doctor`](#interlock-doctor) | check that protection is actually on |
| [`report`](#interlock-report) | summarize a receipt log: blocks, monitor findings, latency |
| [`hook`](#interlock-hook) | decide one coding-agent tool call (run by the agent) |
| [`install-hook`](#interlock-install-hook) | put interlock in front of Claude Code, Codex or Cursor |
| [`policy`](#interlock-policy) | check a declarative policy file, or show a built-in pack |
| [`trust`](#interlock-trust) | trust a project's policy overlay |
| [`mcp`](#interlock-mcp) | inventory the MCP servers configured on this machine |

## `interlock doctor`

Check that interlock protection is actually on.

Runs host-level checks and, when you point it at them, checks your policy,
your sidecar and your receipt log:

```bash
interlock doctor
interlock doctor --rules myapp.policy:RULES --receipts audit.jsonl --key-file audit.key
interlock doctor --sidecar ~/.interlock/guard.sock --json
```

Inside your own process, call interlock.posture.attest() (or require()) instead:
it sees the installed engine, sink, guards and approver directly.

Exit codes: 0 enforced, 1 degraded (warnings), 2 unprotected (a check failed).

```text
usage: interlock doctor [-h] [--rules MODULE:ATTR] [--policy FILE]
                        [--sidecar PATH] [--receipts FILE] [--key-file FILE]
                        [--json]
  --rules                    load this policy (same spec as interlock-sidecar --rules)
  --policy                   load this declarative policy file (JSON, or YAML with PyYAML)
  --sidecar                  probe the sidecar listening on this socket
  --receipts                 check this receipt log
  --key-file                 the receipt MAC key, to verify the log's chain
  --json                     machine-readable output
```

## `interlock report`

Summarize a receipt log: what interlock blocked, rewrote and escalated, what
monitor mode would have done, how long evaluation took, and whether any
receipts were lost.

```bash
interlock report audit.jsonl --key-file audit.key
interlock report audit.jsonl --since 24h --monitor     # "would have blocked"
interlock report audit.jsonl --json
```

The chain is verified first when --key-file is given; the report always says
whether it was. Receipts hold argument digests, never values.

Exit codes: 0 ok, 2 the chain is broken, 3 the log could not be read.

```text
usage: interlock report [-h] [--since DURATION] [--monitor] [--top N]
                        [--key-file FILE] [--json]
                        file
  file                       a receipt log written by FileSink
  --since                    only receipts newer than this: 30m, 24h, 7d (default: all)
  --monitor                  show what monitor mode would have blocked or rewritten
  --top                      rows per table
  --key-file                 the MAC key, to verify the chain
  --json                     machine-readable output
```

## `interlock hook`

Decide one coding-agent tool call (run by the agent, not by you).

The agent passes its hook payload on stdin; the verdict goes back on stdout and
the exit code, in that agent's own protocol. `interlock install-hook` writes
the command line; you do not normally run this by hand, except to test:

```bash
echo '{"hook_event_name":"PreToolUse","tool_name":"Bash",
       "tool_input":{"command":"git push --force origin main"},
       "session_id":"s","cwd":"/tmp"}' | interlock hook --agent claude-code
```

Any error - unreadable input, a policy that will not load, a crash - denies the
call (fail closed) unless --on-error allow, which lets the call through and
says so loudly.

```text
usage: interlock hook [-h] --agent {claude-code,codex,cursor} [--policy FILE]
                      [--rules MODULE:ATTR] [--sidecar PATH] [--receipts FILE]
                      [--key-file FILE] [--no-receipts] [--no-overlay]
                      [--monitor] [--on-error {deny,allow}]
  --agent                    
  --policy                   policy file (default ~/.interlock/policy.json, else the built-in coding-agent pack)
  --rules                    a Python policy module instead
  --sidecar                  ask this sidecar instead
  --receipts                 receipt log (default ~/.interlock/receipts.jsonl when its key exists)
  --key-file                 receipt MAC key
  --no-receipts              write no receipts
  --no-overlay               ignore project overlays
  --monitor                  record what would happen, never block
  --on-error                 what an internal error does (default deny)
```

## `interlock install-hook`

Put interlock in front of a coding agent's tool calls.

```bash
interlock install-hook --for claude-code
interlock install-hook --for all --dry-run       # show the change, write nothing
interlock install-hook --for codex --uninstall
```

Registers `interlock hook --agent <name>` in the agent's hook settings
(~/.claude/settings.json, ~/.codex/hooks.json, ~/.cursor/hooks.json), keeping
every other entry, backing the file up first (<file>.interlock-bak) and
replacing any earlier interlock entry. It also creates ~/.interlock with a
default policy that extends the built-in coding-agent pack and a key for the
receipt log. Restart running agent sessions afterwards.

Run this yourself, outside the agent: the coding-agent pack refuses it from
inside one.

Exit codes: 0 done, 1 an agent could not be configured, 64 bad arguments.

```text
usage: interlock install-hook [-h] --for {claude-code,codex,cursor,all}
                              [--settings FILE] [--policy FILE]
                              [--sidecar PATH] [--receipts FILE]
                              [--key-file FILE] [--monitor] [--dry-run]
                              [--uninstall]
  --for                      
  --settings                 the agent's settings file (default: its usual path)
  --policy                   pin this policy file in the hook
  --sidecar                  decide through this sidecar
  --receipts                 receipt log path
  --key-file                 receipt key path
  --monitor                  install in monitor mode
  --dry-run                  print the change only
  --uninstall                remove interlock's hooks
```

## `interlock policy`

Check a declarative policy file before you rely on it.

```bash
interlock policy check policy.json
interlock policy check ~/.interlock/policy.json --overlay .interlock/policy.json
interlock policy show builtin:coding-agent        # print a built-in pack
```

`check` loads the file the way the guard will: it lists the rules, the locked
ones, any rule quarantined as invalid (with why), and each overlay's status.

Exit codes: 0 valid, 1 loaded with quarantined rules, 2 does not load.

```text
usage: interlock policy [-h] ACTION ...
usage: interlock policy check [-h] [--overlay FILE] [--json] file
usage: interlock policy show [-h] name
```

## `interlock trust`

Trust (or stop trusting) a project's policy overlay.

```bash
interlock trust add                 # the overlay found from this directory
interlock trust add path/to/.interlock/policy.json
interlock trust list                # ok / CHANGED / MISSING
interlock trust remove [PATH]
```

An overlay (.interlock/policy.json in a repository) is ignored until trusted,
and trust is tied to the file's exact content: edit it and it is ignored again
until you re-trust it. `add` shows what the overlay adds before recording it.
Run this yourself, outside the agent - the coding-agent pack refuses it from
inside one.

```text
usage: interlock trust [-h] [--store FILE] ACTION ...
  --store                    trust file (default ~/.interlock/trusted.json)
usage: interlock trust add [-h] [--yes] [path]
usage: interlock trust list [-h]
usage: interlock trust remove [-h] [path]
```

## `interlock mcp`

Inventory the MCP servers configured on this machine.

```bash
interlock mcp scan                       # every server, with risk notes
interlock mcp scan --json
interlock mcp scan --emit-policy mcp.json  # a rule blocking unlisted servers
interlock mcp where github               # every config that defines it
```

Reads Claude Desktop, Claude Code, Cursor, VS Code, Windsurf, Gemini CLI and
Codex configs (user scope, plus the project around --cwd). Never starts a server
and never touches the network. Environment and header values are not read into
the report - only their names.

Exit codes: 0 no risks found, 1 at least one risk note, 2 nothing matched (where).

```text
usage: interlock mcp [-h] ACTION ...
usage: interlock mcp scan [-h] [--json] [--cwd CWD] [--emit-policy FILE]
usage: interlock mcp where [-h] [--cwd CWD] name
```


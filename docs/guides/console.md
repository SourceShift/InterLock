# The console

interlock has no network surface of its own: every check runs in-process,
inside your agent. The console is the one piece that opens a socket — a local
web app for the person running the agent, on the same machine. It shows what
the guard decided, lets you settle the calls waiting on a human, and lets you
write and test the policy behind those decisions. It binds to loopback only,
and the page loads nothing from any other origin.

You'll need: interlock installed, and Node.js to build the web bundle (once,
or whenever the bundle changes — the console server itself uses only the
Python standard library).

## Build the web bundle

```bash
npm --prefix web ci
npm --prefix web run build
```

This produces `web/dist/`, fonts included. Rebuild it whenever `web/src`
changes.

## Launch the console

Point it at the same files your guard uses. For the coding-agent hooks those
are in `~/.interlock/`:

```bash
python -m interlock.console \
  --receipts ~/.interlock/receipts.jsonl --key-file ~/.interlock/receipts.key
```

or, once interlock is installed, `interlock-console` with the same flags. It
prints one line on stdout once it's listening, and the unlock link on stderr:

```
interlock console listening on http://127.0.0.1:7878
unlock writes: http://127.0.0.1:7878/#/unlock/k7Qm-2fXa-9RtL
```

Open the first URL. The console starts **read-only**.

## Unlocking writes

Deciding a review and saving the policy are writes, and the console refuses
them until you unlock the tab. The reason is the agent on the same machine: it
can't run `interlock reviews approve` or write under `~/.interlock` (the
coding-agent pack blocks both), but without a gate it could `curl` the
console's API and do the same thing.

So each launch makes a one-off code and prints it, as the `unlock writes`
link, to the console's own terminal — nowhere else. Open the link, or paste it
into the unlock dialog. That tab gets a token held only in its own session
storage; other tabs stay read-only, and restarting the console re-locks every
tab. **Re-lock** in the banner drops the token. After ten wrong codes the gate
refuses every further attempt until the console restarts.

As a second line, the coding-agent pack's `self-protect-commands` rule treats
an HTTP client calling the console's unlock or write routes as tampering, so an
agent's `curl` to them is blocked before it runs.

## The screens

| Screen | What it's for |
|---|---|
| **Activity** | Is protection on, is the receipt chain intact, is anything waiting on you. Decisions over the last 30 minutes, 24 hours or 7 days: the verdict mix, a timeline you can focus on one slot, the newest decisions as they arrive, the rules that stopped the most, what monitor-mode rules *would* have done, how escalations were settled, evaluation latency. |
| **Reviews** | The [review queue](reviews.md): every held call with its countdown, the rule and the argument preview. Approve, reject with a reason, or revoke an approval the agent hasn't used yet. Keyboard: `j`/`k` to move, `a` to approve, `r` to reject, `?` for the list. |
| **Audit log** | Every [receipt](audit-log.md), newest first, with the chain status. Filter by verdict (including escalated and observed), rule, or text. A receipt's detail shows how an escalation was settled, its epoch, and a link to its review. Follows the log live. |
| **Policy** | The [declarative policy](policies.md) file: its rules (own, inherited, locked, quarantined, disabled), a JSON editor that checks the draft as you type, the epoch the draft would have, project overlays and their trust status, and the built-in pack you extend. Saving changes the epoch, which voids outstanding approvals; the console says how many before you confirm. |
| **Playground** | Run catalog detectors against sample calls. Pick a detector, fill its parameters, edit the events, and see one verdict per event, with rewrites shown as a diff. |
| **Detectors** | The detector catalog: search, filter by category, read a detector's parameters and documentation, and open it in the playground. |
| **Scopes & sandbox** | Resolve a [scope](scopes.md) document for a principal: the parameters it gets, the [sandbox](sandbox.md) profile, and which parts of that profile this host can actually enforce. It computes the plan; nothing runs. |
| **Ops** | `interlock doctor`'s checks, whether Claude Code, Codex and Cursor have the hook installed, every configured MCP server with its risk tags, the sidecar's health and stats, and the receipt log's state. Installing a hook or trusting an overlay stays a command you run yourself — the console shows it with a copy button. |

## Flags

| Flag | Default | What it does |
|---|---|---|
| `--host` | `127.0.0.1` | The address to bind. Must be loopback — `127.0.0.1`, `localhost` or `::1`. Anything else is refused before a socket opens. |
| `--port` | `7878` | The port to bind. A port already in use exits 1 with one line naming it. |
| `--static` | `web/dist` next to the installed package | Where the built web app lives. A missing directory still serves the API, and the page names the build command. |
| `--receipts` | none | The receipt log to read. Without it, Activity and the audit log explain how to point the console at one. |
| `--key-file` | none | The receipt log's MAC key (64 hex characters, or raw bytes), to verify the chain. Without it the chain reads "unverified". The key never leaves the console process. |
| `--receipts-head` | none | The mac the receipt log must end at (64 hex characters). With it, a rolled-back or truncated log verifies "broken" instead of "intact". |
| `--policy` | `~/.interlock/policy.json` | The declarative policy the Policy screen reads and saves. |
| `--reviews-db` | `~/.interlock/reviews.db` | The review queue. The console never creates it just by looking. |
| `--four-eyes` | off | Refuse an approval by the account that filed the review. |
| `--sidecar` | its usual socket, if present | The guard daemon's socket, to probe for Ops. |
| `--sidecar-admin` | none | The daemon's loopback admin address (`interlock-sidecar --admin HOST:PORT`), for its stats and config. |
| `--transcripts` | `~/.claude/projects` | Claude Code transcripts, for the real-data features below. Only ever read. |

### Started without a receipt log

Started without `--receipts`, Activity and the audit log show an empty state
rather than failing: there is no log to read, so every count is zero and the
chain reads "unverified". To fix it:

1. `interlock install-hook --for claude-code` (or `codex`, `cursor`, `all`)
   creates `~/.interlock/receipts.key`; the hooks then write
   `~/.interlock/receipts.jsonl` by default.
2. Let the agent make one guarded call — the first receipt creates the file.
3. Restart the console with `--receipts ~/.interlock/receipts.jsonl
   --key-file ~/.interlock/receipts.key`, pointing `--receipts` at wherever
   your hook writes. `--key-file` is optional and only verifies the chain;
   `--receipts-head` is optional too, and is what catches a truncated log.

`scripts/console_traffic.py /tmp/il-demo` writes a real scratch log, queue and
policy if you want to try the console before installing anything; point
`--receipts` at `/tmp/il-demo/receipts.jsonl`.

## Testing on your real calls

Receipts store a fingerprint of each call's arguments, never the arguments.
Claude Code keeps them, and what each tool returned, in its session
transcripts, and the hook stamps every receipt with Claude Code's own tool-call
id. The console joins the two:

- **The call behind a receipt.** Open a receipt in the audit log and the drawer
  shows the file or command, the output the model saw, and every receipt for
  the same call. It recomputes the argument fingerprint from the transcript, so
  "this is the recorded call" is proven, not guessed. Subagent calls are found
  in their own transcripts.
- **Real calls in the playground.** Pick **Real calls…** in the preset list,
  filter by tool or text, and use the calls (and their outputs) as events. They
  are built by the same adapter the hook uses, so a detector sees exactly what
  it would see live.
- **Test a policy on real calls.** The Policy screen's last tab runs the draft or
  the saved policy over your last 100-2,000 calls and lists the ones it would
  block, rewrite or escalate - and any the guard decided differently at the
  time. Nothing runs and no receipt is written.
- **Sweep the catalog.** On the Detectors screen, run every detector at its
  defaults over your recent calls to see which would fire, how often, and on
  what; open the examples in the playground.

Credentials in arguments and outputs are masked, with the guard's own patterns,
before they reach the page; backtests and sweeps evaluate the unmasked calls.
Transcripts are large, so the console reads only the newest ones (within a
byte budget) and re-reads a growing file from where it stopped.

## Trying it on real traffic

`scripts/console_traffic.py` pipes genuine Claude Code and Codex hook payloads
through `interlock hook` into a scratch directory — allowed calls, blocks,
escalations filed as reviews, monitor-mode calls, a failed call — then settles
a few reviews through `interlock reviews`. Nothing in it is written by hand:

```bash
python3 scripts/console_traffic.py /tmp/il-demo
python3 -m interlock.console --receipts /tmp/il-demo/receipts.jsonl \
  --key-file /tmp/il-demo/receipts.key --policy /tmp/il-demo/policy.json \
  --reviews-db /tmp/il-demo/reviews.db
```

## Verifying the receipt chain

With `--key-file`, the Audit log and Activity screens report whether every
receipt is signed and linked. Without an anchor, a shorter but otherwise valid
log still verifies intact: a prefix of a valid chain is itself a valid chain,
so truncation or a swap to an older signed copy is invisible to the chain
alone. `--receipts-head` is what catches it — pass the mac of the last receipt
you saw, and a log that no longer ends there reports "broken":

```bash
python -m interlock.console --receipts audit.jsonl --key-file receipt.key \
  --receipts-head 6f1c…(64 hex)
```

The badge goes "changed since last check" as soon as a new receipt arrives,
then re-verifies within a couple of seconds; it never keeps claiming "verified"
for a log that changed after the last check. See also
[a cut tail needs a recorded head](audit-log.md#limits).

## Watching a sidecar's receipt log

Point the console at the same `--receipts` file a running
[sidecar](../reference/sidecar.md) is writing, and decisions appear as the
sidecar makes them:

```bash
interlock-sidecar --rules my_service.policies:RULES \
  --receipts audit.jsonl --key-file receipt.key --admin 127.0.0.1:19000

python -m interlock.console --receipts audit.jsonl --key-file receipt.key \
  --sidecar-admin 127.0.0.1:19000
```

## Development

Run the Python server and the Vite dev server side by side; Vite proxies
`/api` to `127.0.0.1:7878`:

```bash
python -m interlock.console --receipts /tmp/il-demo/receipts.jsonl &
npm --prefix web run dev
```

The screens' markup in `web/src/design/` is generated from the designer's file,
`design/console/Interlock Console.dc.html`, by
`scripts/console_design/convert.py`; don't edit it by hand. What the screens
show comes from `web/src/vals.ts`, fed by the API through `web/src/store.ts`.
`npm --prefix web run typecheck` checks every binding in the markup against
the view-model; `npm --prefix web test` runs the unit tests.

## Security model

- **Loopback only.** The console refuses to bind anything else, and refuses a
  request whose `Host` header doesn't name this server, which stops a page
  elsewhere reaching it through your browser (DNS rebinding).
- **No cross-origin access.** No CORS headers; every POST must be
  `application/json`; every HTML response carries `X-Frame-Options: DENY` and a
  `Content-Security-Policy` of `default-src 'self'`. The page loads no script,
  font or image from any other origin.
- **Writes need an unlocked tab** (above), so a process on this machine can't
  approve its own reviews or rewrite its own policy through the console.
- **Secrets stay put.** The receipt key never leaves the console process.
  Receipts carry argument digests, not arguments; the only argument values the
  console shows are review previews, which the review queue stores for the
  human deciding.
- **It only reads, except for the writes above.** Hooks, trust and the sidecar
  are changed by commands you run yourself, outside any agent.

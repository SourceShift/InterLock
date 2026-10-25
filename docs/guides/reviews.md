# Review queue: ask a human without holding the call

[Approvals](approvals.md) ask an approver while the call waits. Often that's not
possible: a coding agent's hook has a timeout, a job has a deadline, Codex can't
open a prompt. The review queue decouples the two. The call is refused now with
a review id, a human decides later, and the **identical** retry runs once.

```mermaid
sequenceDiagram
    participant A as agent
    participant G as interlock
    participant Q as review queue
    participant H as human
    A->>G: npm publish
    G->>Q: file review (bound to this exact call)
    G-->>A: refused: review r-1a2b3c4d is pending
    H->>Q: interlock reviews approve r-1a2b3c4d
    A->>G: npm publish (identical)
    G->>Q: claim the approval (once)
    G-->>A: allowed
```

## In your own agent

```python
import interlock
from interlock.reviews import ReviewQueue, queue_approver

queue = ReviewQueue()            # ~/.interlock/reviews.db
interlock.install(rules=[...], approver=queue_approver(queue))
```

The first escalation raises `NotApproved`: "review r-1a2b3c4d is pending; a
human must run `interlock reviews approve r-1a2b3c4d`, then retry this identical
call". After the approval, the same call (same tool, same effective arguments,
same agent, same working directory, same rule) runs **once**. Two concurrent
retries can't both run: the claim is a single conditional update. A different
call files its own review.

A review is filed for, and previews, the arguments **that will run**: when a
rule rewrites the call before it escalates, the preview shows the merged
`modified_args` and the digest binds that rewrite. An approved retry runs the
rewrite. If the agent's hooks cannot apply a rewrite, the retry is refused
rather than running the original arguments.

`queue_approver(queue, wait=60)` holds the call for up to 60 seconds first, for
callers that can afford to wait.

## For coding agents

The hooks use the queue automatically when an agent can't ask: Codex, and
Cursor file reads. Without it they could only refuse. Claude Code keeps its
native permission prompt; install with `--reviews always` to send its
escalations through the queue too, or `--reviews off` to disable the queue.

## Deciding

```bash
interlock reviews list                       # newest first; --status pending
interlock reviews show r-1a2b3c4d            # reason, rule, agent, the call
interlock reviews approve r-1a2b3c4d         # --as NAME (default: your login)
interlock reviews reject r-1a2b3c4d --reason "use the staging table"
interlock reviews revoke r-1a2b3c4d          # withdraw an approval not yet used
```

A rejected call that is retried unchanged gets the rejection back. It doesn't
file a new review and ask you again.

## Settings

```python
ReviewQueue(path=None, pending_ttl=3600, approval_ttl=900,
            min_approvals=1, allow_self_approval=True,
            key=None, key_path=None)
```

| Setting | Meaning |
|---|---|
| `pending_ttl` | Seconds to decide before the review expires |
| `approval_ttl` | Seconds to *use* an approval, counted from when it was granted |
| `min_approvals` | Distinct approvers needed (four-eyes: `2`) |
| `allow_self_approval` | `False` refuses an approval by the account that filed the review |

Each review row stores the `allow_self_approval`, `min_approvals` and
`approval_ttl` in force when it was filed. The database also records the
strictest policy it has ever been opened with: `allow_self_approval` ratchets to
false, `min_approvals` ratchets up and `approval_ttl` ratchets down. A decision
obeys the stricter of the row and that record, so a CLI or console process that
opens the queue with defaults cannot weaken the rules the review was filed
under (a console started with `--four-eyes` keeps applying it). Nothing loosens
the record implicitly; deleting the database resets it.

Statuses are `pending`, `approved`, `rejected`, `revoked`, `expired` and
`executed` (an approval that was used).

## Integrity

Every row is signed with an HMAC-SHA256 key that lives **beside** the database
(`reviews.key`, mode 0600) and never inside it. The signature covers the
binding, the preview, the status and decision, the approver names and the
approval list. A writer who can edit `reviews.db` but cannot read the key can
no longer promote a pending review, redirect an approval to a different call,
edit the preview a human is shown, or add an approver to satisfy
`min_approvals`; the queue refuses the row with "does not match its signature"
and the call stays refused.

The key is the boundary. A process that can read both files can forge, and one
that can delete either can deny service. Keep the directory private (the queue
creates it 0700), and for a database on shared storage put the key somewhere
else with `key_path=` - or pass the bytes directly with `key=` from a secret
store; decisions made on another machine need the same key to verify. Deleting
or replacing the key invalidates every decision signed with it.

An upgrade from a database written before signing seals its existing rows on
first open, in the reviewer's own process.

A signature cannot see a **wholesale rollback**: restoring an older copy of
both files replays the decisions made since that copy, until `approval_ttl`
runs out. A short TTL bounds the window, and the receipt log remains the
independent record of what actually ran.

## Let the agent check on its review

`interlock reviews mcp` is a read-only MCP server (stdio, no dependencies). It
has three tools: `review_status`, `review_list` and `review_wait`. Each returns
`next: wait | retry_identical_call | stop` and an instruction, so an agent knows
whether to wait, retry or give up. It never approves anything.

```json
{"mcpServers": {"interlock-reviews": {"command": "interlock", "args": ["reviews", "mcp"]}}}
```

## Trust

- The queue file and its key must not be writable by the agent. The
  coding-agent policy locks `~/.interlock`, and refuses
  `interlock reviews approve`/`reject`/`revoke` from inside an agent.
- Approver names come from the OS login (or `--as`). A name is only as good as
  the key that signed the row: a process that can read both the database and
  `reviews.key` can still claim any name, so keep both private (mode 0600, the
  default). Editing the database alone no longer buys an approval.
- The queue stores a preview of each call (its arguments, truncated) so the
  approver can see it. Receipts never do.
- What an approval is bound to includes the policy epoch when it's stable
  across processes (declarative policies). A policy change then voids pending
  approvals.

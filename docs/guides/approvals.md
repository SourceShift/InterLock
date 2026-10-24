# Ask a human (ESCALATE)

Some calls are legal but shouldn't happen without a person deciding: a payment
over a limit, a publish, a force-push. A rule returns `Decision.escalate(...)`,
and the call waits for an approver.

```python
import interlock
from interlock import Decision, guard

def big_payments(event):
    if event.action == "pay" and event.args.get("amount", 0) > 1000:
        return Decision.escalate("payment over 1,000", policy_id="big-payments",
                                 attributed_to="amount")
    return None

interlock.install(rules=[big_payments], approver=interlock.approval.tty_approver())

@guard()
def pay(to: str, amount: int) -> str: ...

pay("acme", 50)       # runs
pay("acme", 5000)     # asks at the terminal; runs only if you approve
```

With **no approver installed, every escalation is blocked**. A deployment that
ignores escalation behaves exactly as before. The refusal is `NotApproved`, a
subclass of `Blocked`, so code that handles blocks already handles it.

## What an approval covers

An approval is bound to one exact request:

- the action and phase
- a digest of the arguments **that will run** (the call after any rewrite)
- the principal
- the working directory the call runs in
- the policy that decided (its [epoch](policies.md#the-policy-epoch))
- the rule
- the reason shown to the approver

The approver decides on the effective arguments, not the pre-rewrite ones: when
another rule rewrites the call and then it escalates, the request carries the
merged `modified_args`, the terminal prompt previews them, and the receipt's
`args_digest` is the digest of what will actually run. Changing the rewrite
changes the binding, so an approval cannot be replayed against a different
call.

Approving `pay(amount=5000)` doesn't approve `pay(amount=9000)`; approving a
call in one directory does not approve the identical call from another, and
reinstalling or reloading the policy voids every grant made under the old one.

An approver returns one of:

| Return | Means |
|---|---|
| `True` or `approve_once()` | run this call, once |
| `approve_for_session()` | this exact request is approved for the rest of the current `span` |
| `approve_for(seconds)` | this exact request is approved for that long |
| `False`, `None`, anything else | declined |

An approver that raises has declined. If the policy changes while the approver
is deciding, the approval is refused.

The reason is cut to one printable line of at most 512 bytes before the approver
sees it, and that exact text is part of the binding. `ApprovalRequest` is
frozen, so nothing can change what was approved after the fact.

## Precedence

A **block from any rule beats an escalation**: the engine only returns ESCALATE
when no rule blocked, so an approval can never override a block. Rewrites from
other rules ride along: an approved call runs with them applied.

## Writing an approver

An approver is any callable that takes an `ApprovalRequest`:

```python
from interlock.approval import approve_for, approve_once

def slack_approver(request):
    # request.action, request.reason, request.attributed_to, request.principal,
    # request.policy_id, request.event.args (the full call, to show a human)
    answer = ask_on_call_engineer(request)      # your code
    if answer == "approve":
        return approve_once()
    if answer == "approve-hour":
        return approve_for(3600)
    return None
```

`interlock.approval.tty_approver()` asks at the controlling terminal. It reads
`/dev/tty` directly, never stdin, so piped input can't answer for you, and it
declines when there is no terminal.

Grants wider than one use are kept in `interlock.approval.grants()`. Call
`grants().active()` to list them, and `grants().revoke(action=..., principal=...)`
or `grants().clear()` to withdraw them. Expired and revoked grants are pruned as
the store is used, and a long-lived store keeps at most 1024 live grants
(dropping the oldest first), so it does not grow without bound.

## Receipts

Every escalation leaves a receipt with `policy_verdict="ESCALATE"`, the
enforced `verdict` (ALLOW, MODIFY or BLOCK) and how it was settled in
`approval`: `approved:once`, `approved:session`, `approved:ttl`,
`reused:session`, `reused:ttl`, `declined`, `no-approver` or `approver-error`.
Under the coding-agent hooks it's `delegated:<agent>`, because the agent's own
prompt asked.

## The limit

The approver runs in the agent's process. Code that is already malicious in
that process could install an approver of its own, the same trust boundary as
every in-process rule (see the [security model](../security-model.md)). For an
approval the agent can't reach, decide outside its process. The coding-agent
hooks hand escalations to the agent's own approval prompt.

The Node.js client takes an `onEscalate` callback with the same contract: it
resolves `true` to run one call, and anything else (including no callback)
blocks.

# Keep secrets out of the model's reach

An agent that needs an API key usually gets it in its prompt or context. From
there it can end up in tool arguments, logs, summaries, or a request to the wrong
host. Placeholder credentials keep the value away from the model entirely: the
agent writes `{{secret:stripe}}` where the key goes, and interlock fills it in
at the last moment, only where you allowed it.

```python
import interlock
from interlock import guard
from interlock.credentials import SecretStore, install_store

store = SecretStore().add(
    "stripe", env="STRIPE_KEY", actions=["http_post"],
    hosts=["api.stripe.com"], label="Stripe live key",
)
install_store(store)

@guard()
def http_post(url: str, headers: dict = None, body: str = "") -> str: ...

# What the agent writes:
http_post("https://api.stripe.com/v1/charges",
          headers={"Authorization": "Bearer {{secret:stripe}}"})
# The function receives the real key. The same placeholder sent to
# https://evil.example raises Blocked: the secret may not go there.
```

## How it works

1. **Policy sees placeholders.** Rules, receipts and logs see `{{secret:stripe}}`,
   never the value, so a rule can reason about *which* secret a call uses.
2. **The value is filled in after the decision.** Once the policy has allowed
   the call (and applied any rewrite), each placeholder is checked: the secret
   must exist, this action must be in its `actions`, and if it has `hosts`,
   every URL in the call must go to one of them. Anything else blocks. Only
   then is the value read and filled in.
3. **Results are scrubbed.** If the tool echoes the secret back, it's replaced
   by its placeholder before any result rule or the agent sees it.
4. **Receipts record ids, never values.** A `credentials` receipt names the
   secrets each call used.

Filling in after the decision is deliberate. A rewrite rule would have to be the
very last rule, and any rule after it would see the real value.

## Sources

Each secret has exactly one source, read on first use:

| Source | Example |
|---|---|
| `env=` | `env="STRIPE_KEY"` |
| `file=` | `file="~/.config/acme/token"` (whitespace stripped) |
| `getter=` | `getter=lambda: keychain.read("acme")`, your own lookup |
| `value=` | a literal, for tests |

A secret that can't be read blocks the call. interlock never reaches out to a
vault or the network itself.

## Telling the agent what it may use

`store.catalog()` returns ids, labels, tags, allowed actions and hosts, and
never values. Expose it as a tool so the agent can pick the right placeholder:

```python
@guard()
def list_credentials() -> list:
    return store.catalog()
```

## Monitor mode

Under `@monitor()`, a placeholder that may not be filled is left as is (the tool
gets the literal placeholder) and the refusal is recorded as observed. Monitor
mode never sends a secret anywhere the policy wouldn't.

## Limits

- The tool function receives the real value. Code inside the tool can log or
  forward it; guard what the tool does with the same care.
- Scrubbing replaces exact matches of values read in this process. A tool that
  transforms the secret (base64, say) before returning it isn't caught.
- The coding-agent hooks don't fill placeholders. A value written into a Claude
  Code tool input becomes part of the agent's own transcript.

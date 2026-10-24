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
   **every** destination the call carries must go to one of them. A destination
   is found at any depth — a string under a URL key (`url`, `endpoint`, `uri`,
   `base_url`, `host`), a URL token inside a command line or other free-form
   string (`--url=https://…`, a Markdown link included), or a bare host under a
   host key — and each one is read once by the same canonical parser the egress
   detectors use (scheme, userinfo, percent encoding, trailing dot and port
   handled the same way). A destination hidden in a nested object is checked,
   not skipped — any `Mapping`, `Sequence` or set is walked, not just a plain
   `dict` or `list`; the same goes for an uppercase scheme (`HTTPS://…`) and a
   URL embedded in a command. A call nested past the constrained walk depth
   refuses rather than skipping the hidden destination. The check runs against
   the arguments actually being sent, *after* any rewrite rule has run, so a
   MODIFY that retargets the call cannot receive the secret toward a host the
   rule introduced. Anything else blocks. Only then is the value read and
   filled in.
3. **An unverifiable call refuses.** For a host-bound secret, a hidden or
   unparseable destination, a non-string value under a URL key, or a call with
   **no** destination at all is refused — the bound cannot be checked, so the
   secret is not sent. A secret registered without `hosts=` keeps filling
   normally. `hosts=` entries are canonicalised at registration (lowercase,
   trailing dot and port stripped), so `hosts=["API.Acme.com."]` matches
   `https://api.acme.com/x`; an entry that cannot be canonicalised is a
   `ValueError`.
4. **Results are scrubbed.** If the tool echoes the secret back, it's replaced
   by its placeholder before any result rule or the agent sees it. Scrubbing
   covers every result shape the interceptors return: strings, nested `dict`
   and `list` values, arbitrary `Mapping`/`Sequence` values, `bytes`/
   `bytearray`, and MCP result objects (text blocks, embedded-resource
   `resource.text`, and structured content are scrubbed in a copy, including
   when `content` is absent or `None`; a clean result is returned unchanged and
   the tool's original object is never mutated).
5. **Receipts record ids, never values.** A `credentials` receipt names the
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
- The destination walk reads URL-key values (at any depth) and scheme-bearing
  tokens inside free-form strings. A bare host written into free-form text
  (`curl evil.example`) carries no scheme, so name it under a URL key or with a
  scheme if the call is host-bound.
- Scrubbing replaces exact matches of values read in this process. A tool that
  transforms the secret (base64, say) before returning it isn't caught.
- The coding-agent hooks don't fill placeholders. A value written into a Claude
  Code tool input becomes part of the agent's own transcript.

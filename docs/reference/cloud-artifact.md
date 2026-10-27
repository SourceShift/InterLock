# The policy artifact reference

The **artifact** is the compiled policy a host enforces. It is data only: the
declarative documents the policy was authored from, the scope bindings that
say which template applies where, and a *reference* to the code that binds
them. It never contains executable policy code.

This page is the byte-level contract. If you are operating a plane, read
[the cloud guide](../guides/cloud.md) first and come back here when you need
to know what a host is actually enforcing.

## Why an artifact and not a source policy

A host enforces a **signed, hashed, immutable** artifact rather than the
source files the policy was written in. Three things follow:

- The plane can prove the host is enforcing the bytes the operator intended.
  The artifact's SHA-256 is in the manifest; the manifest is signed.
- Two hosts cannot drift. Both fetch the artifact by digest.
- The source can keep moving without the hosts moving with it. A new
  artifact is a new version, and the version allocator never reuses one.

## Every field

The artifact is a JSON object with exactly these top-level keys. An **unknown
key is refused**, not ignored: an artifact is a signed contract, and silently
ignoring a field an older host never validates would let a newer producer
smuggle it past.

| Field | Type | Required | What it is |
|---|---|---|---|
| `format` | integer | yes | The artifact format version. This build understands `1` and refuses anything else |
| `epoch` | string | yes | The identity of the exact rule set: 16 hex characters derived from the body (see below) |
| `documents` | list | yes | The normalised declarative policy documents, in the order they were authored |
| `scope` | object | yes | The scope configuration: `version`, `bindings`, `default_scope`, `allow_unscoped` |
| `rules_module` | string or null | no | A `module:attr` spec naming the `templates` mapping the scope engine binds |
| `template_ids` | list of strings | no | The deterministic ids of every template the artifact resolved |
| `catalog` | string | no | The detector catalog id the artifact was compiled against |
| `failure_policy` | object | yes | Per action class, whether a failure fails open or closed |

### `documents`

Each entry is one normalised policy document: the rules the engine actually
kept, with any `extends` overlay already folded in and recorded under
`overlay`. A document whose rules **quarantine** refuses the whole compile.
That is deliberate: signing a rule the host will skip produces a policy that
silently does nothing, and the plane cannot tell the admin afterwards.

### `scope`

```json
{
  "version": 1,
  "bindings": {
    "tenant": [
      {"template": "shell_allowlist", "params": {"allow": ["ls"]}}
    ]
  },
  "default_scope": [],
  "allow_unscoped": false
}
```

`bindings` maps a scope kind to the templates that apply to it. Each entry
names a `template` id and the `params` that template factory is called with.
`default_scope` lists the kinds that apply when a call names none.
`allow_unscoped` says whether a call with no scope at all is evaluated
against the unscoped floor or refused.

### `rules_module` and `template_ids`

Template factories are Python callables and are not serialisable, so the
artifact never embeds code. It names the module instead:
`rules_module` is `"package.module:attribute"`, and the imported attribute
must be a mapping of template id to factory. The artifact's
`template_ids` are the ids that mapping actually resolved to, sorted, so a
host can prove it has every template the plane intended.

Two refusals here matter:

- **Module mismatch.** If the artifact names a module and the host's
  environment names a different one, the artifact is refused. A host never
  binds the wrong templates.
- **Unresolvable template.** If a named template id is not in the mapping,
  the artifact is refused. A missing template is a refusal, not a gap.

An artifact with scope bindings but no `rules_module` is refused too: the
bindings would be unresolvable by construction.

### `catalog`

The id of the detector catalog the artifact was compiled against. It is
informational - the artifact does not carry the detectors - but it tells an
operator whether the hosts are running the same catalog the plane compiled
for.

### `failure_policy`

What a host does when it **cannot** evaluate: a missing rule module, an
artifact that does not match the expected hash, an expired manifest, a
dead evaluator.

| Action class | Default | Meaning |
|---|---|---|
| `read_only` | `open` | Reading cannot change the world, so a failure lets the call through |
| `local` | `open` | Same reasoning, for local resource access |
| `granted_llm` | `open` | The call was already granted by a human; failing closed would undo an approval |
| `shell` | `closed` | A shell can do anything |
| `egress` | `closed` | A failed check must not become an uncontrolled send |
| `delete` | `closed` | Deletion is irreversible |
| `email` | `closed` | A sent mail cannot be recalled |
| `payment` | `closed` | A payment cannot be reversed |

Every class must be present and every value must be `open` or `closed`. A
missing class is a **refusal, not a default**: a host that silently filled one
in would be enforcing a policy the plane never compiled.

## Canonical JSON

There is exactly one serialisation, and it is the one used for hashing,
signing and storage:

```python
json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
```

encoded as UTF-8 with **exactly one trailing newline**.

- `sort_keys=True` - the key order is the sorted order, always.
- `separators=(",", ":")` - no insignificant whitespace.
- `ensure_ascii=False` - the bytes are UTF-8, not escaped ASCII. The hash is
  over the same bytes the host fetches.
- One trailing newline - the file ends like a text file, and the newline is
  part of the hashed bytes.

Any other serialisation produces a different digest for the same policy. That
is why the canonicaliser is the only one in the codebase that is allowed to
produce artifact bytes.

## The epoch

The epoch is the identity of the exact distributed rule set:

```
epoch = sha256(canonical_bytes(body_without_epoch))[:16]
```

Sixteen hex characters, taken from the front of the digest. The body is
canonicalised **without** the `epoch` key, so recomputing an existing
artifact's epoch is a pure function of its content - there is no circular
dependency to resolve.

The epoch is deliberately **not** `PolicyEngine.epoch`. Some engines hash
object identities, which cannot survive a serialise/deserialise round trip.
The artifact's epoch is content-derived, so a host that fetches the same
artifact computes the same epoch, and the two can be compared.

Every receipt the host writes is stamped with the artifact's `epoch` and its
`artifact_sha256`, so a receipt names the exact policy that produced it.

A host that receives an artifact whose `epoch` does not match its body
refuses it. That is the `epoch_mismatch` refusal.

## Determinism

Compiling the same sources twice produces byte-identical artifacts, and the
plane proves it before publishing anything:

1. The source policy is evaluated over a shared corpus.
2. The compiled artifact is evaluated over the *same* corpus.
3. The two sets of decisions are compared.
4. **The first divergence refuses the publish.**

The comparison is on the decision shape, not on the object: the verdict, the
rule id, the reason and the modify payload. So a compile that changes a
verdict is caught, and a compile that only changes an internal detail is
not.

Determinism also holds for the identifiers: `template_ids` are sorted, and
the artifact's `sha256` is a pure function of its bytes.

## The C ABI

The optional native evaluator is loaded over a small C ABI. Three functions
matter on the hot path.

```c
int32_t il_plan_load(const char *plan_json, size_t plan_len, int32_t *err);
```

Parse a plan once and return an opaque handle, or null on error. `err`, when
non-null, is set to `0` on success and `-1` on failure. The handle is a
token, not a pointer into the allocator's memory: it stays valid until
`il_plan_free`, and every use after that returns `-1` rather than touching
freed memory.

```c
int32_t il_eval_plan_handle(
    void *handle,
    const char *event_json, size_t event_len,
    int32_t *out_verdict,
    char *out_policy, size_t policy_cap,
    char *out_reason, size_t reason_cap);
```

Evaluate one event against a loaded handle. The return and out-parameter
contract is the same as `il_eval_plan`. A null, unknown or already-freed
handle returns `-1` and writes nothing.

```c
void il_plan_free(void *handle);
```

Release a handle. A null, unknown or already-freed handle is a no-op, so a
double free is safe by construction rather than by convention.

The original stateless entry point remains:

```c
int32_t il_eval_plan(
    const char *event_json, size_t event_len,
    const char *plan_json, size_t plan_len,
    int32_t *out_verdict,
    char *out_policy, size_t policy_cap,
    char *out_reason, size_t reason_cap);
```

It parses the plan on **every** call. It is kept for compatibility and for
the parity corpus; the load-once path above is what a hot path should use.

On success the return value is `0`, and `out_verdict` is `0` (allow), `1`
(block), `2` (modify) or `3` (escalate). `out_policy` and `out_reason` are
NUL-terminated and truncated on a character boundary to fit; pass a null
pointer or a capacity of `0` to skip either.

A plan that is absent, stale or incompatible is not an error path in the
caller - it selects the failure policy above.

## Parity and budget

Two contracts hold the two evaluator backends together.

**Parity.** Over the shared corpus, the native and the Python evaluator
produce *identical* verdicts, rule ids, reasons, attribution and modify
payloads. A divergence is a bug in one of them, and the corpus test fails.

**Budget.** At a 1 MiB artifact and a 32 KiB event on the reference host:

| Backend | p99 latency |
|---|---|
| Native | under 5 ms |
| Python | under 10 ms |

The Python evaluator is the default and the mandatory fallback. The native
one is an optimisation, never a requirement: if the extension is missing,
the artifact is invalid, or the operator sets `IL_EVAL_NATIVE=0`, the host
falls back to Python and keeps enforcing.

The sidecar enforces a tighter 2 ms deadline for the high-risk action
classes, and reports its own sha256 and epoch so the caller can tell which
artifact produced a verdict.

## Where to go next

- [Rolling out a policy](../guides/cloud-rollout.md) - compile, canary, watch
  the swaps, roll back.
- [The runbook](cloud-runbook.md) - kill switch, manifest expiry, restore.
- [The cloud guide](../guides/cloud.md) - what the plane does around the
  artifact.

# The cloud plane

Everything else in this manual assumes interlock runs next to the agent, on
the same machine, with the same process. This page is about the other
arrangement: a **hosted control plane** that several machines report to and
one person reviews from a browser.

The plane is optional. A single-machine install needs none of it, and the
default console still binds loopback only. What the plane adds is shared
review, a searchable audit trail across hosts, and one compiled policy
published to every host.

## Three planes, not one

The design keeps three things apart on purpose. Confusing them is how a
"control plane" ends up on the verdict path.

| Plane | Where it runs | What it holds | Latency |
|---|---|---|---|
| **Control plane** | Your server | Sessions, review decisions, grants, compiled policy, the audit trail | Seconds to minutes |
| **Data plane** | Each host | One compiled policy artifact, a local evaluator, the host's own key material | Microseconds, per call |
| **Audit plane** | Your server | Receipts and decisions, chained and independently verifiable | Batch, off the hot path |

The rule that keeps them apart: **the control plane is never on the verdict
path**. A hook never opens a network connection. The data plane never asks the
plane for a decision. A held call waits for a grant that the host verifies
locally against a signed chain, with the host holding the only key that can
release it.

So the plane can be slow, unreachable, or down, and a call that the local
policy already allows still goes through. Only a call the local policy
*escalates* waits - and it waits because a human has not decided yet, not
because the network is slow.

## What leaves the host

This is the whole privacy surface of the data plane. A host sends three
things and nothing else.

| What leaves | Why the plane needs it | What is *not* sent |
|---|---|---|
| **Masked preview** | The reviewer has to see what was held to decide it | The raw arguments, the raw event, the tool's output. The preview passes through the [masking engine](databases.md) first, and the upload carries per-entity counts instead of the entities |
| **Receipt fields** | The audit chain needs the verdict, the rule that produced it, and the previous receipt's MAC | Nothing that is not already in the receipt the host signed locally: no arguments, no credentials, no request or response bodies |
| **Heartbeat** | The plane must know a host is alive and which manifest version it is enforcing | Nothing about what the host is doing. It is a liveness ping and a version report |

Two identifiers travel with every upload and neither is content: the host id
(the plane minted it) and a requester label. The requester label is an
HMAC under the host's agent key unless the org explicitly opts into sharing
usernames, so two hosts cannot correlate their reviewers and the plane cannot
invert one.

An argument *digest* also travels - a hash, not the arguments - so the plane
can prove the reviewed call is the call that was released.

Everything the plane stores about a review is encrypted at rest with the
org's key, and reading a decrypted preview is a separately audited event.

## Enrolling a host

Enrollment is a token, one request, and a `0600` file.

1. An owner or admin mints an enrollment token in the plane.
2. The host runs the connector against the plane's URL with that token:

   ```bash
   interlock cloud enroll --url https://plane.example.com --token "$TOKEN"
   ```

3. The connector generates a host seed on the machine, sends only the public
   half, and writes two files under `~/.interlock/cloud/`: `cloud.seed` (the
   private seed) and `cloud.json` (the configuration). Both are created
   through a temporary file with mode `0600` and renamed into place, so there
   is no window in which the agent key is readable by another user.

The token is single-use and is deliberately **not** retried: a retry after a
timeout could consume a second token or enroll the host twice.

The plane pins the host's public key at enrollment. A later call that presents
a different key is refused.

## The review flow

A call that the local policy escalates is held on the host, spooled, and
uploaded. From there:

1. **The host spools, then uploads.** The record is written to the spool
   first, so a plane outage loses nothing and the verdict path is not
   delayed by a network round trip.
2. **The plane stores it encrypted.** The review lands in the queue with its
   preview encrypted at rest. The queue is visible to the reviewers the role
   table allows.
3. **A human decides.** The decision needs a fresh step-up (a WebAuthn or
   TOTP assertion), and, where the org asks for it, two different people.
   An approver cannot approve their own request when the org forbids it.
4. **The grant is signed.** The plane signs a grant bound to the exact call -
   its digest, its policy, its expiry - and chains it per host with a `prev`
   link and a sequence number.
5. **The host verifies and applies.** The connector fetches the grant, checks
   the signature, the sequence, the `prev` chain, the binding and the expiry
   against the call it is holding, and only then releases the call. A grant
   that does not match the call exactly is refused.
6. **The release is recorded.** The receipt of the released call is stamped
   `approval="cloud:<grant_id>"`, and it survives chain verification.

The grant expires on its own. An approval that was never fetched does not
release anything later.

## Reading status

Four surfaces, for four different questions.

| Question | Where to look |
|---|---|
| What is this host doing? | `interlock cloud status` on the host - connector state, spool depth, installed manifest version and epoch |
| What is the fleet doing? | `/admin/hosts` in the plane's console - every host's state, last sync and active key count |
| What has been decided? | `/admin/audit` in the plane's console - actor, action, target, time, and before/after digests |
| Is the plane healthy? | `/healthz` and `/readyz` on the plane, and the metrics endpoint |

The admin pages are server-rendered and role-gated (owner, admin, auditor).
They deliberately show digests rather than content: an audit row shows the
recorded `before_sha256` and `after_sha256`, or the SHA-256 of the detail
object, and never the detail object itself. A raw payload is not a column on
any page.

For a machine-readable view, the plane exposes Prometheus metrics on a
loopback bind (see [the runbook](../reference/cloud-runbook.md#metrics)). The
label set is closed: a route template, a method, a status, and a small number
of fixed enums. No org id, host name, review id, policy id or free-text
reason ever appears in a label, because a scrape endpoint is a place tenant
data leaks.

## Webhooks

An org can register an HTTPS endpoint to be told about plane events
(review created, review decided, grant issued, host frozen, manifest
published, and a few more).

- The URL must be `https`, except for a loopback host, which may be plain
  `http` so a local receiver can be wired without weakening the rule.
- **Redirects are never followed.** A `3xx` is a permanent failure, not a hop
  to another host.
- The signing secret is shown exactly once, when the endpoint is created.
  What is stored is a hash and an encrypted copy; no route returns it again.
- Every delivery is signed as `x-interlock-signature: t=<unix>,v1=<hex>`,
  where the digest is `HMAC-SHA256(secret, "<t>.<body>")`. The receiver
  verifies the signature over the exact bytes it received and should refuse a
  stale timestamp.
- A failure is retried on a fixed ladder - 1 s, 5 s, 30 s, 5 min, 30 min,
  2 h - honouring `Retry-After` when the receiver sends one. A `4xx` other
  than `408` and `429` is permanent: the receiver said the request itself is
  wrong, so sending the same bytes again cannot help.
- Delivery happens after the request that caused it has committed. A slow or
  broken subscriber can never slow down the plane, and a failed delivery
  never rolls back a decision.

The payload is a closed set: the event name, ids, statuses, timestamps and
counts. A payload that would carry a preview, an argument, a receipt, a key,
a token or a body is refused at build time.

## The security model, in short

The full statement is in [the security model](../security-model.md); the
cloud-specific threats and the control that answers each one are in
[its cloud section](../security-model.md#the-cloud-plane).

The short version:

- The plane holds tenant data, so it is a normal web service: sessions with
  CSRF, step-up for anything destructive, a role table, and row-level
  security on every tenant table.
- A deleted org is a tombstone, not a cascade. Agent keys and sessions are
  revoked immediately; receipts and audit rows are retained for the
  configured period.
- The plane can be wrong, and the host does not have to trust it. The host
  verifies every grant, every manifest and every artifact against its own
  pinned keys and hashes.
- Metrics and audit pages carry no content and no tenant identifiers.

## Where to go next

- [Rolling out a policy](cloud-rollout.md) - a worked canary, with
  the metrics to watch and the rollback that does not need a redeploy.
- [The artifact reference](../reference/cloud-artifact.md) - the exact bytes
  a host enforces, and the contract the evaluator keeps.
- [The runbook](../reference/cloud-runbook.md) - key rotation, host freeze,
  chain forks, org deletion, restore, and the incident procedures.

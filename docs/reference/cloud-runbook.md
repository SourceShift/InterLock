# The cloud runbook

Operational procedures for the hosted control plane. Each section names the
symptom, the command, and what to expect. Read
[the cloud guide](../guides/cloud.md) first if you have not.

Nothing here needs a redeploy of the hosts. Every procedure below is a plane
operation, a host command, or both.

## Contents

- [Rotating a host's key](#rotating-a-hosts-key)
- [Freezing and unfreezing a host](#freezing-and-unfreezing-a-host)
- [A forked receipt chain](#a-forked-receipt-chain)
- [Deleting an organisation](#deleting-an-organisation)
- [Restoring a plane, and the version floor](#restoring-a-plane-and-the-version-floor)
- [A manifest that expires during an incident](#a-manifest-that-expires-during-an-incident)
- [The kill switch](#the-kill-switch)
- [Rolling back to the Python evaluator](#rolling-back-to-the-python-evaluator)
- [Triage: webhook deliveries are failing](#triage-webhook-deliveries-are-failing)
- [Backup and restore](#backup-and-restore)
- [Metrics](#metrics)

## Rotating a host's key

**Symptom:** a key may have leaked, or an operator asks for routine rotation.

Rotation issues a new agent key and retires the previous ones after a
24-hour overlap, so a host that missed the new key still works until it
picks the new one up.

```bash
# On the plane, as an owner or admin, with a fresh step-up:
curl -sS -X POST "$PLANE/v1/keys" \
  -H "content-type: application/json" \
  -b "$COOKIE" -H "x-csrf-token: $CSRF" \
  -d '{"host_id": "host_123"}'
```

Then on the host:

```bash
interlock cloud keys rotate --host host_123
```

The host fetches the new key, writes `cloud.json` again (still mode `0600`),
and starts using it. The retired key still works until its overlap expires.

To take a key away immediately - a compromise, a host you are retiring -
revoke it instead of rotating:

```bash
curl -sS -X POST "$PLANE/v1/keys/$KEY_ID/revoke" \
  -H "content-type: application/json" \
  -b "$COOKIE" -H "x-csrf-token: $CSRF" -d '{}'
```

A revoked key is refused at once. The host's next poll fails, and it reports
the refusal in `interlock cloud status` rather than silently stalling.

## Freezing and unfreezing a host

**Symptom:** you need a host to stop accepting new evidence - a suspected
compromise, a host that is disconnected, a decommission in progress.

A frozen host has its **receipt ingest** stopped. Its policy fetch, its
heartbeat and its grants are unaffected, so a frozen host keeps enforcing the
policy it has and stops contributing to the audit trail.

The plane freezes a host automatically when it detects a forked receipt chain
(see below). There is no public freeze route: freezing is a plane-internal
state that the fork handler and the key revocation path set. To stop a host
immediately, revoke its agent key instead - the connector's next request is
refused and the host stops contributing.

To bring a frozen host back:

```bash
curl -sS -X POST "$PLANE/v1/hosts/$HOST_ID/unfreeze" \
  -H "content-type: application/json" \
  -b "$COOKIE" -H "x-csrf-token: $CSRF" -d '{}'
```

Unfreezing is audited. Before you unfreeze, make sure the underlying cause is
gone - unfreezing a host whose chain is still broken simply forks again.

## A forked receipt chain

**Symptom:** an upload returns `409 chain_fork`, and the host's ingest is
frozen.

A fork means the incoming batch does not continue the chain the plane stored
for that host: the previous MAC does not match, a receipt was reordered or
edited, or a receipt was replayed with a different body. The plane refuses
the batch rather than storing a chain it cannot verify.

What the plane does automatically:

1. The host's ingest is frozen.
2. An audit row is written (`receipts.fork`), naming the first bad receipt.
3. An admin alert is opened (`alert.opened`, kind `receipt_chain_fork`).
4. A `host.frozen` webhook event is emitted.

To diagnose, compare the host's chain head with the plane's:

- On the plane: `GET /v1/audit` filtered to that host shows the accepted
  chain and the point of divergence.
- On the host: `interlock cloud status` reports the receipt offset the
  connector believes it is at.

The usual causes, in order of likelihood:

- The host's receipt log was edited or truncated.
- The host was cloned, so two machines are writing the same receipts.
- The host's clock is wrong enough to reorder its own receipts.

If the host's log is intact and the plane is wrong, rewind the host's tailer
to the last receipt the plane accepted and let it re-upload:

```bash
interlock cloud status --reset-offset <LINE> --yes
```

Then unfreeze the host. If the host's log is *not* intact, the fork is real:
the host's receipts after the break are not trustworthy, and the operator
decides whether to re-image the host.

## Deleting an organisation

**Symptom:** an org must go - a trial that ended, a request under a data
erasure policy, a tenant that left.

Deletion is a **tombstone, not a cascade**. What goes at once:

| What | Result |
|---|---|
| Agent keys | Revoked. The key answers `410 revoked` on its next request |
| Sessions | Deleted. Every cookie stops working immediately |
| Enrollment tokens | Spent. No new host can enroll |
| Review preview ciphertext | Dropped |
| Webhook secrets | Destroyed and the endpoints disabled |

What is **retained**, for the configured retention period: the receipts and
the audit trail. The org is marked deleted, and the retention job reclaims
those rows when it next runs.

The action needs the owner role, a fresh step-up, and the org slug typed
into the request body:

```bash
curl -sS -X DELETE "$PLANE/v1/org" \
  -H "content-type: application/json" \
  -b "$COOKIE" -H "x-csrf-token: $CSRF" \
  -d '{"confirm": "acme"}'
```

It writes exactly one audit row, naming what was revoked and what was
retained. After it, any read of that org - from inside or outside it -
answers `404`, so a deleted org cannot be probed for what it held.

## Restoring a plane, and the version floor

**Symptom:** the plane's database is lost or corrupted and you are restoring
a backup.

The dangerous part of a restore is not the data. It is the **manifest version
floor** - the highest manifest version the plane has ever published for an
org. A dump taken before a publish does not contain it, and restoring that
dump lets the plane publish a manifest *older* than the one a host is already
enforcing. The host would then be enforcing a policy that was supposed to be
superseded.

The floor therefore lives in its own table, and the restore refuses to
overwrite it by default.

```bash
# 1. Restore into an EMPTY database. The script refuses otherwise.
deploy/cloud/restore.sh --file /var/backups/interlock/interlock-cloud-20260101T000000Z.dump \
  --dsn "$IL_CLOUD_DSN" --yes

# 2. Find the highest version any host has installed.
#    Ask each host: interlock cloud status reports its manifest version.

# 3. Raise the floor above it. This is the mandatory step.
interlock cloud admin version-floor --org acme --bump-to 42

# 4. Confirm the next publish will be at or above the floor.
interlock cloud admin version-floor --org acme --show

# 5. Only now publish.
```

`--show` prints the floor and the version the next publish would carry. If
`next_version` is below the floor, the restored manifest history is behind
what hosts were already issued, and the operator must decide explicitly.

`--reset-floor` is the only way to lower the floor, and it is deliberately
awkward: it is a separate flag, it is mutually exclusive with `--bump-to`,
and the restore script will not touch a non-empty database without it. Use it
only when you have established that no host is above the floor.

## A manifest that expires during an incident

**Symptom:** a manifest expires while you are mid-incident.

A manifest expires at most seven days after it was issued. A host does **not**
drop its policy when that happens. The expiry behaviour is:

- The host keeps enforcing the last artifact it verified.
- After **15 minutes** past expiry the host's status starts alarming.
- The host exposes a **six-hour grace window** after expiry. After that, the
  operator must act.

So an expired manifest is a slow alarm, not an outage. The host is still
enforcing the policy you published, and it is telling you it is out of date.

The fix is to publish again. A new manifest gets a new, higher version, and
the host picks it up on its next poll - usually within seconds.

If the plane is unavailable and you cannot publish, the host is still
enforcing a verified artifact. That is the designed behaviour: an incident
does not silently remove the guardrails.

## The kill switch

**Symptom:** you need every host to stop applying policy immediately, for
example because a policy change is causing damage.

```bash
curl -sS -X POST "$PLANE/v1/policy/kill" \
  -H "content-type: application/json" \
  -b "$COOKIE" -H "x-csrf-token: $CSRF" -d '{}'

curl -sS "$PLANE/v1/kills" -b "$COOKIE"
```

A kill is a signed document that **does not expire**. Removal is itself a
publication: you publish a manifest again to lift it. That is deliberate -
lifting a kill must be a recorded act, not a side effect of a restart.

Each host honours a kill within one poll cycle. The receipt of a call that
ran under a kill is stamped so the audit trail shows the kill was in force.

While a kill is in force, the plane's `il_kill_active` gauge is `1`.

## Rolling back to the Python evaluator

**Symptom:** the native extension is misbehaving on some hosts, or you are
debugging a parity failure.

The native evaluator is an optimisation. The Python evaluator is the default
and the mandatory fallback, and it is what the parity corpus is written
against.

To turn the native path off for a host:

```bash
export IL_EVAL_NATIVE=0
interlock cloud run
```

The host falls back to Python and keeps enforcing. The parity contract means
the verdicts are identical, so the rollback changes latency and nothing else.
The Python budget is p99 under 10 ms, against the native 5 ms.

To roll back a policy, publish the previous source above every host's
version - the version allocator makes that the normal way to move backwards,
and it is what [the rollout guide](../guides/cloud-rollout.md) does.

## Triage: webhook deliveries are failing

**Symptom:** an org's webhook subscriber stopped receiving events.

Delivery history is metadata only - status, timing, response status and a
digest of the response body. Read it here:

```bash
curl -sS "$PLANE/v1/webhooks/$WEBHOOK_ID/deliveries?limit=50" -H "b: $COOKIE"
```

Read the fields like this:

| Field | What it tells you |
|---|---|
| `status` | `delivered`, `pending` (waiting on the retry ladder) or `failed` (permanent) |
| `attempts` | How many times it has been tried |
| `response_status` | What the subscriber answered |
| `last_error` | The transport error, when there was one |
| `next_attempt` | When the next try is due |
| `duration_ms` | How long the subscriber took |
| `body_digest` | SHA-256 of the response body - compare it, but the body itself is never stored |

The retry ladder is 1 s, 5 s, 30 s, 5 min, 30 min, 2 h, and the last step
repeats. `Retry-After` is honoured when the subscriber sends one.

A `4xx` other than `408` and `429` is **permanent**: the subscriber said the
request itself is wrong, so the same bytes will keep failing. Fix the
subscriber, then disable and re-register the endpoint. A `3xx` is permanent
too - redirects are never followed, because a redirect is a way to send a
signed payload somewhere else.

To stop the retries:

```bash
curl -sS -X DELETE "$PLANE/v1/webhooks/$WEBHOOK_ID" \
  -H "content-type: application/json" \
  -b "$COOKIE" -H "x-csrf-token: $CSRF" -d '{}'
```

Disabling keeps the delivery history. It also needs a fresh step-up, because
it is an administrative action.

## Backup and restore

The plane's state is in one Postgres database. Back it up with the shipped
script:

```bash
IL_CLOUD_DSN=postgresql://interlock@postgres/interlock \
  deploy/cloud/backup.sh --out /var/backups/interlock
```

It writes one timestamped custom-format dump plus a `.sha256` sidecar. To
copy it off the machine, set `IL_CLOUD_BACKUP_S3` to an `s3://` prefix; the
script then uploads both files with the object-store CLI already on `PATH`,
and a missing CLI is an error rather than a silent skip. The upload is
optional: a failure there is reported, not hidden.

Restore it with:

```bash
deploy/cloud/restore.sh --file /var/backups/interlock/interlock-cloud-20260101T000000Z.dump \
  --dsn "$IL_CLOUD_DSN" --yes
```

The restore:

- refuses to run without `--yes`;
- verifies the `.sha256` sidecar when it is there;
- restores only into an **empty** database, because restoring over live data
  would overwrite the version floor;
- prints the mandatory version-floor step at the end.

Add `--reset-floor` only if you have established that no host is above the
dump's floor. See
[restoring a plane](#restoring-a-plane-and-the-version-floor).

**The secrets are not in the dump.** The session secret, the approval key,
the policy key and the preview KEK live in files on the host, mounted into
the container. Back them up separately, and keep them out of the database
backup.

## Metrics

The plane exposes Prometheus metrics. The endpoint is `GET /metrics`, and it
is served on a **loopback bind** by default - port 9101, or whatever
`IL_CLOUD_METRICS_PORT` says. `IL_CLOUD_METRICS_ON_APP=1` also serves it
from the main application bind.

The label set is closed, and that is the point: a scrape endpoint must never
be a place tenant data leaks. Every label value comes from a registered route
template (`/v1/reviews/{id}`, never `/v1/reviews/8f3c...`), a method, a
status, or a small fixed enum. No org id, host name, review id, policy id or
free-text reason ever appears.

| Metric | Type | Labels |
|---|---|---|
| `il_http_requests_total` | counter | `route`, `method`, `status` |
| `il_http_duration_seconds` | histogram | `route`, `method` |
| `il_reviews_pending` | gauge | - |
| `il_grants_issued_total` | counter | - |
| `il_receipts_ingested_total` | counter | - |
| `il_receipt_verify_total` | counter | `level` |
| `il_policy_manifest_version` | gauge | - |
| `il_policy_swaps_total` | counter | `result` |
| `il_kill_active` | gauge | - |
| `il_webhook_deliveries_total` | counter | `outcome` |
| `il_db_pool_in_use` | gauge | - |

`il_policy_swaps_total` is the one to watch during a rollout: its `result`
label is `promoted`, `rolled_back`, `held` or `refused`. See
[the rollout guide](../guides/cloud-rollout.md).

Binding the metrics port to anything other than loopback is an explicit
operator choice, and it needs an authenticating proxy in front of it.

## Where to go next

- [The cloud guide](../guides/cloud.md) - what the plane does and what leaves
  a host.
- [The artifact reference](cloud-artifact.md) - the bytes a host enforces.
- [Rolling out a policy](../guides/cloud-rollout.md) - the worked example.

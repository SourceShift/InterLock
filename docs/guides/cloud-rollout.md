# Rolling out a policy

A policy rollout is the moment a rule change reaches every host. This page
is the worked example: one policy, compiled once, taken to a canary, then to
10%, then to 100%, with a rollback that does not need a redeploy and a metric
that tells you when to use it.

The example changes one rule: an outbound host that was allowlisted becomes
denied. That is a small, safe-looking change that can break a lot if it is
wrong, which is exactly the kind of change a canary is for.

If you are new to the plane, read [the cloud guide](cloud.md) first.

## The shape of a rollout

| Stage | What happens | Who is affected |
|---|---|---|
| **Compile** | The source is compiled into an artifact and checked against the corpus. Nothing is signed, nothing is published | Nobody |
| **Canary** | A manifest is published for a canary ring. A handful of hosts are pointed at that ring | The canary hosts |
| **10%** | The rollout is promoted to 10% | About a tenth |
| **100%** | The rollout is promoted to 100% | Everybody |
| **Rollback** | The previous source is republished **at a higher version** | Everybody, immediately |

Two properties make this safe:

- **Nothing is published until it compiles.** The compile step refuses the
  first divergence between the source policy and the compiled artifact, so a
  broken compile never reaches a host.
- **A rollback is a forward publish.** Rolling back does not rewind the
  version. The previous source is published again at a *higher* version, so
  every host accepts it. A host that refuses a lower version is a host you
  wanted to keep.

## Step 0: compile

Compile first, and read the report.

```bash
curl -sS -X POST "$PLANE/v1/policy/compile" \
  -H "content-type: application/json" \
  -b "$COOKIE" -H "x-csrf-token: $CSRF" \
  -d '{
        "documents": [{
          "version": 1,
          "rules": [
            {"id": "deny-exfil-host", "verdict": "block",
             "reason": "egress to a denied host",
             "when": {"all": [{"action": "http_request"},
                              {"arg": "url", "glob": "https://exfil.test/*"}]}}
          ]
        }],
        "scope": {"version": 1, "bindings": {}}
      }'
```

The response is the compile report. Three fields decide whether you go on:

| Field | What to check |
|---|---|
| `sha256` | The artifact's digest. This is what the manifest will point at |
| `epoch` | The identity of the rule set. It changes when the rules change, and only then |
| `diffs` | Empty. A non-empty diff means the source and the compiled artifact disagree, and the compile was refused |

Compiling also **stores** the artifact, keyed by its sha256. That is what
lets the publish step sign the exact bytes you reviewed, instead of
recompiling and hoping nothing moved in between.

If you change the sources after this, compile again. Do not publish a
`sha256` from an older compile.

## Step 1: publish to the canary

Publishing needs a fresh step-up, and it opens a rollout at the same time.

```bash
curl -sS -X POST "$PLANE/v1/policy/publish" \
  -H "content-type: application/json" \
  -b "$COOKIE" -H "x-csrf-token: $CSRF" \
  -d '{
        "sha256": "<the sha256 from the compile>",
        "target": {"kind": "ring", "id": "canary"},
        "mode": "enforce",
        "rollout": {"id": "r-2026-02-01-a", "ring": "canary", "percent": 0}
      }'
```

The response carries the signed manifest. Check three things:

- `version` - it is **higher** than every version published before. The
  allocator never reuses one, and the version floor guarantees it.
- `expires_at` - at most seven days out. A short expiry is a feature: it
  forces a refresh rather than letting a manifest live forever.
- `artifact.sha256` - it matches the artifact you compiled.

The canary hosts are the ones whose connector is configured with
`ring = "canary"`. Hosts on the default `stable` ring are untouched: the
manifest is targeted at the canary ring, and a host only fetches the
manifest that applies to its own ring.

## Step 2: watch the canary

Watch two things: the plane's metric, and the hosts themselves.

**The plane's metric.** `il_policy_swaps_total` counts distribution events by
result. The exposition is on the metrics bind:

```bash
curl -sS http://127.0.0.1:9101/metrics | grep il_policy_swaps_total
```

```
# HELP il_policy_swaps_total Policy distribution swaps by result.
# TYPE il_policy_swaps_total counter
il_policy_swaps_total{result="promoted"} 1
il_policy_swaps_total{result="held"} 0
il_policy_swaps_total{result="rolled_back"} 0
```

The `result` label is a fixed enum - `promoted`, `rolled_back`, `held`,
`refused` - so this is safe to graph and to alert on. A `held` means the
plane had evidence against the rollout and refused to advance it.

**The hosts.** On a canary host:

```bash
interlock cloud status
```

It reports the installed manifest version and the artifact's epoch and
sha256. When the version matches the manifest you published, the host has
the new artifact.

**The behaviour.** This is the part the metrics cannot tell you. Watch the
canary's error rate and its review queue. A rule that blocks something it
should not will show up as held calls, not as a failed swap.

## Step 3: promote to 10%

When the canary is healthy, promote:

```bash
curl -sS -X POST "$PLANE/v1/policy/rollouts/r-2026-02-01-a/promote" \
  -H "content-type: application/json" \
  -b "$COOKIE" -H "x-csrf-token: $CSRF" \
  -d '{"action": "promote"}'
```

With no `percent`, the rollout takes the next stage of the ladder: canary to
10. You can also name the stage explicitly - `"percent": 10` - and the only
accepted values are `0`, `10` and `100`.

The promotion is audited and `il_policy_swaps_total{result="promoted"}`
moves.

**If a stage regresses, hold it.** Send the health observation with the
promotion:

```bash
curl -sS -X POST "$PLANE/v1/policy/rollouts/r-2026-02-01-a/promote" \
  -H "content-type: application/json" \
  -b "$COOKIE" -H "x-csrf-token: $CSRF" \
  -d '{"action": "promote", "health": "regressed"}'
```

`failed`, `regressed`, `regression`, `unhealthy` and `error` all hold the
rollout where it is. The percentage does not advance, the failure is recorded
against the rollout, and `il_policy_swaps_total{result="held"}` moves. A
canary the plane has evidence against must not advance because somebody asked
for the next promotion.

Hold first, diagnose second, roll back third. Holding is cheap; rolling
back is a policy change you have to live with.

## Step 4: promote to 100%

Same command, one more time. The ladder's last step is 100.

```bash
curl -sS -X POST "$PLANE/v1/policy/rollouts/r-2026-02-01-a/promote" \
  -H "content-type: application/json" \
  -b "$COOKIE" -H "x-csrf-token: $CSRF" \
  -d '{"action": "promote", "percent": 100}'
```

Watch `il_policy_swaps_total` and the review queue together. A rising
`promoted` count with a rising held-call count means the rule is firing more
than you expected. That is a policy question, not a rollout fault, and the
rollout is already as wide as it needs to be.

## Step 5: roll back

Rolling back does not rewind. It **republishes the previous source above
every host's version**, so every host accepts it:

```bash
curl -sS -X POST "$PLANE/v1/policy/rollouts/r-2026-02-01-a/promote" \
  -H "content-type: application/json" \
  -b "$COOKIE" -H "x-csrf-token: $CSRF" \
  -d '{"action": "rollback"}'
```

The response carries the new manifest. Its version is **higher** than the one
you are rolling back from - check it, because that is the whole point. The
previous source is published again at that version, the rollout is marked
`rolled_back`, and `il_policy_swaps_total{result="rolled_back"}` moves.

Two things to know about a rollback:

- It needs a fresh step-up. It is a policy change.
- It reverts the *source*, not the ring. Hosts move back to the earlier
  rules; the rollout record stays, marked `rolled_back`, so the audit trail
  shows what happened.

To roll back without a rollout record - for example when the rollout itself
is the problem - publish the previous source directly with
`POST /v1/policy/publish`, at whatever version the allocator gives you. It
will be higher than every version before it, which is exactly what you want.

## After the rollout

Two housekeeping steps.

**Close the rollout.** A finished rollout is left at 100%. Record that it is
done in whatever change-management record you use; the plane's own record is
the rollout row and its audit entries.

**Check the version floor.** The floor is the highest version ever published
for the org, and every publish advanced it:

```bash
interlock cloud admin version-floor --org acme --show
```

If you have restored a plane from an older backup, this is the command that
tells you whether the next publish is safe. See
[the runbook](../reference/cloud-runbook.md#restoring-a-plane-and-the-version-floor).

## A note on manifest expiry

A published manifest expires at most seven days after it was issued. The
host does not drop its policy when that happens: it keeps enforcing the last
artifact it verified, starts alarming after fifteen minutes, and exposes a
six-hour grace window. If you are running a long-lived fleet, publish
regularly enough that no host sits near its expiry - a weekly manifest
refresh is the usual answer.

## Where to go next

- [The artifact reference](../reference/cloud-artifact.md) - what the host is
  enforcing, byte for byte.
- [The runbook](../reference/cloud-runbook.md) - the kill switch, key
  rotation, chain forks, restore.
- [The cloud guide](cloud.md) - the planes, enrollment, and the review flow.

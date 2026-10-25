# Governance

This file says who holds the keys of the mesh commons this project runs, and
the rules for changing who holds them. How code gets into the repository is in
[CONTRIBUTING.md](CONTRIBUTING.md). The reasoning behind these rules is
decision R1 in [`research/mesh-decisions.md`](research/mesh-decisions.md).

Every subscribed node trusts the commons through one pinned file, its **root**:
the keys and thresholds of every role. Whoever can sign a new root can change
what every node installs. So the root keys are held by named people, offline,
and no one of them can act alone.

## Root keyholders

| Seat | Keyholder | Employer | Term start | Root key id |
|---|---|---|---|---|
| 1 | Amir Khakshour (maintainer) | recorded at the first ceremony | the first root ceremony | recorded at the first ceremony |
| 2 | open | an organisation other than seat 1's and seat 3's | | |
| 3 | open | an organisation other than seat 1's and seat 2's | | |

A seat is filled at a root ceremony, in the same pull request that adds the
keyholder's key. The root itself records each key's holder and term start, as
`x-interlock-keyowner` and `x-interlock-term-start`, so this table can be
checked against what subscribers actually trust. The two tables must agree; if
they do not, the root is what counts and this file is fixed.

A term runs from the ceremony that adds a keyholder's key to the ceremony that
removes it. A keyholder steps down by asking for that ceremony, and then moves
to the emeritus list.

### Emeritus

None yet.

## The rule: two of three

- The root has three keys and a threshold of two. Any new root needs
  signatures from two of the three.
- The three keys belong to three people: the maintainer, and two people
  employed by two different organisations, neither of them the maintainer's.
- Each root key is generated and kept offline, on its keyholder's own machine
  or in a hardware token. It is never copied to the machine that publishes.
- A new root must also be signed by a threshold of the root it replaces. This
  is the rule every subscriber enforces (`interlock mesh root assemble` checks
  it before anything is written), so a ceremony cannot skip it.

Two of three survives the loss of any one key, means no single stolen laptop
can re-root the commons, and lets the two other keyholders act if the
maintainer cannot (see [Succession](#succession)).

## Signing schedule

A root is valid for 197 days. The last 46 are its **signing period**: `interlock
mesh publish` warns, and `interlock doctor` on every subscribed node reports
it, until a new root is published. So every keyholder signs about twice a year,
and every signing is also a test that each key still works. The procedure is
the [root ceremony](docs/guides/mesh-root-ceremony.md).

If a ceremony cannot collect two signatures within its signing period, this
arrangement is not working, and decision R1 is reopened.

## Rotation trigger

When the credential issuer's ledger (see below) shows **three admitted member
organisations**, the root is rotated to **at least 3-of-5 keys across at least
three organisations**. This is the planned next step, not a failure, and it is
carried out as a normal root ceremony: the current 2-of-3 signs the new root.

## Succession

If the commons' timestamp has been expired for **30 days**, so the maintainer
has stopped publishing and nobody has said why, the two non-maintainer
keyholders may rotate the online roles to a successor. Their two keys meet the
threshold without the maintainer's. The successor generates new online keys
(`interlock mesh keys init`, keeping only the targets, snapshot, timestamp and
log key files), drafts a root that names them against a copy of the published
site, and the two keyholders sign it in a ceremony like any other. The
succession is announced in the ceremony's pull request.

## Online keys

The online keys sign routinely, on the machine that publishes, and cost a
ceremony to change: a root has to name the new key.

| Key | Signs | Held by | Kept |
|---|---|---|---|
| targets | the list of published packs, with their hashes | the maintainer | on the publishing machine (`keys/targets.*.json`) |
| snapshot | the version and hash of targets | the maintainer | on the publishing machine (`keys/snapshot.*.json`) |
| timestamp | the daily heartbeat: the current snapshot, valid for a day | the maintainer | on the publishing machine (`keys/timestamp.*.json`) |
| log | the transparency log's checkpoints | the maintainer | on the publishing machine (`keys/log.*.json`) |
| credential issuer | membership certificates for reporting nodes (`interlock/mesh/credential.py`) | the maintainer | offline, in the directory `interlock mesh credential init` wrote, with its private ledger of admitted members |

The issuer key is not a role in the root. The collectors are told its public
key directly (`interlock mesh serve --issuer`), so changing it means telling
them, not a ceremony.

## Changing this file

A change to the keyholder table lands in the pull request of the ceremony that
makes it true. A change to the rules above starts as a change to decision R1,
which records why they are what they are, and this file follows it.

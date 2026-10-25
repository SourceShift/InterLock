# Mesh root ceremony

A commons' **root** names the keys of every role, and every subscribed node
trusts the commons through it. The root keys stay offline, each on its
keyholder's own machine or hardware token, so a new root cannot be signed in
one place. A **ceremony** is how it gets signed: one person drafts the next
root, each keyholder adds a detached signature on their own machine, and the
signatures are assembled into the new root only when the old root's threshold
and the new root's own have both signed.

Who holds the keys of the commons this project runs, and the rules for
changing that, are in
[`GOVERNANCE.md`](https://github.com/SourceShift/InterLock/blob/main/GOVERNANCE.md).
How a commons is published day to day is in the [mesh guide](mesh.md#run-a-commons).

## When to hold one

- **In the signing period.** A root is valid for 197 days, and its last 46
  are its signing period. `interlock mesh publish` warns, and `interlock
  doctor` on every subscribed node reports the root as due. Start the ceremony
  when the period opens, so a missing keyholder has weeks, not days.
- **When an online key changes.** `publish` refuses to sign with a targets,
  snapshot, timestamp or log key the current root does not name, and says a
  new root is needed.
- **When a keyholder changes**, or the root's threshold does.
- **For the first root** of a commons whose root keys were never on the
  publishing machine. With no previous root, only the new root's own threshold
  is checked.

`publish` keeps working without any root key until then: it re-publishes the
current root as long as the online keys match it and it has not expired.

## What you need

**A root key per keyholder.** Each keyholder makes theirs on their own machine:

```bash
interlock mesh keys init --out ~/interlock-root-key/   # then keep root.1.json, delete the rest
```

or uses a hardware token whose signing program can sign raw bytes with Ed25519
(see [Signing with a hardware token](#signing-with-a-hardware-token)). Only the
public key ever leaves the machine.

**`keys/root-keys.json`** on the machine that publishes: the root's public
keys, and who holds each one. Only public keys, so it is safe to commit.

```json
{
 "version": 1,
 "keys": [
  {"public": "<64 hex characters>", "owner": "Alice Example", "term_start": "2026-11-01"},
  {"public": "<64 hex characters>", "owner": "Bob Example", "term_start": "2026-11-01"},
  {"public": "<64 hex characters>", "owner": "Carol Example", "term_start": "2027-04-12"}
 ]
}
```

`owner` and `term_start` are optional strings. They are written into the new
root as `x-interlock-keyowner` and `x-interlock-term-start` on each key, signed
with the rest, so the custody record is public and checkable. A subscriber
does not act on them.

**The root threshold** is the `root` entry of `keys/roles.json`, e.g.
`{"version": 1, "thresholds": {"root": 2, "targets": 1, ...}}` for 2-of-3. The
online keys (`targets`, `snapshot`, `timestamp`, `log`) are the key files in
`keys/`, as for `publish`.

## The ceremony

Each ceremony is one pull request, on a branch named `ceremony/YYYY-MM-DD`
after the day it opens, in the repository that holds the commons. Everything
it produces goes into that pull request, so the transcript is public.

### 1. Draft

Whoever coordinates (usually the maintainer) drafts the next root against the
published site:

```bash
git switch -c ceremony/2027-04-12
interlock mesh root draft --site site/ --keys keys/ --out ceremony/2027-04-12/root-3.json
```

The draft is version N+1 of the site's `metadata/root.json`, valid for 197
days (`--expires-days N` to change it; it must be longer than the 46-day
signing period). `draft` prints every role's keys and threshold, which keys of
the current root must approve it, and the **SHA-256 of the bytes each
keyholder will sign**. Put that digest in the pull request description, and
commit the draft. `draft` never overwrites a file.

### 2. Review

**The draft is the single file a witness checks.** It is sorted, indented
JSON: `signed` is the new root exactly as it will be published, and
`previous_root` lists the keys of the root it replaces. A witness, someone who
is not signing, checks:

- `signed.version` is one more than the root subscribers have now, and
  `signed.expires` is about 197 days away;
- the `root` role's key ids, owners and term starts match the keyholder table
  in `GOVERNANCE.md` after this ceremony, and its threshold is the agreed one;
- the `targets`, `snapshot`, `timestamp` and `log` key ids are the keys the
  maintainers actually hold, and nothing else changed;
- `previous_root` matches the site's current root;
- the digest in the pull request is the digest of `signed`. To compute it
  independently:

```bash
python3 -c 'import hashlib, json, sys; s = json.load(open(sys.argv[1]))["signed"]; print(hashlib.sha256(json.dumps(s, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest())' ceremony/2027-04-12/root-3.json
```

The witness approves the pull request. Nobody signs before that.

### 3. Sign, each keyholder on their own machine

Each keyholder checks out the branch, confirms the digest themselves, and
signs:

```bash
interlock mesh root sign ceremony/2027-04-12/root-3.json --key ~/interlock-root-key/root.1.json
```

`sign` prints the digest again and writes one small file,
`root-3.json.sig.<keyid>`, holding the key id and the signature. It refuses a
key that is in neither the draft's root nor the root it replaces. A key only
in the old root may sign: it counts toward the old root's threshold. The
keyholder commits the `.sig` file (it holds nothing secret) and adds a line to
the transcript.

### 4. Assemble, then publish

Once enough signatures are in:

```bash
interlock mesh root assemble ceremony/2027-04-12/root-3.json \
  --sig ceremony/2027-04-12/root-3.json.sig.* --site site/
interlock mesh publish --source commons/ --out site/ --keys keys/
interlock mesh verify site/
```

`assemble` refuses unless a threshold of the current root's keys and a
threshold of the new root's keys have both signed the draft. It then runs the
same check every subscriber runs on the exact bytes, and only after that writes
`metadata/<N>.root.json` and `metadata/root.json`. A signature that does not
verify over the draft, or comes from a key in neither root, fails it outright.
When the site has a transparency log, the new root is added to it; the next
`publish` signs a checkpoint over it. Publish straight away, so the timestamp,
snapshot and targets are signed under the new root, then merge the pull
request. Nodes follow the rotation on their next `interlock mesh sync`.

## The transcript

Keep a `TRANSCRIPT.md` beside the draft. Each participant appends a line as
they act: who, when, which key id, the digest they saw, and what they did
(drafted, witnessed, signed, assembled, published). It is merged with the
pull request and stays public, so anyone can later check who approved each
root.

## When a ceremony fails

A ceremony fails when a draft has to change after anyone signed it, when it
cannot collect its signatures, or when assembly refuses it. **A failed ceremony
is moved aside and never reused:** move its directory under
`ceremony/failed/`, record why in its transcript, merge that record, and open a
new ceremony with a new branch and a new draft. Never edit a draft that has
been signed, and never carry its signatures over. The tools hold to this:
`draft` does not overwrite a file, a signature over a different draft does not
verify, and `assemble` refuses a draft for a root the site already has and
never overwrites a published root.

If a ceremony runs past the root's expiry, nodes refuse every update from the
commons and `publish` refuses too, but a late ceremony still works: `assemble`
accepts a new root signed by the expired one's keys, and nodes follow the
rotation before they check expiry. `interlock doctor` reports the expired root
as a failure on every node until then.

## Signing with a hardware token

`--external-signer CMD` replaces `--key`:

```bash
interlock mesh root sign ceremony/2027-04-12/root-3.json --external-signer "./token-sign --slot 9c"
```

`CMD` is split like a shell command line (but not run through a shell). It
receives the exact bytes to sign on standard input, must print the 64-byte
Ed25519 signature as hex on standard output, and must exit 0, within two
minutes. `sign` finds which root key the signature verifies under, and writes
nothing if it verifies under none. interlock itself stays standard-library
only: driving the token is the helper's job.

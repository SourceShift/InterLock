# Security policy

interlock is a security tool: people rely on it to stop a bad action before it
runs. If you find a way past it, that is a security bug and we want to hear
about it before anyone else does.

## Supported versions

interlock is alpha. Only the latest release and `main` are supported; there are
no back-ports to older tags yet.

| Version | Supported |
|---|---|
| `main` | Yes |
| latest release | Yes |
| older tags | No |

## Reporting a vulnerability

**Do not open a public issue.** Use GitHub's [private vulnerability
reporting][report]: open the **Security** tab on
[SourceShift/InterLock][repo] and choose **Report a vulnerability**. If you
can't use that, contact the maintainers through the repository owner's GitHub
profile.

Please include:

- what you were able to bypass, and the verdict you got instead of the one you
  expected (an `allow` where a `block` was due is the interesting case);
- a minimal, runnable reproduction — the rule you installed, the call you made,
  and the output;
- the interlock version or commit, your Python version, and your OS;
- whether the `interlock_scopes` native module was loaded (the pure-Python
  fallback and the Rust path are separate implementations of the same tree).

If the issue also affects a dependency, note it, but report it upstream too.

### What counts as a vulnerability

Anything that makes a decision *weaker than the policy said it would be*:

- a call that runs when a rule returned a block or a rewrite;
- a rewrite that drops or restores the argument a rule meant to change;
- a result check that lets injected content through to the agent;
- a way for a sub-agent to exceed its parent scope;
- receipts that can be altered, dropped, or reordered without detection;
- the sandbox allowing something the policy denied.

### What does not

Some limits are documented and deliberate, not defects. The most common:

- **No rules installed means everything is allowed.** That is the designed
  default, described in the [security model](docs/security-model.md).
- **Detectors match patterns, not meaning.** A reworded attack evading a
  detector is a recall gap, not a bypass — report it as a detector issue (a
  false negative), and say which detector missed it.
- **A blocked result does not undo the tool.** Result checks run after the tool
  ran; the side effect stands. This is stated in the README.

Read [the security model](docs/security-model.md) first — it lists the settings
that weaken protection and the threats interlock does not claim to stop. If your
report is one of those, we'll still read it, and we'd rather tell you it's known
than have you wonder.

### When your report is not a vulnerability

If it turns out to be a bug or a missing check rather than a bypass, we'll move
it to a public issue and credit you there. Either way, we'll confirm we received
it, tell you whether it's in scope, and keep you posted until it's fixed.

## How we handle a report

1. Acknowledge within a few days.
2. Reproduce, and decide together whether it is in scope.
3. Fix on a branch, add a regression test that fails before the fix, and ship.
4. Publish the fix and credit you, unless you'd rather stay anonymous.

Please give us a reasonable window to ship a fix before writing publicly about
it. We're an alpha, pre-1.0 project, so that window should be short.

## Hardening checklist for users

The [security model](docs/security-model.md) has the full list. The three that
matter most:

- Assert at startup that your rules are installed — an empty rule set allows
  everything.
- Keep `fail_open` off. interlock is fail-closed by default; know where you
  turned that off.
- Run code you don't trust inside the BRACE sandbox rather than beside your
  agent, since in-process code shares interlock's trust boundary.

[report]: https://github.com/SourceShift/InterLock/security/advisories/new
[repo]: https://github.com/SourceShift/InterLock

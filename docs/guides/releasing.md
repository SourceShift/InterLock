# Releasing

interlock publishes two packages from one tag:

| Registry | Package | Source |
|---|---|---|
| PyPI | `interlock-guard` | the repository root (`pyproject.toml`) |
| npm | `interlock-guard` | `js/` |

The release workflow is `.github/workflows/release.yml`. It runs on a `v*`
tag, checks that the tag agrees with every version in the tree, builds and
tests the artifacts, and only then publishes. Neither registry accepts a
second upload of the same version, so a release is checked before it is
irreversible.

## One-time: trusted publishers

There is **no PyPI or npm token in this repository**. Both registries use
[trusted publishing](https://docs.pypi.org/trusted-publishers/): the workflow
proves which repository, workflow and environment it is with an OpenID Connect
token, and the registry matches that against a publisher configured on the
package. Configure each once, as a package owner:

**PyPI** — *Publishing → Trusted publishers → Add a new publisher*:

| Field | Value |
|---|---|
| PyPI Project Name | `interlock-guard` (create the "pending publisher" before the first release) |
| Owner | `SourceShift` |
| Repository name | `InterLock` |
| Workflow name | `release.yml` |
| Environment name | `pypi` |

**npm** — *Package settings → Trusted publishing → Add publisher*:

| Field | Value |
|---|---|
| Publisher | GitHub Actions |
| Organization or user | `SourceShift` |
| Repository | `InterLock` |
| Workflow filename | `release.yml` |
| Environment | `npm` |

The `pypi` and `npm` fields above are the GitHub **environments** the publish
jobs declare. If your repository protects those environments (required
reviewers), a release waits for that approval before anything is uploaded —
which is the point of naming them.

## Cut a release

1. **Bump all three versions.** They must match:

   ```bash
   # pyproject.toml:   [project] version
   # js/package.json:  version
   # web/package.json: version   (the console ships inside the Python package)
   ```

2. **Give the changelog a section for it.** `scripts/check_release.py` looks
   for an exact heading, so `[Unreleased]` must become the version:

   ```markdown
   ## [0.0.2] — 2026-11-01
   ```

3. **Let the gate check it before you tag.** This is the same check the
   workflow runs first:

   ```bash
   python3 scripts/check_release.py v0.0.2
   ```

4. **Land the bump on `main`** through the normal worktree loop (see the
   repository's `CLAUDE.md`). The tag must point at a commit on `main`.

5. **Tag and push the tag.**

   ```bash
   git fetch origin main
   git switch main && git merge --ff-only origin/main
   git tag -a v0.0.2 -m "interlock 0.0.2"
   git push origin v0.0.2
   ```

The tag push starts the release. Nothing else needs to be triggered.

## What the workflow does

| Job | What it proves |
|---|---|
| `verify` | The tag, `pyproject.toml`, `js/package.json`, `web/package.json` and `CHANGELOG.md` all name the same version; the Python suite passes; the sdist and wheel build, pass `twine check`, and the wheel installs and reports that version |
| `verify-node` | The npm tests pass, the published build compiles, and `npm pack --dry-run` lists what would ship |
| `publish-pypi` | Uploads with an OIDC token and a **PEP 740 provenance attestation** (`attestations: true`), so PyPI records which repository and commit produced each file |
| `publish-npm` | Uploads with `--provenance`, so npm attaches a signed statement linking the tarball to this repository and commit |
| `github-release` | Creates the GitHub release and attaches the sdist and wheel |

The PyPI upload is the line that matters: the attestation is what lets someone
who downloads a wheel check it was built from this repository's tag rather
than from a laptop that happened to hold a token.

## Verify what you downloaded

PyPI shows a **Provenance** section on the release's files page; the
attestation names the repository, the workflow and the commit. Locally, the
same evidence is in the wheel's metadata:

```bash
pip download --no-deps interlock-guard==0.0.2
python3 -c "import zipfile; print(zipfile.ZipFile('interlock_guard-0.0.2-py3-none-any.whl').namelist()[:5])"
```

For npm, a project that installed the package can check the registry
signatures it recorded:

```bash
npm audit signatures
```

A package without a provenance attestation is not necessarily malicious — but
a package with one can be traced, and an interlock release always has one.

## When a release fails

The jobs are ordered so the irreversible step is last. If `verify` fails
nothing was published; fix the tree and tag again with a **new** tag if the
version changed (a tag that was never pushed to a registry can be deleted and
re-created; a version that was uploaded cannot).

If one registry publishes and the other fails, the published version is spent.
Fix the cause, bump the patch version, and release again. Do not try to
overwrite the uploaded files: neither registry allows it, and an unsigned
re-upload would be worse than a missing npm release.

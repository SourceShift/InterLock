## What this changes

<!-- One or two sentences. What moved, and why. -->

## Why

<!-- The problem this solves. For a detector, name the attack it catches.
     For a fix, say what was wrong before. Link the issue if there is one. -->

Closes #

## How it was tested

<!-- Paste the commands you ran and their result. "Ran the suite" is not enough —
     we want to see it. -->

```
python -m pytest tests -q
```

## Type of change

- [ ] Bug fix
- [ ] New detector
- [ ] New feature
- [ ] Docs
- [ ] Refactor or internal change

## Checklist

- [ ] I ran `make check` (ruff, detector catalog `--check`, full Python suite) and it passes.
- [ ] **If I touched `js/`:** `make check-js` passes (test + build).
- [ ] **If I touched `web/`:** `make check-web` passes (typecheck + test + build).
- [ ] **If I touched a detector:** `python scripts/gen_detector_catalog.py` was re-run and `--check` passes, and the module is listed in `CATEGORIES`.
- [ ] **If I touched a detector:** there is a test for the match *and* one for the non-match.
- [ ] **If I changed a code snippet in `README.md` or `docs/`:** I ran it again and pasted the new output.
- [ ] **If I changed a count** (detectors, tests): I re-checked it rather than assuming.
- [ ] **If this changes user-visible behaviour:** I added a `CHANGELOG.md` entry under `## [Unreleased]`.
- [ ] My commits follow [Conventional Commits](https://www.conventionalcommits.org/) (`feat(mcp): …`, `fix(guard): …`, `docs: …`) and are signed off (`git commit -s`).
- [ ] My diff touches only the files this change needs — no unrelated reformatting.
- [ ] I have not added a runtime dependency to the core package.
- [ ] Docs are updated for anything user-facing.

## Notes for the reviewer

<!-- Anything you're unsure about, an approach you rejected, or a trade-off worth a second opinion. -->

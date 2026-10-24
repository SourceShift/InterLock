# One entry point for the repo's four toolchains. `make check` is the gate a
# Python change needs; `make check-all` is everything CI runs (except Rust,
# which they build separately — see check-rust).
#
# These targets are for humans. CI keeps its own explicit steps so a change to
# one of them is visible in the workflow diff, not hidden behind a Makefile.

PY ?= python3
NPM ?= npm
RUFF ?= ruff

.DEFAULT_GOAL := help
.PHONY: help check check-python check-js check-web check-rust check-all

help: ## Show the available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

check: check-python ## The gate for a Python change (lint, catalog, full suite)

check-python: ## Lint the package, prove the detector catalog is current, run pytest
	$(RUFF) check --select E9,F interlock/
	$(PY) scripts/gen_detector_catalog.py --check
	$(PY) -m pytest -q

check-js: ## Install, test and build the Node client (js/)
	$(NPM) --prefix js ci
	$(NPM) --prefix js test
	$(NPM) --prefix js run build

check-web: ## Typecheck, test and build the console UI (web/)
	$(NPM) --prefix web ci
	$(NPM) --prefix web run typecheck
	$(NPM) --prefix web test
	$(NPM) --prefix web run build

check-rust: ## Build the native scope store and run its parity suite
	# This installs the native module into the current environment, so every
	# later `make check` runs the suite against the Rust backend. That is the
	# point, but it is why this target is not part of check-all.
	cd rust && maturin develop --release
	$(PY) -m pytest -q tests/test_scope_backend.py tests/test_scopes.py

check-all: check check-js check-web ## Everything except the optional Rust build

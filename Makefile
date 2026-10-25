# One entry point for the repo's four toolchains. `make check` is the gate a
# Python change needs; `make check-all` is everything CI runs (except Rust,
# which they build separately — see check-rust).
#
# These targets are for humans. CI keeps its own explicit steps so a change to
# one of them is visible in the workflow diff, not hidden behind a Makefile.

PY ?= python3
NPM ?= npm
RUFF ?= ruff
# Zensical is pinned in .github/workflows/docs.yml; without an install, run
# `make docs ZENSICAL='uvx --from zensical==0.0.70 zensical'`.
ZENSICAL ?= zensical

.DEFAULT_GOAL := help
.PHONY: help check check-python check-js check-web check-rust check-all docs docs-serve

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

docs: ## Build the whole site into site/ (landing, then the manual) and check it
	# Two builds, in this order: the landing build owns site/ and empties it,
	# the manual's then writes site/docs/ beside it. See zensical.landing.toml.
	rm -rf site
	$(ZENSICAL) build -f zensical.landing.toml --clean --strict
	$(ZENSICAL) build --clean --strict
	$(PY) scripts/check_site.py

docs-serve: docs ## Serve the built site at http://localhost:8000/ with both halves linked
	# `zensical serve` previews one build at a time and the links between the
	# two lead nowhere; this serves the finished tree, so they resolve.
	$(PY) -m http.server 8000 --bind 127.0.0.1 --directory site

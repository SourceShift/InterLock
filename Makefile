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
# The console port the Vite dev server proxies /api to (web/vite.config.ts).
PORT ?= 7878
# The console reads no receipt log unless pointed at one. Development uses the
# log the installed hooks write, when there is one, so Activity shows real calls
# instead of the "point the console at a receipt log" prompt. The wildcards are
# expanded at parse time: an uninstalled hook leaves the flags off and the
# console explains itself. The key goes only with that log — pairing it with
# another one makes the chain read broken — so RECEIPTS= elsewhere wants its own
# KEY_FILE=. A repeat of the same flag in CONSOLE_ARGS wins: argparse keeps the
# last.
HOOK_RECEIPTS = $(wildcard $(HOME)/.interlock/receipts.jsonl)
RECEIPTS ?= $(HOOK_RECEIPTS)
KEY_FILE ?= $(if $(filter $(HOOK_RECEIPTS),$(RECEIPTS)),$(wildcard $(HOME)/.interlock/receipts.key))
RECEIPT_FLAGS = $(if $(RECEIPTS),--receipts $(RECEIPTS)) \
	$(if $(KEY_FILE),--key-file $(KEY_FILE))
# Extra console flags, e.g. make dev CONSOLE_ARGS='--four-eyes'
CONSOLE_ARGS ?=

.DEFAULT_GOAL := help
.PHONY: help dev check check-python check-js check-web check-rust check-all docs docs-serve

help: ## Show the available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

# Both halves of the console, side by side: the Python server restarted by a
# watcher on every change under interlock/, and Vite with HMR for the UI. Open
# the Vite address; its /api proxy reaches the console, which must stay on
# PORT because the proxy target is hard-coded. Ctrl-C stops both.
#
# A restart reissues this launch's unlock code, so writes in an already
# unlocked tab start failing until the link below is pasted again.
dev: ## Run the console (auto-restart) and the Vite dev server together
	@command -v watchfiles >/dev/null || { \
		echo "make dev needs watchfiles: $(PY) -m pip install watchfiles" >&2; exit 1; }
	@test -x web/node_modules/.bin/vite || { \
		echo "make dev needs the web dependencies: $(NPM) --prefix web ci" >&2; exit 1; }
	@$(PY) -c 'import socket, sys; s = socket.socket(); s.settimeout(0.2); \
		sys.exit(0 if s.connect_ex(("127.0.0.1", $(PORT))) else 1)' || { \
		echo "port $(PORT) is already in use; stop it, or pass PORT=... and update the" >&2; \
		echo "proxy target in web/vite.config.ts to match" >&2; exit 1; }
	@echo "api  http://127.0.0.1:$(PORT)   (the unlock link prints below)"
	@echo "web  Vite prints its own address below — open that one"
	@echo "log  $(if $(RECEIPTS),$(RECEIPTS),none — install a hook, or pass RECEIPTS=…)"
	@trap 'kill 0' EXIT INT TERM; \
	watchfiles --filter python \
		"$(PY) -m interlock.console --port $(PORT) $(RECEIPT_FLAGS) $(CONSOLE_ARGS)" interlock/ & \
	$(NPM) --prefix web run dev & \
	wait

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
	cargo test --manifest-path rust/engine/Cargo.toml
	bash scripts/check_native_abi.sh
	cd rust && maturin develop --release
	$(PY) -m pytest -q tests/test_scope_backend.py tests/test_scopes.py tests/test_native_engine.py tests/test_bench_overhead.py

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

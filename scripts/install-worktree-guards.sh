#!/usr/bin/env bash
# Turn the worktree guards in .githooks/ on (or off) for this clone.
#
#   bash scripts/install-worktree-guards.sh            point core.hooksPath at .githooks
#   bash scripts/install-worktree-guards.sh --uninstall
#
# core.hooksPath lives in the shared config, so one install covers the primary
# checkout and every worktree. A relative path resolves inside each checkout, so
# a worktree on a branch older than .githooks/ simply runs no hooks.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd "$(dirname "$(git -C "$script_dir" rev-parse --path-format=absolute --git-common-dir)")" && pwd -P)"

if [ "${1:-}" = "--uninstall" ]; then
  git -C "$ROOT" config --unset core.hooksPath || true
  echo "[worktree-guards] uninstalled (core.hooksPath unset)"
  exit 0
fi

existing="$(git -C "$ROOT" config --get core.hooksPath || true)"
if [ -n "$existing" ] && [ "$existing" != ".githooks" ]; then
  echo "[worktree-guards] core.hooksPath is already '$existing'; refusing to replace it" >&2
  exit 1
fi

[ -d "$ROOT/.githooks" ] || { echo "[worktree-guards] $ROOT/.githooks is missing (is this checkout up to date?)" >&2; exit 1; }
chmod +x "$ROOT/.githooks/reference-transaction" "$ROOT/.githooks/pre-commit" \
         "$ROOT/.githooks/pre-merge-commit" "$ROOT/.githooks/pre-push"
git -C "$ROOT" config core.hooksPath .githooks
echo "[worktree-guards] installed: core.hooksPath=.githooks (worktree-guard, G1, G10, G3/G4)"

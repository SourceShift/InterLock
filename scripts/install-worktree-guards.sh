#!/usr/bin/env bash
# Turn the worktree guards on (or off) for this clone.
#
#   bash scripts/install-worktree-guards.sh            copy .githooks/* into the shared hooks dir
#   bash scripts/install-worktree-guards.sh --uninstall
#
# The hooks are copied into <git-common-dir>/hooks/, which every checkout of the
# clone shares regardless of the branch it has checked out. A relative
# core.hooksPath would resolve inside each checkout instead, so a primary
# checkout sitting on a branch older than .githooks/ would run no guards at all,
# which is exactly when they are needed. Re-run after .githooks/ changes.
set -euo pipefail

HOOKS=(_primary.sh reference-transaction pre-commit pre-merge-commit pre-push)
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
src="$(cd "$script_dir/../.githooks" && pwd -P)"
common="$(git -C "$script_dir" rev-parse --path-format=absolute --git-common-dir)"
dest="$common/hooks"
marker="# interlock worktree guard"

if [ -n "$(git -C "$script_dir" config --get core.hooksPath || true)" ]; then
  echo "[worktree-guards] core.hooksPath is set, so $dest would be ignored; unset it first:" >&2
  echo "                  git config --unset core.hooksPath" >&2
  exit 1
fi
mkdir -p "$dest"

if [ "${1:-}" = "--uninstall" ]; then
  for h in "${HOOKS[@]}"; do
    if [ -f "$dest/$h" ] && grep -q "$marker" "$dest/$h"; then rm -f "$dest/$h"; fi
  done
  echo "[worktree-guards] uninstalled from $dest"
  exit 0
fi

for h in "${HOOKS[@]}"; do
  [ -f "$src/$h" ] || { echo "[worktree-guards] missing $src/$h" >&2; exit 1; }
  if [ -f "$dest/$h" ] && ! grep -q "$marker" "$dest/$h"; then
    echo "[worktree-guards] $dest/$h exists and is not ours; refusing to overwrite it" >&2
    exit 1
  fi
done
for h in "${HOOKS[@]}"; do
  { head -1 "$src/$h"; echo "$marker (installed from .githooks/$h; edit there, then re-run scripts/install-worktree-guards.sh)"; tail -n +2 "$src/$h"; } >"$dest/$h.tmp"
  mv "$dest/$h.tmp" "$dest/$h"
  [ "$h" = "_primary.sh" ] || chmod +x "$dest/$h"
done
echo "[worktree-guards] installed into $dest: worktree-guard, G1, G10, G3/G4"

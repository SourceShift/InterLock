# Sourced by the guard hooks: decides whether this checkout is the PRIMARY one.
#
# The primary checkout is the directory that owns the shared .git; every other
# checkout is a linked worktree made by scripts/codex-worktree.sh. Derived from
# git itself rather than a hardcoded path, so the guards work in any clone and
# resolve ~/ps symlinks the same way the real path does.
_common="$(git rev-parse --path-format=absolute --git-common-dir 2>/dev/null || echo)"
_top="$(git rev-parse --show-toplevel 2>/dev/null || echo)"
PRIMARY_CHECKOUT="$(cd "$(dirname "$_common")" 2>/dev/null && pwd -P || echo)"
THIS_CHECKOUT="$(cd "$_top" 2>/dev/null && pwd -P || echo)"
in_primary_checkout() { [ -n "$PRIMARY_CHECKOUT" ] && [ "$PRIMARY_CHECKOUT" = "$THIS_CHECKOUT" ]; }

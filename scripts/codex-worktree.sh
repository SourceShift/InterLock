#!/usr/bin/env bash
# The only sanctioned way to branch in this repo, and the way work lands on main.
#
#   bash scripts/codex-worktree.sh create <slug>           new worktree on codex/<slug>, from origin/main
#   bash scripts/codex-worktree.sh list                    worktrees, ahead/behind origin/main, dirty count
#   bash scripts/codex-worktree.sh ship <slug>             rebase, scope check, ff-push to main, refresh
#   bash scripts/codex-worktree.sh remove <slug> [--force] delete a shipped (or abandoned) worktree
#
# Every change happens in a worktree under $INTERLOCK_WORKTREES_DIR (default: a
# sibling `interlock-worktrees/` of the primary checkout), never in the primary
# checkout, which only fast-forwards from origin/main. The guards in .githooks/
# enforce this; install them with scripts/install-worktree-guards.sh.
set -euo pipefail

die() { echo "[codex-worktree] $*" >&2; exit 1; }
say() { echo "[codex-worktree] $*"; }

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
common_dir="$(git -C "$script_dir" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" \
  || die "not inside a git checkout: $script_dir"
ROOT="$(cd "$(dirname "$common_dir")" && pwd -P)"
WORKTREES_DIR="${INTERLOCK_WORKTREES_DIR:-$(dirname "$ROOT")/$(basename "$ROOT")-worktrees}"

sanitize_slug() {
  local slug="${1:-}"
  slug="${slug//[^A-Za-z0-9._-]/-}"
  slug="${slug##-}"
  slug="${slug%%-}"
  [ -n "$slug" ] || die "slug must contain at least one alphanumeric character"
  printf '%s\n' "$slug"
}

worktree_for() { printf '%s/%s\n' "$WORKTREES_DIR" "$1"; }

cmd_create() {
  local slug wt branch
  slug="$(sanitize_slug "${1:-}")"
  wt="$(worktree_for "$slug")"
  branch="codex/$slug"
  [ ! -e "$wt" ] || die "$wt already exists"
  if git -C "$ROOT" show-ref --verify --quiet "refs/heads/$branch"; then
    die "branch $branch already exists; pick another slug or remove the old worktree"
  fi
  git -C "$ROOT" fetch origin main --quiet
  mkdir -p "$WORKTREES_DIR"
  ALLOW_WORKTREE_BRANCH_CREATE=1 git -C "$ROOT" worktree add -q -b "$branch" "$wt" origin/main
  say "created $wt on $branch (from origin/main @ $(git -C "$wt" rev-parse --short HEAD))"
  say "work there, commit EXPLICIT paths (never git add -A), then: bash scripts/codex-worktree.sh ship $slug"
}

cmd_list() {
  git -C "$ROOT" fetch origin main --quiet 2>/dev/null || true
  local path branch ahead behind dirty
  git -C "$ROOT" worktree list --porcelain | awk '/^worktree /{p=$2} /^branch /{print p" "$2}' |
  while read -r path branch; do
    case "$path" in "$WORKTREES_DIR"/*) ;; *) continue ;; esac
    ahead="$(git -C "$path" rev-list --count origin/main..HEAD 2>/dev/null || echo '?')"
    behind="$(git -C "$path" rev-list --count HEAD..origin/main 2>/dev/null || echo '?')"
    dirty="$(git -C "$path" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
    printf '%-40s %-36s ahead %-3s behind %-3s dirty %s\n' "$(basename "$path")" "${branch#refs/heads/}" "$ahead" "$behind" "$dirty"
  done
}

refresh_primary() {
  # Bring the primary checkout's main up to origin/main without ever touching a
  # branch someone else has checked out there.
  local primary_branch main_wt
  git -C "$ROOT" fetch origin main --quiet
  primary_branch="$(git -C "$ROOT" symbolic-ref --short HEAD 2>/dev/null || echo)"
  if [ "$primary_branch" = "main" ]; then
    git -C "$ROOT" merge --ff-only origin/main \
      || die "primary main cannot fast-forward: it holds commits origin/main lacks. STOP and reconcile (see CLAUDE.md); never reset --hard."
    say "primary checkout fast-forwarded to $(git -C "$ROOT" rev-parse --short HEAD)"
    return
  fi
  main_wt="$(git -C "$ROOT" worktree list --porcelain | awk '/^worktree /{p=$2} /^branch refs\/heads\/main$/{print p}')"
  if [ -z "$main_wt" ]; then
    git -C "$ROOT" fetch origin main:main --quiet \
      || die "local main cannot fast-forward to origin/main; reconcile by hand (see CLAUDE.md)"
    say "local main ref fast-forwarded (the primary checkout is on '$primary_branch', left untouched)"
  else
    say "WARNING: main is checked out at $main_wt; refresh it there: git -C $main_wt merge --ff-only origin/main"
  fi
}

cmd_ship() {
  local slug wt branch dirty deleted ahead
  slug="$(sanitize_slug "${1:-}")"
  wt="$(worktree_for "$slug")"
  [ -d "$wt" ] || die "no worktree at $wt"
  branch="$(git -C "$wt" symbolic-ref --short HEAD)"

  dirty="$(git -C "$wt" status --porcelain)"
  [ -z "$dirty" ] || die "uncommitted changes in $wt; commit EXPLICIT paths first (never git add -A):
$dirty"

  # 1. Rebase: a multi-minute gap is enough for a concurrent ship to land.
  git -C "$wt" fetch origin main --quiet
  if ! git -C "$wt" rebase --quiet origin/main; then
    git -C "$wt" rebase --abort || true
    die "rebase onto origin/main conflicted; resolve it in $wt, then ship again"
  fi

  ahead="$(git -C "$wt" rev-list --count origin/main..HEAD)"
  [ "$ahead" -gt 0 ] || die "$branch has no commits beyond origin/main; nothing to ship"

  # 3. Scope assertion: the diff must hold only what this task touched.
  say "shipping $ahead commit(s) from $branch; files changed vs origin/main:"
  git -C "$wt" diff --stat origin/main...HEAD | sed 's/^/    /'
  deleted="$(git -C "$wt" diff --name-only --diff-filter=D origin/main...HEAD)"
  if [ -n "$deleted" ] && [ "${SHIP_ALLOW_DELETIONS:-}" != "1" ]; then
    die "the diff DELETES files; if you did not author these deletions the base is stale:
$deleted
Confirm they are intended, then: SHIP_ALLOW_DELETIONS=1 bash scripts/codex-worktree.sh ship $slug"
  fi

  # 4. Ship: a direct fast-forward push (the pre-push guard re-checks ff), then refresh.
  git -C "$wt" push --quiet origin "HEAD:main"
  say "pushed $branch -> origin/main @ $(git -C "$wt" rev-parse --short HEAD)"
  refresh_primary
  say "next: gh run watch, then smoke it (CLAUDE.md, Dev loop). When done: bash scripts/codex-worktree.sh remove $slug"
}

cmd_remove() {
  local slug wt branch force="${2:-}"
  slug="$(sanitize_slug "${1:-}")"
  wt="$(worktree_for "$slug")"
  [ -d "$wt" ] || die "no worktree at $wt"
  branch="$(git -C "$wt" symbolic-ref --short HEAD 2>/dev/null || echo)"
  if [ "$force" != "--force" ]; then
    [ -z "$(git -C "$wt" status --porcelain)" ] || die "$wt has uncommitted changes; pass --force to discard them"
    git -C "$ROOT" fetch origin main --quiet
    if [ -n "$branch" ] && [ "$(git -C "$wt" rev-list --count origin/main..HEAD)" -gt 0 ]; then
      die "$branch has commits not on origin/main; ship it, or pass --force to drop them"
    fi
  fi
  git -C "$ROOT" worktree remove ${force:+--force} "$wt"
  [ -z "$branch" ] || git -C "$ROOT" branch -D "$branch" >/dev/null
  say "removed $wt${branch:+ and $branch}"
}

case "${1:-}" in
  create) shift; cmd_create "$@" ;;
  list) shift; cmd_list ;;
  ship) shift; cmd_ship "$@" ;;
  remove) shift; cmd_remove "$@" ;;
  -h|--help|help|"") sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) die "unknown command '$1' (create | list | ship | remove)" ;;
esac

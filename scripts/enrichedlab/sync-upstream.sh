#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 Richard Stoker
# SPDX-License-Identifier: Apache-2.0
#
# Keep the fork in step with upstream OpenShell. See FORK.md for the branch model.
#
#   scripts/enrichedlab/sync-upstream.sh [--merge vX.Y.Z] [--push REMOTE]
#
# Without --push it changes only local branches and prints what a person should review. It never moves
# enrichedlab/main; a person fast-forwards that branch to a merge branch after CI passes.
set -euo pipefail

usage() { echo "usage: $0 [--merge vX.Y.Z] [--push REMOTE]" >&2; exit 2; }

merge_tag=""
push_remote=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --merge) merge_tag=${2:-}; [[ -n $merge_tag ]] || usage; shift 2 ;;
    --push) push_remote=${2:-}; [[ -n $push_remote ]] || usage; shift 2 ;;
    *) usage ;;
  esac
done

upstream=${OPENSHELL_UPSTREAM_REMOTE:-upstream}
series=enrichedlab/main
root=$(git rev-parse --show-toplevel)
cd "$root"

if [[ -n $(git status --porcelain --untracked-files=no) ]]; then
  echo "refused: the working tree has uncommitted changes" >&2
  exit 2
fi
start_branch=$(git rev-parse --abbrev-ref HEAD)
trap 'git checkout -q "$start_branch" 2>/dev/null || true' EXIT

# Reuse conflict resolutions: one made on enrichedlab/next is replayed when the release is merged.
git config rerere.enabled true
git config rerere.autoupdate true

# Release tags only: upstream also moves rolling tags such as `dev`, which a plain --tags fetch refuses to update.
if ! git fetch --quiet --no-tags "$upstream" "+refs/heads/main:refs/remotes/$upstream/main" 'refs/tags/v*:refs/tags/v*'; then
  echo "refused: fetching $upstream failed; run the fetch by hand to see why" >&2
  exit 4
fi

# 1. main follows upstream main, fast-forward only.
if git show-ref --verify --quiet refs/heads/main; then
  git checkout -q main
  if ! git merge --ff-only --quiet "$upstream/main"; then
    echo "refused: local main has diverged from $upstream/main; it must never carry local commits" >&2
    exit 3
  fi
else
  git branch --quiet --track main "$upstream/main"
fi
echo "main: $(git rev-parse --short main) ($upstream/main)"

stable() { git tag --list 'v[0-9]*' --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$'; }
contained=$(git describe --tags --abbrev=0 --match 'v[0-9]*' --exclude '*-*' "$series")
newest=$(stable | head -1)
echo "$series: contains upstream $contained; newest upstream release is $newest"

status=0
merge_into() {
  local branch=$1 target=$2 message=$3
  git checkout -q -B "$branch" "$series"
  if git merge --no-ff --quiet -m "$message" "$target" >/dev/null 2>&1; then
    echo "$branch: merged $target ($(git rev-parse --short "$branch"))"
    return 0
  fi
  # rerere may have resolved every conflict from an earlier resolution.
  if [[ -z $(git diff --name-only --diff-filter=U) ]]; then
    git commit --quiet --no-edit
    echo "$branch: merged $target with recorded resolutions ($(git rev-parse --short "$branch"))"
    return 0
  fi
  echo "$branch: CONFLICT merging $target in:" >&2
  git diff --name-only --diff-filter=U | sed 's/^/  /' >&2
  git merge --abort
  git checkout -q -B "$branch" "$series"
  return 1
}

# 2. next: preview of the series with upstream main, rebuilt every time.
merge_into enrichedlab/next "$upstream/main" "Preview: merge upstream main" || status=1

# 3. A requested release gets its own merge branch for CI.
if [[ -n $merge_tag ]]; then
  stable | grep -qx "$merge_tag" || { echo "refused: $merge_tag is not an upstream stable release tag" >&2; exit 2; }
  if git merge-base --is-ancestor "$merge_tag" "$series"; then
    echo "$series already contains $merge_tag"
    merge_tag=""
  else
    merge_into "enrichedlab/merge-$merge_tag" "$merge_tag" "Merge upstream $merge_tag" || status=1
  fi
elif [[ $newest != "$contained" ]]; then
  echo "to prepare it: $0 --merge $newest"
fi

if [[ -n $push_remote ]]; then
  git push --quiet "$push_remote" main
  git push --quiet --force-with-lease "$push_remote" enrichedlab/next
  if [[ -n $merge_tag ]]; then
    git push --quiet "$push_remote" "$merge_tag" "enrichedlab/merge-$merge_tag"
  fi
  echo "pushed main, enrichedlab/next${merge_tag:+ and enrichedlab/merge-$merge_tag} to $push_remote"
  "$root/scripts/enrichedlab/quiet-upstream-workflows.sh" "$push_remote"
fi
exit $status

#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 Richard Stoker
# SPDX-License-Identifier: Apache-2.0
#
# Disable every upstream workflow that GitHub has enabled in the fork, leaving only .github/workflows/enrichedlab-*.
# Upstream's workflows target NVIDIA's self-hosted runners and secrets, so in a fork they only fail or spend minutes.
#
#   scripts/enrichedlab/quiet-upstream-workflows.sh [REMOTE]   (default: origin; needs an authenticated gh)
set -euo pipefail

remote=${1:-origin}
url=$(git remote get-url "$remote")
repo=$(printf '%s\n' "$url" | sed -E 's#^(https://github.com/|git@github.com:)##; s#\.git$##')

gh api --paginate "repos/$repo/actions/workflows" --jq '.workflows[] | [.id, .state, .path] | @tsv' |
  while IFS=$'\t' read -r id state path; do
    case $path in
      .github/workflows/enrichedlab-*) continue ;;
    esac
    if [[ $state == active ]]; then
      gh api --method PUT "repos/$repo/actions/workflows/$id/disable" >/dev/null
      echo "disabled $path"
    fi
  done

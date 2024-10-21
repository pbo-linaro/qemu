#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "usage: branch [git-publish options]..."
    exit 1
fi

patches=$(mktemp -d)
trap "rm -rf $patches; git checkout master" EXIT

branch=$1; shift
base_revision=${branch}_base

git format-patch ${base_revision}..${branch} -o $patches
git fetch -a upstream
git checkout -b $branch-publish || git checkout $branch-publish
git reset --hard upstream/master
if ! git am $patches/*; then
    git am --show-current-patch=diff
    git am --abort
    exit 1
fi
if ! git publish --base upstream/master "$@"; then
    exit 1
fi
exit 0

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later

set -euo pipefail

patches=$(mktemp -d)
trap "rm -rf $patches; git checkout master" EXIT

if [ $# -lt 2 ]; then
    echo "usage: base_revision branch [git-publish options]..."
    exit 1
fi

base_revision=$1; shift
branch=$1; shift

git format-patch ${base_revision}..${branch} -o $patches
git fetch -a upstream
git checkout -b $branch-publish || git checkout $branch-publish
git reset --hard upstream/master
if ! git am $patches/*; then
    git am --abort
    exit 1
fi
if ! git publish --base upstream/master "$@"; then
    exit 1
fi
exit 0

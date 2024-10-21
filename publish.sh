#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "usage: branch [git-publish options]..."
    exit 1
fi

current_branch=$(git branch --show-current)
patches=$(mktemp -d)
trap "rm -rf $patches; git checkout $current_branch" EXIT

branch=$1; shift
base_revision=${branch}_base

# export patches
git format-patch ${base_revision}..${branch} -o $patches

# create publish branch
git fetch -a upstream
git checkout -b $branch-publish || git checkout $branch-publish
git reset --hard upstream/master

# apply and check patches
if ! git am $patches/*; then
    git am --show-current-patch=diff
    git am --abort
    exit 1
fi
./scripts/checkpatch.pl $(git merge-base upstream/master HEAD)..HEAD

# add CI on top
git checkout -b $branch-publish-ci || git checkout $branch-publish-ci
git reset --hard $branch-publish
git merge ci --squash --ff
mv .github/workflows/build.yml build.yml
git rm -f .github/workflows/*
mkdir -p .github/workflows/
mv build.yml .github/workflows/
git add .github
git commit -a -m 'ci' --signoff

# publish
git checkout $branch-publish
if ! git publish --base upstream/master "$@"; then
    exit 1
fi
exit 0

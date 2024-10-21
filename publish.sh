#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "usage: branch [git-publish options]..."
    exit 1
fi

PULL_REQUEST=${PULL_REQUEST:-}

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

# check reviewed-bin
if [ "$PULL_REQUEST" == "1" ]; then
    echo "--------------------------------------------------------"
    err=0
    for p in $patches/*; do
        if ! grep -q -i Reviewed-by $p > /dev/null; then
            echo ERROR: $p missing 'Reviewed-by'
            err=1
        fi
    done

    if [ $err == 1 ]; then
        echo "ERROR: missing reviews"
        echo "--------------------------------------------------------"
        exit 1
    fi
    echo "--------------------------------------------------------"
fi

# add CI on top
echo "--------------------------------------------------------"
git checkout -b $branch-publish-ci || git checkout $branch-publish-ci
git reset --hard $branch-publish
git merge ci --squash --ff
mv .github/workflows/build.yml build.yml
git rm -f .github/workflows/*
mkdir -p .github/workflows/
mv build.yml .github/workflows/
git add .github
git commit -a -m 'ci' --signoff
echo "--------------------------------------------------------"

# Add Gitlab CI and tag for pull request
if [ "$PULL_REQUEST" == "1" ]; then
    echo "--------------------------------------------------------"
    git checkout -b pr-$branch-ci ||
        git checkout pr-$branch-ci
    git reset --hard $branch-publish
    git tag --delete pr-$branch || true
    git tag -s pr-$branch
    git cherry-pick gitlab_ci_full~1
    # replace remote tag
    git push --delete gitlab pr-$branch || true
    git push gitlab pr-$branch
    echo "--------------------------------------------------------"
fi

# publish (! pull request)
if [ "$PULL_REQUEST" != "1" ]; then
    git checkout $branch-publish
    if ! git publish --base upstream/master "$@"; then
        exit 1
    fi
fi
exit 0

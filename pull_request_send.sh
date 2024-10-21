#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later

set -euo pipefail

if [ $# -ne 2 ]; then
    echo "usage: tag subject"
    exit 1
fi

patches=$(mktemp -d)
trap "rm -rf $patches" EXIT

pr=pr-$1
subject="$2"
git tag -v $pr
base=$(git merge-base upstream/master $pr)

git format-patch -o "$patches" $base..$pr --subject-prefix=PULL --numbered --cover-letter
COVERLETTER="$patches/0000-cover-letter.patch"
sed -i -e "s/^Subject: \[PULL\(.*\)].*/Subject: [PULL\1] $subject/;/^$/q" "$COVERLETTER"
git request-pull master "https://gitlab.com/pbo-linaro/qemu" "$pr" >>"$COVERLETTER"
vi "$COVERLETTER"
git send-email $patches --to qemu-devel@nongnu.org

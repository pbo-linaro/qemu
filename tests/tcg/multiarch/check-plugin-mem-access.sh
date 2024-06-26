#!/usr/bin/env bash

set -euo pipefail

die()
{
    echo "$@" 1>&2
    exit 1
}

check()
{
    file=$1
    pattern=$2
    grep "$pattern" "$file" > /dev/null || die "\"$pattern\" not found in $file"
}

[ $# -eq 1 ] || die "usage: plugin_out_file"

plugin_out=$1

expected()
{
    ./test-plugin-mem-access ||
        die "running test-plugin-mem-access executable failed"
}

expected | while read line; do
    check "$plugin_out" "$line"
done

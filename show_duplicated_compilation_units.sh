#!/usr/bin/env bash

set -euo pipefail

jq --raw-output < build/compile_commands.json '.[].file' |
    sort | uniq -c | sort -rn | grep -v '^\s*1 ' | less

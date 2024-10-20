#!/usr/bin/env bash

set -euo pipefail

jq < build/compile_commands.json '.[] | .file' | sort | uniq -c | sort -rn | less

#!/usr/bin/env bash

set -euo pipefail

rsync -av ./build/qapi/ generated_qapi/

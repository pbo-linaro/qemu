#!/usr/bin/env bash

set -euo pipefail

if [ "${CONTAINER:-}" == "" ]; then
    ./container.sh ./build.sh "$@"
    exit 0
fi
if [ ! -f build/.configured ]; then 
    ./configure --cross-prefix=aarch64-linux-gnu- --disable-werror \
        --enable-virtfs --enable-slirp
    touch build/.configured
fi
ninja -C build qemu-system-aarch64 "$@"

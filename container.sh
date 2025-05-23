#!/usr/bin/env bash

set -euo pipefail

img=cross-qemu-aarch64
podman build -t $img - < ./Dockerfile
podman run --init -e CONTAINER=1 \
    --rm -it -v $(pwd):$(pwd) -w $(pwd) $img \
    "$@"

#!/usr/bin/env bash

set -euo pipefail

die()
{
    echo "$@" >&2
    exit 1
}

[ $# -ge 2 ] || die "usage: arch command [args...]
arch: (amd64|arm64v8|i386)"
arch=$1;shift

script_dir=$(dirname $(readlink -f $0))
pushd $script_dir

image=qemu-$arch
podman build -t $image -f - --build-arg arch=$arch < Dockerfile
mkdir -p build_$arch build
podman run -it \
    -e CCACHE_DIR=$HOME/.cache/ccache \
    -v $HOME/.cache/ccache/:$HOME/.cache/ccache/ \
    -v $(pwd):$(pwd) -v $(pwd)/build_$arch:$(pwd)/build -w $(pwd)\
    $image "$@"

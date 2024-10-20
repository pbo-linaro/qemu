#!/usr/bin/env bash

set -euo pipefail

die()
{
    echo "$@" >&2
    exit 1
}

[ $# -ge 2 ] || die "usage: arch command [args...]
arch: (x86_64|arm64|armhf|i386|s390x)"
arch=$1;shift

script_dir=$(dirname $(readlink -f $0))
pushd $script_dir

image=qemu-$arch
podman build -t $image -f - --build-arg arch=$arch < Dockerfile
mkdir -p build_$arch build
mkdir -p $HOME/.cache/ccache
# run privileged container: kvm + all capability (ptrace needed for Lsan)
podman run -it \
    --privileged \
    -e CCACHE_DIR=$HOME/.cache/ccache \
    -v $HOME/.cache/ccache/:$HOME/.cache/ccache/ \
    -v $(pwd):$(pwd) -v $(pwd)/build_$arch:$(pwd)/build -w $(pwd)\
    -v /:/host \
    $image "$@"

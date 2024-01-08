#!/usr/bin/env bash

set -euo pipefail

x64="x86_64-linux-user,x86_64-softmmu"
i386="i386-linux-user,i386-softmmu"
aarch64="aarch64-linux-user,aarch64-softmmu"

type=debug
if [ $# -eq 1 ]; then
    type=$1
fi

mkdir -p build
touch build/.build_type
previous_type="$(cat build/.build_type)"

if [ "$previous_type" != "$type" ]; then
    echo "build type is different ($previous_type -> $type)"
    rm -rf build || true
    mkdir -p build
    echo "$type" > build/.build_type
fi

pushd build
if [ ! -f .configured ]; then
    export CC="ccache cc"
    export CXX="ccache cxx"
    configure_flags=
    case $type in
    opt)
        configure_flags=
        ;;
    debug)
        configure_flags="--enable-debug -Dsanitizers=true"
        ;;
    tsan)
        configure_flags="--enable-debug -Dtsan=true"
        ;;
    *)
        echo "Unknown build type $type (choices: opt, debug, tsan)"
        exit 1
        ;;
    esac
    ../configure --target-list=$x64,$i386,$aarch64 $configure_flags
    touch .configured
fi
ninja -k0
make -B -C contrib/plugins/ > /dev/null
popd

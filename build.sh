#!/usr/bin/env bash

set -euo pipefail

type=
if [ $# -ge 1 ]; then
    type=$1; shift
fi

mkdir -p build
touch build/.build_type
previous_type="$(cat build/.build_type)"

if [ "$type" == "" ]; then
    type=$previous_type
fi
if [ "$type" == "" ]; then
    type=dev
fi

if [ "$previous_type" != "$type" ]; then
    echo "build type is different ($previous_type -> $type)"
    rm -rf build || true
    mkdir -p build
    echo "$type" > build/.build_type
fi

echo "build: $type"

if [ $type == tsan ]; then
    echo "Build with TSAN: use export LD_LIBRARY_PATH=$(pwd)/build/glib_tsan"
fi

target="--target-list=aarch64-linux-user,x86_64-linux-user"
target=$target,aarch64-softmmu,x86_64-softmmu,arm-softmmu

pushd build > /dev/null
if [ ! -f .configured ]; then
    export CC="ccache gcc"
    export CXX="ccache g++"
    configure_flags=
    case $type in
    dev)
        configure_flags="--enable-debug-tcg --enable-debug-graph-lock \
                         --enable-debug-mutex --enable-asan --enable-ubsan"
        export CFLAGS="-fno-omit-frame-pointer"
        ;;
    debug)
        configure_flags="--enable-debug"
        export CFLAGS="-fno-omit-frame-pointer"
        ;;
    opt)
        configure_flags=""
        export CFLAGS="-fno-omit-frame-pointer"
        ;;
    uftrace)
        configure_flags=""
        export CFLAGS="-fno-omit-frame-pointer -pg -fno-inline"
        # -pg is faster than -finstrument-functions (x2)
        # we need to disable inlining or we skip inlined func.
        ;;
    tsan)
        if [ ! -d glib_tsan ]; then
            rm -rf glib
            git clone --depth=1 --branch=2.81.0 \
                https://github.com/GNOME/glib.git
            pushd glib
            CFLAGS="-O2 -g -fsanitize=thread" meson setup \
                --prefix=$(pwd)/out \
                build -Dtests=false
            ninja -C build install
            popd
            mkdir -p glib_tsan
            rsync -av glib/out/lib/*/* glib_tsan/
            rm -rf glib/
        fi
        configure_flags="--enable-tsan"
        ;;
    clang)
        export CC="ccache clang"
        export CXX="ccache clang++"
        ;;
    all-debug)
        configure_flags="--enable-debug"
        export CFLAGS="-fno-omit-frame-pointer"
        target= # build all targets
        ;;
    all-opt)
        configure_flags=""
        export CFLAGS="-fno-omit-frame-pointer"
        target= # build all targets
        ;;
    all-coverage)
        export CFLAGS="--coverage"
        target= # build all targets
        ;;
    docs)
        configure_flags="--enable-docs"
        target="--target-list=" # no target
        ;;
    *)
        choices="dev, debug, opt, uftrace, tsan, clang, docs,"
        choices="$choices,all-debug, all-opt, all-coverage"
        echo "Unknown build type $type (choices: $choices)"
        exit 1
        ;;
    esac
    ../configure $target --disable-docs $configure_flags
    touch .configured
fi
ninja "$@" | sed -e "s#^\.\./#$(readlink -f ../)/#"
popd > /dev/null

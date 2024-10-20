#!/usr/bin/env bash

set -euo pipefail

type=
if [ $# -eq 1 ]; then
    type=$1
fi

mkdir -p build
touch build/.build_type
previous_type="$(cat build/.build_type)"

if [ "$type" == "" ]; then
    type=$previous_type
fi
if [ "$type" == "" ]; then
    type=opt
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

target=aarch64-linux-user,x86_64-linux-user,i386-linux-user
target=$target,aarch64-softmmu,x86_64-softmmu,i386-softmmu

pushd build > /dev/null
if [ ! -f .configured ]; then
    export CC="ccache cc"
    export CXX="ccache cxx"
    configure_flags=
    case $type in
    opt)
        configure_flags=""
        export CFLAGS="-O2 -g -fno-omit-frame-pointer"
        ;;
    opt-gcov)
        configure_flags=""
        export CFLAGS="-O2 -g -fno-omit-frame-pointer --coverage"
        export LDFLAGS="--coverage"
        ;;
    debug)
        configure_flags="--enable-debug -Dasan=true -Dubsan=true"
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
        configure_flags="--enable-debug -Dtsan=true"
        ;;
    clang)
        export CC="ccache clang"
        export CXX="ccache clang++"
        ;;
    *)
        choices="opt, debug, tsan, clang"
        echo "Unknown build type $type (choices: $choices)"
        exit 1
        ;;
    esac
    ../configure --target-list=$target $configure_flags
    touch .configured
fi
ninja | sed -e "s#^\.\./#$(readlink -f ../)/#"
popd > /dev/null

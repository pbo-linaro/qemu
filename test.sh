#!/usr/bin/env bash

set -eu

./build.sh

ARCH=${ARCH:-amd64}
qemu_system_args=
if [ "$ARCH" == amd64 ]; then
    qemu_suffix=x86_64
elif [ "$ARCH" == i386 ]; then
    qemu_suffix=i386
elif [ "$ARCH" == arm64v8 ]; then
    qemu_suffix=aarch64
    qemu_system_args="-M virt"
fi

gui_run=$(which xvfb-run || true)

g++ mt.cpp -o build/mt

qemu_user=./build/qemu-$qemu_suffix
qemu_system="./build/qemu-system-$qemu_suffix $qemu_system_args"
bin="build/mt 17 1000" # 17 threads, 1000 iterations
$qemu_user -plugin build/tests/plugin/libinline.so "$@" $bin
#$qemu_user -plugin build/tests/plugin/libinline.so "$@" \
#  -d op,op_opt,in_asm,out_asm $bin |& head -n 1000 > build/plugin.on
#$qemu_user "$@" -d op,op_opt,in_asm,out_asm $bin |&
# head -n 1000 > build/plugin.off
echo -----------------------------------------
#$gui_run timeout --preserve-status 2 $qemu_system\
#    -plugin build/tests/plugin/libinline.so -smp 8
#vim build/plugin_sys
#vimdiff build/plugin.*

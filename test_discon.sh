#!/usr/bin/env bash

set -euo pipefail

./build.sh
./build/qemu-system-aarch64 -M virt\
    -plugin ./build/tests/tcg/plugins/libdiscons.so,abort=on\
    -m 8G -device virtio-blk-pci,drive=root \
    -drive if=none,id=root,file=/home/user/.work/images/debianaarch64.img \
    -M virt -cpu max,pauth=off \
    -drive if=pflash,readonly=on,file=/usr/share/AAVMF/AAVMF_CODE.fd \
    -drive if=pflash,file=/home/user/.work/images/AAVMF_VARS.fd \
    -d plugin,in_asm,op -D crash.log -display none

#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later

set -euo pipefail
set -x

run()
{
    setarch -R ./build/qemu-x86_64 "$@" -d plugin ./mt 1 2000
}


run -plugin ./build/tests/tcg/plugins/libinsn
run -plugin ./build/contrib/plugins/libhowvec
run -plugin ./build/tests/tcg/plugins/libsyscall
run -plugin ./build/tests/tcg/plugins/libmem,region-summary=on
run -plugin ./build/contrib/plugins/libstoptrigger,icount=10000
run -plugin ./build/contrib/plugins/libstoptrigger,addr=0x7ffff5654930
run -plugin ./build/contrib/plugins/libcache
run -plugin ./build/contrib/plugins/libhotblocks
run -plugin ./build/contrib/plugins/libcflow
setarch -R ./build/qemu-system-x86_64 -display none \
-plugin ./build/contrib/plugins/libhwprofile,source=off \
-plugin ./build/contrib/plugins/libstoptrigger,icount=100000000 \
-d plugin
setarch -R ./build/qemu-system-x86_64 -display none \
-plugin ./build/contrib/plugins/libhwprofile,source=on \
-plugin ./build/contrib/plugins/libstoptrigger,icount=100000000 \
-d plugin
run -plugin ./build/contrib/plugins/libhotpages

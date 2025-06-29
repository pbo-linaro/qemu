#!/usr/bin/env bash

set -euo pipefail

mkdir -p uftrace.data

cat > uftrace.data/task.txt << EOF
SESS timestamp=0.0 pid=0 sid=0 exename="/home/user/a.out"
TASK timestamp=0.0 tid=0 pid=0
TASK timestamp=0.0 tid=1 pid=0
TASK timestamp=0.0 tid=2 pid=0
TASK timestamp=0.0 tid=3 pid=0
EOF

# map stack on highest address possible, else uftrace considers kernel addresses
# as special
rm -f uftrace.data/sid-0.map

sym()
{
    f=$1; shift
    load_addr=$1; shift
    name=$(basename $f)
    nm -US --numeric-sort $f | sort -n | grep '[a-f0-9] [0]' > uftrace.data/$name.sym.raw
    offset=$(readelf -S $f | grep ' .text ' | sed -e 's/.*PROGBITS\s*//' -e 's/\s.*//')
    last_offset=$(tail -n 1 uftrace.data/$name.sym.raw | cut -f 1 -d ' ')
    last_size=$(tail -n 1 uftrace.data/$name.sym.raw | cut -f 2 -d ' ')
    last_end=$((0x$last_offset + 0x$last_size))
    last_end=$(printf '%x' $last_end)

    offset=$(python3 -c "print(f'{(int('$offset', 16)) & 0xffffffffffff:x}')")
    last_end=$(python3 -c "print(f'{(int('$last_end', 16)) & 0xffffffffffff:x}')")

    cat << EOF | python3 > uftrace.data/$name.sym
import fileinput
for s in fileinput.input("uftrace.data/$name.sym.raw"):
    s = s.split()
    offset = int('$offset', 16)
    addr = int(s[0], 16) & 0xffffffffffff
    addr = addr - offset
    print(f'{addr:x}', s[1], s[2], s[3])
EOF

    offset=$((0x$offset + $load_addr))
    offset=$(printf '%x' $offset)
    last_end=$((0x$last_end + $load_addr))
    last_end=$(printf '%x' $last_end)
    echo "$offset-$last_end r-p 00000000 00:00 0 $name" >> uftrace.data/sid-0.map
}

sym /home/user/.work/qemu-linux-stack/arm-trusted-firmware/build/qemu/debug/bl1/bl1.elf 0
sym /home/user/.work/qemu-linux-stack/arm-trusted-firmware/build/qemu/debug/bl2/bl2.elf 0
sym /home/user/.work/qemu-linux-stack/arm-trusted-firmware/build/qemu/debug/bl31/bl31.elf 0
# INFO:    BL31: Preparing for EL3 exit to normal world
# INFO:    Entry point address = 0x60000000
sym /home/user/.work/qemu-linux-stack/u-boot/u-boot $((0x60000000))
sym /home/user/.work/qemu-linux-stack/linux/vmlinux 0

cat >> uftrace.data/sid-0.map << EOF
ffffffffffffffff-ffffffffffffffff rw-p 00000000 00:00 0                          [stack]
EOF
cat uftrace.data/sid-0.map

# uftrace dump --debug
#uftrace file header: magic         = 4674726163652100
#uftrace file header: version       = 4
#uftrace file header: header size   = 40
#uftrace file header: endian        = 1 (little)
#uftrace file header: class         = 2 (64 bit)
#uftrace file header: features      = 0x1263 (PLTHOOK | TASK_SESSION | SYM_REL_ADDR | MAX_STACK | AUTO_ARGS | SYM_SIZE)
#uftrace file header: info          = 0x7bff (EXE_NAME | EXE_BUILD_ID | EXIT_STATUS | CMDLINE | CPUINFO | MEMINFO | OSINFO | TASKINFO | USAGEINFO | LOADINFO | RECORD_DATE | PATTERN_TYPE | VERSION | UTC_OFFSET)
# <0000000000000000>: 46 74 72 61 63 65 21 00  04 00 00 00 28 00 01 02
# <0000000000000010>: 63 12 00 00 00 00 00 00  ff 7b 00 00 00 00 00 00
# <0000000000000020>: 00 04 00 00 00 00 00 00
printf "\x46\x74\x72\x61\x63\x65\x21\x00\x04\x00\x00\x00\x28\x00\x01\x02" > uftrace.data/info
printf "\x63\x12\x00\x00\x00\x00\x00\x00\xff\x7b\x00\x00\x00\x00\x00\x00" >> uftrace.data/info
printf "\x00\x04\x00\x00\x00\x00\x00\x00" >> uftrace.data/info

cat >> uftrace.data/info << EOF
exename:/home/user/a.out
build_id:eb07eb2aa53cae0a397bdd65ee3308feccec8f01
exit_status:0
cmdline:uftrace record ./a.out
cpuinfo:lines=2
cpuinfo:nr_cpus=22 / 22 (online/possible)
cpuinfo:desc=Intel(R) Core(TM) Ultra 9 185H
meminfo:18.1 / 30.8 GB (free / total)
osinfo:lines=3
osinfo:kernel=Linux 6.12.33+deb13-amd64
osinfo:hostname=pc
osinfo:distro="Debian GNU/Linux 13 (trixie)"
taskinfo:lines=2
taskinfo:nr_tid=4
taskinfo:tids=0,1,2,3
usageinfo:lines=6
usageinfo:systime=0.000000
usageinfo:usrtime=0.003544
usageinfo:ctxsw=2 / 2 (voluntary / involuntary)
usageinfo:maxrss=8016
usageinfo:pagefault=0 / 631 (major / minor)
usageinfo:iops=0 / 8 (read / write)
loadinfo:0.45 / 0.49 / 0.53
record_date:Fri Jul  4 17:42:58 2025
elapsed_time:1000000000000.0 sec
pattern_type:regex
uftrace_version:v0.17 ( x86_64 dwarf python3 luajit tui perf sched dynamic kernel )
utc_offset:1751552954
EOF

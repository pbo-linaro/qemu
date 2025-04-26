/*
 * QEMU target info helpers
 *
 *  Copyright (c) Linaro
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/target-info.h"
#include "qemu/target-info-impl.h"

const char *target_name(void)
{
    return target_info()->target_name;
}

unsigned target_long_bits(void)
{
    return target_info()->long_bits;
}

const char *target_cpu_type(void)
{
    return target_info()->cpu_type;
}

const char *target_machine_typename(void)
{
    return target_info()->machine_typename;
}

bool target_i386(void)
{
#ifdef TARGET_I386
    return true;
#else
    return false;
#endif
}

bool target_x86_64(void)
{
#ifdef TARGET_X86_64
    return true;
#else
    return false;
#endif
}

bool target_arm(void)
{
#ifdef TARGET_ARM
    return true;
#else
    return false;
#endif
}

bool target_aarch64(void)
{
#ifdef TARGET_AARCH64
    return true;
#else
    return false;
#endif
}

bool target_s390x(void)
{
#ifdef TARGET_S390X
    return true;
#else
    return false;
#endif
}

bool target_mips(void)
{
#ifdef TARGET_MIPS
    return true;
#else
    return false;
#endif
}

bool target_mips64(void)
{
#ifdef TARGET_MIPS64
    return true;
#else
    return false;
#endif
}

bool target_loongarch64(void)
{
#ifdef TARGET_LOONGARCH64
    return true;
#else
    return false;
#endif
}

bool target_riscv32(void)
{
#ifdef TARGET_RISCV32
    return true;
#else
    return false;
#endif
}

bool target_riscv64(void)
{
#ifdef TARGET_RISCV64
    return true;
#else
    return false;
#endif
}

bool target_ppc(void)
{
#ifdef TARGET_PPC
    return true;
#else
    return false;
#endif
}

bool target_ppc64(void)
{
#ifdef TARGET_ppc64
    return true;
#else
    return false;
#endif
}

bool target_has_kvm(void)
{
#ifdef CONFIG_KVM
    return true;
#else
    return false;
#endif
}

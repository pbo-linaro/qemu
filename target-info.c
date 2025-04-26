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

bool target_aarch64(void)
{
#ifdef TARGET_AARCH64
    return true;
#else
    return false;
#endif
}

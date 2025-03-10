/*
 * Various stubs for xen functions
 *
 * Those functions are used only if xen_enabled(). This file is linked only if
 * CONFIG_XEN is not set, so they should never be called.
 *
 * Copyright (c) 2025 Linaro, Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>

#define NEVER_CALLED_STUB(name)     \
void name(void); void name(void)    \
{                                   \
    g_assert_not_reached();         \
}

NEVER_CALLED_STUB(xen_hvm_modified_memory);
NEVER_CALLED_STUB(xen_ram_alloc);
NEVER_CALLED_STUB(xen_invalidate_map_cache_entry);
NEVER_CALLED_STUB(xen_map_cache);
NEVER_CALLED_STUB(xen_mr_is_memory);
NEVER_CALLED_STUB(xen_ram_addr_from_mapcache);

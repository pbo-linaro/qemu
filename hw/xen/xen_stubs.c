/* xen stubs */

#define VOID_STUB(name) void name(void); void name(void) {}

VOID_STUB(xen_hvm_modified_memory);
VOID_STUB(xen_ram_alloc);
VOID_STUB(xen_invalidate_map_cache_entry);
VOID_STUB(xen_map_cache);
VOID_STUB(xen_mr_is_memory);
VOID_STUB(xen_ram_addr_from_mapcache);

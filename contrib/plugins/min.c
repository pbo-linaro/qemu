#include <stdio.h>
#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

qemu_plugin_id_t plugin_id = {0};

static void post_reset(qemu_plugin_id_t id)
{
    printf("Reset finished\n");
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    printf("Translating basic block\n");
    qemu_plugin_reset(plugin_id, post_reset);
    printf("Reset request issued\n");
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                   const qemu_info_t *info, int argc, char **argv) {

    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    plugin_id = id;
    return 0;
}

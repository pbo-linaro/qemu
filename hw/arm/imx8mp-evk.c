/*
 * NXP i.MX 8M Plus Evaluation Kit System Emulation
 *
 * Copyright (c) 2024, Bernhard Beschow <shentey@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "exec/address-spaces.h"
#include "hw/arm/boot.h"
#include "hw/arm/fsl-imx8mp.h"
#include "hw/boards.h"
#include "system/qtest.h"
#include "qemu/error-report.h"
#include "qapi/error.h"

static void imx8mp_evk_init(MachineState *machine)
{
    static struct arm_boot_info boot_info;
    FslImx8mpState *s;

    if (machine->ram_size > FSL_IMX8MP_RAM_SIZE_MAX) {
        error_report("RAM size " RAM_ADDR_FMT " above max supported (%08" PRIx64 ")",
                     machine->ram_size, FSL_IMX8MP_RAM_SIZE_MAX);
        exit(1);
    }

    boot_info = (struct arm_boot_info) {
        .loader_start = FSL_IMX8MP_RAM_START,
        .board_id = -1,
        .ram_size = machine->ram_size,
        .psci_conduit = QEMU_PSCI_CONDUIT_SMC,
    };

    s = FSL_IMX8MP(object_new(TYPE_FSL_IMX8MP));
    object_property_add_child(OBJECT(machine), "soc", OBJECT(s));
    qdev_realize(DEVICE(s), NULL, &error_fatal);

    memory_region_add_subregion(get_system_memory(), FSL_IMX8MP_RAM_START,
                                machine->ram);

    if (!qtest_enabled()) {
        arm_load_kernel(&s->cpu[0], machine, &boot_info);
    }
}

static void imx8mp_evk_machine_init(MachineClass *mc)
{
    mc->desc = "NXP i.MX 8M Plus EVK Board";
    mc->init = imx8mp_evk_init;
    mc->max_cpus = FSL_IMX8MP_NUM_CPUS;
    mc->default_ram_id = "imx8mp-evk.ram";
}
DEFINE_MACHINE("imx8mp-evk", imx8mp_evk_machine_init)

/*
 * QEMU ICH Emulation
 *
 * Copyright (c) 2010 Sebastian Herbszt <herbszt@gmx.de>
 * Copyright (c) 2010 Alexander Graf <agraf@suse.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 *
 *
 * lspci dump of a ICH-9 real device
 *
 * 00:1f.2 SATA controller [0106]: Intel Corporation 82801IR/IO/IH (ICH9R/DO/DH) 6 port SATA AHCI Controller [8086:2922] (rev 02) (prog-if 01 [AHCI 1.0])
 *         Subsystem: Intel Corporation 82801IR/IO/IH (ICH9R/DO/DH) 6 port SATA AHCI Controller [8086:2922]
 *         Control: I/O+ Mem+ BusMaster+ SpecCycle- MemWINV- VGASnoop- ParErr- Stepping- SERR- FastB2B- DisINTx+
 *         Status: Cap+ 66MHz+ UDF- FastB2B+ ParErr- DEVSEL=medium >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
 *         Latency: 0
 *         Interrupt: pin B routed to IRQ 222
 *         Region 0: I/O ports at d000 [size=8]
 *         Region 1: I/O ports at cc00 [size=4]
 *         Region 2: I/O ports at c880 [size=8]
 *         Region 3: I/O ports at c800 [size=4]
 *         Region 4: I/O ports at c480 [size=32]
 *         Region 5: Memory at febf9000 (32-bit, non-prefetchable) [size=2K]
 *         Capabilities: [80] Message Signalled Interrupts: Mask- 64bit- Count=1/16 Enable+
 *                 Address: fee0f00c  Data: 41d9
 *         Capabilities: [70] Power Management version 3
 *                 Flags: PMEClk- DSI- D1- D2- AuxCurrent=0mA PME(D0-,D1-,D2-,D3hot+,D3cold-)
 *                 Status: D0 PME-Enable- DSel=0 DScale=0 PME-
 *         Capabilities: [a8] SATA HBA <?>
 *         Capabilities: [b0] Vendor Specific Information <?>
 *         Kernel driver in use: ahci
 *         Kernel modules: ahci
 * 00: 86 80 22 29 07 04 b0 02 02 01 06 01 00 00 00 00
 * 10: 01 d0 00 00 01 cc 00 00 81 c8 00 00 01 c8 00 00
 * 20: 81 c4 00 00 00 90 bf fe 00 00 00 00 86 80 22 29
 * 30: 00 00 00 00 80 00 00 00 00 00 00 00 0f 02 00 00
 * 40: 00 80 00 80 00 00 00 00 00 00 00 00 00 00 00 00
 * 50: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 * 60: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 * 70: 01 a8 03 40 08 00 00 00 00 00 00 00 00 00 00 00
 * 80: 05 70 09 00 0c f0 e0 fe d9 41 00 00 00 00 00 00
 * 90: 40 00 0f 82 93 01 00 00 00 00 00 00 00 00 00 00
 * a0: ac 00 00 00 0a 00 12 00 12 b0 10 00 48 00 00 00
 * b0: 09 00 06 20 00 00 00 00 00 00 00 00 00 00 00 00
 * c0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 * d0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 * e0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 * f0: 00 00 00 00 00 00 00 00 86 0f 02 00 00 00 00 00
 *
 */

#include "qemu/osdep.h"
#include "hw/pci/msi.h"
#include "hw/pci/pci.h"
#include "migration/vmstate.h"
#include "qemu/module.h"
#include "hw/isa/isa.h"
#include "system/dma.h"
#include "hw/ide/pci.h"
#include "hw/ide/ahci-pci.h"
#include "ahci-internal.h"
#include "system/spdm-socket.h"

#define ICH9_MSI_CAP_OFFSET     0x80
#define ICH9_SATA_CAP_OFFSET    0xA8

#define ICH9_IDP_BAR            4
#define ICH9_MEM_BAR            5

#define ICH9_IDP_INDEX          0x10
#define ICH9_IDP_INDEX_LOG2     0x04

static const VMStateDescription vmstate_ich9_ahci = {
    .name = "ich9_ahci",
    .version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_PCI_DEVICE(parent_obj, AHCIPCIState),
        VMSTATE_AHCI(ahci, AHCIPCIState),
        VMSTATE_END_OF_LIST()
    },
};

static const Property ich_props[] = {
    DEFINE_PROP_UINT16("spdm_port", PCIDevice, spdm_port, 0),
};

static void pci_ich9_ahci_update_irq(void *opaque, int irq_num, int level)
{
    PCIDevice *pci_dev = opaque;

    if (msi_enabled(pci_dev)) {
        if (level) {
            msi_notify(pci_dev, 0);
        }
    } else {
        pci_set_irq(pci_dev, level);
    }
}

static void pci_ich9_reset(DeviceState *dev)
{
    AHCIPCIState *d = ICH9_AHCI(dev);

    ahci_reset(&d->ahci);
}

static void pci_ich9_ahci_init(Object *obj)
{
    AHCIPCIState *d = ICH9_AHCI(obj);

    qemu_init_irq(&d->irq, pci_ich9_ahci_update_irq, d, 0);
    ahci_init(&d->ahci, DEVICE(obj));
    d->ahci.irq = &d->irq;
}

static bool pcie_doe_spdm_rsp(DOECap *doe_cap)
{
    void *req = pcie_doe_get_write_mbox_ptr(doe_cap);
    uint32_t req_len = pcie_doe_get_obj_len(req) * 4;
    void *rsp = doe_cap->read_mbox;
    uint32_t rsp_len = SPDM_SOCKET_MAX_MESSAGE_BUFFER_SIZE;

    uint32_t recvd = spdm_socket_rsp(doe_cap->spdm_socket,
                             SPDM_SOCKET_TRANSPORT_TYPE_PCI_DOE,
                             req, req_len, rsp, rsp_len);
    doe_cap->read_mbox_len += DIV_ROUND_UP(recvd, 4);

    return recvd != 0;
}

static DOEProtocol doe_spdm_prot[] = {
    { PCI_VENDOR_ID_PCI_SIG, PCI_SIG_DOE_CMA, pcie_doe_spdm_rsp },
    { PCI_VENDOR_ID_PCI_SIG, PCI_SIG_DOE_SECURED_CMA, pcie_doe_spdm_rsp },
    { }
};

static void pci_ich9_ahci_realize(PCIDevice *dev, Error **errp)
{
    AHCIPCIState *d;
    int sata_cap_offset;
    uint8_t *sata_cap;
    d = ICH9_AHCI(dev);
    int ret;

    d->ahci.ports = 6;
    ahci_realize(&d->ahci, DEVICE(dev), pci_get_address_space(dev));

    pci_config_set_prog_interface(dev->config, AHCI_PROGMODE_MAJOR_REV_1);

    dev->config[PCI_CACHE_LINE_SIZE] = 0x08;  /* Cache line size */
    dev->config[PCI_LATENCY_TIMER]   = 0x00;  /* Latency timer */
    pci_config_set_interrupt_pin(dev->config, 1);

    /* XXX Software should program this register */
    dev->config[0x90]   = 1 << 6; /* Address Map Register - AHCI mode */

    pci_register_bar(dev, ICH9_IDP_BAR, PCI_BASE_ADDRESS_SPACE_IO,
                     &d->ahci.idp);
    pci_register_bar(dev, ICH9_MEM_BAR, PCI_BASE_ADDRESS_SPACE_MEMORY,
                     &d->ahci.mem);

    pcie_endpoint_cap_init(dev, 0xa8 + 0x8); /* right after SATA */

    sata_cap_offset = pci_add_capability(dev, PCI_CAP_ID_SATA,
                                          ICH9_SATA_CAP_OFFSET, SATA_CAP_SIZE,
                                          errp);
    if (sata_cap_offset < 0) {
        return;
    }

    sata_cap = dev->config + sata_cap_offset;
    pci_set_word(sata_cap + SATA_CAP_REV, 0x10);
    pci_set_long(sata_cap + SATA_CAP_BAR,
                 (ICH9_IDP_BAR + 0x4) | (ICH9_IDP_INDEX_LOG2 << 4));
    d->ahci.idp_offset = ICH9_IDP_INDEX;

    /* Although the AHCI 1.3 specification states that the first capability
     * should be PMCAP, the Intel ICH9 data sheet specifies that the ICH9
     * AHCI device puts the MSI capability first, pointing to 0x80. */
    ret = msi_init(dev, ICH9_MSI_CAP_OFFSET, 1, true, false, NULL);
    /* Any error other than -ENOTSUP(board's MSI support is broken)
     * is a programming error.  Fall back to INTx silently on -ENOTSUP */
    assert(!ret || ret == -ENOTSUP);

    uint16_t cap_offset = PCI_CONFIG_SPACE_SIZE;

    if (dev->spdm_port) {
        pcie_doe_init(dev, &dev->doe_spdm, cap_offset,
                      doe_spdm_prot, true, 0);
        cap_offset += PCI_DOE_SIZEOF;

        dev->doe_spdm.spdm_socket = spdm_socket_connect(dev->spdm_port,
                                                            errp);
        assert(dev->doe_spdm.spdm_socket > 0);
    }

    /* ide */
    pcie_ide_init(dev, cap_offset);
    cap_offset += PCI_IDE_SIZEOF;

    /* tee */
    pcie_cap_tee_init(dev);
}

static void pci_ich9_uninit(PCIDevice *dev)
{
    AHCIPCIState *d;
    d = ICH9_AHCI(dev);

    msi_uninit(dev);
    ahci_uninit(&d->ahci);
}

static uint32_t ich_read_config(PCIDevice *dev, uint32_t address, int len)
{
    uint32_t val;
    if (dev->spdm_port && pcie_find_capability(dev, PCI_EXT_CAP_ID_DOE)) {
        if (pcie_doe_read_config(&dev->doe_spdm, address, len, &val)) {
            return val;
        }
    }
    return pci_default_read_config(dev, address, len);
}

static void ich_write_config(PCIDevice *dev, uint32_t address,
                                  uint32_t val, int len)
{
    if (pcie_find_capability(dev, PCI_EXT_CAP_ID_DOE)) {
        pcie_doe_write_config(&dev->doe_spdm, address, val, len);
    }
    pci_default_write_config(dev, address, val, len);
}

static void ich_ahci_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(klass);

    k->realize = pci_ich9_ahci_realize;
    k->config_write = ich_write_config;
    k->config_read = ich_read_config;
    k->exit = pci_ich9_uninit;
    k->vendor_id = PCI_VENDOR_ID_INTEL;
    k->device_id = PCI_DEVICE_ID_INTEL_82801IR;
    k->revision = 0x02;
    k->class_id = PCI_CLASS_STORAGE_SATA;
    dc->vmsd = &vmstate_ich9_ahci;
    device_class_set_props(dc, ich_props);
    device_class_set_legacy_reset(dc, pci_ich9_reset);
    set_bit(DEVICE_CATEGORY_STORAGE, dc->categories);
}

static const TypeInfo ich_ahci_info = {
    .name          = TYPE_ICH9_AHCI,
    .parent        = TYPE_PCI_DEVICE,
    .instance_size = sizeof(AHCIPCIState),
    .instance_init = pci_ich9_ahci_init,
    .class_init    = ich_ahci_class_init,
    .interfaces = (const InterfaceInfo[]) {
        { INTERFACE_PCIE_DEVICE },
        { },
    },
};

static void ich_ahci_register_types(void)
{
    type_register_static(&ich_ahci_info);
}

type_init(ich_ahci_register_types)

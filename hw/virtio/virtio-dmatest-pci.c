/*
 * Virtio DMA Test PCI Bindings
 *
 * Written by Eric Auger for virtio-iommu
 * Copyright (c) 2019 Red Hat, Inc.
 * Copyright (c) 2022 Linaro, Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"

#include "hw/virtio/virtio-dmatest.h"
#include "hw/virtio/virtio-pci.h"

typedef struct VirtIODMATestPCI VirtIODMATestPCI;

DECLARE_INSTANCE_CHECKER(VirtIODMATestPCI, VIRTIO_DMATEST_PCI,
                         TYPE_VIRTIO_DMATEST_PCI)

struct VirtIODMATestPCI {
    VirtIOPCIProxy parent_obj;
    VirtIODMATest vdev;
};

static const Property virtio_dmatest_pci_properties[] = {
    DEFINE_PROP_UINT32("vectors", VirtIOPCIProxy, nvectors,
                       DEV_NVECTORS_UNSPECIFIED),
};

static void virtio_dmatest_pci_realize(VirtIOPCIProxy *vpci_dev, Error **errp)
{
    VirtIODMATestPCI *dev = VIRTIO_DMATEST_PCI(vpci_dev);
    DeviceState *vdev = DEVICE(&dev->vdev);
    VirtIODMATest *dmatest = VIRTIO_DMATEST(vdev);

    if (vpci_dev->nvectors == DEV_NVECTORS_UNSPECIFIED) {
        vpci_dev->nvectors = MAX(dmatest->num_queues, 1)
                           + 1 /* Config interrupt */;
    }

    virtio_pci_force_virtio_1(vpci_dev);
    qdev_realize(vdev, BUS(&vpci_dev->bus), errp);
}

static void virtio_dmatest_pci_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioPCIClass *k = VIRTIO_PCI_CLASS(klass);
    PCIDeviceClass *pcidev_k = PCI_DEVICE_CLASS(klass);

    device_class_set_props(dc, virtio_dmatest_pci_properties);
    k->realize = virtio_dmatest_pci_realize;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);

    pcidev_k->vendor_id = PCI_VENDOR_ID_REDHAT_QUMRANET;
    pcidev_k->device_id = 0;
    pcidev_k->revision = VIRTIO_PCI_ABI_VERSION;
    pcidev_k->class_id = PCI_CLASS_OTHERS;
}

static void virtio_dmatest_pci_instance_init(Object *obj)
{
    VirtIODMATestPCI *dev = VIRTIO_DMATEST_PCI(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_DMATEST);
}

static const VirtioPCIDeviceTypeInfo virtio_dmatest_pci_info = {
    .generic_name  = TYPE_VIRTIO_DMATEST_PCI,
    .instance_size = sizeof(VirtIODMATestPCI),
    .instance_init = virtio_dmatest_pci_instance_init,
    .class_init    = virtio_dmatest_pci_class_init,
};

static void virtio_dmatest_pci_register(void)
{
    virtio_pci_types_register(&virtio_dmatest_pci_info);
}

type_init(virtio_dmatest_pci_register)

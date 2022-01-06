/*
 * virtio-dmatest device
 *
 * Copyright (c) 2020 Red Hat, Inc.
 * Copyright (c) 2022 Linaro Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef VIRTIO_DMATEST_H_
#define VIRTIO_DMATEST_H_

#include "qom/object.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/vhost.h"

#define TYPE_VIRTIO_DMATEST "virtio-dma-test"
#define TYPE_VIRTIO_DMATEST_PCI "virtio-dma-test-pci"

OBJECT_DECLARE_SIMPLE_TYPE(VirtIODMATest, VIRTIO_DMATEST)

typedef struct VhostDMATestQueue {
    struct vhost_dev dev;
    int fd;
} VhostDMATestQueue;

typedef struct VhostDMATest {
    struct VhostDMATestQueue *queues;
    bool started;
} VhostDMATest;

struct VirtIODMATest {
    VirtIODevice parent_obj;
    VirtQueue **job_vqs;
    uint64_t features;
    uint16_t num_queues;
    bool use_vhost;
    VhostDMATest *vhost;
};

#endif

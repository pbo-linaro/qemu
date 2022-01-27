/*
 * DMA test device
 *
 * A simple DMA engine that helps testing DMA and IOMMU infrastructure.
 * It should be simple enough to be implemented in any software with a virtio
 * device or driver.
 *
 * Skeleton copied from virtio-iommu.c
 *
 * Copyright (c) 2020 Red Hat, Inc.
 * Copyright (c) 2022 Linaro, Ltd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/iov.h"
#include "qemu/log.h"
#include "system/dma.h"
#include "trace.h"

#include "hw/virtio/virtio-dmatest.h"

#include "standard-headers/linux/virtio_ids.h"
#include "standard-headers/linux/virtio_dmatest.h"

#define DMATE_DEFAULT_QUEUE_SIZE    256

/*
 * Keep track of DMA region (@addr, @size). Areas of the region (@mapped_ptr,
 * @mapped_size) are mapped sequentially until the whole region has been
 * consumed. Chunks of those areas (@cur_ptr, @cur_size) are used sequentially.
 */
struct virtio_dmatest_buf {
    uint64_t    addr;
    ssize_t     size;
    void        *mapped_ptr;
    uint64_t mapped_size;
    uint8_t     *cur_ptr;
    size_t      cur_size;
    DMADirection dir;
};

static void virtio_dmatest_unmap_buf(VirtIODevice *vdev,
                                     struct virtio_dmatest_buf *buf)
{
    if (!buf->mapped_size) {
        return;
    }

    dma_memory_unmap(vdev->dma_as, buf->mapped_ptr, buf->mapped_size, buf->dir,
                     buf->mapped_size - buf->cur_size);
    buf->mapped_ptr = NULL;
    buf->mapped_size = 0;
    buf->cur_ptr = NULL;
    buf->cur_size = 0;
}

static int virtio_dmatest_eat_buf(VirtIODevice *vdev,
                                  struct virtio_dmatest_buf *buf,
                                  size_t used_size, DMADirection dir)
{
    uint64_t mapped_size;

    assert(used_size <= buf->cur_size);
    buf->cur_size -= used_size;
    buf->cur_ptr += used_size;

    if (buf->cur_size) {
        return 0;
    }

    mapped_size = buf->mapped_size;
    virtio_dmatest_unmap_buf(vdev, buf);

    buf->size -= mapped_size;
    buf->addr += mapped_size;
    if (buf->size <= 0) {
        buf->size = 0;
        return -ENOSPC;
    }

    buf->mapped_size = buf->size;
    buf->mapped_ptr = dma_memory_map(vdev->dma_as, buf->addr,
                                     &buf->mapped_size,
                                     dir, MEMTXATTRS_UNSPECIFIED);
    if (!buf->mapped_ptr) {
        warn_report_once("could not map %s buffer 0x%"PRIx64" 0x%zx\n",
                         dir == DMA_DIRECTION_TO_DEVICE ? "input" : "output",
                         buf->addr, buf->size);
        buf->mapped_size = 0;
        return -ENOMEM;
    }
    buf->dir = dir;
    buf->cur_ptr = buf->mapped_ptr;
    buf->cur_size = buf->mapped_size;

    return 0;
}

static void virtio_dmatest_handle_memset(VirtIODevice *vdev, VirtQueue *vq,
                                         struct virtio_dmatest_memset *job)
{
    int ret;
    struct virtio_dmatest_buf buf = {};

    uint64_t input_value    = le64_to_cpu(job->input_value);
    uint64_t output_start   = le64_to_cpu(job->addr_start);
    uint64_t output_end     = le64_to_cpu(job->addr_end);

    if (output_end < output_start) {
        qemu_log_mask(LOG_GUEST_ERROR, "inconsistent buffer len\n");
        job->status = VIRTIO_DMATEST_S_INVAL;
        return;
    }

    buf.addr = output_start;
    buf.size = output_end - output_start + 1;
    while (true) {
        ret = virtio_dmatest_eat_buf(vdev, &buf, buf.cur_size,
                                     DMA_DIRECTION_FROM_DEVICE);
        if (!buf.size) {
            break;
        } else if (ret) {
            job->status = VIRTIO_DMATEST_S_IO;
            goto out_unmap;
        }

        memset(buf.cur_ptr, input_value & 0xff, buf.cur_size);
    }
    job->status = VIRTIO_DMATEST_S_OK;

out_unmap:
    virtio_dmatest_unmap_buf(vdev, &buf);
}

static void virtio_dmatest_handle_hash(VirtIODevice *vdev, VirtQueue *vq,
                                       struct virtio_dmatest_hash *job)
{
    int i, ret;
    struct virtio_dmatest_buf buf = {};
    uint64_t hash = 5381; /* djb2 magic */

    uint64_t input_start    = le64_to_cpu(job->addr_start);
    uint64_t input_end      = le64_to_cpu(job->addr_end);

    if (input_end < input_start) {
        qemu_log_mask(LOG_GUEST_ERROR, "inconsistent buffer len\n");
        job->status = VIRTIO_DMATEST_S_INVAL;
        return;
    }

    buf.addr = input_start;
    buf.size = input_end - input_start + 1;
    while (true) {
        ret = virtio_dmatest_eat_buf(vdev, &buf, buf.cur_size,
                                     DMA_DIRECTION_TO_DEVICE);
        if (!buf.size) {
            break;
        } else if (ret) {
            job->status = VIRTIO_DMATEST_S_IO;
            goto out_unmap;
        }

        for (i = 0; i < buf.cur_size; i++) {
            hash = (hash << 5) + hash + buf.cur_ptr[i];
        }
    }
    job->hash = cpu_to_le64(hash);
    job->status = VIRTIO_DMATEST_S_OK;

out_unmap:
    virtio_dmatest_unmap_buf(vdev, &buf);
}

static int virtio_dmatest_handle_one(VirtIODevice *vdev, VirtQueue *vq)
{
    size_t in_size = 0;
    size_t size, out_size;
    VirtQueueElement *elem;

    union {
        struct virtio_dmatest_job           job;
        struct virtio_dmatest_memset        memset;
        struct virtio_dmatest_hash          hash;
    } job = {};

    elem = virtqueue_pop(vq, sizeof(VirtQueueElement));
    if (!elem) {
        return 1;
    }

    out_size = offsetof(struct virtio_dmatest_job, status);
    in_size = sizeof(job) - out_size;

    size = iov_to_buf(elem->out_sg, elem->out_num, 0, &job, out_size);
    if (size != out_size) {
        virtio_error(vdev, "virtio-dmatest: invalid dev-readable size");
        goto out_push;
    }

    trace_virtio_dmatest_handle_enter(job.job.type);

    switch (job.job.type) {
    case VIRTIO_DMATEST_J_MEMSET:
        virtio_dmatest_handle_memset(vdev, vq, &job.memset);
        break;
    case VIRTIO_DMATEST_J_HASH:
        virtio_dmatest_handle_hash(vdev, vq, &job.hash);
        break;
    default:
        job.job.status = VIRTIO_DMATEST_S_INVAL;
        break;
    }

    size = iov_from_buf(elem->in_sg, elem->in_num, 0, &job.job.status, in_size);
    if (size != in_size) {
        virtio_error(vdev, "virtio-dmatest: invalide dev-writable size");
    }

out_push:
    trace_virtio_dmatest_handle_exit(job.job.type);
    virtqueue_push(vq, elem, in_size);
    virtio_notify(vdev, vq);
    trace_virtio_dmatest_notified(job.job.type);
    g_free(elem);
    return 0;
}

static void virtio_dmatest_handle_command(VirtIODevice *vdev, VirtQueue *vq)
{
    while (!virtio_dmatest_handle_one(vdev, vq)) {
        ;
    }
}

static void virtio_dmatest_device_realize(DeviceState *dev, Error **errp)
{
    int i;
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIODMATest *dmate = VIRTIO_DMATEST(dev);

    virtio_init(vdev, VIRTIO_ID_DMATEST, sizeof(struct virtio_dmatest_config));

    if (dmate->num_queues < 1) {
        error_setg(errp, "invalid number of queues");
        return;
    }

    dmate->job_vqs = g_malloc0_n(dmate->num_queues, sizeof(*dmate->job_vqs));
    for (i = 0; i < dmate->num_queues; i++) {
        dmate->job_vqs[i] = virtio_add_queue(vdev, DMATE_DEFAULT_QUEUE_SIZE,
                                             virtio_dmatest_handle_command);
        if (!dmate->job_vqs[i]) {
            error_setg(errp, "could not initialize queue %d", i);
            return;
        }
    }

    virtio_add_feature(&dmate->features, VIRTIO_RING_F_EVENT_IDX);
    virtio_add_feature(&dmate->features, VIRTIO_RING_F_INDIRECT_DESC);
    virtio_add_feature(&dmate->features, VIRTIO_F_VERSION_1);

    /*
     * FIXME: how to make sure that when an IOMMU is present, iommu_platform is
     * enabled?  Currently this isn't enforced and the device is unusable.
     */
    if (!object_property_get_bool(OBJECT(vdev), "iommu_platform", errp)) {
        warn_report("iommu_platform should be enabled for DMA test");
    }

    vhost_dmatest_init(dmate, errp);
}

static void virtio_dmatest_device_unrealize(DeviceState *dev)
{
    int i;
    VirtIODMATest *dmate = VIRTIO_DMATEST(dev);

    for (i = 0; i < dmate->num_queues; i++) {
        virtio_delete_queue(dmate->job_vqs[i]);
    }
    g_free(dmate->job_vqs);
}

static void virtio_dmatest_device_reset(VirtIODevice *vdev)
{
}

static void virtio_dmatest_get_config(VirtIODevice *vdev, uint8_t *config_data)
{
    VirtIODMATest *dmate = VIRTIO_DMATEST(vdev);
    struct virtio_dmatest_config *out_config = (void *)config_data;

    out_config->num_queues = cpu_to_le16(dmate->num_queues);
}

static uint64_t virtio_dmatest_get_features(VirtIODevice *vdev, uint64_t f,
                                            Error **errp)
{
    VirtIODMATest *dmate = VIRTIO_DMATEST(vdev);

    return dmate->features | f;
}

static void virtio_dmatest_set_status(VirtIODevice *vdev, uint8_t status)
{
}

static void virtio_dmatest_instance_init(Object *obj)
{
}

static const Property virtio_dmatest_properties[] = {
    DEFINE_PROP_UINT16("num-queues", VirtIODMATest, num_queues, 1),
};

static void virtio_dmatest_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    device_class_set_props(dc, virtio_dmatest_properties);

    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    vdc->realize = virtio_dmatest_device_realize;
    vdc->unrealize = virtio_dmatest_device_unrealize;
    vdc->reset = virtio_dmatest_device_reset;
    vdc->get_config = virtio_dmatest_get_config;
    vdc->get_features = virtio_dmatest_get_features;
    vdc->set_status = virtio_dmatest_set_status;
}

static const TypeInfo virtio_dmatest_info = {
    .name = TYPE_VIRTIO_DMATEST,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIODMATest),
    .instance_init = virtio_dmatest_instance_init,
    .class_init = virtio_dmatest_class_init,
};

static void virtio_register_types(void)
{
    type_register_static(&virtio_dmatest_info);
}

type_init(virtio_register_types)

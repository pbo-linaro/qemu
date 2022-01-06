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

#include "hw/virtio/virtio-bus.h"
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

static const int vhost_dmatest_feature_bits[] = {
    VIRTIO_F_NOTIFY_ON_EMPTY,
    VIRTIO_RING_F_INDIRECT_DESC,
    VIRTIO_RING_F_EVENT_IDX,
    VIRTIO_F_VERSION_1,
    VIRTIO_F_IOMMU_PLATFORM,
    VHOST_INVALID_FEATURE_BIT
};

static void vhost_dmatest_init(VirtIODMATest *dmate, Error **errp)
{
    int i, fd, ret;
    VhostDMATest *dmate_vhost;

    if (!dmate->use_vhost) {
        return;
    }

    dmate_vhost = g_new0(VhostDMATest, 1);
    dmate_vhost->queues = g_new0(VhostDMATestQueue, dmate->num_queues);

    for (i = 0; i < dmate->num_queues; i++) {
        VhostDMATestQueue *q = &dmate_vhost->queues[i];

        fd = open("/dev/vhost-dmatest", O_RDWR);
        if (fd < 0) {
            error_setg_errno(errp, errno, "while opening /dev/vhost-dmatest");
            return;
        }

        if (!g_unix_set_fd_nonblocking(fd, true, NULL)) {
            error_setg_errno(errp, errno, "Failed to set FD nonblocking");
            return;
        }

        q->dev.nvqs = 1;
        q->dev.vqs = g_malloc0(sizeof(*q->dev.vqs));

        q->fd = fd;
        ret = vhost_dev_init(&q->dev, (void *)(uintptr_t)fd,
                             VHOST_BACKEND_TYPE_KERNEL, 0, errp);
        if (ret) {
            error_setg(errp, "cannot init vhost dev");
            return;
        }
    }

    dmate->vhost = dmate_vhost;
}

static void vhost_dmatest_cleanup(VirtIODMATest *dmate)
{
    int i;

    if (!dmate->vhost) {
        return;
    }

    for (i = 0; i < dmate->num_queues; i++) {
        vhost_dev_cleanup(&dmate->vhost->queues[i].dev);
    }

    g_free(dmate->vhost->queues);
    g_free(dmate->vhost);
    dmate->vhost = NULL;
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

    vhost_dmatest_cleanup(dmate);

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

    f |= dmate->features;

    if (dmate->vhost) {
        /* All queues have the same feature set */
        assert(dmate->num_queues > 0);
        f = vhost_get_features(&dmate->vhost->queues[0].dev,
                               vhost_dmatest_feature_bits, f);
    }
    return f;
}

static void virtio_dmatest_set_features(VirtIODevice *vdev, uint64_t features)
{
    int i;
    VirtIODMATest *dmate = VIRTIO_DMATEST(vdev);

    if (!dmate->vhost) {
        return;
    }

    for (i = 0; i < dmate->num_queues; i++) {
        vhost_ack_features(&dmate->vhost->queues[i].dev,
                           vhost_dmatest_feature_bits, features);
    }
}

static int vhost_dmatest_start(VirtIODMATest *dmate)
{
    int i;
    int ret;
    uint16_t nqueues = dmate->num_queues;
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(dmate)));
    VirtioBusState *vbus = VIRTIO_BUS(qbus);
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(vbus);
    VirtIODevice *vdev = VIRTIO_DEVICE(dmate);

    if (!k->set_guest_notifiers) {
        error_report("binding does not support guest notifiers");
        return -ENOSYS;
    }

    for (i = 0; i < nqueues; i++) {
        dmate->vhost->queues[i].dev.vq_index = i;
        dmate->vhost->queues[i].dev.vq_index_end = nqueues;
    }

    ret = k->set_guest_notifiers(qbus->parent, nqueues, true);
    if (ret < 0) {
        error_report("Error binding guest notifier: %d", -ret);
        return ret;
    }

    for (i = 0; i < nqueues; i++) {
        ret = vhost_dev_enable_notifiers(&dmate->vhost->queues[i].dev, vdev);
        if (ret) {
            goto err_clear_notifiers;
        }

        ret = vhost_dev_start(&dmate->vhost->queues[i].dev, vdev, false);
        if (ret) {
            vhost_dev_disable_notifiers(&dmate->vhost->queues[i].dev, vdev);
            goto err_disable;
        }
    }

    return 0;

err_disable:
    for (--i; i >= 0; --i) {
            vhost_dev_disable_notifiers(&dmate->vhost->queues[i].dev, vdev);
            vhost_dev_stop(&dmate->vhost->queues[i].dev, vdev, true);
    }
err_clear_notifiers:
    k->set_guest_notifiers(qbus->parent, nqueues, false);
    return ret;
}

static int vhost_dmatest_stop(VirtIODMATest *dmate)
{
    int i;
    BusState *qbus = BUS(qdev_get_parent_bus(DEVICE(dmate)));
    VirtioBusState *vbus = VIRTIO_BUS(qbus);
    VirtioBusClass *k = VIRTIO_BUS_GET_CLASS(vbus);
    VirtIODevice *vdev = VIRTIO_DEVICE(dmate);

    for (i = 0; i < dmate->num_queues; i++) {
            vhost_dev_disable_notifiers(&dmate->vhost->queues[i].dev, vdev);
            vhost_dev_stop(&dmate->vhost->queues[i].dev, vdev, true);
    }
    k->set_guest_notifiers(qbus->parent, dmate->num_queues, false);
    return 0;
}

static int vhost_dmatest_set_status(struct VirtIODMATest *dmate, uint8_t status)
{
    int i, ret;

    for (i = 0; i < dmate->num_queues; i++) {
        struct vhost_dev *hdev = &dmate->vhost->queues[i].dev;

        if (hdev->vhost_ops->vhost_set_status) {
            ret = hdev->vhost_ops->vhost_set_status(hdev, status);
            if (ret) {
                error_report("Failed to set status: %d", ret);
            }
        }
    }
    return 0;
}

static int virtio_dmatest_set_status(VirtIODevice *vdev, uint8_t status)
{
    VirtIODMATest *dmate = VIRTIO_DMATEST(vdev);
    bool started = status & VIRTIO_CONFIG_S_DRIVER_OK;

    if (!dmate->vhost) {
        return 0;
    }

    if (dmate->vhost->started == started) {
        return 0;
    }

    if (!dmate->vhost->started) {
        int ret = vhost_dmatest_start(dmate);
        if (ret < 0) {
            vhost_dmatest_set_status(dmate, status & ~VIRTIO_CONFIG_S_DRIVER_OK);
            error_report("unable to start vhost dmatest: %d",  -ret);
            return ret;
        }
    } else {
        vhost_dmatest_stop(dmate);
    }

    int ret = vhost_dmatest_set_status(dmate, status);
    if (ret) {
        return ret;
    }

    dmate->vhost->started = started;
    return 0;
}

static void virtio_dmatest_guest_notifier_mask(VirtIODevice *vdev, int idx,
                                               bool mask)
{
    VirtIODMATest *dmate = VIRTIO_DMATEST(vdev);

    if (idx == VIRTIO_CONFIG_IRQ_IDX) {
        /* FIXME! */
        error_report("%s: unhandled", __func__);
        /* vhost_config_mask(&net->dev, dev, mask); */
        return;
    }

    if (idx >= dmate->num_queues) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: bogus vq index ignored\n", __func__);
        return;
    }
    vhost_virtqueue_mask(&dmate->vhost->queues[idx].dev, vdev, idx, mask);
}

static bool virtio_dmatest_guest_notifier_pending(VirtIODevice *vdev, int idx)
{
    VirtIODMATest *dmate = VIRTIO_DMATEST(vdev);

    if (idx == VIRTIO_CONFIG_IRQ_IDX) {
        /* FIXME! */
        error_report("%s: unhandled", __func__);
        /* vhost_config_mask(&net->dev, dev, mask); */
        return false;
    }

    if (idx >= dmate->num_queues) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: bogus vq index ignored\n", __func__);
        return false;
    }
    return vhost_virtqueue_pending(&dmate->vhost->queues[idx].dev, idx);
}

static void virtio_dmatest_instance_init(Object *obj)
{
}

static const Property virtio_dmatest_properties[] = {
    DEFINE_PROP_UINT16("num-queues", VirtIODMATest, num_queues, 1),
    DEFINE_PROP_BOOL("vhost", VirtIODMATest, use_vhost, false),
};

static void virtio_dmatest_class_init(ObjectClass *klass, const void *data)
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
    vdc->set_features = virtio_dmatest_set_features;
    vdc->set_status = virtio_dmatest_set_status;
    vdc->guest_notifier_mask = virtio_dmatest_guest_notifier_mask;
    vdc->guest_notifier_pending = virtio_dmatest_guest_notifier_pending;
    vdc->toggle_device_iotlb = vhost_toggle_device_iotlb;
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

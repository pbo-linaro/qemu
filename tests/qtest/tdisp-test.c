/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "hw/pci/pci.h"
#include "hw/pci/pcie_doe.h"
#include "libqos/qgraph.h"
#include "libqos/pci.h"

#ifndef LIBSPDM_HAL_PASS_SPDM_CONTEXT
#define LIBSPDM_HAL_PASS_SPDM_CONTEXT 1
#endif

/*< libspdm >*/
#include "industry_standard/spdm.h"
#include "hal/library/requester/reqasymsignlib.h"
#include "hal/library/responder/asymsignlib.h"
#include "hal/library/responder/csrlib.h"
#include "hal/library/responder/measlib.h"
#include "hal/library/responder/psklib.h"
#include "hal/library/responder/setcertlib.h"
#include "library/spdm_common_lib.h"
#include "library/spdm_requester_lib.h"
#include "library/spdm_transport_pcidoe_lib.h"

#define PCI_EXP_DOE 0x100
#define DATA_TRANSFER_SIZE_DEFAULT 0x1200
#define MAX_SPDM_MSG_SIZE_DEFAULT  0x1200

#define SENDER_BUFFER_SIZE (LIBSPDM_PCI_DOE_TRANSPORT_HEADER_SIZE \
        + DATA_TRANSFER_SIZE_DEFAULT \
        + LIBSPDM_PCI_DOE_TRANSPORT_TAIL_SIZE)

#define RECEIVER_BUFFER_SIZE (LIBSPDM_PCI_DOE_TRANSPORT_HEADER_SIZE \
        + DATA_TRANSFER_SIZE_DEFAULT \
        + LIBSPDM_PCI_DOE_TRANSPORT_TAIL_SIZE)

#define assert_libspdm_is_success(status) \
    g_assert_cmpuint(status, ==, LIBSPDM_STATUS_SUCCESS)

typedef struct QTDISPTestDev {
    QOSGraphObject obj;
    QPCIDevice dev;
    void *spdm_context;
    void *scratch_buffer;
    void *sender_buffer;
    void *receiver_buffer;
} QTDISPTestDev;

bool libspdm_requester_data_sign(
    void *spdm_context, spdm_version_number_t spdm_version, uint8_t op_code,
    uint16_t req_base_asym_alg, uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size, uint8_t *signature,
    size_t *sig_size)
{
    return false;
}

bool libspdm_encap_challenge_opaque_data(
    void *spdm_context, spdm_version_number_t spdm_version, uint8_t slot_id,
    uint8_t *measurement_summary_hash, size_t measurement_summary_hash_size,
    void *opaque_data, size_t *opaque_data_size)
{
    return false;
}

bool libspdm_challenge_opaque_data(
    void *spdm_context, spdm_version_number_t spdm_version, uint8_t slot_id,
    uint8_t *measurment_summary_hash, size_t measurement_summary_hash_size,
    void *opaque_data, size_t *opaque_data_size)
{
    return false;
}

bool libspdm_responder_data_sign(
    void *spdm_context, spdm_version_number_t spdm_version, uint8_t op_code,
    uint32_t base_asym_algo, uint32_t base_hash_algo, bool is_data_hash,
    const uint8_t *message, size_t message_size, uint8_t *signature,
    size_t *sig_size)
{
    return false;
}

bool libspdm_gen_csr(
    void *spdm_context, uint32_t base_hash_algo, uint32_t base_asym_algo,
    bool *need_reset, const void *request, size_t request_size,
    uint8_t *requester_info, size_t requester_info_length,
    uint8_t *opaque_data, uint16_t opaque_data_length, size_t *csr_len,
    uint8_t *csr_pointer, bool is_device_cert_model)
{
    return false;
}

bool libspdm_gen_csr_ex(
    void *spdm_context, uint32_t base_hash_algo, uint32_t base_asym_algo,
    bool *need_reset, const void *request, size_t request_size,
    uint8_t *requester_info, size_t requester_info_length,
    uint8_t *opaque_data, uint16_t opaque_data_length, size_t *csr_len,
    uint8_t *csr_pointer, uint8_t req_cert_model,
    uint8_t *req_csr_tracking_tag, uint8_t req_key_pair_id, bool overwrite)
{
    return false;
}

libspdm_return_t libspdm_measurement_collection(
    void *spdm_context, spdm_version_number_t spdm_version,
    uint8_t measurement_specification, uint32_t measurement_hash_algo,
    uint8_t measurement_index, uint8_t request_attribute,
    uint8_t *content_changed, uint8_t *measurements_count, void *measurements,
    size_t *measurements_size)
{
    return LIBSPDM_STATUS_UNSUPPORTED_CAP;
}

bool libspdm_measurement_opaque_data(
    void *spdm_context, spdm_version_number_t spdm_version,
    uint8_t measurement_specification, uint32_t measurement_hash_algo,
    uint8_t measurement_index, uint8_t request_attribute, void *opaque_data,
    size_t *opaque_data_size)
{
    return false;
}

bool libspdm_generate_measurement_summary_hash(
    void *spdm_context, spdm_version_number_t spdm_version,
    uint32_t base_hash_algo, uint8_t measurement_specification,
    uint32_t measurement_hash_algo, uint8_t measurement_summary_hash_type,
    uint8_t *measurement_summary_hash, uint32_t measurement_summary_hash_size)
{
    return false;
}

bool libspdm_psk_handshake_secret_hkdf_expand(
    spdm_version_number_t spdm_version, uint32_t base_hash_algo,
    const uint8_t *psk_hint, size_t psk_hint_size, const uint8_t *info,
    size_t info_size, uint8_t *out, size_t out_size)
{
    return false;
}

bool libspdm_psk_master_secret_hkdf_expand(
    spdm_version_number_t spdm_version, uint32_t base_hash_algo,
    const uint8_t *psk_hint, size_t psk_hint_size, const uint8_t *info,
    size_t info_size, uint8_t *out, size_t out_size)
{
    return false;
}

bool libspdm_is_in_trusted_environment(void *spdm_context)
{
    return false;
}

bool libspdm_write_certificate_to_nvm(
    void *spdm_context, uint8_t slot_id, const void *cert_chain,
    size_t cert_chain_size, uint32_t base_hash_algo,
    uint32_t base_asym_algo)
{
    return false;
}

static QTDISPTestDev *tdisp_testdev_get_from_context(void *spdm_context)
{
    libspdm_data_parameter_t parameter;
    libspdm_return_t status;
    void *dev = NULL;
    size_t data_size = sizeof(dev);
    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    status = libspdm_get_data(
        spdm_context, LIBSPDM_DATA_APP_CONTEXT_DATA, &parameter, &dev,
        &data_size);
    assert(LIBSPDM_STATUS_IS_SUCCESS(status));
    return dev;
}

static libspdm_return_t tdisp_testdev_acquire_sender_buffer(
    void *spdm_context, void **msg_buf_ptr)
{
    QTDISPTestDev *dev = tdisp_testdev_get_from_context(spdm_context);
    *msg_buf_ptr = dev->sender_buffer;
    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t tdisp_testdev_acquire_receiver_buffer(
    void *spdm_context, void **msg_buf_ptr)
{
    QTDISPTestDev *dev = tdisp_testdev_get_from_context(spdm_context);
    *msg_buf_ptr = dev->receiver_buffer;
    return LIBSPDM_STATUS_SUCCESS;
}

static void tdisp_testdev_release_buffer(
    void *spdm_context, const void *msg_buf_ptr)
{
}

static libspdm_return_t tdisp_testdev_send_message(
    void *spdm_context, size_t message_size, const void *message,
    uint64_t timeout)
{
    QTDISPTestDev *dev = tdisp_testdev_get_from_context(spdm_context);
    const uint32_t *data = message;
    uint32_t value;

    g_assert_cmpuint(message_size % sizeof(uint32_t), ==, 0);

    do {
        value = qpcie_config_readl(
            &dev->dev, PCI_EXP_DOE + PCI_EXP_DOE_STATUS);
    } while (FIELD_EX32(value, PCI_DOE_CAP_STATUS, DOE_BUSY));

    if (FIELD_EX32(value, PCI_DOE_CAP_STATUS, DOE_ERROR)) {
        return LIBSPDM_STATUS_SEND_FAIL;
    }

    for (size_t index; index < message_size / sizeof(uint32_t); ++index) {
        qpcie_config_writel(&dev->dev, PCI_EXP_DOE + PCI_EXP_DOE_WR_DATA_MBOX,
                            data[index]);
    }

    value = FIELD_DP32(0, PCI_DOE_CAP_CONTROL, DOE_GO, 1);
    qpcie_config_writel(&dev->dev, PCI_EXP_DOE + PCI_EXP_DOE_CTRL, value);
    return LIBSPDM_STATUS_SUCCESS;
}

static libspdm_return_t tdisp_testdev_receive_message(
    void *spdm_context, size_t *message_size, void **message, uint64_t timeout)
{
    QTDISPTestDev *dev = tdisp_testdev_get_from_context(spdm_context);
    uint32_t *data = *message;
    uint32_t value;
    size_t index, length;

    g_assert_cmpuint(*message_size, >=, sizeof(DOEHeader));

    do {
        value = qpcie_config_readl(
            &dev->dev, PCI_EXP_DOE + PCI_EXP_DOE_STATUS);

        if (FIELD_EX32(value, PCI_DOE_CAP_STATUS, DOE_ERROR)) {
            return LIBSPDM_STATUS_RECEIVE_FAIL;
        }
    } while (!FIELD_EX32(value, PCI_DOE_CAP_STATUS, DATA_OBJ_RDY));

    for (index = 0; index < sizeof(DOEHeader) / sizeof(uint32_t); ++index) {
        if (!FIELD_EX32(value, PCI_DOE_CAP_STATUS, DATA_OBJ_RDY)) {
            *message_size = index * sizeof(uint32_t);
            return FIELD_EX32(value, PCI_DOE_CAP_STATUS, DOE_ERROR) ?
                LIBSPDM_STATUS_RECEIVE_FAIL : LIBSPDM_STATUS_SUCCESS;
        }

        data[index] = qpcie_config_readl(&dev->dev, PCI_EXP_DOE +
                                         PCI_EXP_DOE_RD_DATA_MBOX);
        qpcie_config_writel(
            &dev->dev, PCI_EXP_DOE + PCI_EXP_DOE_RD_DATA_MBOX, 0);
        value = qpcie_config_readl(
            &dev->dev, PCI_EXP_DOE + PCI_EXP_DOE_STATUS);
    }

    length = pcie_doe_data_object_length_in_dword((DOEHeader *)data);
    length = MIN(length, *message_size / sizeof(uint32_t));

    for (; index < length; ++index) {
        if (!FIELD_EX32(value, PCI_DOE_CAP_STATUS, DATA_OBJ_RDY)) {
            break;
        }

        data[index] = qpcie_config_readl(&dev->dev, PCI_EXP_DOE +
                                         PCI_EXP_DOE_RD_DATA_MBOX);
        qpcie_config_writel(
            &dev->dev, PCI_EXP_DOE + PCI_EXP_DOE_RD_DATA_MBOX, 0);
        value = qpcie_config_readl(
            &dev->dev, PCI_EXP_DOE + PCI_EXP_DOE_STATUS);
    }

    *message_size = index * sizeof(uint32_t);

    return FIELD_EX32(value, PCI_DOE_CAP_STATUS, DOE_ERROR) ?
        LIBSPDM_STATUS_RECEIVE_FAIL : LIBSPDM_STATUS_SUCCESS;
}

static void tdisp_testdev_pci_bus_init(QPCIBus *root_bus, uint32_t busnr)
{
    QPCIDevice *dev;
    uint8_t secondary_bus;

    for (int devnr = 0; devnr < 32; ++devnr) {
        dev = qpci_device_find(root_bus, QPCI_DEVFN(busnr << 5 | devnr, 0));

        if (!dev) {
            continue;
        }

        if (qpci_config_readw(dev, PCI_CLASS_DEVICE) != PCI_CLASS_BRIDGE_PCI) {
            g_free(dev);
            continue;
        }

        qpci_device_enable(dev);
        secondary_bus = qpci_config_readb(dev, PCI_SECONDARY_BUS);
        tdisp_testdev_pci_bus_init(root_bus, secondary_bus);
        g_free(dev);
    }
}

static void tdisp_testdev_pci_init(
    QPCIDevice *dev, QPCIBus *root_bus, QPCIAddress *addr)
{
    int last_bus = qpci_secondary_buses_init(root_bus);
    addr->devfn |= last_bus << 8;

    tdisp_testdev_pci_bus_init(root_bus, 0);
    qpci_device_init(dev, root_bus, addr);
    qpci_device_enable(dev);
}

static void tdisp_testdev_spdm_init(QTDISPTestDev *dev)
{
    libspdm_data_parameter_t parameter;
    size_t scratch_buffer_size;

    dev->spdm_context = g_malloc(libspdm_get_context_size());
    assert_libspdm_is_success(libspdm_init_context(dev->spdm_context));

    dev->sender_buffer = g_malloc0(SENDER_BUFFER_SIZE);
    dev->receiver_buffer = g_malloc0(RECEIVER_BUFFER_SIZE);
    libspdm_register_device_io_func(dev->spdm_context,
        tdisp_testdev_send_message,
        tdisp_testdev_receive_message);
    libspdm_register_transport_layer_func(dev->spdm_context,
        0x1200,
        LIBSPDM_PCI_DOE_TRANSPORT_HEADER_SIZE,
        LIBSPDM_PCI_DOE_TRANSPORT_TAIL_SIZE,
        libspdm_transport_pci_doe_encode_message,
        libspdm_transport_pci_doe_decode_message);
    libspdm_register_device_buffer_func(dev->spdm_context,
        SENDER_BUFFER_SIZE, RECEIVER_BUFFER_SIZE,
        tdisp_testdev_acquire_sender_buffer,
        tdisp_testdev_release_buffer,
        tdisp_testdev_acquire_receiver_buffer,
        tdisp_testdev_release_buffer);

    scratch_buffer_size =
        libspdm_get_sizeof_required_scratch_buffer(dev->spdm_context);
    dev->scratch_buffer = g_malloc0(scratch_buffer_size);
    libspdm_set_scratch_buffer(dev->spdm_context, dev->scratch_buffer,
        scratch_buffer_size);

    parameter.location = LIBSPDM_DATA_LOCATION_LOCAL;
    assert_libspdm_is_success(libspdm_set_data(dev->spdm_context,
        LIBSPDM_DATA_APP_CONTEXT_DATA, &parameter, &dev, sizeof(dev)));
    g_assert_true(libspdm_check_context(dev->spdm_context));
}

static void tdisp_testdev_destructor(QOSGraphObject *obj)
{
    QTDISPTestDev *dev = (QTDISPTestDev *)obj;
    libspdm_deinit_context(dev->spdm_context);
    g_free(dev->spdm_context);
    g_free(dev->scratch_buffer);
    g_free(dev->sender_buffer);
    g_free(dev->receiver_buffer);
}

static void *tdisp_testdev_create(
    void *pci_bus, QGuestAllocator *alloc, void *addr)
{
    QTDISPTestDev *tdisp = g_new0(QTDISPTestDev, 1);

    tdisp_testdev_pci_init(&tdisp->dev, pci_bus, addr);
    tdisp_testdev_spdm_init(tdisp);

    tdisp->obj.destructor = tdisp_testdev_destructor;
    return &tdisp->obj;
}

/* Test GET_VERSION, GET_CAPABILITIES, and NEGOTIATE_ALGORITHM. */
static void tdisp_testdev_get_vca(
    void *obj, void *data, QGuestAllocator *alloc)
{
    QTDISPTestDev *tdisp = obj;
    libspdm_data_parameter_t parameter = {
        .location = LIBSPDM_DATA_LOCATION_CONNECTION,
    };
    libspdm_connection_state_t connection_state;
    size_t size = sizeof(connection_state);
    uint32_t value;

    qpci_device_enable(&tdisp->dev);
    assert_libspdm_is_success(
        libspdm_get_data(tdisp->spdm_context, LIBSPDM_DATA_CONNECTION_STATE,
            &parameter, &connection_state, &size));
    g_assert_cmpuint(
        connection_state, ==, LIBSPDM_CONNECTION_STATE_NOT_STARTED);

    assert_libspdm_is_success(
        libspdm_init_connection(tdisp->spdm_context, false));
    value = qpcie_config_readw(&tdisp->dev, PCI_EXP_DOE + PCI_EXP_DOE_STATUS);
    g_assert_false(FIELD_EX32(value, PCI_DOE_CAP_STATUS, DATA_OBJ_RDY));
    g_assert_false(FIELD_EX32(value, PCI_DOE_CAP_STATUS, DOE_ERROR));

    assert_libspdm_is_success(
        libspdm_get_data(tdisp->spdm_context, LIBSPDM_DATA_CONNECTION_STATE,
                         &parameter, &connection_state, &size));
    g_assert_cmpuint(
        connection_state, ==, LIBSPDM_CONNECTION_STATE_NEGOTIATED);
}

static void tdisp_testdev_authenticate(
    void *obj, void *data, QGuestAllocator *alloc)
{
    QTDISPTestDev *tdisp = obj;
    uint8_t slot_mask;
    uint8_t total_digest_buffer[LIBSPDM_MAX_HASH_SIZE * SPDM_MAX_SLOT_COUNT];

    qpci_device_enable(&tdisp->dev);
    assert_libspdm_is_success(libspdm_init_connection(
        tdisp->spdm_context, false));
    assert_libspdm_is_success(libspdm_get_digest(
        tdisp->spdm_context, NULL, &slot_mask, total_digest_buffer));
}

static void tdisp_testdev_register_driver(void)
{
    QOSGraphEdgeOptions opts = {
        .before_cmd_line = "-device pcie-root-port,id=pcie.1",
        .extra_device_opts = "bus=pcie.1,addr=00.0,spdm-responder=spdm.0",
        .after_cmd_line = "-object spdm-responder-libspdm,id=spdm.0",
    };
    QPCIAddress addr = {
        .devfn = QPCI_DEVFN(0 , 0),
        .vendor_id = PCI_VENDOR_ID_QEMU,
        .device_id = 0x11e9,
    };

    add_qpci_address(&opts, &addr);

    qos_node_create_driver("tdisp-testdev", tdisp_testdev_create);
    qos_node_consumes("tdisp-testdev", "pcie-bus", &opts);
}

static void tdisp_testdev_register_tests(void)
{
    qos_add_test("get-vca", "tdisp-testdev", tdisp_testdev_get_vca, NULL);
    qos_add_test(
        "authenticate", "tdisp-testdev", tdisp_testdev_authenticate, NULL);
}

libqos_init(tdisp_testdev_register_driver);
libqos_init(tdisp_testdev_register_tests);

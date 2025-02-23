/*
 * i.MX 8M Plus SoC Definitions
 *
 * Copyright (c) 2024, Bernhard Beschow <shentey@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FSL_IMX8MP_H
#define FSL_IMX8MP_H

#include "cpu.h"
#include "hw/char/imx_serial.h"
#include "hw/intc/arm_gicv3_common.h"
#include "qom/object.h"
#include "qemu/units.h"

#define TYPE_FSL_IMX8MP "fsl-imx8mp"
OBJECT_DECLARE_SIMPLE_TYPE(FslImx8mpState, FSL_IMX8MP)

#define FSL_IMX8MP_RAM_START        0x40000000
#define FSL_IMX8MP_RAM_SIZE_MAX     (8 * GiB)

enum FslImx8mpConfiguration {
    FSL_IMX8MP_NUM_CPUS         = 4,
    FSL_IMX8MP_NUM_IRQS         = 160,
    FSL_IMX8MP_NUM_UARTS        = 4,
};

struct FslImx8mpState {
    DeviceState    parent_obj;

    ARMCPU             cpu[FSL_IMX8MP_NUM_CPUS];
    GICv3State         gic;
    IMXSerialState     uart[FSL_IMX8MP_NUM_UARTS];
};

enum FslImx8mpMemoryRegions {
    FSL_IMX8MP_A53_DAP,
    FSL_IMX8MP_AIPS1_CONFIGURATION,
    FSL_IMX8MP_AIPS2_CONFIGURATION,
    FSL_IMX8MP_AIPS3_CONFIGURATION,
    FSL_IMX8MP_AIPS4_CONFIGURATION,
    FSL_IMX8MP_AIPS5_CONFIGURATION,
    FSL_IMX8MP_ANA_OSC,
    FSL_IMX8MP_ANA_PLL,
    FSL_IMX8MP_ANA_TSENSOR,
    FSL_IMX8MP_APBH_DMA,
    FSL_IMX8MP_ASRC,
    FSL_IMX8MP_AUDIO_BLK_CTRL,
    FSL_IMX8MP_AUDIO_DSP,
    FSL_IMX8MP_AUDIO_XCVR_RX,
    FSL_IMX8MP_AUD_IRQ_STEER,
    FSL_IMX8MP_BOOT_ROM,
    FSL_IMX8MP_BOOT_ROM_PROTECTED,
    FSL_IMX8MP_CAAM,
    FSL_IMX8MP_CAAM_MEM,
    FSL_IMX8MP_CCM,
    FSL_IMX8MP_CSU,
    FSL_IMX8MP_DDR_BLK_CTRL,
    FSL_IMX8MP_DDR_CTL,
    FSL_IMX8MP_DDR_PERF_MON,
    FSL_IMX8MP_DDR_PHY,
    FSL_IMX8MP_DDR_PHY_BROADCAST,
    FSL_IMX8MP_ECSPI1,
    FSL_IMX8MP_ECSPI2,
    FSL_IMX8MP_ECSPI3,
    FSL_IMX8MP_EDMA_CHANNELS,
    FSL_IMX8MP_EDMA_MANAGEMENT_PAGE,
    FSL_IMX8MP_ENET1,
    FSL_IMX8MP_ENET2_TSN,
    FSL_IMX8MP_FLEXCAN1,
    FSL_IMX8MP_FLEXCAN2,
    FSL_IMX8MP_GIC_DIST,
    FSL_IMX8MP_GIC_REDIST,
    FSL_IMX8MP_GPC,
    FSL_IMX8MP_GPIO1,
    FSL_IMX8MP_GPIO2,
    FSL_IMX8MP_GPIO3,
    FSL_IMX8MP_GPIO4,
    FSL_IMX8MP_GPIO5,
    FSL_IMX8MP_GPT1,
    FSL_IMX8MP_GPT2,
    FSL_IMX8MP_GPT3,
    FSL_IMX8MP_GPT4,
    FSL_IMX8MP_GPT5,
    FSL_IMX8MP_GPT6,
    FSL_IMX8MP_GPU2D,
    FSL_IMX8MP_GPU3D,
    FSL_IMX8MP_HDMI_TX,
    FSL_IMX8MP_HDMI_TX_AUDLNK_MSTR,
    FSL_IMX8MP_HSIO_BLK_CTL,
    FSL_IMX8MP_I2C1,
    FSL_IMX8MP_I2C2,
    FSL_IMX8MP_I2C3,
    FSL_IMX8MP_I2C4,
    FSL_IMX8MP_I2C5,
    FSL_IMX8MP_I2C6,
    FSL_IMX8MP_INTERCONNECT,
    FSL_IMX8MP_IOMUXC,
    FSL_IMX8MP_IOMUXC_GPR,
    FSL_IMX8MP_IPS_DEWARP,
    FSL_IMX8MP_ISI,
    FSL_IMX8MP_ISP1,
    FSL_IMX8MP_ISP2,
    FSL_IMX8MP_LCDIF1,
    FSL_IMX8MP_LCDIF2,
    FSL_IMX8MP_MEDIA_BLK_CTL,
    FSL_IMX8MP_MIPI_CSI1,
    FSL_IMX8MP_MIPI_CSI2,
    FSL_IMX8MP_MIPI_DSI1,
    FSL_IMX8MP_MU_1_A,
    FSL_IMX8MP_MU_1_B,
    FSL_IMX8MP_MU_2_A,
    FSL_IMX8MP_MU_2_B,
    FSL_IMX8MP_MU_3_A,
    FSL_IMX8MP_MU_3_B,
    FSL_IMX8MP_NPU,
    FSL_IMX8MP_OCOTP_CTRL,
    FSL_IMX8MP_OCRAM,
    FSL_IMX8MP_OCRAM_S,
    FSL_IMX8MP_PCIE1,
    FSL_IMX8MP_PCIE1_MEM,
    FSL_IMX8MP_PCIE_PHY1,
    FSL_IMX8MP_PDM,
    FSL_IMX8MP_PERFMON1,
    FSL_IMX8MP_PERFMON2,
    FSL_IMX8MP_PWM1,
    FSL_IMX8MP_PWM2,
    FSL_IMX8MP_PWM3,
    FSL_IMX8MP_PWM4,
    FSL_IMX8MP_QOSC,
    FSL_IMX8MP_QSPI,
    FSL_IMX8MP_QSPI1_RX_BUFFER,
    FSL_IMX8MP_QSPI1_TX_BUFFER,
    FSL_IMX8MP_QSPI_MEM,
    FSL_IMX8MP_RAM,
    FSL_IMX8MP_RDC,
    FSL_IMX8MP_SAI1,
    FSL_IMX8MP_SAI2,
    FSL_IMX8MP_SAI3,
    FSL_IMX8MP_SAI5,
    FSL_IMX8MP_SAI6,
    FSL_IMX8MP_SAI7,
    FSL_IMX8MP_SDMA1,
    FSL_IMX8MP_SDMA2,
    FSL_IMX8MP_SDMA3,
    FSL_IMX8MP_SEMAPHORE1,
    FSL_IMX8MP_SEMAPHORE2,
    FSL_IMX8MP_SEMAPHORE_HS,
    FSL_IMX8MP_SNVS_HP,
    FSL_IMX8MP_SPBA1,
    FSL_IMX8MP_SPBA2,
    FSL_IMX8MP_SRC,
    FSL_IMX8MP_SYSCNT_CMP,
    FSL_IMX8MP_SYSCNT_CTRL,
    FSL_IMX8MP_SYSCNT_RD,
    FSL_IMX8MP_TCM_DTCM,
    FSL_IMX8MP_TCM_ITCM,
    FSL_IMX8MP_TZASC,
    FSL_IMX8MP_UART1,
    FSL_IMX8MP_UART2,
    FSL_IMX8MP_UART3,
    FSL_IMX8MP_UART4,
    FSL_IMX8MP_USB1,
    FSL_IMX8MP_USB2,
    FSL_IMX8MP_USDHC1,
    FSL_IMX8MP_USDHC2,
    FSL_IMX8MP_USDHC3,
    FSL_IMX8MP_VPU,
    FSL_IMX8MP_VPU_BLK_CTRL,
    FSL_IMX8MP_VPU_G1_DECODER,
    FSL_IMX8MP_VPU_G2_DECODER,
    FSL_IMX8MP_VPU_VC8000E_ENCODER,
    FSL_IMX8MP_WDOG1,
    FSL_IMX8MP_WDOG2,
    FSL_IMX8MP_WDOG3,
};

enum FslImx8mpIrqs {
    FSL_IMX8MP_UART1_IRQ    = 26,
    FSL_IMX8MP_UART2_IRQ    = 27,
    FSL_IMX8MP_UART3_IRQ    = 28,
    FSL_IMX8MP_UART4_IRQ    = 29,
    FSL_IMX8MP_UART5_IRQ    = 30,
    FSL_IMX8MP_UART6_IRQ    = 16,
};

#endif /* FSL_IMX8MP_H */

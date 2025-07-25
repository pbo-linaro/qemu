/*
 * Target-specific parts of semihosting/arm-compat-semi.c.
 *
 * Copyright (c) 2005, 2007 CodeSourcery.
 * Copyright (c) 2019, 2022 Linaro
 * Copyright © 2020 by Keith Packard <keithp@keithp.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "cpu.h"

static inline uint64_t common_semi_arg(CPUState *cs, int argno)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    return env->gpr[xA0 + argno];
}

static inline void common_semi_set_ret(CPUState *cs, uint64_t ret)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    env->gpr[xA0] = ret;
}

static inline bool is_64bit_semihosting(CPUArchState *env)
{
    return riscv_cpu_mxl(env) != MXL_RV32;
}

static inline uint64_t common_semi_stack_bottom(CPUState *cs)
{
    RISCVCPU *cpu = RISCV_CPU(cs);
    CPURISCVState *env = &cpu->env;
    return env->gpr[xSP];
}

static inline bool common_semi_has_synccache(CPUArchState *env)
{
    return true;
}

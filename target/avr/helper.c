/*
 * QEMU AVR CPU helpers
 *
 * Copyright (c) 2016-2020 Michael Rolnik
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
 * License along with this library; if not, see
 * <http://www.gnu.org/licenses/lgpl-2.1.html>
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "cpu.h"
#include "accel/tcg/cpu-ops.h"
#include "exec/cputlb.h"
#include "exec/page-protection.h"
#include "exec/cpu_ldst.h"
#include "exec/target_page.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "exec/helper-proto.h"
#include "qemu/plugin.h"

bool avr_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    CPUAVRState *env = cpu_env(cs);

    /*
     * We cannot separate a skip from the next instruction,
     * as the skip would not be preserved across the interrupt.
     * Separating the two insn normally only happens at page boundaries.
     */
    if (env->skip) {
        return false;
    }

    if (interrupt_request & CPU_INTERRUPT_RESET) {
        if (cpu_interrupts_enabled(env)) {
            cs->exception_index = EXCP_RESET;
            avr_cpu_do_interrupt(cs);

            cs->interrupt_request &= ~CPU_INTERRUPT_RESET;
            return true;
        }
    }
    if (interrupt_request & CPU_INTERRUPT_HARD) {
        if (cpu_interrupts_enabled(env) && env->intsrc != 0) {
            int index = ctz64(env->intsrc);
            cs->exception_index = EXCP_INT(index);
            avr_cpu_do_interrupt(cs);

            env->intsrc &= env->intsrc - 1; /* clear the interrupt */
            if (!env->intsrc) {
                cs->interrupt_request &= ~CPU_INTERRUPT_HARD;
            }
            return true;
        }
    }
    return false;
}

void avr_cpu_do_interrupt(CPUState *cs)
{
    CPUAVRState *env = cpu_env(cs);

    uint32_t ret = env->pc_w;
    int vector = 0;
    int size = avr_feature(env, AVR_FEATURE_JMP_CALL) ? 2 : 1;
    int base = 0;

    if (cs->exception_index == EXCP_RESET) {
        vector = 0;
    } else if (env->intsrc != 0) {
        vector = ctz64(env->intsrc) + 1;
    }

    if (avr_feature(env, AVR_FEATURE_3_BYTE_PC)) {
        cpu_stb_data(env, env->sp--, (ret & 0x0000ff));
        cpu_stb_data(env, env->sp--, (ret & 0x00ff00) >> 8);
        cpu_stb_data(env, env->sp--, (ret & 0xff0000) >> 16);
    } else if (avr_feature(env, AVR_FEATURE_2_BYTE_PC)) {
        cpu_stb_data(env, env->sp--, (ret & 0x0000ff));
        cpu_stb_data(env, env->sp--, (ret & 0x00ff00) >> 8);
    } else {
        cpu_stb_data(env, env->sp--, (ret & 0x0000ff));
    }

    env->pc_w = base + vector * size;
    env->sregI = 0; /* clear Global Interrupt Flag */

    cs->exception_index = -1;

    qemu_plugin_vcpu_interrupt_cb(cs, ret, env->pc_w);
}

hwaddr avr_cpu_get_phys_page_debug(CPUState *cs, vaddr addr)
{
    return addr; /* I assume 1:1 address correspondence */
}

bool avr_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                      MMUAccessType access_type, int mmu_idx,
                      bool probe, uintptr_t retaddr)
{
    int prot, page_size = TARGET_PAGE_SIZE;
    uint32_t paddr;

    address &= TARGET_PAGE_MASK;

    if (mmu_idx == MMU_CODE_IDX) {
        /* Access to code in flash. */
        paddr = OFFSET_CODE + address;
        prot = PAGE_READ | PAGE_EXEC;
        if (paddr >= OFFSET_DATA) {
            /*
             * This should not be possible via any architectural operations.
             * There is certainly not an exception that we can deliver.
             * Accept probing that might come from generic code.
             */
            if (probe) {
                return false;
            }
            error_report("execution left flash memory");
            abort();
        }
    } else {
        /* Access to memory. */
        paddr = OFFSET_DATA + address;
        prot = PAGE_READ | PAGE_WRITE;
        if (address < NUMBER_OF_CPU_REGISTERS + NUMBER_OF_IO_REGISTERS) {
            /*
             * Access to CPU registers, exit and rebuilt this TB to use
             * full access in case it touches specially handled registers
             * like SREG or SP.  For probing, set page_size = 1, in order
             * to force tlb_fill to be called for the next access.
             */
            if (probe) {
                page_size = 1;
            } else {
                cpu_env(cs)->fullacc = 1;
                cpu_loop_exit_restore(cs, retaddr);
            }
        }
    }

    tlb_set_page(cs, address, paddr, prot, mmu_idx, page_size);
    return true;
}

/*
 *  helpers
 */

void helper_sleep(CPUAVRState *env)
{
    CPUState *cs = env_cpu(env);

    cs->exception_index = EXCP_HLT;
    cpu_loop_exit(cs);
}

void helper_unsupported(CPUAVRState *env)
{
    CPUState *cs = env_cpu(env);

    /*
     *  I count not find what happens on the real platform, so
     *  it's EXCP_DEBUG for meanwhile
     */
    cs->exception_index = EXCP_DEBUG;
    if (qemu_loglevel_mask(LOG_UNIMP)) {
        qemu_log("UNSUPPORTED\n");
        cpu_dump_state(cs, stderr, 0);
    }
    cpu_loop_exit(cs);
}

void helper_debug(CPUAVRState *env)
{
    CPUState *cs = env_cpu(env);

    cs->exception_index = EXCP_DEBUG;
    cpu_loop_exit(cs);
}

void helper_break(CPUAVRState *env)
{
    CPUState *cs = env_cpu(env);

    cs->exception_index = EXCP_DEBUG;
    cpu_loop_exit(cs);
}

void helper_wdr(CPUAVRState *env)
{
    qemu_log_mask(LOG_UNIMP, "WDG reset (not implemented)\n");
}

/*
 * This function implements IN instruction
 *
 * It does the following
 * a.  if an IO register belongs to CPU, its value is read and returned
 * b.  otherwise io address is translated to mem address and physical memory
 *     is read.
 * c.  it caches the value for sake of SBI, SBIC, SBIS & CBI implementation
 *
 */
target_ulong helper_inb(CPUAVRState *env, uint32_t port)
{
    target_ulong data = 0;

    switch (port) {
    case 0x38: /* RAMPD */
        data = 0xff & (env->rampD >> 16);
        break;
    case 0x39: /* RAMPX */
        data = 0xff & (env->rampX >> 16);
        break;
    case 0x3a: /* RAMPY */
        data = 0xff & (env->rampY >> 16);
        break;
    case 0x3b: /* RAMPZ */
        data = 0xff & (env->rampZ >> 16);
        break;
    case 0x3c: /* EIND */
        data = 0xff & (env->eind >> 16);
        break;
    case 0x3d: /* SPL */
        data = env->sp & 0x00ff;
        break;
    case 0x3e: /* SPH */
        data = env->sp >> 8;
        break;
    case 0x3f: /* SREG */
        data = cpu_get_sreg(env);
        break;
    default:
        /* not a special register, pass to normal memory access */
        data = address_space_ldub(&address_space_memory,
                                  OFFSET_IO_REGISTERS + port,
                                  MEMTXATTRS_UNSPECIFIED, NULL);
    }

    return data;
}

/*
 *  This function implements OUT instruction
 *
 *  It does the following
 *  a.  if an IO register belongs to CPU, its value is written into the register
 *  b.  otherwise io address is translated to mem address and physical memory
 *      is written.
 *  c.  it caches the value for sake of SBI, SBIC, SBIS & CBI implementation
 *
 */
void helper_outb(CPUAVRState *env, uint32_t port, uint32_t data)
{
    data &= 0x000000ff;

    switch (port) {
    case 0x38: /* RAMPD */
        if (avr_feature(env, AVR_FEATURE_RAMPD)) {
            env->rampD = (data & 0xff) << 16;
        }
        break;
    case 0x39: /* RAMPX */
        if (avr_feature(env, AVR_FEATURE_RAMPX)) {
            env->rampX = (data & 0xff) << 16;
        }
        break;
    case 0x3a: /* RAMPY */
        if (avr_feature(env, AVR_FEATURE_RAMPY)) {
            env->rampY = (data & 0xff) << 16;
        }
        break;
    case 0x3b: /* RAMPZ */
        if (avr_feature(env, AVR_FEATURE_RAMPZ)) {
            env->rampZ = (data & 0xff) << 16;
        }
        break;
    case 0x3c: /* EIDN */
        env->eind = (data & 0xff) << 16;
        break;
    case 0x3d: /* SPL */
        env->sp = (env->sp & 0xff00) | (data);
        break;
    case 0x3e: /* SPH */
        if (avr_feature(env, AVR_FEATURE_2_BYTE_SP)) {
            env->sp = (env->sp & 0x00ff) | (data << 8);
        }
        break;
    case 0x3f: /* SREG */
        cpu_set_sreg(env, data);
        break;
    default:
        /* not a special register, pass to normal memory access */
        address_space_stb(&address_space_memory, OFFSET_IO_REGISTERS + port,
                          data, MEMTXATTRS_UNSPECIFIED, NULL);
    }
}

/*
 *  this function implements LD instruction when there is a possibility to read
 *  from a CPU register
 */
target_ulong helper_fullrd(CPUAVRState *env, uint32_t addr)
{
    uint8_t data;

    env->fullacc = false;

    if (addr < NUMBER_OF_CPU_REGISTERS) {
        /* CPU registers */
        data = env->r[addr];
    } else if (addr < NUMBER_OF_CPU_REGISTERS + NUMBER_OF_IO_REGISTERS) {
        /* IO registers */
        data = helper_inb(env, addr - NUMBER_OF_CPU_REGISTERS);
    } else {
        /* memory */
        data = address_space_ldub(&address_space_memory, OFFSET_DATA + addr,
                                  MEMTXATTRS_UNSPECIFIED, NULL);
    }
    return data;
}

/*
 *  this function implements ST instruction when there is a possibility to write
 *  into a CPU register
 */
void helper_fullwr(CPUAVRState *env, uint32_t data, uint32_t addr)
{
    env->fullacc = false;

    /* Following logic assumes this: */
    assert(OFFSET_CPU_REGISTERS == OFFSET_DATA);
    assert(OFFSET_IO_REGISTERS == OFFSET_CPU_REGISTERS +
                                  NUMBER_OF_CPU_REGISTERS);

    if (addr < NUMBER_OF_CPU_REGISTERS) {
        /* CPU registers */
        env->r[addr] = data;
    } else if (addr < NUMBER_OF_CPU_REGISTERS + NUMBER_OF_IO_REGISTERS) {
        /* IO registers */
        helper_outb(env, addr - NUMBER_OF_CPU_REGISTERS, data);
    } else {
        /* memory */
        address_space_stb(&address_space_memory, OFFSET_DATA + addr, data,
                          MEMTXATTRS_UNSPECIFIED, NULL);
    }
}

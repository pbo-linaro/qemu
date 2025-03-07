/*
 * Get host pc for helper unwinding.
 *
 * Copyright (c) 2003 Fabrice Bellard
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#ifndef HELPER_GETPC_H
#define HELPER_GETPC_H

/* GETPC is the true target of the return instruction that we'll execute.  */
#if defined(CONFIG_TCG_INTERPRETER)
extern __thread uintptr_t tci_tb_ptr;
# define GETPC() tci_tb_ptr
#else
# define GETPC() \
    ((uintptr_t)__builtin_extract_return_addr(__builtin_return_address(0)))
#endif

/*
 * The true return address will often point to a host insn that is part of
 * the next translated guest insn.  Adjust the address backward to point to
 * the middle of the call insn.  Subtracting one would do the job except for
 * several compressed mode architectures (arm, mips) which set the low bit
 * to indicate the compressed mode; subtracting two works around that.  It
 * is also the case that there are no host isas that contain a call insn
 * smaller than 4 bytes, so we don't worry about special-casing this.
 */
#define GETPC_ADJ   2

#endif /* HELPER_GETPC_H */

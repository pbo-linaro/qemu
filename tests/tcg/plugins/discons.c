/*
 * Copyright (C) 2024, Julian Ganz <neither@nut.email>
 *
 * License: GNU GPL, version 2 or later.
 *   See the COPYING file in the top-level directory.
 */
#include <stdio.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

struct cpu_state {
    uint64_t next_pc;
    bool has_next;
};

static struct qemu_plugin_scoreboard *states;

static bool abort_on_mismatch;

static void vcpu_discon(qemu_plugin_id_t id, unsigned int vcpu_index,
                        enum qemu_plugin_discon_type type, uint64_t from_pc,
                        uint64_t to_pc)
{
    struct cpu_state *state = qemu_plugin_scoreboard_find(states, vcpu_index);
    state->next_pc = to_pc;
    state->has_next = true;
}

static void insn_exec(unsigned int vcpu_index, void *userdata)
{
    struct cpu_state *state = qemu_plugin_scoreboard_find(states, vcpu_index);
    uint64_t pc = (uint64_t) userdata;
    GString *report;

    if (state->has_next) {
        if (state->next_pc != pc) {
            report = g_string_new("Trap target PC mismatch\n");
            g_string_append_printf(report,
                                   "Expected:    %"PRIx64"\nEncountered: %"
                                   PRIx64"\n",
                                   state->next_pc, pc);
            qemu_plugin_outs(report->str);
            if (abort_on_mismatch) {
                g_abort();
            }
            g_string_free(report, true);
        }
        state->has_next = false;
    }
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t i;
    size_t n_insns = qemu_plugin_tb_n_insns(tb);

    g_autoptr(GString) s = g_string_new("");
    uint64_t vaddr = qemu_plugin_tb_vaddr(tb);
    g_string_append_printf(s, "translate 0x%"PRIx64", %"PRIu64" insn\n", vaddr, n_insns);
    qemu_plugin_outs(s->str);

    for (i = 0; i < n_insns; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uint64_t pc = qemu_plugin_insn_vaddr(insn);
        qemu_plugin_register_vcpu_insn_exec_cb(insn, insn_exec,
                                               QEMU_PLUGIN_CB_NO_REGS,
                                               (void *) pc);
    }
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    int i;

    for (i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);
        if (g_strcmp0(tokens[0], "abort") == 0) {
            if (!qemu_plugin_bool_parse(tokens[0], tokens[1], &abort_on_mismatch)) {
                fprintf(stderr, "boolean argument parsing failed: %s\n", opt);
                return -1;
            }
        } else {
            fprintf(stderr, "option parsing failed: %s\n", opt);
            return -1;
        }
    }

    states = qemu_plugin_scoreboard_new(sizeof(struct cpu_state));

    qemu_plugin_register_vcpu_discon_cb(id, QEMU_PLUGIN_DISCON_ALL,
                                        vcpu_discon);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);

    return 0;
}

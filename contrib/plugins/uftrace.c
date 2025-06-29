#include <qemu-plugin.h>
#include <glib.h>
#include <stdio.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

typedef struct {
    GArray* s;
} call_stack;

typedef struct {
    uint64_t pc;
    uint64_t frame_pointer;
} call_stack_entry;

static struct qemu_plugin_register *reg_fp;
static struct qemu_plugin_register *reg_lr;
static struct qemu_plugin_register *reg_cpsr;
static GByteArray *buf;
uint64_t last_lr;
call_stack *cs_el0;
call_stack *cs_el1;
call_stack *cs_el2;
call_stack *cs_el3;
static GArray *trace_el0;
static GArray *trace_el1;
static GArray *trace_el2;
static GArray *trace_el3;
static struct qemu_plugin_scoreboard *score;
static qemu_plugin_u64 insn_count;
static uint8_t current_el;

typedef struct {
    uint64_t timestamp;
    uint64_t data;
} uftrace_entry;

enum uftrace_record_type {
	UFTRACE_ENTRY,
	UFTRACE_EXIT,
	UFTRACE_LOST,
	UFTRACE_EVENT,
};

#define RECORD_MAGIC_V4 0x5
#define RECORD_MAGIC RECORD_MAGIC_V4

static call_stack *get_cs(uint8_t el)
{
    switch (el) {
    case 0: return cs_el0;
    case 1: return cs_el1;
    case 2: return cs_el2;
    case 3: return cs_el3;
    default: g_assert_not_reached();
    }
}

static GArray *get_trace(uint8_t el)
{
    return trace_el0; /* TODO: merge all data in el0 */
    switch (el) {
    case 0: return trace_el0;
    case 1: return trace_el1;
    case 2: return trace_el2;
    case 3: return trace_el3;
    default: g_assert_not_reached();
    }
}

static call_stack *call_stack_new(void)
{
    call_stack *cs = g_malloc0(sizeof(call_stack));
    cs->s = g_array_new(false, false, sizeof(call_stack_entry));
    return cs;
}

static void call_stack_free(call_stack *cs)
{
    g_array_free(cs->s, true);
}

static size_t call_stack_depth(const call_stack *cs)
{
    return cs->s->len;
}

static size_t call_stack_empty(const call_stack *cs)
{
    return !cs->s->len;
}

static call_stack_entry call_stack_top(const call_stack *cs)
{
    if (call_stack_depth(cs) >= 1) {
        return g_array_index(cs->s, call_stack_entry, cs->s->len - 1);
    }
    return (call_stack_entry){};
}

static call_stack_entry call_stack_caller(const call_stack *cs)
{
    if (call_stack_depth(cs) >= 2) {
        return g_array_index(cs->s, call_stack_entry, cs->s->len - 2);
    }
    return (call_stack_entry){};
}

static void call_stack_push(call_stack *cs, call_stack_entry e)
{
    g_array_append_val(cs->s, e);
}

static call_stack_entry call_stack_pop(call_stack *cs)
{
    g_assert(!call_stack_empty(cs));
    call_stack_entry e = call_stack_top(cs);
    g_array_set_size(cs->s, call_stack_depth(cs) - 1);
    return e;
}

static uint64_t read_register64(struct qemu_plugin_register *reg)
{
    g_byte_array_set_size(buf, 0);
    size_t sz = qemu_plugin_read_register(reg, buf);
    g_assert(sz == 8);
    g_assert(buf->len == 8);
    return *((uint64_t *) buf->data);
}

static uint32_t read_register32(struct qemu_plugin_register *reg)
{
    g_byte_array_set_size(buf, 0);
    size_t sz = qemu_plugin_read_register(reg, buf);
    g_assert(sz == 4);
    g_assert(buf->len == 4);
    return *((uint32_t *) buf->data);
}

static uint64_t read_memory(uint64_t addr)
{
    g_byte_array_set_size(buf, 0);
    if (addr == 0) {
        return 0;
    }
    bool read = qemu_plugin_read_memory_vaddr(addr, buf, 8);
    if (!read) {
        return 0;
    }
    g_assert(buf->len == 8);
    return *((uint64_t *) buf->data);
}

static void add_entry(uint64_t timestamp, uint64_t pc,
                      enum uftrace_record_type type)
{
   /* libmcount/record.c:record_event */
    uint64_t data = type | RECORD_MAGIC << 3;
	data += call_stack_depth(get_cs(current_el)) << 6;
	data += pc << 16;
    uftrace_entry e = {.timestamp = timestamp, .data = data};
    g_array_append_val(get_trace(current_el), e);
}

static void enter_function(uint64_t timestamp, uint64_t pc)
{
    add_entry(timestamp, pc, UFTRACE_ENTRY);
}

static void exit_function(uint64_t timestamp, uint64_t pc)
{
    add_entry(timestamp, pc, UFTRACE_EXIT);
}


static void enter_stack(call_stack *cs, uint64_t frame_pointer, uint64_t pc,
                        uint64_t timestamp)
{
    if (pc == 0) {
        return;
    }
    if (frame_pointer) {
        uint64_t caller_fp = read_memory(frame_pointer);
        uint64_t caller_ret = read_memory(frame_pointer + 8);
        enter_stack(cs, caller_fp, caller_ret, timestamp);
    }
    call_stack_push(cs, (call_stack_entry) {.frame_pointer = frame_pointer,
                                            .pc = pc});
    enter_function(timestamp, pc);
    //fprintf(stderr, " %"PRIx64"", pc);
}

static void exit_stack(call_stack *cs, uint64_t timestamp)
{
    if (call_stack_empty(cs)) {
        return;
    }

    call_stack_entry e = call_stack_pop(cs);
    exit_stack(cs, timestamp);
    exit_function(timestamp, e.pc);
    //fprintf(stderr, " %"PRIx64"", e.pc);
}

static void insn_exec(unsigned int cpu_index, void *udata)
{
    uint64_t pc = (uintptr_t) udata;
    uint64_t timestamp = qemu_plugin_u64_get(insn_count, cpu_index);

    uint64_t fp = read_register64(reg_fp);
    uint8_t new_el = read_register32(reg_cpsr) >> 2 & 0b11;
    if (new_el != current_el) {
        exit_stack(get_cs(current_el), timestamp);
        current_el = new_el;
    }
    call_stack* cs = get_cs(new_el);

    call_stack_entry top = call_stack_top(cs);
    if (fp && fp == top.frame_pointer) {
        /* same context */
        return;
    }

    call_stack_entry caller = call_stack_caller(cs);
    if (fp && fp == caller.frame_pointer) {
        /* ret */
        call_stack_entry e = call_stack_pop(cs);
        exit_function(timestamp, e.pc);
        //fprintf(stderr, "EXIT %"PRIx64"\n", top.pc);
        return;
    }

    uint64_t caller_fp = read_memory(fp);
    uint64_t caller_caller_fp = read_memory(caller_fp);
    if (fp && caller_fp == top.frame_pointer &&
        caller_caller_fp == caller.frame_pointer) {
        /* call */
        call_stack_push(cs, (call_stack_entry){.frame_pointer = fp,
                                               .pc = pc}); 
        enter_function(timestamp, pc);
        //fprintf(stderr, "ENTER %"PRIx64"\n", pc);
        return;
    }

    /* discontinuity */
    //fprintf(stderr, "DISCON ");
    exit_stack(cs, timestamp);
    //fprintf(stderr, "\n");
    //fprintf(stderr, "NEW_STACK ");
    enter_stack(cs, fp, pc, timestamp);
    //fprintf(stderr, "\n");
}

static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    size_t n_insns = qemu_plugin_tb_n_insns(tb);

    for (int i = 0; i < n_insns; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        uintptr_t pc = qemu_plugin_insn_vaddr(insn);
        qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
            insn, QEMU_PLUGIN_INLINE_ADD_U64, insn_count, 1);
        qemu_plugin_register_vcpu_insn_exec_cb(insn, insn_exec, QEMU_PLUGIN_CB_R_REGS,
                                               (void *) pc);
    }

}

static void init_registers(void)
{
    g_autoptr(GArray) regs = qemu_plugin_get_registers();
    for (int i = 0; i < regs->len; ++i) {
        qemu_plugin_reg_descriptor *reg;
        reg = &g_array_index(regs, qemu_plugin_reg_descriptor, i);
        if (!strcmp(reg->name, "x29")) {
            reg_fp = reg->handle;
        } else if (!strcmp(reg->name, "x30")) {
            reg_lr = reg->handle;
        } else if (!strcmp(reg->name, "cpsr")) {
            reg_cpsr = reg->handle;
        }
    }
    if (!reg_fp || !reg_lr || !reg_cpsr) {
        fprintf(stderr, "this plugin works only on qemu-system-aarch64");
        exit(1);
    }
}

static void vcpu_init(qemu_plugin_id_t id, unsigned int vcpu_index)
{
    init_registers();
}

static void at_exit(qemu_plugin_id_t id, void *data)
{
    FILE *dat_el0 = fopen("./uftrace.data/0.dat", "wb");
    FILE *dat_el1 = fopen("./uftrace.data/1.dat", "wb");
    FILE *dat_el2 = fopen("./uftrace.data/2.dat", "wb");
    FILE *dat_el3 = fopen("./uftrace.data/3.dat", "wb");
    g_assert(dat_el0);
    g_assert(dat_el1);
    g_assert(dat_el2);
    g_assert(dat_el3);
    fwrite(trace_el0->data, trace_el0->len, sizeof(uftrace_entry), dat_el0);
    fwrite(trace_el1->data, trace_el1->len, sizeof(uftrace_entry), dat_el1);
    fwrite(trace_el2->data, trace_el2->len, sizeof(uftrace_entry), dat_el2);
    fwrite(trace_el3->data, trace_el3->len, sizeof(uftrace_entry), dat_el3);
    fclose(dat_el0);
    fclose(dat_el1);
    fclose(dat_el2);
    fclose(dat_el3);
    g_byte_array_free(buf, true);
    g_array_free(trace_el0, true);
    g_array_free(trace_el1, true);
    g_array_free(trace_el2, true);
    g_array_free(trace_el3, true);
    call_stack_free(cs_el0);
    call_stack_free(cs_el1);
    call_stack_free(cs_el2);
    call_stack_free(cs_el3);
    qemu_plugin_scoreboard_free(score);
}

QEMU_PLUGIN_EXPORT int qemu_plugin_install(qemu_plugin_id_t id,
                                           const qemu_info_t *info,
                                           int argc, char **argv)
{
    buf = g_byte_array_new();
    trace_el0 = g_array_new(false, false, sizeof(uftrace_entry));
    trace_el1 = g_array_new(false, false, sizeof(uftrace_entry));
    trace_el2 = g_array_new(false, false, sizeof(uftrace_entry));
    trace_el3 = g_array_new(false, false, sizeof(uftrace_entry));
    score = qemu_plugin_scoreboard_new(sizeof(uint64_t));
    insn_count = qemu_plugin_scoreboard_u64(score);
    cs_el0 = call_stack_new();
    cs_el1 = call_stack_new();
    cs_el2 = call_stack_new();
    cs_el3 = call_stack_new();
    qemu_plugin_register_vcpu_init_cb(id, vcpu_init);
    qemu_plugin_register_atexit_cb(id, at_exit, 0);
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    return 0;
}

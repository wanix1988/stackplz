#include "types.h"
#include "common/arguments.h"
#include "common/common.h"
#include "common/consts.h"
#include "common/context.h"
#include "common/filtering.h"

#include "utils.h"

SEC("raw_tracepoint/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    long ret = 0;
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    struct task_struct *parent = (struct task_struct *) ctx->args[0];
    struct task_struct *child = (struct task_struct *) ctx->args[1];

    u32 parent_ns_pid = get_task_ns_pid(parent);
    u32 parent_ns_tgid = get_task_ns_tgid(parent);
    u32 child_ns_pid = get_task_ns_pid(child);
    u32 child_ns_tgid = get_task_ns_tgid(child);

    u32* pid = bpf_map_lookup_elem(&child_parent_map, &parent_ns_pid);
    if (unlikely(pid == NULL)) return 0;

    if (*pid == parent_ns_pid){
        ret = bpf_map_update_elem(&child_parent_map, &child_ns_pid, &parent_ns_pid, BPF_ANY);
    } else {
        bpf_printk("[stack] parent pid from map:%d\n", *pid);
    }
    return 0;
}

static __always_inline u32 probe_stack_warp(struct pt_regs* ctx, u32 point_key) {
    program_data_t p = {};
    if (!init_program_data(&p, ctx)) {
        return 0;
    }

    if (!should_trace(&p))
        return 0;
    point_args_t* point_args = bpf_map_lookup_elem(&uprobe_point_args, &point_key);
    if (unlikely(point_args == NULL)) return 0;

    u32 filter_key = 0;
    common_filter_t* filter = bpf_map_lookup_elem(&common_filter, &filter_key);
    if (unlikely(filter == NULL)) return 0;

    ctx_regs_t saved_regs = {};
    for (int i = 0; i < 31; i++) {
        saved_regs.regs[i] = READ_KERN(ctx->regs[i]);
    }
    saved_regs.sp = READ_KERN(ctx->sp);
    saved_regs.pc = READ_KERN(ctx->pc);

    if (point_args->enter_key == 0) {
        /* pass */
    } else if (point_args->enter_key == point_key + 1) {
        // 保存寄存器
        save_regs(&saved_regs, UPROBE_ENTER + point_key + 1);
    } else {
        // 加载寄存器
        if (load_regs(&saved_regs, UPROBE_ENTER + point_args->enter_key) != 0) {
            return 0;
        }
        // 清理map中的寄存器
        del_regs(UPROBE_ENTER + point_args->enter_key);
    }

    save_to_submit_buf(p.event, (void *) &point_key, sizeof(u32), 0);
    u64 lr = 0;
    u64 sp = 0;
    if(filter->is_32bit) {
        bpf_probe_read_kernel(&lr, sizeof(lr), &ctx->regs[14]);
        save_to_submit_buf(p.event, (void *) &lr, sizeof(u64), 1);
        bpf_probe_read_kernel(&sp, sizeof(sp), &ctx->regs[13]);
        save_to_submit_buf(p.event, (void *) &sp, sizeof(u64), 2);
    }
    else {
        bpf_probe_read_kernel(&lr, sizeof(lr), &ctx->regs[30]);
        save_to_submit_buf(p.event, (void *) &lr, sizeof(u64), 1);
        bpf_probe_read_kernel(&sp, sizeof(sp), &ctx->sp);
        save_to_submit_buf(p.event, (void *) &sp, sizeof(u64), 2);
    }
    u64 pc = 0;
    bpf_probe_read_kernel(&pc, sizeof(pc), &ctx->pc);
    save_to_submit_buf(p.event, (void *) &pc, sizeof(u64), 3);

    int ctx_index = 0;
    op_ctx_t* op_ctx = bpf_map_lookup_elem(&op_ctx_map, &ctx_index);
    if (unlikely(op_ctx == NULL)) return 0;
    __builtin_memset((void *)op_ctx, 0, sizeof(op_ctx));

    op_ctx->reg_0 = saved_regs.regs[0];
    op_ctx->save_index = 4;
    op_ctx->op_key_index = 0;

    read_args(&p, point_args, op_ctx, &saved_regs);

    if (op_ctx->skip_flag) {
        op_ctx->skip_flag = 0;
        return 0;
    }

    events_perf_submit(&p, UPROBE_ENTER);
    if (filter->signal > 0) {
        bpf_send_signal(filter->signal);
    }
    if (filter->tsignal > 0) {
        bpf_send_signal_thread(filter->tsignal);
    }
    if (point_args->signal > 0) {
        bpf_send_signal_thread(point_args->signal);
    }
    return 0;
}

static __always_inline u32 uretprobe_stack_warp(struct pt_regs* ctx, u32 point_key) {
    program_data_t p = {};
    if (!init_program_data(&p, ctx)) {
        return 0;
    }

    if (!should_trace(&p))
        return 0;
    // uretprobe 使用独立的配置（包含 ret 的读取规则）
    point_args_t* point_args = bpf_map_lookup_elem(&uretprobe_point_args, &point_key);
    if (unlikely(point_args == NULL)) return 0;

    u32 filter_key = 0;
    common_filter_t* filter = bpf_map_lookup_elem(&common_filter, &filter_key);
    if (unlikely(filter == NULL)) return 0;

    // 加载之前保存的寄存器（如果需要的话）
    ctx_regs_t saved_regs = {};
    if (point_args->enter_key != 0) {
        if (load_regs(&saved_regs, UPROBE_ENTER + point_args->enter_key) != 0) {
            return 0;
        }
        // 清理map中的寄存器
        del_regs(UPROBE_ENTER + point_args->enter_key);
    } else {
        // 如果没有保存的寄存器，从当前上下文读取
        for (int i = 0; i < 31; i++) {
            saved_regs.regs[i] = READ_KERN(ctx->regs[i]);
        }
        saved_regs.sp = READ_KERN(ctx->sp);
        saved_regs.pc = READ_KERN(ctx->pc);
    }

    // 读取返回值（x0 寄存器）。更复杂的返回类型（如 std::string）会通过 OP_READ_RET + OP_READ_STD_STRING 解析
    u64 ret_value = READ_KERN(ctx->regs[0]);

    save_to_submit_buf(p.event, (void *) &point_key, sizeof(u32), 0);
    u64 lr = 0;
    u64 sp = 0;
    if(filter->is_32bit) {
        bpf_probe_read_kernel(&lr, sizeof(lr), &ctx->regs[14]);
        save_to_submit_buf(p.event, (void *) &lr, sizeof(u64), 1);
        bpf_probe_read_kernel(&sp, sizeof(sp), &ctx->regs[13]);
        save_to_submit_buf(p.event, (void *) &sp, sizeof(u64), 2);
    }
    else {
        bpf_probe_read_kernel(&lr, sizeof(lr), &ctx->regs[30]);
        save_to_submit_buf(p.event, (void *) &lr, sizeof(u64), 1);
        bpf_probe_read_kernel(&sp, sizeof(sp), &ctx->sp);
        save_to_submit_buf(p.event, (void *) &sp, sizeof(u64), 2);
    }
    u64 pc = 0;
    bpf_probe_read_kernel(&pc, sizeof(pc), &ctx->pc);
    save_to_submit_buf(p.event, (void *) &pc, sizeof(u64), 3);

    int ctx_index = 0;
    op_ctx_t* op_ctx = bpf_map_lookup_elem(&op_ctx_map, &ctx_index);
    if (unlikely(op_ctx == NULL)) return 0;
    __builtin_memset((void *)op_ctx, 0, sizeof(op_ctx));

    op_ctx->reg_0 = ret_value;
    // uretprobe 从 index 4 开始保存（ret 会由 OP_READ_RET 生成）
    op_ctx->save_index = 4;
    op_ctx->op_key_index = 0;

    // 读取 uretprobe 配置的参数（包含 ret + 原始入参）
    if (point_args->op_count > 0) {
        read_args(&p, point_args, op_ctx, &saved_regs);
    }

    if (op_ctx->skip_flag) {
        op_ctx->skip_flag = 0;
        return 0;
    }

    events_perf_submit(&p, UPROBE_EXIT);
    if (filter->signal > 0) {
        bpf_send_signal(filter->signal);
    }
    if (filter->tsignal > 0) {
        bpf_send_signal_thread(filter->tsignal);
    }
    if (point_args->signal > 0) {
        bpf_send_signal_thread(point_args->signal);
    }
    return 0;
}

SEC("uprobe/stack_0")
int probe_stack_0(struct pt_regs* ctx) {
    u32 point_key = 0;
    return probe_stack_warp(ctx, point_key);
}

#define PROBE_STACK(name)                          \
    SEC("uprobe/stack_##name")                     \
    int probe_stack_##name(struct pt_regs* ctx)    \
    {                                              \
        u32 point_key = name;                       \
        return probe_stack_warp(ctx, point_key);    \
    }

// PROBE_STACK(0);
PROBE_STACK(1);
PROBE_STACK(2);
PROBE_STACK(3);
PROBE_STACK(4);
PROBE_STACK(5);
// PROBE_STACK(6);
// PROBE_STACK(7);
// PROBE_STACK(8);
// PROBE_STACK(9);
// PROBE_STACK(10);
// PROBE_STACK(11);
// PROBE_STACK(12);
// PROBE_STACK(13);
// PROBE_STACK(14);
// PROBE_STACK(15);
// PROBE_STACK(16);
// PROBE_STACK(17);
// PROBE_STACK(18);
// PROBE_STACK(19);

SEC("uretprobe/stack_0")
int uretprobe_stack_0(struct pt_regs* ctx) {
    u32 point_key = 0;
    return uretprobe_stack_warp(ctx, point_key);
}

#define URETPROBE_STACK(name)                          \
    SEC("uretprobe/stack_##name")                      \
    int uretprobe_stack_##name(struct pt_regs* ctx)    \
    {                                                  \
        u32 point_key = name;                          \
        return uretprobe_stack_warp(ctx, point_key);   \
    }

// URETPROBE_STACK(0);
URETPROBE_STACK(1);
URETPROBE_STACK(2);
URETPROBE_STACK(3);
URETPROBE_STACK(4);
URETPROBE_STACK(5);
// URETPROBE_STACK(6);
// URETPROBE_STACK(7);
// URETPROBE_STACK(8);
// URETPROBE_STACK(9);
// URETPROBE_STACK(10);
// URETPROBE_STACK(11);
// URETPROBE_STACK(12);
// URETPROBE_STACK(13);
// URETPROBE_STACK(14);
// URETPROBE_STACK(15);
// URETPROBE_STACK(16);
// URETPROBE_STACK(17);
// URETPROBE_STACK(18);
// URETPROBE_STACK(19);
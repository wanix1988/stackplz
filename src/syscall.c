#include "utils.h"
#include <stdbool.h>

#include "types.h"
#include "common/arguments.h"
#include "common/buffer.h"
#include "common/common.h"
#include "common/consts.h"
#include "common/context.h"
#include "common/filesystem.h"
#include "common/filtering.h"
#include "common/probes.h"

#define MAX_POINT_ARG_COUNT 6

typedef struct point_arg_t {
    u32 read_flag;
    u32 alias_type;
    u32 type;
    u32 size;
	u32 item_persize;
	s32 item_countindex;
} point_arg;

// syscall过滤配置
struct syscall_filter_t {
    u32 is_32bit;
    u32 syscall_all;
    u32 syscall_mask;
    u32 syscall[MAX_COUNT];
    u32 syscall_blacklist_mask;
    u32 syscall_blacklist[MAX_COUNT];
};

typedef struct syscall_point_args_t {
    // u32 nr;
    u32 count;
    point_arg point_args[MAX_POINT_ARG_COUNT];
    point_arg point_arg_ret;
} syscall_point_args;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, MAX_WATCH_PROC_COUNT);
} watch_proc_map SEC(".maps");

// syscall_point_args_map 的 key 就是 nr
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct syscall_point_args_t);
    __uint(max_entries, 512);
} syscall_point_args_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, struct syscall_filter_t);
    __uint(max_entries, 1);
} syscall_filter SEC(".maps");

static __always_inline u32 save_bytes_with_len(program_data_t p, u64 ptr, u32 read_len, u32 next_arg_index) {
    if (read_len > MAX_BUF_READ_SIZE) {
        read_len = MAX_BUF_READ_SIZE;
    }
    int status = save_bytes_to_buf(p.event, (void *)(ptr & 0xffffffffff), read_len, next_arg_index);
    if (status == 0) {
        buf_t *zero_p = get_buf(ZERO_BUF_IDX);
        if (zero_p == NULL) {
            return next_arg_index;
        }
        save_bytes_to_buf(p.event, &zero_p->buf[0], read_len, next_arg_index);
    }
    next_arg_index += 1;
    return next_arg_index;
}
static __always_inline u32 read_arg(program_data_t p, struct point_arg_t* point_arg, u64 ptr, u32 read_count, u32 next_arg_index) {
    if (point_arg->type == TYPE_NONE) {
        return next_arg_index;
    }
    if (point_arg->type == TYPE_NUM) {
        // 这种具体类型转换交给前端做
        return next_arg_index;
    }
    if (point_arg->type == TYPE_STRING) {
        u32 buf_off = 0;
        buf_t *string_p = get_buf(STRING_BUF_IDX);
        if (string_p == NULL) {
            return next_arg_index;
        }
        int status = bpf_probe_read_user(&string_p->buf[buf_off], MAX_STRING_SIZE, (void *)ptr);
        if (status < 0) {
            // MTE 其实也正常读取到了
            bpf_probe_read_user_str(&string_p->buf[buf_off], MAX_STRING_SIZE, (void *)ptr);
        }
        save_str_to_buf(p.event, &string_p->buf[buf_off], next_arg_index);
        next_arg_index += 1;
        return next_arg_index;
    }
    if (point_arg->type == TYPE_STRING_ARR && ptr != 0) {
        save_str_arr_to_buf(p.event, (const char *const *) ptr /*ptr*/, next_arg_index);
        next_arg_index += 1;
        return next_arg_index;
    }
    if (point_arg->type == TYPE_POINTER) {
        // 指针类型 通常读一下对应指针的数据即可 后续记得考虑兼容下32位
        
        // point_arg->alias_type
        // 某些成员是指针 有可能有必要再深入读取
        // 这个时候可以根据 alias_type 取出对应的参数配置 然后解析保存
        // 这个后面增补
        if (point_arg->alias_type == TYPE_BUFFER_T) {
            // buffer 的单个元素长度就是 1 所以这里就是 read_count
            u32 read_len = read_count * 1;
            int status = save_bytes_to_buf(p.event, (void *)(ptr & 0xffffffffff), read_len, next_arg_index);
            if (status == 0) {
                buf_t *zero_p = get_buf(ZERO_BUF_IDX);
                if (zero_p == NULL) {
                    return next_arg_index;
                }
                save_bytes_to_buf(p.event, &zero_p->buf[0], read_len, next_arg_index);
                next_arg_index += 1;
            } else {
                next_arg_index += 1;
            }
            return next_arg_index;
        }

        u64 addr = 0;
        bpf_probe_read_user(&addr, sizeof(addr), (void*) ptr);
        save_to_submit_buf(p.event, (void *) &addr, sizeof(u64), next_arg_index);
        next_arg_index += 1;
        return next_arg_index;
    }
    if (point_arg->type == TYPE_STRUCT && ptr != 0) {

        if (point_arg->alias_type == TYPE_IOVEC) {
            struct iovec iovec_ptr;
            int errno = bpf_probe_read_user(&iovec_ptr, sizeof(iovec_ptr), (void*) ptr);
            if (errno == 0) {
                save_to_submit_buf(p.event, (void *)&iovec_ptr, sizeof(iovec_ptr), next_arg_index);
                next_arg_index += 1;
                // 目前这样只是读取了第一个 iov 实际上要多次读取 数量是 iovcnt
                // 但是注意多个缓冲区并不是连续的
                u64 iov_base = (u64)iovec_ptr.iov_base;
                u32 iov_len = (u64)iovec_ptr.iov_len;
                // u32 read_len = read_count * iov_len;
                u32 read_len = iov_len;
                if (read_len > MAX_BUF_READ_SIZE) {
                    read_len = MAX_BUF_READ_SIZE;
                }
                // save_to_submit_buf(p.event, (void *)&iov_base, sizeof(iov_base), next_arg_index);
                // next_arg_index += 1;
                // // 注意 这里存放的大小是 u64 与结构体大小保持一致
                // save_to_submit_buf(p.event, (void *)&read_len, sizeof(read_len), next_arg_index);
                // next_arg_index += 1;
                next_arg_index = save_bytes_with_len(p, iov_base, read_len, next_arg_index);
                return next_arg_index;
            }
        }

        // 结构体类型 直接读取对应大小的数据 具体转换交给前端
        u32 struct_size = MAX_BYTES_ARR_SIZE;
        if (point_arg->size <= struct_size) {
            struct_size = point_arg->size;
        }
        // 修复 MTE 读取可能不正常的情况
        int status = save_bytes_to_buf(p.event, (void *)(ptr & 0xffffffffff), struct_size, next_arg_index);
        if (status == 0) {
            // 保存失败的情况 比如 ptr 是一个非法的地址 ...
            buf_t *zero_p = get_buf(ZERO_BUF_IDX);
            if (zero_p == NULL) {
                return next_arg_index;
            }
            // 这个时候填充一个全0的内容进去 不然前端不好解析
            save_bytes_to_buf(p.event, &zero_p->buf[0], struct_size, next_arg_index);
            next_arg_index += 1;
        } else {
            next_arg_index += 1;
        }
        return next_arg_index;
    }
    return next_arg_index;
}

SEC("raw_tracepoint/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct bpf_raw_tracepoint_args *ctx)
{
    long ret = 0;
    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    struct task_struct *parent = (struct task_struct *) ctx->args[0];
    struct task_struct *child = (struct task_struct *) ctx->args[1];

    // 为了实现仅指定单个pid时 能追踪其产生的子进程的相关系统调用 设计如下
    // 维护一个 map
    // - 其 key 为进程 pid 
    // - 其 value 为其父进程 pid
    // 逻辑如下
    // 当进入此处后，先获取进程本身信息，然后通过自己的父进程 pid 去 map 中取出对应的value
    // 如果没有取到则说明这个进程不是要追踪的进程
    // 取到了，则说明这个是之前产生的进程，然后向map存入进程信息 key 就是进程本身 pid 而 value则是父进程pid
    // 那么最开始的 pid 从哪里来呢 答案是从首次通过 sys_enter 的过滤之后 向该map存放第一个key value
    // 1. parent_child_map => {}
    // 2. 出现第一个通过 sys_enter 处的过滤的进程，则更新map -> parent_child_map => {12345: 12345}
    // 3. sched_process_fork 获取进程的父进程信息，检查map，发现父进程存在其中，则更新map -> parent_child_map => {12345: 12345, 22222: 12345}
    // 4. sys_enter/sys_exit 有限次遍历 parent_child_map 取出key逐个比较当前进程的pid
    // 待实现...
    return 0;
}

SEC("raw_tracepoint/sys_enter")
int raw_syscalls_sys_enter(struct bpf_raw_tracepoint_args* ctx) {

    // 除了实现对指定进程的系统调用跟踪 也要将其产生的子进程 加入追踪范围
    // 为了实现这个目的 fork 系统调用结束之后 应当检查其 父进程是否归属于当前被追踪的进程

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct pt_regs *regs = (struct pt_regs*)(ctx->args[0]);
    u64 syscallno = READ_KERN(regs->syscallno);
    // 先根据调用号确定有没有对应的参数获取方案 没有直接结束
    struct syscall_point_args_t* syscall_point_args = bpf_map_lookup_elem(&syscall_point_args_map, &syscallno);
    if (syscall_point_args == NULL) {
        bpf_printk("[syscall] unsupport nr:%d\n", syscallno);
        return 0;
    }

    u32 filter_key = 0;
    struct syscall_filter_t* filter = bpf_map_lookup_elem(&syscall_filter, &filter_key);
    if (filter == NULL) {
        return 0;
    }
    // 到这里的说明是命中了 追踪范围
    // 先收集下寄存器
    args_t args = {};
    args.args[0] = READ_KERN(regs->regs[0]);
    args.args[1] = READ_KERN(regs->regs[1]);
    args.args[2] = READ_KERN(regs->regs[2]);
    args.args[3] = READ_KERN(regs->regs[3]);
    args.args[4] = READ_KERN(regs->regs[4]);
    if (save_args(&args, SYSCALL_ENTER) != 0) {
        return 0;
    };

    if (filter->syscall_all == 0) {
        // syscall 白名单过滤
        bool has_find = false;
        #pragma unroll
        for (int i = 0; i < MAX_COUNT; i++) {
            if ((filter->syscall_mask & (1 << i))) {
                if (filter->syscall[i] == (u32)syscallno) {
                    has_find = true;
                    break;
                }
            } else {
                if (i == 0) {
                    // 如果没有设置白名单 则将 has_find 置为 true
                    has_find = true;
                }
                // 减少不必要的循环
                break;
            }
        }
        // 不满足白名单规则 则跳过
        if (!has_find) {
            return 0;
        }

        // syscall 黑名单过滤
        #pragma unroll
        for (int i = 0; i < MAX_COUNT; i++) {
            if ((filter->syscall_blacklist_mask & (1 << i))) {
                if (filter->syscall_blacklist[i] == (u32)syscallno) {
                    // 在syscall黑名单直接结束跳过
                    return 0;
                }
            } else {
                // 减少不必要的循环
                break;
            }
        }
    }

    // event->context 已经有进程的信息了
    save_to_submit_buf(p.event, (void *) &syscallno, sizeof(u32), 0);

    // 先获取 lr sp pc 并发送 这样可以尽早计算调用来源情况
    // READ_KERN 好像有问题
    u64 lr = 0;
    if(filter->is_32bit) {
        bpf_probe_read_kernel(&lr, sizeof(lr), &regs->regs[14]);
        save_to_submit_buf(p.event, (void *) &lr, sizeof(u64), 1);
    }
    else {
        bpf_probe_read_kernel(&lr, sizeof(lr), &regs->regs[30]);
        save_to_submit_buf(p.event, (void *) &lr, sizeof(u64), 1);
    }
    u64 pc = 0;
    u64 sp = 0;
    bpf_probe_read_kernel(&pc, sizeof(pc), &regs->pc);
    bpf_probe_read_kernel(&sp, sizeof(sp), &regs->sp);
    save_to_submit_buf(p.event, (void *) &pc, sizeof(u64), 2);
    save_to_submit_buf(p.event, (void *) &sp, sizeof(u64), 3);

    u32 point_arg_count = MAX_POINT_ARG_COUNT;
    if (syscall_point_args->count <= point_arg_count) {
        point_arg_count = syscall_point_args->count;
    }

    int next_arg_index = 4;
    // #pragma unroll
    for (int i = 0; i < point_arg_count; i++) {
        // 先保存寄存器
        save_to_submit_buf(p.event, (void *)&args.args[i], sizeof(u64), next_arg_index);
        next_arg_index += 1;
        struct point_arg_t* point_arg = (struct point_arg_t*) &syscall_point_args->point_args[i];
        if (point_arg->read_flag != SYS_ENTER) {
            continue;
        }
        u32 read_count = MAX_BUF_READ_SIZE;
        if (point_arg->item_countindex >= 0) {
            // math between fp pointer and register with unbounded min value is not allowed
            // 后面取寄存器可能存在越界 所以必须保证索引必须是在正确的范围内
            // 这里必须把 item_countindex 赋值给临时变量 并且必须转换类型
            // 然后通过 if 比较来明确它不会越界 然后后面再用它作为取寄存器的索引
            // 最后计算要读取数据的最终大小 当然这里也必须有一个上限大小
            u32 item_index = (u32) point_arg->item_countindex;
            if (item_index >= 6) {
                return 0;
            }
            u32 item_count = (u32) args.args[item_index];
            if (item_count <= read_count) {
                read_count = item_count;
            }
        }
        next_arg_index = read_arg(p, point_arg, args.args[i], read_count, next_arg_index);
    }
    u32 out_size = sizeof(event_context_t) + p.event->buf_off;
    save_to_submit_buf(p.event, (void *) &out_size, sizeof(u32), next_arg_index);
    events_perf_submit(&p, SYSCALL_ENTER);
    return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_syscalls_sys_exit(struct bpf_raw_tracepoint_args* ctx) {

    program_data_t p = {};
    if (!init_program_data(&p, ctx))
        return 0;

    if (!should_trace(&p))
        return 0;

    struct pt_regs *regs = (struct pt_regs*)(ctx->args[0]);
    u64 syscallno = READ_KERN(regs->syscallno);

    struct syscall_point_args_t* syscall_point_args = bpf_map_lookup_elem(&syscall_point_args_map, &syscallno);
    if (syscall_point_args == NULL) {
        return 0;
    }

    u32 filter_key = 0;
    struct syscall_filter_t* filter = bpf_map_lookup_elem(&syscall_filter, &filter_key);
    if (filter == NULL) {
        return 0;
    }

    args_t saved_args;
    if (load_args(&saved_args, SYSCALL_ENTER) != 0) {
        return 0;
    }

    if (filter->syscall_all == 0) {
        // syscall 白名单过滤
        bool has_find = false;
        #pragma unroll
        for (int i = 0; i < MAX_COUNT; i++) {
            if ((filter->syscall_mask & (1 << i))) {
                if (filter->syscall[i] == (u32)syscallno) {
                    has_find = true;
                    break;
                }
            } else {
                if (i == 0) {
                    // 如果没有设置白名单 则将 has_find 置为 true
                    has_find = true;
                }
                // 减少不必要的循环
                break;
            }
        }
        // 不满足白名单规则 则跳过
        if (!has_find) {
            return 0;
        }

        // syscall 黑名单过滤
        #pragma unroll
        for (int i = 0; i < MAX_COUNT; i++) {
            if ((filter->syscall_blacklist_mask & (1 << i))) {
                if (filter->syscall_blacklist[i] == (u32)syscallno) {
                    // 在syscall黑名单直接结束跳过
                    return 0;
                }
            } else {
                // 减少不必要的循环
                break;
            }
        }
    }

    int next_arg_index = 0;
    save_to_submit_buf(p.event, (void *) &syscallno, sizeof(u32), next_arg_index);
    next_arg_index += 1;

    u32 point_arg_count = MAX_POINT_ARG_COUNT;
    if (syscall_point_args->count <= point_arg_count) {
        point_arg_count = syscall_point_args->count;
    }
    // #pragma unroll
    for (int i = 0; i < point_arg_count; i++) {
        // 保存参数的寄存器
        save_to_submit_buf(p.event, (void *)&saved_args.args[i], sizeof(u64), next_arg_index);
        next_arg_index += 1;
        struct point_arg_t* point_arg = (struct point_arg_t*) &syscall_point_args->point_args[i];
        if (point_arg->read_flag != SYS_EXIT) {
            continue;
        }
        u32 read_count = MAX_BUF_READ_SIZE;
        if (point_arg->item_countindex >= 0) {
            // math between fp pointer and register with unbounded min value is not allowed
            // 后面取寄存器可能存在越界 所以必须保证索引必须是在正确的范围内
            // 这里必须把 item_countindex 赋值给临时变量 并且必须转换类型
            // 然后通过 if 比较来明确它不会越界 然后后面再用它作为取寄存器的索引
            // 最后计算要读取数据的最终大小 当然这里也必须有一个上限大小
            u32 item_index = (u32) point_arg->item_countindex;
            if (item_index >= 6) {
                return 0;
            }
            u32 item_count = (u32) saved_args.args[item_index];
            if (item_count <= read_count) {
                read_count = item_count;
            }
        }
        next_arg_index = read_arg(p, point_arg, saved_args.args[i], read_count, next_arg_index);
    }
    // 读取返回值
    u64 ret = READ_KERN(regs->regs[0]);
    // 保存之
    save_to_submit_buf(p.event, (void *) &ret, sizeof(ret), next_arg_index);
    next_arg_index += 1;
    // 取返回值的参数配置 并尝试进一步读取
    struct point_arg_t* point_arg = (struct point_arg_t*) &syscall_point_args->point_arg_ret;
    next_arg_index = read_arg(p, point_arg, ret, 0, next_arg_index);
    u32 out_size = sizeof(event_context_t) + p.event->buf_off;
    save_to_submit_buf(p.event, (void *) &out_size, sizeof(u32), next_arg_index);
    // 发送数据
    events_perf_submit(&p, SYSCALL_EXIT);
    return 0;
}
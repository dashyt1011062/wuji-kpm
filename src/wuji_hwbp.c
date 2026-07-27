/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <common.h>
#include <compiler.h>
#include <kallsyms.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <uapi/asm-generic/errno.h>

#define WUJI_HWBP_MAX 8

#define PERF_TYPE_BREAKPOINT 5

#define HW_BREAKPOINT_LEN_1 1
#define HW_BREAKPOINT_LEN_2 2
#define HW_BREAKPOINT_LEN_4 4
#define HW_BREAKPOINT_LEN_8 8

#define HW_BREAKPOINT_R 1
#define HW_BREAKPOINT_W 2
#define HW_BREAKPOINT_RW (HW_BREAKPOINT_R | HW_BREAKPOINT_W)
#define HW_BREAKPOINT_X 4

struct perf_event;
struct perf_sample_data;
struct task_struct;

struct pt_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

struct perf_event_attr {
    uint32_t type;
    uint32_t size;
    uint64_t config;
    union {
        uint64_t sample_period;
        uint64_t sample_freq;
    };
    uint64_t sample_type;
    uint64_t read_format;
    uint64_t disabled : 1;
    uint64_t inherit : 1;
    uint64_t pinned : 1;
    uint64_t exclusive : 1;
    uint64_t exclude_user : 1;
    uint64_t exclude_kernel : 1;
    uint64_t exclude_hv : 1;
    uint64_t exclude_idle : 1;
    uint64_t mmap : 1;
    uint64_t comm : 1;
    uint64_t freq : 1;
    uint64_t inherit_stat : 1;
    uint64_t enable_on_exec : 1;
    uint64_t task : 1;
    uint64_t watermark : 1;
    uint64_t precise_ip : 2;
    uint64_t mmap_data : 1;
    uint64_t sample_id_all : 1;
    uint64_t exclude_host : 1;
    uint64_t exclude_guest : 1;
    uint64_t exclude_callchain_kernel : 1;
    uint64_t exclude_callchain_user : 1;
    uint64_t mmap2 : 1;
    uint64_t comm_exec : 1;
    uint64_t use_clockid : 1;
    uint64_t context_switch : 1;
    uint64_t write_backward : 1;
    uint64_t namespaces : 1;
    uint64_t ksymbol : 1;
    uint64_t bpf_event : 1;
    uint64_t aux_output : 1;
    uint64_t cgroup : 1;
    uint64_t text_poke : 1;
    uint64_t build_id : 1;
    uint64_t inherit_thread : 1;
    uint64_t remove_on_exec : 1;
    uint64_t sigtrap : 1;
    uint64_t __reserved_1 : 26;
    union {
        uint32_t wakeup_events;
        uint32_t wakeup_watermark;
    };
    uint32_t bp_type;
    union {
        uint64_t bp_addr;
        uint64_t kprobe_func;
        uint64_t uprobe_path;
        uint64_t config1;
    };
    union {
        uint64_t bp_len;
        uint64_t kprobe_addr;
        uint64_t probe_offset;
        uint64_t config2;
    };
};

typedef void (*perf_overflow_handler_t)(struct perf_event *event,
                                        struct perf_sample_data *data,
                                        struct pt_regs *regs);
typedef struct perf_event *(*register_user_hw_breakpoint_t)(
    struct perf_event_attr *attr, perf_overflow_handler_t triggered,
    void *context, struct task_struct *task);
typedef void (*unregister_hw_breakpoint_t)(struct perf_event *bp);

struct hwbp_slot {
    bool used;
    pid_t pid;
    uint64_t addr;
    uint64_t len;
    uint64_t hits;
    uint64_t last_pc;
    struct perf_event *event;
};

KPM_NAME("wuji-hwbp");
KPM_VERSION("0.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("dashyt1011062");
KPM_DESCRIPTION("First-stage WuJi hardware execute breakpoint KPM.");

static register_user_hw_breakpoint_t g_register_user_hw_breakpoint;
static unregister_hw_breakpoint_t g_unregister_hw_breakpoint;
static struct hwbp_slot g_slots[WUJI_HWBP_MAX];
static uint64_t g_total_hits;
static uint64_t g_install_attempts;
static uint64_t g_install_failures;

static long copy_reply(char *__user out_msg, int outlen, const char *msg)
{
    int len;

    if (!out_msg || outlen <= 0) {
        return 0;
    }

    len = (int)strlen(msg) + 1;
    if (len > outlen) {
        len = outlen;
    }

    if (compat_copy_to_user(out_msg, msg, len)) {
        return -EFAULT;
    }

    return 0;
}

static int resolve_symbols(void)
{
    if (g_register_user_hw_breakpoint && g_unregister_hw_breakpoint) {
        return 0;
    }

    if (!kallsyms_lookup_name) {
        return -ENOSYS;
    }

    g_register_user_hw_breakpoint =
        (register_user_hw_breakpoint_t)kallsyms_lookup_name("register_user_hw_breakpoint");
    g_unregister_hw_breakpoint =
        (unregister_hw_breakpoint_t)kallsyms_lookup_name("unregister_hw_breakpoint");

    if (!g_register_user_hw_breakpoint || !g_unregister_hw_breakpoint) {
        pr_err("wuji-hwbp: required hw breakpoint symbols are missing\n");
        return -ENOSYS;
    }

    return 0;
}

static void wuji_hwbp_handler(struct perf_event *event,
                              struct perf_sample_data *data,
                              struct pt_regs *regs)
{
    int i;

    (void)data;

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        if (!g_slots[i].used || g_slots[i].event != event) {
            continue;
        }

        g_slots[i].hits++;
        g_total_hits++;
        if (regs) {
            g_slots[i].last_pc = regs->pc;
        }
        return;
    }
}

static int validate_len(uint64_t len)
{
    return len == HW_BREAKPOINT_LEN_1 || len == HW_BREAKPOINT_LEN_2 ||
           len == HW_BREAKPOINT_LEN_4 || len == HW_BREAKPOINT_LEN_8;
}

static int find_free_slot(void)
{
    int i;

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        if (!g_slots[i].used) {
            return i;
        }
    }

    return -1;
}

static long uninstall_slot(int i)
{
    struct perf_event *event;

    if (i < 0 || i >= WUJI_HWBP_MAX || !g_slots[i].used) {
        return -ENOENT;
    }

    event = g_slots[i].event;
    g_slots[i].used = false;
    g_slots[i].event = NULL;

    if (event && g_unregister_hw_breakpoint) {
        g_unregister_hw_breakpoint(event);
    }

    memset(&g_slots[i], 0, sizeof(g_slots[i]));
    return 0;
}

static long uninstall_handle(uint64_t handle)
{
    int i;

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        if (g_slots[i].used && (uint64_t)(uintptr_t)g_slots[i].event == handle) {
            return uninstall_slot(i);
        }
    }

    return -ENOENT;
}

static void uninstall_all(void)
{
    int i;

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        (void)uninstall_slot(i);
    }
}

static long install_exec_breakpoint(pid_t pid, uint64_t addr, uint64_t len,
                                    char *__user out_msg, int outlen)
{
    struct perf_event_attr attr;
    struct perf_event *event;
    struct pid *pid_ref;
    struct task_struct *task;
    int slot;
    int ret;
    char reply[192];

    if (pid <= 0 || !addr) {
        return copy_reply(out_msg, outlen, "error: invalid pid/address\n");
    }
    if (!validate_len(len)) {
        return copy_reply(out_msg, outlen, "error: invalid breakpoint length\n");
    }

    ret = resolve_symbols();
    if (ret) {
        snprintf(reply, sizeof(reply), "error: required symbols missing ret=%d\n", ret);
        return copy_reply(out_msg, outlen, reply);
    }

    slot = find_free_slot();
    if (slot < 0) {
        return copy_reply(out_msg, outlen, "error: no free hwbp slot\n");
    }

    pid_ref = find_get_pid(pid);
    if (!pid_ref) {
        return copy_reply(out_msg, outlen, "error: pid not found\n");
    }

    task = pid_task(pid_ref, PIDTYPE_PID);
    if (!task) {
        put_pid(pid_ref);
        return copy_reply(out_msg, outlen, "error: task not found\n");
    }

    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.bp_type = HW_BREAKPOINT_X;
    attr.bp_addr = addr;
    attr.bp_len = len;
    attr.disabled = 0;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;

    g_install_attempts++;
    event = g_register_user_hw_breakpoint(&attr, wuji_hwbp_handler, NULL, task);
    put_pid(pid_ref);

    if (IS_ERR(event)) {
        ret = (int)PTR_ERR(event);
        g_install_failures++;
        snprintf(reply, sizeof(reply), "error: register_user_hw_breakpoint ret=%d\n", ret);
        return copy_reply(out_msg, outlen, reply);
    }
    if (!event) {
        g_install_failures++;
        return copy_reply(out_msg, outlen, "error: register_user_hw_breakpoint returned NULL\n");
    }

    g_slots[slot].used = true;
    g_slots[slot].pid = pid;
    g_slots[slot].addr = addr;
    g_slots[slot].len = len;
    g_slots[slot].hits = 0;
    g_slots[slot].last_pc = 0;
    g_slots[slot].event = event;

    snprintf(reply, sizeof(reply),
             "ok: slot=%d handle=0x%llx pid=%d addr=0x%llx len=%llu\n",
             slot, (unsigned long long)(uintptr_t)event, pid,
             (unsigned long long)addr, (unsigned long long)len);
    pr_info("wuji-hwbp: %s", reply);
    return copy_reply(out_msg, outlen, reply);
}

static long status(char *__user out_msg, int outlen)
{
    char reply[1024];
    int off = 0;
    int i;

    off += snprintf(reply + off, sizeof(reply) - off,
                    "wuji-hwbp: slots=%d total_hits=%llu install_attempts=%llu install_failures=%llu symbols=%d\n",
                    WUJI_HWBP_MAX, (unsigned long long)g_total_hits,
                    (unsigned long long)g_install_attempts,
                    (unsigned long long)g_install_failures,
                    g_register_user_hw_breakpoint && g_unregister_hw_breakpoint ? 1 : 0);

    for (i = 0; i < WUJI_HWBP_MAX && off < (int)sizeof(reply); ++i) {
        if (!g_slots[i].used) {
            continue;
        }

        off += snprintf(reply + off, sizeof(reply) - off,
                        "slot=%d handle=0x%llx pid=%d addr=0x%llx len=%llu hits=%llu last_pc=0x%llx\n",
                        i, (unsigned long long)(uintptr_t)g_slots[i].event,
                        g_slots[i].pid, (unsigned long long)g_slots[i].addr,
                        (unsigned long long)g_slots[i].len,
                        (unsigned long long)g_slots[i].hits,
                        (unsigned long long)g_slots[i].last_pc);
    }

    return copy_reply(out_msg, outlen, reply);
}

static long wuji_hwbp_init(const char *args, const char *event, void *__user reserved)
{
    int ret;

    (void)args;
    (void)event;
    (void)reserved;

    memset(g_slots, 0, sizeof(g_slots));
    g_total_hits = 0;
    g_install_attempts = 0;
    g_install_failures = 0;

    ret = resolve_symbols();
    if (ret) {
        pr_err("wuji-hwbp: loaded without hw breakpoint symbols ret=%d\n", ret);
        return 0;
    }

    pr_info("wuji-hwbp: loaded\n");
    return 0;
}

static long wuji_hwbp_control(const char *args, char *__user out_msg, int outlen)
{
    pid_t pid = 0;
    unsigned long long addr = 0;
    unsigned long long len = HW_BREAKPOINT_LEN_4;
    unsigned long long handle = 0;
    int matched;
    long ret;
    char reply[128];

    if (!args || !*args) {
        return copy_reply(out_msg, outlen,
                          "usage: status | install <pid> <hex_addr> [len] | uninstall <handle> | clear\n");
    }

    if (!strcmp(args, "status")) {
        (void)resolve_symbols();
        return status(out_msg, outlen);
    }

    matched = sscanf(args, "install %d %llx %llu", &pid, &addr, &len);
    if (matched >= 2) {
        return install_exec_breakpoint(pid, (uint64_t)addr, (uint64_t)len,
                                       out_msg, outlen);
    }

    matched = sscanf(args, "uninstall %llx", &handle);
    if (matched == 1) {
        ret = uninstall_handle((uint64_t)handle);
        snprintf(reply, sizeof(reply), "uninstall handle=0x%llx ret=%ld\n", handle, ret);
        return copy_reply(out_msg, outlen, reply);
    }

    if (!strcmp(args, "clear")) {
        uninstall_all();
        return copy_reply(out_msg, outlen, "ok: cleared\n");
    }

    return copy_reply(out_msg, outlen,
                      "error: unknown command; use status | install <pid> <hex_addr> [len] | uninstall <handle> | clear\n");
}

static long wuji_hwbp_exit(void *__user reserved)
{
    (void)reserved;
    uninstall_all();
    pr_info("wuji-hwbp: unloaded\n");
    return 0;
}

KPM_INIT(wuji_hwbp_init);
KPM_CTL0(wuji_hwbp_control);
KPM_EXIT(wuji_hwbp_exit);

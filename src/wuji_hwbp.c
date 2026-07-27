/* SPDX-License-Identifier: GPL-2.0-or-later */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <common.h>
#include <compiler.h>
#include <hook.h>
#include <kallsyms.h>
#include <kpmodule.h>
#include <kputils.h>
#include <linux/err.h>
#include <linux/kernel.h>
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

#define WUJI_REQ_NONE 0
#define WUJI_REQ_INSTALL 1
#define WUJI_REQ_UNINSTALL 2
#define WUJI_REQ_CLEAR 3

#define WUJI_READ_ONCE(x) (*(const volatile typeof(x) *)&(x))
#define WUJI_WRITE_ONCE(x, val) \
    do { (*(volatile typeof(x) *)&(x)) = (val); } while (0)

struct perf_event;
struct perf_sample_data;
struct pid;
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
    uint64_t branch_sample_type;
    uint64_t sample_regs_user;
    uint32_t sample_stack_user;
    int32_t clockid;
    uint64_t sample_regs_intr;
    uint32_t aux_watermark;
    uint16_t sample_max_stack;
    uint16_t __reserved_2;
    uint32_t aux_sample_size;
    uint32_t __reserved_3;
    uint64_t sig_data;
    uint64_t config3;
};

typedef void (*perf_overflow_handler_t)(struct perf_event *event,
                                        struct perf_sample_data *data,
                                        struct pt_regs *regs);
typedef unsigned long (*find_symbol_t)(const char *name);
typedef struct perf_event *(*register_user_hw_breakpoint_t)(
    struct perf_event_attr *attr, perf_overflow_handler_t triggered,
    void *context, struct task_struct *task);
typedef void (*unregister_hw_breakpoint_t)(struct perf_event *bp);
typedef struct pid *(*find_get_pid_t)(int nr);
typedef struct task_struct *(*pid_task_t)(struct pid *pid, int type);
typedef struct task_struct *(*get_pid_task_t)(struct pid *pid, int type);
typedef void (*put_pid_t)(struct pid *pid);
typedef void (*put_task_struct_t)(struct task_struct *task);
typedef struct task_struct *(*kthread_create_on_node_t)(
    int (*threadfn)(void *data), void *data, int node, const char *namefmt, ...);
typedef int (*wake_up_process_t)(struct task_struct *tsk);
typedef void (*user_enable_single_step_t)(struct task_struct *task);
typedef void (*user_disable_single_step_t)(struct task_struct *task);
typedef void (*perf_event_disable_inatomic_t)(struct perf_event *event);
typedef void (*perf_event_enable_t)(struct perf_event *event);

struct hwbp_slot {
    bool used;
    bool stepping;
    pid_t pid;
    uint64_t addr;
    uint64_t len;
    uint64_t hits;
    uint64_t last_pc;
    uint64_t step_starts;
    uint64_t step_completes;
    uint64_t last_step_pc;
    struct perf_event *event;
    struct task_struct *step_task;
};

KPM_NAME("wuji-hwbp");
KPM_VERSION("0.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("dashyt1011062");
KPM_DESCRIPTION("First-stage WuJi hardware execute breakpoint KPM.");

static register_user_hw_breakpoint_t g_register_user_hw_breakpoint;
static unregister_hw_breakpoint_t g_unregister_hw_breakpoint;
static find_symbol_t g_find_symbol;
static find_get_pid_t g_find_get_pid;
static pid_task_t g_pid_task;
static get_pid_task_t g_get_pid_task;
static put_pid_t g_put_pid;
static put_task_struct_t g_put_task_struct;
static kthread_create_on_node_t g_kthread_create_on_node;
static wake_up_process_t g_wake_up_process;
static user_enable_single_step_t g_user_enable_single_step;
static user_disable_single_step_t g_user_disable_single_step;
static perf_event_disable_inatomic_t g_perf_event_disable_inatomic;
static perf_event_enable_t g_perf_event_enable;
static unsigned long g_single_step_handler_addr;
static int g_step_hook_installed;
static struct task_struct *g_worker_task;
static struct hwbp_slot g_slots[WUJI_HWBP_MAX];
static uint64_t g_total_hits;
static uint64_t g_unknown_hits;
static uint64_t g_last_hit_pc;
static uint64_t g_last_hit_event;
static uint64_t g_step_starts;
static uint64_t g_step_completes;
static uint64_t g_step_failures;
static int g_last_step_error;
static uint64_t g_install_attempts;
static uint64_t g_install_failures;
static uint64_t g_uninstall_attempts;
static uint64_t g_uninstall_failures;
static uint64_t g_prepare_attempts;
static uint64_t g_prepare_failures;
static uint64_t g_submit_seq;
static uint64_t g_done_seq;
static volatile int g_req_type;
static volatile int g_worker_alive;
static volatile int g_worker_busy;
static pid_t g_req_pid;
static uint64_t g_req_addr;
static uint64_t g_req_len;
static uint64_t g_req_handle;
static int g_last_resolve_error;
static int g_last_prepare_error;
static int g_last_worker_error;
static const char *g_resolver_name = "none";
static char g_last_worker_msg[256];

static int wuji_hwbp_worker(void *data);
static void wuji_single_step_before(hook_fargs3_t *fargs, void *udata);

static inline struct task_struct *wuji_current_task(void)
{
    uint64_t sp_el0;

    asm volatile("mrs %0, sp_el0" : "=r"(sp_el0));
    return (struct task_struct *)(uintptr_t)sp_el0;
}

static long copy_reply(char *__user out_msg, int outlen, const char *msg)
{
    int len;

    if (!msg) {
        msg = "";
    }

    if (msg && *msg) {
        pr_info("wuji-hwbp: %s", msg);
    }

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

static unsigned long lookup_symbol(const char *name)
{
    unsigned long addr;

    if (!name || !*name) {
        return 0;
    }

    /*
     * SukiSU-Ultra exposes sukisu_compact_find_symbol(), whose address table
     * also provides the KPM-facing "compact_find_symbol" alias.  Do not import
     * ordinary kernel functions as KPM undefined symbols: the KPM loader only
     * resolves its own exported KP symbols at relocation time.  Resolve normal
     * kernel APIs lazily here instead.
     */
    if (!g_find_symbol) {
        if (!kallsyms_lookup_name) {
            g_resolver_name = "missing-kallsyms";
            return 0;
        }

        g_find_symbol =
            (find_symbol_t)kallsyms_lookup_name("sukisu_compact_find_symbol");
        if (g_find_symbol) {
            g_resolver_name = "sukisu_compact_find_symbol";
        } else {
            g_find_symbol = kallsyms_lookup_name;
            g_resolver_name = "kallsyms_lookup_name";
        }
    }

    addr = g_find_symbol(name);
    if (!addr && g_find_symbol != kallsyms_lookup_name && kallsyms_lookup_name) {
        addr = kallsyms_lookup_name(name);
    }

    return addr;
}

static int resolve_symbols(void)
{
    if (g_register_user_hw_breakpoint && g_unregister_hw_breakpoint &&
        g_find_get_pid && g_put_pid &&
        ((g_get_pid_task && g_put_task_struct) || g_pid_task)) {
        return 0;
    }

    if (!lookup_symbol("sukisu_compact_find_symbol") && !kallsyms_lookup_name) {
        g_last_resolve_error = -ENOSYS;
        return -ENOSYS;
    }

    g_register_user_hw_breakpoint =
        (register_user_hw_breakpoint_t)lookup_symbol("register_user_hw_breakpoint");
    g_unregister_hw_breakpoint =
        (unregister_hw_breakpoint_t)lookup_symbol("unregister_hw_breakpoint");
    g_find_get_pid = (find_get_pid_t)lookup_symbol("find_get_pid");
    g_get_pid_task = (get_pid_task_t)lookup_symbol("get_pid_task");
    g_put_task_struct = (put_task_struct_t)lookup_symbol("put_task_struct");
    g_pid_task = (pid_task_t)lookup_symbol("pid_task");
    g_put_pid = (put_pid_t)lookup_symbol("put_pid");

    if (!g_register_user_hw_breakpoint || !g_unregister_hw_breakpoint ||
        !g_find_get_pid || !g_put_pid ||
        !((g_get_pid_task && g_put_task_struct) || g_pid_task)) {
        g_last_resolve_error = -ENOSYS;
        pr_err("wuji-hwbp: required symbols missing resolver=%s hwbp=%px/%px pid=%px get_pid_task=%px put_task=%px pid_task=%px put_pid=%px\n",
               g_resolver_name, g_register_user_hw_breakpoint,
               g_unregister_hw_breakpoint, g_find_get_pid, g_get_pid_task,
               g_put_task_struct, g_pid_task, g_put_pid);
        return g_last_resolve_error;
    }

    g_last_resolve_error = 0;
    return 0;
}

static int resolve_worker_symbols(void)
{
    if (g_kthread_create_on_node && g_wake_up_process) {
        return 0;
    }

    if (!lookup_symbol("sukisu_compact_find_symbol") && !kallsyms_lookup_name) {
        return -ENOSYS;
    }

    g_kthread_create_on_node =
        (kthread_create_on_node_t)lookup_symbol("kthread_create_on_node");
    g_wake_up_process = (wake_up_process_t)lookup_symbol("wake_up_process");

    if (!g_kthread_create_on_node || !g_wake_up_process) {
        g_last_worker_error = -ENOSYS;
        pr_err("wuji-hwbp: worker symbols missing create=%px wake=%px\n",
               g_kthread_create_on_node, g_wake_up_process);
        return -ENOSYS;
    }

    return 0;
}

static int start_worker(void)
{
    struct task_struct *task;
    int ret;

    if (WUJI_READ_ONCE(g_worker_alive) || g_worker_task) {
        return -EBUSY;
    }

    ret = resolve_worker_symbols();
    if (ret) {
        return ret;
    }

    task = g_kthread_create_on_node(wuji_hwbp_worker, NULL, -1, "wuji-hwbp");
    if (IS_ERR(task)) {
        ret = (int)PTR_ERR(task);
        pr_err("wuji-hwbp: failed to create worker ret=%d\n", ret);
        return ret;
    }
    if (!task) {
        pr_err("wuji-hwbp: kthread_create_on_node returned NULL\n");
        return -ENOMEM;
    }

    g_worker_task = task;
    WUJI_WRITE_ONCE(g_worker_alive, 1);
    g_wake_up_process(task);
    return 0;
}

static int resolve_step_symbols(void)
{
    if (g_user_enable_single_step && g_user_disable_single_step &&
        g_perf_event_disable_inatomic && g_perf_event_enable &&
        g_single_step_handler_addr) {
        return 0;
    }

    if (!lookup_symbol("sukisu_compact_find_symbol") && !kallsyms_lookup_name) {
        g_last_step_error = -ENOSYS;
        return -ENOSYS;
    }

    g_user_enable_single_step =
        (user_enable_single_step_t)lookup_symbol("user_enable_single_step");
    g_user_disable_single_step =
        (user_disable_single_step_t)lookup_symbol("user_disable_single_step");
    g_perf_event_disable_inatomic =
        (perf_event_disable_inatomic_t)lookup_symbol("perf_event_disable_inatomic");
    g_perf_event_enable =
        (perf_event_enable_t)lookup_symbol("perf_event_enable");
    g_single_step_handler_addr = lookup_symbol("single_step_handler");

    if (!g_user_enable_single_step || !g_user_disable_single_step ||
        !g_perf_event_disable_inatomic || !g_perf_event_enable ||
        !g_single_step_handler_addr) {
        g_last_step_error = -ENOSYS;
        pr_err("wuji-hwbp: step symbols missing enable=%px disable=%px perf_disable_inatomic=%px perf_enable=%px single_step_handler=0x%llx\n",
               g_user_enable_single_step, g_user_disable_single_step,
               g_perf_event_disable_inatomic, g_perf_event_enable,
               (unsigned long long)g_single_step_handler_addr);
        return -ENOSYS;
    }

    g_last_step_error = 0;
    return 0;
}

static int ensure_step_hook(void)
{
    hook_err_t err;
    int ret;

    if (g_step_hook_installed) {
        return 0;
    }

    ret = resolve_step_symbols();
    if (ret) {
        return ret;
    }

    err = hook_wrap3((void *)g_single_step_handler_addr,
                     wuji_single_step_before, NULL, NULL);
    if (err != HOOK_NO_ERR) {
        g_last_step_error = -(int)err;
        pr_err("wuji-hwbp: hook single_step_handler failed err=%d addr=0x%llx\n",
               err, (unsigned long long)g_single_step_handler_addr);
        return g_last_step_error;
    }

    g_step_hook_installed = 1;
    g_last_step_error = 0;
    pr_info("wuji-hwbp: hooked single_step_handler addr=0x%llx\n",
            (unsigned long long)g_single_step_handler_addr);
    return 0;
}

static void remove_step_hook(void)
{
    if (!g_step_hook_installed || !g_single_step_handler_addr) {
        return;
    }

    hook_unwrap((void *)g_single_step_handler_addr,
                wuji_single_step_before, NULL);
    g_step_hook_installed = 0;
    pr_info("wuji-hwbp: unhooked single_step_handler\n");
}

static void wuji_hwbp_handler(struct perf_event *event,
                              struct perf_sample_data *data,
                              struct pt_regs *regs)
{
    struct task_struct *task;
    uint64_t pc = 0;
    int i;

    (void)data;

    if (regs) {
        pc = regs->pc;
    }

    g_total_hits++;
    g_last_hit_pc = pc;
    g_last_hit_event = (uint64_t)(uintptr_t)event;
    task = wuji_current_task();

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        if (!g_slots[i].used) {
            continue;
        }

        if (g_slots[i].event != event &&
            (pc < g_slots[i].addr || pc >= g_slots[i].addr + g_slots[i].len)) {
            continue;
        }

        g_slots[i].hits++;
        g_slots[i].last_pc = pc;
        if (!task || !g_user_enable_single_step ||
            !g_perf_event_disable_inatomic || !g_step_hook_installed) {
            g_step_failures++;
            if (event && g_perf_event_disable_inatomic) {
                g_perf_event_disable_inatomic(event);
            }
            pr_err("wuji-hwbp: hit without step support task=%px enable=%px disable_event=%px hook=%d\n",
                   task, g_user_enable_single_step, g_perf_event_disable_inatomic,
                   g_step_hook_installed);
            return;
        }

        if (g_slots[i].stepping) {
            g_step_failures++;
            pr_err("wuji-hwbp: nested hit slot=%d pid=%d pc=0x%llx step_task=%px current=%px\n",
                   i, g_slots[i].pid, (unsigned long long)pc,
                   g_slots[i].step_task, task);
            return;
        }

        g_slots[i].stepping = true;
        g_slots[i].step_task = task;
        g_slots[i].step_starts++;
        g_step_starts++;
        g_perf_event_disable_inatomic(event);
        g_user_enable_single_step(task);
        return;
    }

    g_unknown_hits++;
}

static void wuji_single_step_before(hook_fargs3_t *fargs, void *udata)
{
    struct task_struct *task;
    struct pt_regs *regs;
    uint64_t pc = 0;
    int i;

    (void)udata;

    task = wuji_current_task();
    regs = fargs ? (struct pt_regs *)(uintptr_t)fargs->arg2 : NULL;
    if (regs) {
        pc = regs->pc;
    }

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        if (!g_slots[i].used || !g_slots[i].stepping ||
            g_slots[i].step_task != task) {
            continue;
        }

        if (g_user_disable_single_step) {
            g_user_disable_single_step(task);
        }

        if (g_slots[i].event && g_perf_event_enable) {
            g_perf_event_enable(g_slots[i].event);
        }

        g_slots[i].stepping = false;
        g_slots[i].step_task = NULL;
        g_slots[i].step_completes++;
        g_slots[i].last_step_pc = pc;
        g_step_completes++;

        if (fargs) {
            fargs->ret = 0;
            fargs->skip_origin = 1;
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

static int count_active_slots(void)
{
    int i;
    int active = 0;

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        if (g_slots[i].used) {
            active++;
        }
    }

    return active;
}

static long worker_uninstall_slot(int i)
{
    struct perf_event *event;
    int ret;

    if (i < 0 || i >= WUJI_HWBP_MAX || !g_slots[i].used) {
        return -ENOENT;
    }

    event = g_slots[i].event;

    if (g_slots[i].stepping && g_slots[i].step_task &&
        g_user_disable_single_step) {
        g_user_disable_single_step(g_slots[i].step_task);
    }
    g_slots[i].stepping = false;
    g_slots[i].step_task = NULL;

    if (event && !g_unregister_hw_breakpoint) {
        ret = resolve_symbols();
        if (ret) {
            return ret;
        }
    }

    if (event && g_unregister_hw_breakpoint) {
        g_unregister_hw_breakpoint(event);
    }

    memset(&g_slots[i], 0, sizeof(g_slots[i]));
    return 0;
}

static long worker_uninstall_handle(uint64_t handle)
{
    int i;
    long ret;

    g_uninstall_attempts++;
    g_last_worker_error = 0;
    if (!handle) {
        g_uninstall_failures++;
        g_last_worker_error = -EINVAL;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: invalid handle\n");
        return g_last_worker_error;
    }

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        if (g_slots[i].used && (uint64_t)(uintptr_t)g_slots[i].event == handle) {
            ret = worker_uninstall_slot(i);
            if (ret) {
                g_uninstall_failures++;
                g_last_worker_error = (int)ret;
                snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                         "error: uninstall handle=0x%llx ret=%ld\n",
                         (unsigned long long)handle, ret);
                return ret;
            }

            snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                     "ok: uninstalled handle=0x%llx slot=%d\n",
                     (unsigned long long)handle, i);
            pr_info("wuji-hwbp: %s", g_last_worker_msg);
            if (count_active_slots() == 0) {
                remove_step_hook();
            }
            return 0;
        }
    }

    g_uninstall_failures++;
    g_last_worker_error = -ENOENT;
    snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
             "error: handle not found 0x%llx\n",
             (unsigned long long)handle);
    return -ENOENT;
}

static long worker_uninstall_all(void)
{
    int i;
    int cleared = 0;
    long first_ret = 0;
    long ret;

    g_uninstall_attempts++;
    g_last_worker_error = 0;

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        if (!g_slots[i].used) {
            continue;
        }

        ret = worker_uninstall_slot(i);
        if (ret && !first_ret) {
            first_ret = ret;
        } else if (!ret) {
            cleared++;
        }
    }

    if (first_ret) {
        g_uninstall_failures++;
        g_last_worker_error = (int)first_ret;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: clear ret=%ld cleared=%d\n", first_ret, cleared);
        pr_info("wuji-hwbp: %s", g_last_worker_msg);
        return first_ret;
    }

    snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
             "ok: cleared slots=%d\n", cleared);
    pr_info("wuji-hwbp: %s", g_last_worker_msg);
    if (count_active_slots() == 0) {
        remove_step_hook();
    }
    return 0;
}

static long worker_install_exec_breakpoint(pid_t pid, uint64_t addr, uint64_t len)
{
    struct perf_event_attr attr;
    struct perf_event *event;
    struct pid *pid_ref;
    struct task_struct *task;
    int slot;
    int ret;
    int task_ref = 0;

    g_install_attempts++;
    g_last_worker_error = 0;
    if (pid <= 0 || !addr) {
        g_install_failures++;
        g_last_worker_error = -EINVAL;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: invalid pid/address\n");
        return g_last_worker_error;
    }
    if (!validate_len(len)) {
        g_install_failures++;
        g_last_worker_error = -EINVAL;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: invalid breakpoint length\n");
        return g_last_worker_error;
    }

    ret = resolve_symbols();
    if (ret) {
        g_install_failures++;
        g_last_worker_error = ret;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: required symbols missing ret=%d\n", ret);
        return ret;
    }

    slot = find_free_slot();
    if (slot < 0) {
        g_install_failures++;
        g_last_worker_error = -ENOSPC;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: no free hwbp slot\n");
        return g_last_worker_error;
    }

    pid_ref = g_find_get_pid(pid);
    if (!pid_ref) {
        g_install_failures++;
        g_last_worker_error = -ESRCH;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: pid not found\n");
        return g_last_worker_error;
    }

    if (g_get_pid_task && g_put_task_struct) {
        task = g_get_pid_task(pid_ref, 0);
        task_ref = task ? 1 : 0;
    } else {
        task = g_pid_task(pid_ref, 0);
    }
    if (!task) {
        g_put_pid(pid_ref);
        g_install_failures++;
        g_last_worker_error = -ESRCH;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: task not found\n");
        return g_last_worker_error;
    }

    ret = ensure_step_hook();
    if (ret) {
        if (task_ref) {
            g_put_task_struct(task);
        }
        g_put_pid(pid_ref);
        g_install_failures++;
        g_last_worker_error = ret;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: single-step hook unavailable ret=%d\n", ret);
        return ret;
    }

    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.sample_period = 1;
    attr.bp_type = HW_BREAKPOINT_X;
    attr.bp_addr = addr;
    attr.bp_len = len;
    attr.disabled = 0;
    attr.pinned = 1;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;

    snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
             "worker: registering pid=%d addr=0x%llx len=%llu\n",
             pid, (unsigned long long)addr, (unsigned long long)len);
    pr_info("wuji-hwbp: %s", g_last_worker_msg);

    event = g_register_user_hw_breakpoint(&attr, wuji_hwbp_handler, NULL, task);
    if (task_ref) {
        g_put_task_struct(task);
    }
    g_put_pid(pid_ref);

    if (IS_ERR(event)) {
        ret = (int)PTR_ERR(event);
        if (count_active_slots() == 0) {
            remove_step_hook();
        }
        g_install_failures++;
        g_last_worker_error = ret;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: register_user_hw_breakpoint ret=%d\n", ret);
        pr_info("wuji-hwbp: %s", g_last_worker_msg);
        return ret;
    }
    if (!event) {
        if (count_active_slots() == 0) {
            remove_step_hook();
        }
        g_install_failures++;
        g_last_worker_error = -EINVAL;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: register_user_hw_breakpoint returned NULL\n");
        return g_last_worker_error;
    }

    g_slots[slot].used = true;
    g_slots[slot].pid = pid;
    g_slots[slot].addr = addr;
    g_slots[slot].len = len;
    g_slots[slot].hits = 0;
    g_slots[slot].last_pc = 0;
    g_slots[slot].event = event;

    snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
             "ok: slot=%d handle=0x%llx pid=%d addr=0x%llx len=%llu\n",
             slot, (unsigned long long)(uintptr_t)event, pid,
             (unsigned long long)addr, (unsigned long long)len);
    pr_info("wuji-hwbp: %s", g_last_worker_msg);
    return 0;
}

static int wuji_hwbp_worker(void *data)
{
    int req_type;
    pid_t pid;
    uint64_t addr;
    uint64_t len;
    uint64_t handle;
    long ret;

    (void)data;

    WUJI_WRITE_ONCE(g_worker_alive, 1);
    req_type = WUJI_READ_ONCE(g_req_type);
    pid = g_req_pid;
    addr = g_req_addr;
    len = g_req_len;
    handle = g_req_handle;

    switch (req_type) {
    case WUJI_REQ_INSTALL:
        ret = worker_install_exec_breakpoint(pid, addr, len);
        break;
    case WUJI_REQ_UNINSTALL:
        ret = worker_uninstall_handle(handle);
        break;
    case WUJI_REQ_CLEAR:
        ret = worker_uninstall_all();
        break;
    default:
        ret = -EINVAL;
        g_last_worker_error = (int)ret;
        snprintf(g_last_worker_msg, sizeof(g_last_worker_msg),
                 "error: unknown worker request=%d\n", req_type);
        pr_info("wuji-hwbp: %s", g_last_worker_msg);
        break;
    }

    g_last_worker_error = (int)ret;
    g_done_seq = g_submit_seq;
    barrier();
    WUJI_WRITE_ONCE(g_req_type, WUJI_REQ_NONE);
    WUJI_WRITE_ONCE(g_worker_busy, WUJI_REQ_NONE);
    WUJI_WRITE_ONCE(g_worker_alive, 0);
    g_worker_task = NULL;
    return 0;
}

static long submit_worker_request(int req_type, pid_t pid, uint64_t addr,
                                  uint64_t len, uint64_t handle,
                                  char *__user out_msg, int outlen)
{
    char reply[256];
    uint64_t seq;
    int ret;

    if (WUJI_READ_ONCE(g_req_type) != WUJI_REQ_NONE ||
        WUJI_READ_ONCE(g_worker_busy) != WUJI_REQ_NONE ||
        WUJI_READ_ONCE(g_worker_alive) || g_worker_task) {
        snprintf(reply, sizeof(reply),
                 "error: worker busy pending=%d busy=%d alive=%d submit_seq=%llu done_seq=%llu last=%s",
                 WUJI_READ_ONCE(g_req_type), WUJI_READ_ONCE(g_worker_busy),
                 WUJI_READ_ONCE(g_worker_alive),
                 (unsigned long long)g_submit_seq,
                 (unsigned long long)g_done_seq, g_last_worker_msg);
        return copy_reply(out_msg, outlen, reply);
    }

    g_req_pid = pid;
    g_req_addr = addr;
    g_req_len = len;
    g_req_handle = handle;
    seq = ++g_submit_seq;
    barrier();
    WUJI_WRITE_ONCE(g_worker_busy, req_type);
    WUJI_WRITE_ONCE(g_req_type, req_type);

    ret = start_worker();
    if (ret) {
        WUJI_WRITE_ONCE(g_req_type, WUJI_REQ_NONE);
        WUJI_WRITE_ONCE(g_worker_busy, WUJI_REQ_NONE);
        WUJI_WRITE_ONCE(g_worker_alive, 0);
        g_worker_task = NULL;
        g_last_worker_error = ret;
        snprintf(reply, sizeof(reply), "error: worker unavailable ret=%d\n", ret);
        return copy_reply(out_msg, outlen, reply);
    }

    snprintf(reply, sizeof(reply),
             "queued: seq=%llu req=%d pid=%d addr=0x%llx len=%llu handle=0x%llx\n",
             (unsigned long long)seq, req_type, pid,
             (unsigned long long)addr, (unsigned long long)len,
             (unsigned long long)handle);
    return copy_reply(out_msg, outlen, reply);
}

static long install_exec_breakpoint(pid_t pid, uint64_t addr, uint64_t len,
                                    char *__user out_msg, int outlen)
{
    if (pid <= 0 || !addr) {
        return copy_reply(out_msg, outlen, "error: invalid pid/address\n");
    }
    if (!validate_len(len)) {
        return copy_reply(out_msg, outlen, "error: invalid breakpoint length\n");
    }

    return submit_worker_request(WUJI_REQ_INSTALL, pid, addr, len, 0,
                                 out_msg, outlen);
}

static long prepare_exec_breakpoint(pid_t pid, uint64_t addr, uint64_t len,
                                    char *__user out_msg, int outlen)
{
    struct pid *pid_ref;
    struct task_struct *task;
    int task_ref = 0;
    int ret;
    char reply[256];

    g_prepare_attempts++;
    g_last_prepare_error = 0;

    if (pid <= 0 || !addr) {
        g_prepare_failures++;
        g_last_prepare_error = -EINVAL;
        return copy_reply(out_msg, outlen, "error: invalid pid/address\n");
    }
    if (!validate_len(len)) {
        g_prepare_failures++;
        g_last_prepare_error = -EINVAL;
        return copy_reply(out_msg, outlen, "error: invalid breakpoint length\n");
    }

    ret = resolve_symbols();
    if (ret) {
        g_prepare_failures++;
        g_last_prepare_error = ret;
        snprintf(reply, sizeof(reply), "error: required symbols missing ret=%d\n", ret);
        return copy_reply(out_msg, outlen, reply);
    }

    ret = resolve_step_symbols();
    if (ret) {
        g_prepare_failures++;
        g_last_prepare_error = ret;
        snprintf(reply, sizeof(reply), "error: step symbols missing ret=%d\n", ret);
        return copy_reply(out_msg, outlen, reply);
    }

    pid_ref = g_find_get_pid(pid);
    if (!pid_ref) {
        g_prepare_failures++;
        g_last_prepare_error = -ESRCH;
        return copy_reply(out_msg, outlen, "error: pid not found\n");
    }

    if (g_get_pid_task && g_put_task_struct) {
        task = g_get_pid_task(pid_ref, 0);
        task_ref = task ? 1 : 0;
    } else {
        task = g_pid_task(pid_ref, 0);
    }

    if (task_ref) {
        g_put_task_struct(task);
    }
    g_put_pid(pid_ref);

    if (!task) {
        g_prepare_failures++;
        g_last_prepare_error = -ESRCH;
        return copy_reply(out_msg, outlen, "error: task not found\n");
    }

    snprintf(reply, sizeof(reply),
             "ok: prepare-only pid=%d addr=0x%llx len=%llu symbols=1 step_symbols=1 install=async-worker\n",
             pid, (unsigned long long)addr, (unsigned long long)len);
    return copy_reply(out_msg, outlen, reply);
}

static long status(char *__user out_msg, int outlen)
{
    char reply[2048];
    int off = 0;
    int i;
    int symbols_ok;
    int step_symbols_ok;

    symbols_ok = g_register_user_hw_breakpoint && g_unregister_hw_breakpoint &&
                 g_find_get_pid && g_put_pid &&
                 ((g_get_pid_task && g_put_task_struct) || g_pid_task) ? 1 : 0;
    step_symbols_ok = g_user_enable_single_step && g_user_disable_single_step &&
                      g_perf_event_disable_inatomic && g_perf_event_enable &&
                      g_single_step_handler_addr ? 1 : 0;

    off += snprintf(reply + off, sizeof(reply) - off,
                    "wuji-hwbp: mode=single-step slots=%d total_hits=%llu unknown_hits=%llu last_hit_pc=0x%llx last_hit_event=0x%llx step_starts=%llu step_completes=%llu step_failures=%llu step_symbols=%d step_hook=%d single_step_handler=0x%llx last_step=%d install_attempts=%llu install_failures=%llu uninstall_attempts=%llu uninstall_failures=%llu prepare_attempts=%llu prepare_failures=%llu symbols=%d resolver=%s last_resolve=%d last_prepare=%d worker_alive=%d worker_busy=%d pending=%d submit_seq=%llu done_seq=%llu last_worker=%d last_msg=%s\n",
                    WUJI_HWBP_MAX, (unsigned long long)g_total_hits,
                    (unsigned long long)g_unknown_hits,
                    (unsigned long long)g_last_hit_pc,
                    (unsigned long long)g_last_hit_event,
                    (unsigned long long)g_step_starts,
                    (unsigned long long)g_step_completes,
                    (unsigned long long)g_step_failures,
                    step_symbols_ok, g_step_hook_installed,
                    (unsigned long long)g_single_step_handler_addr,
                    g_last_step_error,
                    (unsigned long long)g_install_attempts,
                    (unsigned long long)g_install_failures,
                    (unsigned long long)g_uninstall_attempts,
                    (unsigned long long)g_uninstall_failures,
                    (unsigned long long)g_prepare_attempts,
                    (unsigned long long)g_prepare_failures,
                    symbols_ok, g_resolver_name, g_last_resolve_error,
                    g_last_prepare_error, WUJI_READ_ONCE(g_worker_alive),
                    WUJI_READ_ONCE(g_worker_busy), WUJI_READ_ONCE(g_req_type),
                    (unsigned long long)g_submit_seq,
                    (unsigned long long)g_done_seq, g_last_worker_error,
                    g_last_worker_msg);

    if (off < 0) {
        off = 0;
    } else if (off >= (int)sizeof(reply)) {
        off = (int)sizeof(reply) - 1;
    }

    for (i = 0; i < WUJI_HWBP_MAX && off < (int)sizeof(reply); ++i) {
        if (!g_slots[i].used) {
            continue;
        }

        off += snprintf(reply + off, sizeof(reply) - off,
                        "slot=%d handle=0x%llx pid=%d addr=0x%llx len=%llu hits=%llu last_pc=0x%llx stepping=%d step_starts=%llu step_completes=%llu last_step_pc=0x%llx\n",
                        i, (unsigned long long)(uintptr_t)g_slots[i].event,
                        g_slots[i].pid, (unsigned long long)g_slots[i].addr,
                        (unsigned long long)g_slots[i].len,
                        (unsigned long long)g_slots[i].hits,
                        (unsigned long long)g_slots[i].last_pc,
                        g_slots[i].stepping ? 1 : 0,
                        (unsigned long long)g_slots[i].step_starts,
                        (unsigned long long)g_slots[i].step_completes,
                        (unsigned long long)g_slots[i].last_step_pc);
        if (off < 0) {
            off = 0;
        } else if (off >= (int)sizeof(reply)) {
            off = (int)sizeof(reply) - 1;
        }
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
    g_unknown_hits = 0;
    g_last_hit_pc = 0;
    g_last_hit_event = 0;
    g_step_starts = 0;
    g_step_completes = 0;
    g_step_failures = 0;
    g_last_step_error = 0;
    g_step_hook_installed = 0;
    g_single_step_handler_addr = 0;
    g_install_attempts = 0;
    g_install_failures = 0;
    g_uninstall_attempts = 0;
    g_uninstall_failures = 0;
    g_prepare_attempts = 0;
    g_prepare_failures = 0;
    g_submit_seq = 0;
    g_done_seq = 0;
    g_req_type = WUJI_REQ_NONE;
    g_worker_alive = 0;
    g_worker_busy = WUJI_REQ_NONE;
    g_req_pid = 0;
    g_req_addr = 0;
    g_req_len = 0;
    g_req_handle = 0;
    g_worker_task = NULL;
    g_last_prepare_error = 0;
    g_last_worker_error = 0;
    g_last_worker_msg[0] = '\0';

    ret = resolve_symbols();
    if (ret) {
        pr_err("wuji-hwbp: loaded without hw breakpoint symbols ret=%d\n", ret);
        return 0;
    }

    pr_info("wuji-hwbp: loaded async-worker\n");
    return 0;
}

static long wuji_hwbp_control(const char *args, char *__user out_msg, int outlen)
{
    pid_t pid = 0;
    unsigned long long addr = 0;
    unsigned long long len = HW_BREAKPOINT_LEN_4;
    unsigned long long handle = 0;
    int matched;

    if (!args || !*args) {
        return copy_reply(out_msg, outlen,
                          "usage: status | prepare <pid> <hex_addr> [len] | install <pid> <hex_addr> [len] | uninstall <handle> | clear\n");
    }

    if (!strcmp(args, "status")) {
        (void)resolve_symbols();
        (void)resolve_step_symbols();
        return status(out_msg, outlen);
    }

    matched = sscanf(args, "install %d %llx %llu", &pid, &addr, &len);
    if (matched >= 2) {
        return install_exec_breakpoint(pid, (uint64_t)addr, (uint64_t)len,
                                       out_msg, outlen);
    }

    len = HW_BREAKPOINT_LEN_4;
    matched = sscanf(args, "prepare %d %llx %llu", &pid, &addr, &len);
    if (matched >= 2) {
        return prepare_exec_breakpoint(pid, (uint64_t)addr, (uint64_t)len,
                                       out_msg, outlen);
    }

    matched = sscanf(args, "uninstall %llx", &handle);
    if (matched == 1) {
        return submit_worker_request(WUJI_REQ_UNINSTALL, 0, 0, 0,
                                     (uint64_t)handle, out_msg, outlen);
    }

    if (!strcmp(args, "clear")) {
        return submit_worker_request(WUJI_REQ_CLEAR, 0, 0, 0, 0,
                                     out_msg, outlen);
    }

    return copy_reply(out_msg, outlen,
                      "error: unknown command; use status | prepare <pid> <hex_addr> [len] | install <pid> <hex_addr> [len] | uninstall <handle> | clear\n");
}

static long wuji_hwbp_exit(void *__user reserved)
{
    int active = 0;
    int i;

    (void)reserved;

    for (i = 0; i < WUJI_HWBP_MAX; ++i) {
        if (g_slots[i].used) {
            active++;
        }
    }

    if (WUJI_READ_ONCE(g_worker_alive) ||
        WUJI_READ_ONCE(g_worker_busy) != WUJI_REQ_NONE || g_worker_task) {
        pr_err("wuji-hwbp: unsafe unload while worker active alive=%d busy=%d active_slots=%d\n",
               WUJI_READ_ONCE(g_worker_alive), WUJI_READ_ONCE(g_worker_busy),
               active);
        return -EBUSY;
    }

    if (active) {
        pr_err("wuji-hwbp: unsafe unload with active hardware breakpoints active_slots=%d; run clear and wait done first\n",
               active);
        return -EBUSY;
    }

    remove_step_hook();
    pr_info("wuji-hwbp: unloaded idle\n");
    return 0;
}

KPM_INIT(wuji_hwbp_init);
KPM_CTL0(wuji_hwbp_control);
KPM_EXIT(wuji_hwbp_exit);

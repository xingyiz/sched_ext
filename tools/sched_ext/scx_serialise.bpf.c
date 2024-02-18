#include <scx/common.bpf.h>
#include <string.h>

char _license[] SEC("license") = "GPL";

/* =================================
 * Stats
 * ================================= */

struct user_exit_info uei;
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 2); /* [local, global] */
} stats SEC(".maps");

static void stat_inc(u32 idx) {
    u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
    if (cnt_p)
        (*cnt_p)++;
}

/* =================================
 * Macros
 * ================================= */

#define SCHED_EXT 7
#define MAX_THREADS 95

const volatile u32 debug = 2;
#define warn(fmt, args...) bpf_printk(fmt, ##args)
#define dbg(fmt, args...)                   \
    do {                                    \
        if (debug) bpf_printk(fmt, ##args); \
    } while (0)
#define trace(fmt, args...)                     \
    do {                                        \
        if (debug > 1) bpf_printk(fmt, ##args); \
    } while (0)

/* =================================
 * Setup for serialise
 * ================================= */

bool yield_flag = false;
// bool preempt_me = false;

struct task_ctx {
    s32 priority;
    bool enqueued;
    struct bpf_spin_lock lock;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, pid_t);              // pid
    __type(value, struct task_ctx);  // priority, enqueued
    __uint(max_entries, MAX_THREADS);
} task_ctx_map SEC(".maps");

struct tctx_callback_ctx {
    pid_t highest_priority_pid;
    s32 highest_priority;
    u32 num_enqueued;
};

/* =================================
 * PCT set up & helper functions
 * ================================= */

const volatile u32 depth = 3, seed = 0xdeadbeef;
u32 iterations, max_num_events, num_events, schedule_counter;

/* xorshift random generator */
struct xorshift32_state {
    u32 a;
} rng_state;

/* The state must be initialized to non-zero */
u32 xorshift32(struct xorshift32_state *state) {
    u32 x = state->a;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return state->a = x;
}

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, MAX_THREADS);
} pct_priorities SEC(".maps");

static inline void swap(u32 *a, u32 *b) {
    u32 temp = *a;
    *a = *b;
    *b = temp;
}

static void shuffle_prios(struct xorshift32_state *state) {
    u32 *prio_value, *value_i, *value_j;
    u32 index, i, actual_i, actual_j;

    bpf_for(i, depth, depth + MAX_THREADS) {
        index = i - depth;
        prio_value = bpf_map_lookup_elem(&pct_priorities, &index);
        if (prio_value)
            *prio_value = i;
    }

    bpf_for(i, 1, MAX_THREADS) {
        actual_i = MAX_THREADS - i;
        actual_j = xorshift32(state) % actual_i;
        value_i = bpf_map_lookup_elem(&pct_priorities, &actual_i);
        value_j = bpf_map_lookup_elem(&pct_priorities, &actual_j);
        if (value_i && value_j) {
            swap(value_i, value_j);
        }
    }
}

s32 assign_priority(pid_t pid) {
    u32 index = (u32)pid % MAX_THREADS;
    u32 *prio_value = bpf_map_lookup_elem(&pct_priorities, &index);
    if (prio_value)
        return *prio_value;

    return -1;
}

static inline void update_priority(pid_t pid, s32 new_prio) {
    u32 index = (u32)pid % MAX_THREADS;
    u32 *prio_value = bpf_map_lookup_elem(&pct_priorities, &index);
    if (prio_value)
        *prio_value = new_prio;
}

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, MAX_THREADS);  // should be depth - 1 tho, but this needs a constant
} pct_change_points SEC(".maps");

static void choose_change_points(struct xorshift32_state *state) {
    if (max_num_events == 0) {
        // set all change points to 0
        u32 i, n = depth - 1;
        bpf_for(i, 0, n) {
            u32 change_point = 0;
            long status = bpf_map_update_elem(&pct_change_points, &i, &change_point, BPF_ANY);
            if (status)
                warn("[choose_change_points] failed to update change_point[%d]: %d\n", i, change_point);
        }
        return;
    }

    u32 i, n, change_point;
    long status;

    n = depth - 1;
    if (n > MAX_THREADS) {
        warn("[choose_change_points] n: %d, MAX_THREADS: %d\n", n, MAX_THREADS);
        return;
    }

    bpf_for(i, 0, n) {
        /* NOTE: THERE MAY BE DUPLICATE CHANGE POINTS */
        change_point = (xorshift32(state) % max_num_events) + 1;  // [1, max_num_events]
        status = bpf_map_update_elem(&pct_change_points, &i, &change_point, BPF_ANY);
        if (status)
            warn("[choose_change_points] failed to update change_point[%d]: %d\n", i, change_point);
    }

    bpf_for(i, 0, n) {
        u32 *change_point = bpf_map_lookup_elem(&pct_change_points, &i);
        if (change_point)
            dbg("[choose_change_points] change_point[%d]: %d\n", i, *change_point);
    }
}

/* =================================
 * Helper functions
 * ================================= */

static bool check_policy(const struct task_struct *p) {
    int policy;
    long status;

    status = bpf_probe_read_kernel(&policy, sizeof(policy), &p->policy);
    if (status)
        return false;

    return policy == SCHED_EXT;
}

static inline int serialise_get_pid_tgid(struct task_struct *p, pid_t *pid, pid_t *tgid) {
    p = (struct task_struct *)bpf_get_current_task();
    if (!check_policy(p))
        return -1;

    u64 id = bpf_get_current_pid_tgid();
    *tgid = id >> 32;
    *pid = (u32)id;
    return 0;
}

static int tctx_map_insert(pid_t new_pid, s32 modify_prio, bool enqueued, bool should_exist) {
    long status;
    struct task_ctx zero = {}, *tctx;

    tctx = bpf_map_lookup_elem(&task_ctx_map, &new_pid);
    if (!tctx) {
        if (should_exist)
            return -1;

        /* add new element to map */
        status = bpf_map_update_elem(&task_ctx_map, &new_pid, &zero, BPF_NOEXIST);
        if (status)
            return status;

        tctx = bpf_map_lookup_elem(&task_ctx_map, &new_pid);
        if (!tctx)
            return -1;
    }

    bpf_spin_lock(&tctx->lock);
    if (modify_prio)
        tctx->priority = modify_prio;
    tctx->enqueued = enqueued;
    bpf_spin_unlock(&tctx->lock);

    return 0;
}

static inline int tctx_map_remove(pid_t pid) {
    long status;

    status = bpf_map_delete_elem(&task_ctx_map, &pid);
    if (status)
        return status;

    return 0;
}

static __u64 get_highest_priority(struct bpf_map *map, pid_t *key, struct task_ctx *tctx, struct tctx_callback_ctx *tcallbackctx) {
    bpf_spin_lock(&tctx->lock);

    if (tctx->enqueued) {
        if (tctx->priority > tcallbackctx->highest_priority) {
            tcallbackctx->highest_priority = tctx->priority;
            tcallbackctx->highest_priority_pid = *key;
        }
        tcallbackctx->num_enqueued++;
    }

    bpf_spin_unlock(&tctx->lock);
    return 0;
}

// static __u64 dump_error(struct bpf_map *map, pid_t *key, struct task_ctx *tctx, struct tctx_callback_ctx *tcallbackctx) {
//     dbg("[dump_error] pid: %d, priority: %d, enqueued: %d\n", *key, tctx->priority, tctx->enqueued);
//     return 0;
// }

static void dispatch_highest_priority_thread(struct tctx_callback_ctx *tcallbackctx) {
    // dbg("[dispatch] highest_priority_pid: %d, highest_priority: %d\n", tcallbackctx->highest_priority_pid, tcallbackctx->highest_priority);
    int status;
    pid_t dispatched_pid = -1;
    if (tcallbackctx->highest_priority_pid != -1) {
        /* dispatch highest priority thread */
        struct task_struct *highest_prio_p;
        dispatched_pid = tcallbackctx->highest_priority_pid;

        highest_prio_p = bpf_task_from_pid(dispatched_pid);
        if (!highest_prio_p) {
            warn("[dispatch] failed to get task_struct from pid: %d\n", dispatched_pid);
            return;
        }
        dbg("[dispatch] dispatching pid: %d, with priority: %d\n", dispatched_pid, tcallbackctx->highest_priority);
        scx_bpf_dispatch(highest_prio_p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
        bpf_task_release(highest_prio_p);
        status = tctx_map_insert(dispatched_pid, 0, false, true);
        if (status < 0) {
            warn("[dispatch] failed to update tctx for pid: %d\n", dispatched_pid);
            return;
        }
    }
}

/* =================================
 * SCX_SERIALISE FUNCTIONS
 * ================================= */
void BPF_STRUCT_OPS(serialise_enqueue, struct task_struct *p, u64 enq_flags) {
    pid_t pid = p->pid, tgid = p->tgid;
    dbg("[enqueue] pid: %d, tgid: %d, enq_flags: %d\n", pid, tgid, enq_flags);

    __sync_fetch_and_add(&num_events, 1);

    if (iterations == 0) {
        scx_bpf_dispatch(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, 0);
        return;
    }

    if (pid == tgid) {
        stat_inc(0);
    } else
        stat_inc(1);

    u32 n = depth - 1, i;
    s32 priority = -1;

    if (n > MAX_THREADS) {
        warn("[enqueue] n: %d, MAX_THREADS: %d\n", n, MAX_THREADS);
        return;
    }

    bpf_for(i, 0, n) {
        // check if num_events == change_point
        u32 *change_point = bpf_map_lookup_elem(&pct_change_points, &i);
        if (change_point) {
            if (num_events == *change_point) {
                priority = i + 1;
                update_priority(pid, priority);
                dbg("[enqueue] UPDATE pid: %d, priority: %d\n", pid, priority);
                break;
            }
        }
    }

    priority = assign_priority(pid);
    if (priority < 0) {
        warn("[enqueue] failed to assign priority for pid: %d\n", pid);
        return;
    }

    tctx_map_insert(pid, priority, true, false);
}

void BPF_STRUCT_OPS(serialise_dispatch, s32 cpu, struct task_struct *p) {
    int num_threads_alive;
    struct tctx_callback_ctx tcallbackctx = {
        .highest_priority_pid = -1,
        .highest_priority = -100,
        .num_enqueued = 0,
    };

    // if (preempt_me) {
    //     dbg("[dispatch] preempt_me: %d\n", preempt_me);
    //     preempt_me = false;
    //     scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
    //     return;
    // }

    num_threads_alive = bpf_for_each_map_elem(&task_ctx_map, get_highest_priority, &tcallbackctx, 0);
    if (num_threads_alive == -EINVAL) {
        warn("[dispatch] failed to iterate over task_ctx_map\n");
        return;
    }

    if (tcallbackctx.num_enqueued == num_threads_alive && num_threads_alive != 0) {
        dispatch_highest_priority_thread(&tcallbackctx);

    } else if (yield_flag) {
        // dbg("[dispatch] yield_flag: %d\n", yield_flag);
        yield_flag = false;
        dispatch_highest_priority_thread(&tcallbackctx);
    }

    // else if (num_threads_alive != 0 && tcallbackctx.num_enqueued != 0) {
    // dbg("[dispatch] threads_enqueued: %d, threads_alive: %d\n", tcallbackctx.num_enqueued, num_threads_alive);
    // bpf_for_each_map_elem(&task_ctx_map, dump_error, 0, 0);
    // }
}

bool BPF_STRUCT_OPS(serialise_yield, struct task_struct *from, struct task_struct *to) {
    dbg("[yield] from: %d\n", from->pid);

    /* tell dispatch that it's ok to dispatch */
    if (iterations > 0)
        yield_flag = true;

    /* set slice to 0 so that dispatch() will be called when its timeslot is up */
    from->scx.slice = 0;

    /* can't get ref to "to" despite null checks and task_acquire()
     * it's not impt so we don't care about it */
    return false;
}

void BPF_STRUCT_OPS(serialise_runnable, struct task_struct *p, u64 enq_flags) {
    trace("[runnable] pid: %d\n", p->pid);
}

void BPF_STRUCT_OPS(serialise_running, struct task_struct *p) {
    trace("[running] pid: %d\n", p->pid);
}

void BPF_STRUCT_OPS(serialise_stopping, struct task_struct *p, bool runnable) {
    trace("[stopping] pid: %d\n", p->pid);
}

void BPF_STRUCT_OPS(serialise_quiescent, struct task_struct *p, u64 deq_flags) {
    dbg("[quiescent] pid: %d\n", p->pid);
    if (iterations == 0)
        return;

    tctx_map_remove(p->pid);
}

void BPF_STRUCT_OPS(serialise_enable, struct task_struct *p) {
    if (!check_policy(p))
        return;

    trace("[enable] pid: %d\n", p->pid);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(serialise_init) {
    dbg("[init] scx_serialise init LMAO TEST \n");
    dbg("[init] depth: %d, seed: %d\n", depth, seed);
    rng_state.a = seed;
    shuffle_prios(&rng_state);
    iterations = 0;
    max_num_events = 0;
    num_events = 0;
    schedule_counter = 0;
    return 0;
}

void BPF_STRUCT_OPS(serialise_exit, struct scx_exit_info *ei) {
    uei_record(&uei, ei);
}

SEC(".struct_ops.link")
struct sched_ext_ops serialise_ops = {
    // .select_cpu = (void *)serialise_select_cpu,
    .enqueue = (void *)serialise_enqueue,
    // .dequeue = (void *)serialise_dequeue,
    .dispatch = (void *)serialise_dispatch,
    .runnable = (void *)serialise_runnable,
    .running = (void *)serialise_running,
    .stopping = (void *)serialise_stopping,
    .quiescent = (void *)serialise_quiescent,
    .yield = (void *)serialise_yield,
    // .prep_enable = (void *)serialise_prep_enable,
    .enable = (void *)serialise_enable,
    .init = (void *)serialise_init,
    .exit = (void *)serialise_exit,
    .flags = SCX_OPS_ENQ_LAST,
    .name = "serialise",
};

/* =================================
 * Hooks
 * ================================= */
SEC("tp/sched/sched_process_exit")
int sched_process_exit_tp(struct trace_event_raw_sched_process_template *args) {
    long status;
    struct task_struct *p = NULL;
    pid_t pid, tgid;

    status = serialise_get_pid_tgid(p, &pid, &tgid);
    if (status)
        return 0;

    if (pid != tgid) {
        dbg("[sched_process_exit] THREAD pid: %d, tgid: %d\n", pid, tgid);
    } else {
        dbg("[sched_process_exit] PROCESS pid: %d, tgid: %d\n", pid, tgid);
        __sync_fetch_and_add(&iterations, 1);
        if (num_events > max_num_events)
            max_num_events = num_events;
        else if ((num_events - max_num_events) > 0 && (num_events - max_num_events) > 18)
            max_num_events = num_events;
        else if ((num_events - max_num_events) < 0 && (num_events - max_num_events) < -18)
            max_num_events = num_events;
        num_events = 0;

        dbg("[sched_process_exit] iterations: %d, max_num_events: %d\n", iterations, max_num_events);

        if (iterations > 0) {
            shuffle_prios(&rng_state);
            choose_change_points(&rng_state);
        }
    }

    return 0;
}

SEC("kprobe/__udelay")
int BPF_KPROBE(udelay_probe) {
    struct task_struct *p = (struct task_struct *)bpf_get_current_task();
    if (!check_policy(p))
        return 0;

    __sync_fetch_and_add(&schedule_counter, 1);
    if (schedule_counter == 300) {
        schedule_counter = 0;
        dbg("[udelay_probe] bpf schedule called\n");
        bpf_schedule();
    }
    return 0;
}

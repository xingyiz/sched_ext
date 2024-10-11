/*
 * scx_serialise: simple scheduler to serialise the execution of threads
 *
 * This scheduler attempts to serialise the execution of threads by 
 * dispatching the highest priority thread in the system, only when all
 * threads have been enqueued.
 * 
 */
#include <scx/common.bpf.h>
#include <string.h>
#include <limits.h>
#include "scx_simple_signal.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * The maximum number of threads that is supported by the scheduler.
 *
 * This value defines the size of the map used to store the priorities 
 * and enqueued status of each thread. Adjust this value according to 
 * how many threads you expect the program-under-test to create.
 */
#define MAX_THREADS 50

const volatile u32 seed = 0xdeadbeef;

/* xorshift random generator */
struct xorshift32_state rng_state;

/* The state must be initialized to non-zero */
u32 xorshift32(struct xorshift32_state *state)
{
	u32 x = state->a;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	return state->a = x;
}

/* Communication channels to/from user-space */
struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256 * 1024);
} user_ringbuf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} kernel_ringbuf SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct sched_req);
	__uint(max_entries, 10);
} sched_req_map SEC(".maps");


/*
 * Task context that is used to store the priority and enqueued status of
 * each task. These variables are protected by a spin lock to sieve out
 * concurrent updates.
 */
struct task_ctx {
	s32 priority;
	u32 id; // id of executor
	bool enqueued;
	struct bpf_spin_lock lock;
};

/*
 * The map used to store the task context of each task. The key is the pid
 * of the task and the value is the task context.
 * 
 * This map is iterated in dispatch() to determine the total number of runnable
 * tasks, the number of enqueued tasks, and the highest priority task.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, pid_t); /* pid of the task */
	__type(value, struct task_ctx);
	__uint(max_entries, MAX_THREADS);
} task_ctx_map SEC(".maps");

/*
 * Dispatch statistics. This map is used to keep track of the number of times
 * a main thread or a worker thread has been dispatched.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 2); /* [main, worker] */
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

static long receive_req(struct bpf_dynptr *dynptr, void *context)
{
	struct sched_req req;

	if (bpf_dynptr_read(&req, sizeof(req), dynptr, 0, 0) < 0) {
		bpf_printk("[receive_req] error reading dynptr data");
		return 0;
	}

	if (bpf_map_update_elem(&sched_req_map, &req.pid, &req, BPF_ANY) < 0) {
		bpf_printk("[receive_req] fail to add sched request");
	}

	rng_state.a = req.rng_seed;
	bpf_printk("[receive_req] rng seed is %d", req.rng_seed);

	return 0;
}

/* The number used in the Linux kernel for the sched_ext scheduling policy */
#define SCHED_EXT 7

const volatile u32 use_udelay = 0;

/* Debugging macros */
const volatile u32 debug = 1;

#define warn(fmt, args...) bpf_printk(fmt, ##args)

#define dbg(fmt, args...)                        \
	do {                                     \
		if (debug)                       \
			bpf_printk(fmt, ##args); \
	} while (0)

#define trace(fmt, args...)                      \
	do {                                     \
		if (debug > 1)                   \
			bpf_printk(fmt, ##args); \
	} while (0)

/*
 * This flag indicates whether a task has yielded. It is used to signal
 * the dispatch function to dispatch the next highest priority thread.
 */
// bool yield_flag = false;

/*
 * Insert or update the task context of a task in the task context map. 
 * Call this fn when a task is enqueued, dequeued, or dispatched.
 */
static int tctx_map_insert(pid_t new_pid, s32 modify_prio, bool enqueued,
			   bool should_exist)
{
	long status;
	struct task_ctx zero = {}, *tctx;

	tctx = bpf_map_lookup_elem(&task_ctx_map, &new_pid);
	if (!tctx) {
		/* If task should exist, flag this out and return error */
		if (should_exist) {
			warn("[tctx_map_insert] task context does not exist for pid: %d\n",
			     new_pid);
			return -1;
		}

		/* Otherwise, add new element to map */
		status = bpf_map_update_elem(&task_ctx_map, &new_pid, &zero,
					     BPF_NOEXIST);
		if (status) {
			warn("[tctx_map_insert] failed to add task context for pid: %d\n",
			     new_pid);
			return status;
		}

		/* Retrieve the newly added element so that tctx is not NULL*/
		tctx = bpf_map_lookup_elem(&task_ctx_map, &new_pid);
		if (!tctx) {
			warn("[tctx_map_insert] failed to get task context for pid: %d\n",
			     new_pid);
			return -1;
		}
	}

	/* Update priority and enqueued status */
	bpf_spin_lock(&tctx->lock);
	if (modify_prio)
		tctx->priority = modify_prio;
	tctx->enqueued = enqueued;
	bpf_spin_unlock(&tctx->lock);

	return 0;
}

/*
 * Remove the task context of a task from the task context map.
 */
static int tctx_map_remove(pid_t pid)
{
	long status;

	status = bpf_map_delete_elem(&task_ctx_map, &pid);
	if (status) {
		warn("[tctx_map_remove] failed to remove task context for pid: %d\n",
		     pid);
		return status;
	}

	return 0;
}

/*
 * The callback context used in dispatch() to store the highest priority task
 * and the number of enqueued tasks.
 */
struct tctx_callback_ctx {
	pid_t highest_priority_pid;
	s32 highest_priority;
	u32 num_enqueued;
};

/*
 * Callback function used in dispatch() to iterate over the task context map
 * to determine the highest priority task and the number of enqueued tasks.
 */
static __u64 get_highest_priority(struct bpf_map *map, pid_t *key,
				  struct task_ctx *tctx,
				  struct tctx_callback_ctx *tcallbackctx)
{
	bpf_spin_lock(&tctx->lock);

	if (tctx->enqueued) {
		/* 
		 * If two tasks have the same priority, the one that is stored 
		 * first in the map will be dispatched first. Random Walk may
		 * have this issue, but PCT should not have this issue.
		 */
		if (tctx->priority > tcallbackctx->highest_priority) {
			tcallbackctx->highest_priority = tctx->priority;
			tcallbackctx->highest_priority_pid = *key;
		}
		tcallbackctx->num_enqueued++;
	}

	bpf_spin_unlock(&tctx->lock);
	// dbg("[highest_prio] --- %d \n", tctx->priority);
	return 0;
}

/* 
 * Heartbeat timer to periodically trigger reschedules in the system.
 *
 * This hopefully helps to trigger sufficient reschedules so that the 
 * priority of the long-running task can be updated (in PCT) and prevent
 * the sched_ext watchdog from auto-killing the scheduler.
 */
#define NSEC_PER_SEC 1000000000L
#define CLOCK_BOOTTIME 7
#define SCHED_DELAY_SEC 30

struct heartbeat {
	struct bpf_timer timer;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct heartbeat);
} heartbeat_timer SEC(".maps");

/* 
 * The callback function for the heartbeat timer. This function is called
 * every second to trigger a reschedule.
 */
static int heartbeat_timer_fn(void *map, u32 *key, struct bpf_timer *timer)
{
	int status = 0;

	/* 
	 * Kick the scheduler.
	 * TODO: Try to keep track of whether the same task is running or not.
	 */
	dbg("[heartbeat_timer_fn] kicking the scheduler\n");
	bpf_schedule();

	/* Restart the timer */
	status = bpf_timer_start(timer, SCHED_DELAY_SEC * NSEC_PER_SEC, 0);
	if (status) {
		warn("[heartbeat_timer_fn] failed to start timer\n");
	}

	return 0;
}

/*
 * Initialise the heartbeat timer.
 */
static int heartbeat_timer_init(void)
{
	struct bpf_timer *timer;
	u32 key = 0;
	int status;

	timer = bpf_map_lookup_elem(&heartbeat_timer, &key);
	if (!timer) {
		warn("[heartbeat_timer_init] failed to get timer\n");
		return -1;
	}

	bpf_timer_init(timer, &heartbeat_timer, CLOCK_BOOTTIME);
	bpf_timer_set_callback(timer, &heartbeat_timer_fn);
	status = bpf_timer_start(timer, SCHED_DELAY_SEC * NSEC_PER_SEC, 0);
	if (status) {
		warn("[heartbeat_timer_init] failed to start timer\n");
		return status;
	}

	return 0;
}

/*
 * Return true if the target task @p is a kernel thread.
 */
static inline bool is_kthread(const struct task_struct *p)
{
	return !!(p->flags & PF_KTHREAD);
}

/*
 * Return true if the target task @p is a sched_ext task.
 */
static inline bool is_sched_ext(const struct task_struct *p)
{
	int policy;
	long status;

	status = bpf_probe_read_kernel(&policy, sizeof(policy), &p->policy);
	if (status)
		return false;

	return policy == SCHED_EXT;
}

// static __u64 dump_error(struct bpf_map *map, pid_t *key, struct task_ctx *tctx, struct tctx_callback_ctx *tcallbackctx) {
//     dbg("[dump_error] pid: %d, priority: %d, enqueued: %d\n", *key, tctx->priority, tctx->enqueued);
//     return 0;
// }

const volatile int use_pct = 0;
const volatile int use_random_priority_walk = 0;
const volatile int use_random_walk = 1;

#include "scx_scheduling_algorithms.c"


static u32 get_executor_id(const struct task_struct *p) {
	char comm[TASK_COMM_LEN];
	u32 eid;
	long status;

	status = bpf_probe_read_kernel(&comm, sizeof(comm), p->comm);
	if (status) {
		bpf_printk("[get_executor_id] error reading p->comm");
		return 0;
	}

	// comm: `syz-executor.X`
	eid = (u32)comm[13];
	return eid;
}


/*
 * Task @p becomes ready to run. We update the task's priority and 
 * the task context to indicate that the task is enqueued.
 */
void BPF_STRUCT_OPS(serialise_enqueue, struct task_struct *p, u64 enq_flags)
{
	pid_t pid = p->pid, tgid = p->tgid;
	u32 eid;
	struct event *e;

	if (is_sched_ext(p) && (bpf_user_ringbuf_drain(&user_ringbuf, receive_req, NULL, 0) > 0)) {
		init_scheduling_algo();

		e = bpf_ringbuf_reserve(&kernel_ringbuf, sizeof(*e), 0);
		if (e) {
			e->pid = p->pid;
			bpf_printk("[bpf_ringbuf_submit] pid: %d\n", p->pid);
			/* send data to user-space for post-processing */
			bpf_ringbuf_submit(e, 0);
		}
	}

	if (is_sched_ext(p)) {
		eid = get_executor_id(p);
		// Start scheduling if condition is satisfied
	} 

	dbg("[enqueue] pid: %d, tgid: %d, enq_flags: %d\n", pid, tgid, enq_flags);

	// READ TASK SLICE
	// Is there something on the task struct that will tell us we are in a spin lock?
	// Need to investigate other fields. Can comment out
	// struct sched_entity se;
	// if (p != NULL) {
	// 	long status = bpf_probe_read_kernel(&se, sizeof(se), &p->se);
	// 	if (status) {
	// 		dbg("[enqueue] task_struct read status %ld\n", status);
	// 	} else {
	// 		dbg("[enqueue] %d total exec time\n",
	// 		    se.sum_exec_runtime);
	// 	}
	// }

	/* Update statistics */
	__sync_fetch_and_add(&num_events, 1);

	if (pid == tgid) {
		stat_inc(0);
	} else
		stat_inc(1);

	/*
	 * Always dispatch per-CPU kthreads on the same CPU, bypassing our scheduler.
	 *
	 * In this way we can prioritize critical kernel threads that may
	 * potentially slow down the entire system if they are blocked for too
	 * long (i.e., ksoftirqd/N, rcuop/N, etc.).
	 */
	if (is_kthread(p) && p->nr_cpus_allowed == 1) {
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
		return;
	}

	update_priorities(pid);
}

/*
 * Task @p is being removed from the scheduler. We remove the task context
 * of the task from the task context map.
 */
void BPF_STRUCT_OPS(serialise_dequeue, struct task_struct *p, u64 deq_flags)
{
	pid_t pid = p->pid;
	dbg("[dequeue] pid: %d, deq_flags: %d\n", pid, deq_flags);

	int status = tctx_map_remove(pid);
	if (status < 0)
		warn("[dequeue] failed to remove tctx for pid: %d\n", pid);
}

/* 
 * Dispatch the highest priority thread in the process. Called when all
 * threads have been enqueued, or when a thread has yielded by dispatch()
 */
static void
dispatch_highest_priority_thread(struct tctx_callback_ctx *tcallbackctx)
{
	int status;
	pid_t dispatched_pid = -1;

	if (tcallbackctx->highest_priority_pid != -1) {
		struct task_struct *highest_prio_p;
		dispatched_pid = tcallbackctx->highest_priority_pid;

		/* Get reference to highest priority task */
		highest_prio_p = bpf_task_from_pid(dispatched_pid);
		if (!highest_prio_p) {
			warn("[dispatch] failed to get task_struct from pid: %d\n",
			     dispatched_pid);
			return;
		}

		dbg("[dispatch] dispatching pid: %d, with priority: %d\n",
		    dispatched_pid, tcallbackctx->highest_priority);

		/* Dispatch the task */
		scx_bpf_dispatch(highest_prio_p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL,
				 0);

		/* Clean up and release reference to the task */
		bpf_task_release(highest_prio_p);

		/* Update the task context map */
		status = tctx_map_insert(dispatched_pid, 0, false, true);
		if (status < 0) {
			warn("[dispatch] failed to update tctx for pid: %d\n",
			     dispatched_pid);
			return;
		}
	}
}

/*
 * Dispatch the highest priority thread in the system. This function is called
 * very frequently by the kernel, so we should keep it as lightweight as possible.
 */
void BPF_STRUCT_OPS(serialise_dispatch, s32 cpu, struct task_struct *p)
{
	int num_threads_alive;

	struct tctx_callback_ctx tcallbackctx = {
		.highest_priority_pid = -1,
		.highest_priority = S32_MIN,
		.num_enqueued = 0,
	};

	num_threads_alive = bpf_for_each_map_elem(
		&task_ctx_map, get_highest_priority, &tcallbackctx, 0);

	if (num_threads_alive == -EINVAL) {
		warn("[dispatch] failed to iterate over task_ctx_map\n");
		return;
	}

	/* If all tasks are enqueued, dispatch highest priority thread*/
	if (tcallbackctx.num_enqueued == num_threads_alive &&
	    num_threads_alive != 0) {
		dbg("[dispatch] %d / %d (enqd / aliv) of %d \n",
		    tcallbackctx.num_enqueued, num_threads_alive, task_count);

		dispatch_highest_priority_thread(&tcallbackctx);
	}
	/* 
	 * If a previous task has yielded and not yet returned to enqueue(),
	 * dispatch the next highest priority thread
	 * 
	 * Note: This will prevent the same thread from being picked to run
	 * again; another thread will be dispatched instead.
	 */
	// else if (yield_flag) {
	// 	// dbg("[dispatch] yield_flag: %d\n", yield_flag);
	// 	yield_flag = false;
	// 	dispatch_highest_priority_thread(&tcallbackctx);
	// }

	// else if (num_threads_alive != 0 && tcallbackctx.num_enqueued != 0) {
	// dbg("[dispatch] threads_enqueued: %d, threads_alive: %d\n", tcallbackctx.num_enqueued, num_threads_alive);
	// bpf_for_each_map_elem(&task_ctx_map, dump_error, 0, 0);
	// }
}

/*
 * A task has yielded. Set the yield flag to true, and its time slice to 0.
 */
bool BPF_STRUCT_OPS(serialise_yield, struct task_struct *from,
		    struct task_struct *to)
{
	dbg("[yield] from: %d\n", from->pid);

	/* Tell dispatch that it's ok to dispatch */
	// yield_flag = true;

	/* Set slice to 0 so that dispatch() will be called when its timeslot is up */
	from->scx.slice = 0;

	/* can't get ref to "to" despite null checks and task_acquire()
     * it's not impt so we don't care about it */
	return false;
}

void BPF_STRUCT_OPS(serialise_runnable, struct task_struct *p, u64 enq_flags)
{
	trace("[runnable] pid: %d\n", p->pid);
}

void BPF_STRUCT_OPS(serialise_running, struct task_struct *p)
{
	trace("[running] pid: %d\n", p->pid);
}

void BPF_STRUCT_OPS(serialise_stopping, struct task_struct *p, bool runnable)
{
	trace("[stopping] pid: %d\n", p->pid);
}

/*
 * A task is becoming unavailable for scheduling. We remove the task context
 * of the task from the task context map. We do this also when the task calls
 * sleep(), since there is no guarantee when the task will wake up.
 * 
 * Note that once a (sleeping) task is ready to be called again, it will be
 * enqueued again, and its task context will be updated. This way, we will always 
 * get the most up-to-date number of tasks alive. 
 */
void BPF_STRUCT_OPS(serialise_quiescent, struct task_struct *p, u64 deq_flags)
{
	dbg("[quiescent] pid: %d\n", p->pid);

	tctx_map_remove(p->pid);
}

/*
 * A new task is being created. 
 *
 * We do not need to do anything here, as the task context will be updated
 * when the task becomes runnable. But, we could use this to initialise
 * task-related info when we want to.
 */
s32 BPF_STRUCT_OPS(serialise_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	if (!is_sched_ext(p))
		return 0;

	__sync_fetch_and_add(&task_count, 1);

	dbg("[init_task] pid: %d\n", p->pid);
	return 0;
}

/*
 * A task is exiting. Update the statistics required for the scheduling algorithm.
 */
void BPF_STRUCT_OPS(serialise_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	if (!is_sched_ext(p))
		return;

	__sync_fetch_and_sub(&task_count, 1);

	struct task_struct *ptask = NULL;
	long status =
		bpf_probe_read_kernel(&ptask, sizeof(ptask), &p->real_parent);
	if (status) {
		warn("[exit_task] failed to read parent task\n");
		return;
	}

	pid_t ppid;
	status = bpf_probe_read_kernel(&ppid, sizeof(ppid), &ptask->pid);
	if (status) {
		warn("[exit_task] failed to read parent pid\n");
		return;
	}

	bool is_root_proc = !is_sched_ext(ptask);

	if (p->pid != p->tgid) {
		dbg("[exit_task] THREAD pid: %d, tgid: %d, ppid: %d\n", p->pid,
		    p->tgid, ppid);
	} else if (!is_root_proc) {
		dbg("[exit_task] VANILLA PROCESS pid: %d, tgid: %d, ppid: %d\n",
		    p->pid, p->tgid, ppid);
	} else {
		dbg("[exit_task] ROOT PROCESS pid: %d, tgid: %d, ppid: %d\n",
		    p->pid, p->tgid, ppid);
	}

	dbg("[exit_task] max_num_events: %d\n", max_num_events);

	initial_max_num_events = max_num_events;
	num_events = 0;
}

/*
 * Initialize our scheduler
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(serialise_init)
{
	dbg("[init] scx_serialise init LMAO TEST \n");

	int status;

	status = heartbeat_timer_init();
	if (status) {
		warn("[init] failed to init heartbeat timer\n");
		return status;
	}

	rng_state.a = seed;

	return 0;
}

/*
 * Unregister our scheduler
 */
void BPF_STRUCT_OPS(serialise_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

/*
 * Scheduling class declaration.
 */
SEC(".struct_ops.link")
struct sched_ext_ops serialise_ops = {
	.enqueue = (void *)serialise_enqueue,
	.dequeue = (void *)serialise_dequeue,
	.dispatch = (void *)serialise_dispatch,
	.runnable = (void *)serialise_runnable,
	.running = (void *)serialise_running,
	.stopping = (void *)serialise_stopping,
	.quiescent = (void *)serialise_quiescent,
	.yield = (void *)serialise_yield,
	.init_task = (void *)serialise_init_task,
	.exit_task = (void *)serialise_exit_task,
	.init = (void *)serialise_init,
	.exit = (void *)serialise_exit,
	.flags = SCX_OPS_ENQ_LAST | SCX_OPS_SWITCH_PARTIAL,
	.timeout_ms = 30000,
	.name = "serialise",
};


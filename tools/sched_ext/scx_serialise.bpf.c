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
#include "scx_serialise.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * The maximum number of threads that is supported by the scheduler.
 *
 * This value defines the size of the map used to store the priorities 
 * and enqueued status of each thread. Adjust this value according to 
 * how many threads you expect the program-under-test to create.
 */
#define MAX_THREADS 200

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

struct sched_job {
	int pid;
	int num_total;
	int num_ready;
	int num_alive;
	u32 rng_seed;
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u32);
	__type(value, struct sched_job);
	__uint(max_entries, 10);
} sched_job_map SEC(".maps");

/*
 * Task context that is used to store the priority and enqueued status of
 * each task. These variables are protected by a spin lock to sieve out
 * concurrent updates.
 */
struct task_ctx {
	s32 priority;
	u32 eid; // id of executor
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
 * The queue is used to manage the dispatch ordering of task groups. Each 
 * task group represents a test case that originates from an executor identified by `eid`. 
 * 
 * `eid` are enqueued into this map using the `enqueue_eid_for_dispatch()` function when tasks are ready.
 * `eid` are dequeued using `dequeue_eid_for_dispatch()` to dispatch tasks from specific groups.
 *   in the group is dispatched.
 */
struct {
	__uint(type, BPF_MAP_TYPE_QUEUE);
	__uint(max_entries, 64);
	__type(value, u32);
} group_dispatch_queue SEC(".maps");

static void enqueue_eid_for_dispatch(u32 eid) {
	int status = bpf_map_push_elem(&group_dispatch_queue, &eid, BPF_EXIST);
	if (status < 0)
        bpf_printk("[enqueue_eid_for_dispatch] Failed to update group_dispatch_queue\n");
}

static u32 dequeue_eid_for_dispatch() {
	u32 eid;
	if (bpf_map_pop_elem(&group_dispatch_queue, &eid) < 0) {
		bpf_printk("[dequeue_eid_for_dispatch] Failed to dequeue group_dispatch_queue\n");
		return 0;
	}
	return eid;
}

static long receive_req(struct bpf_dynptr *dynptr, void *context)
{
	struct sched_req req;
	struct sched_job job;

	if (bpf_dynptr_read(&req, sizeof(req), dynptr, 0, 0) < 0) {
		bpf_printk("[receive_req] error reading dynptr data");
		return 0;
	}

	job.num_total = req.num_call;
	job.pid = req.pid;
	job.num_ready = 0;
	job.num_alive = req.num_call;
	job.rng_seed = req.rng_seed;
	if (bpf_map_update_elem(&sched_job_map, &req.pid, &job, BPF_ANY) < 0) {
		bpf_printk("[receive_req] fail to add sched request");
	}

	// rng_state.a = req.rng_seed;
	// bpf_printk("[receive_req] rng seed is %d", req.rng_seed);

	return 0;
}

/* The number used in the Linux kernel for the sched_ext scheduling policy */
#define SCHED_EXT 7

/* Debugging macros */
const volatile u32 debug = 1;

#define dbg(fmt, args...)                        \
	do {                                     \
		if (debug)                       \
			bpf_printk(fmt, ##args); \
	} while (0)

/*
 * The callback context used in dispatch() to store the highest priority task
 * and the number of enqueued tasks.
 */
struct tctx_callback_ctx {
	pid_t highest_priority_pid;
	s32 highest_priority;
	u32 num_enqueued;
	u32 eid;
};

/*
 * Callback function used in dispatch() to iterate over the task context map
 * to determine the highest priority task and the number of enqueued tasks.
 */
static u64 get_highest_priority(struct bpf_map *map, pid_t *pid,
				  struct task_ctx *tctx,
				  struct tctx_callback_ctx *tcallbackctx)
{
	if (tctx->eid != tcallbackctx->eid)
		return 0;

	bpf_spin_lock(&tctx->lock);

	if (tctx->enqueued) {
		/* 
		 * If two tasks have the same priority, the one that is stored 
		 * first in the map will be dispatched first. Random Walk may
		 * have this issue, but PCT should not have this issue.
		 */
		if (tctx->priority > tcallbackctx->highest_priority) {
			tcallbackctx->highest_priority = tctx->priority;
			tcallbackctx->highest_priority_pid = *pid;
		}
		tcallbackctx->num_enqueued++;
	}

	bpf_spin_unlock(&tctx->lock);
	// dbg("[highest_prio] --- %d \n", tctx->priority);
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

const volatile int use_pct = 0;
const volatile int use_random_priority_walk = 0;
const volatile int use_random_walk = 1;

static void update_priority(pid_t pid, s32 priority) {
	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
	if (!tctx) {
		bpf_printk("[update_priority] task context not found\n");
		return;
	}

	bpf_spin_lock(&tctx->lock);
	tctx->priority = priority;
	bpf_spin_unlock(&tctx->lock);
}

#include "scx_scheduling_algorithms.c"


static u32 identify_group(const struct task_struct *p) {
	char comm[TASK_COMM_LEN] = {};
	u32 eid = 0;
	long status;

	status = bpf_probe_read_kernel(comm, sizeof(comm), p->comm);
	if (status) {
		bpf_printk("[identify_group] error reading p->comm");
		return 0;
	}

	// comm: `syz-executor.X`
	if (comm[13] != '\0')
		eid = (u32)comm[13];
	return eid;
}


/* 
 * This function handles tasks flagged with SCHED_EXT to trigger concurrency issues.
 * 
 * - First, it checks for new scheduling requests from the user space via a ring buffer. If new requests 
 *   are found, it add the request to `sched_job_map` and initializes the scheduling algorithm.
 * 
 * - It then looks up the task's executor ID (`eid`) and updates the scheduling job status for 
 *   that executor in the `sched_job_map`. The tasks to be scheduled then follows asynchronously
 *   and the function should be invoked repeatedly. Suppose the following tasks are desired.
 * 
 * - If the task is newly created and not yet in the `task_ctx_map`, it creates a new task context 
 *   and adds it to the map. Keep waiting for other tasks in from the same executor.
 * 
 * - Finally, if all tasks for the given executor are ready, it updates task priorities and enqueues 
 *   the `eid` for dispatch in the `group_dispatch_queue`.
 */
static void handle_sched_ext(struct task_struct *p)
{
	int i;

    if (bpf_user_ringbuf_drain(&user_ringbuf, receive_req, NULL, 0) > 0) {
        init_scheduling_algo();
        struct event *e = bpf_ringbuf_reserve(&kernel_ringbuf, sizeof(*e), 0);
        if (e) {
            e->pid = p->pid;
            bpf_printk("[handle_sched_ext] pid: %d\n", p->pid);
            bpf_ringbuf_submit(e, 0);
        }
    }

    u32 eid = identify_group(p);
	// Lookup the scheduling job for this executor ID in the job map.
    struct sched_job *job = bpf_map_lookup_elem(&sched_job_map, &eid);
    if (!job) {
        bpf_printk("[handle_sched_ext] job not found\n");
        return;
    }

	pid_t pid = p->pid;
	struct task_ctx *tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
	if (!tctx) {
		// If it is a newly created task, add it into `task_ctx_map`
		struct task_ctx new_task = {
 			.priority = 0,
		    .eid = eid,
		    .enqueued = false,
    		.lock = {},
		};
		if (bpf_map_update_elem(&task_ctx_map, &pid, &new_task, BPF_NOEXIST) < 0) {
			bpf_printk("[handle_sched_ext] fail to insert new task ctx\n");
			return;
		}
	}

	bpf_spin_lock(&job->lock);

    job->num_ready++;
	int num_expected = (!tctx ? job->num_total:job->num_alive);
	// If all the tasks are ready, update task priorities.
	bool all_tasks_ready = (job->num_ready == num_expected);

	bpf_spin_unlock(&job->lock);

	if (all_tasks_ready) {
		update_priorities(eid);
		bpf_for(i, 0, num_expected) {
			enqueue_eid_for_dispatch(eid);
		}

		bpf_spin_lock(&job->lock);
		job->num_ready = 0;
		bpf_spin_unlock(&job->lock);
	}
}

/*
 * Task @p becomes ready to run. We update the task's priority and 
 * the task context to indicate that the task is enqueued.
 * 
 * - For tasks using the SCHED_EXT policy, it calls `handle_sched_ext()` 
 *   to manage the task’s scheduling process, including updating the task 
 *   context and managing task priorities.
 * - If the task does not use SCHED_EXT, it is dispatched immediately using 
 *   the default scheduling slice.
 */
void BPF_STRUCT_OPS(serialise_enqueue, struct task_struct *p, u64 enq_flags)
{
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

	if (is_sched_ext(p))
        handle_sched_ext(p);
	else
		// Always dispatch non-concurrency tasks directly.
		scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
}

/*
 * Task @p is being removed from the scheduler. We remove the task context
 * of the task from the task context map.
 */
void BPF_STRUCT_OPS(serialise_dequeue, struct task_struct *p, u64 deq_flags)
{
	if (!is_sched_ext(p))
		return;

	// Update the number of ready tasks
	u32 eid = identify_group(p);
	struct sched_job* job = bpf_map_lookup_elem(&sched_job_map, &eid);
	if (!job) {
		bpf_printk("[dequeue] job not found\n");
		return;
	}
	bpf_spin_lock(&job->lock);
	job->num_ready--;
	bpf_spin_unlock(&job->lock);
}

/* 
 * Dispatch the highest priority thread in the process. Called when all
 * threads have been enqueued, or when a thread has yielded by dispatch()
 */
static void
dispatch_highest_priority_thread(struct tctx_callback_ctx *tcallbackctx)
{
	pid_t dispatched_pid = -1;

	if (tcallbackctx->highest_priority_pid != -1) {
		struct task_struct *highest_prio_p;
		dispatched_pid = tcallbackctx->highest_priority_pid;

		/* Get reference to highest priority task */
		highest_prio_p = bpf_task_from_pid(dispatched_pid);
		if (!highest_prio_p) {
			bpf_printk("[dispatch] failed to get task_struct from pid: %d\n",
			     dispatched_pid);
			return;
		}

		/* Update the task context map */
		struct task_ctx* tctx = bpf_map_lookup_elem(&task_ctx_map, &dispatched_pid);
		if (tctx) {
			bpf_spin_lock(&tctx->lock);
			tctx->enqueued = false;
			bpf_spin_unlock(&tctx->lock);
		}

		dbg("[dispatch] dispatching pid: %d, with priority: %d\n",
		    dispatched_pid, tcallbackctx->highest_priority);

		/* Dispatch the task */
		scx_bpf_dispatch(highest_prio_p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL,
				 0);

		/* Clean up and release reference to the task */
		bpf_task_release(highest_prio_p);
	}
}

/*
 * Dispatch the highest priority thread in the system. This function is called
 * very frequently by the kernel, so we should keep it as lightweight as possible.
 * 
 * - First, it dequeues the next `eid` (executor ID) from the `group_dispatch_queue`. It means tasks
 * 	 labeled with `eid` is under test and should be prioritized when dispatching tasks.
 * 
 * - It then iterates over all tasks in the `task_ctx_map` using `bpf_for_each_map_elem()` and 
 *   calls the `get_highest_priority` function to find the task with the highest priority within 
 *   the specified `eid` group. If iteration fails, a bpf_printking is logged.
 * 
 * - Once the highest priority task is found, `dispatch_highest_priority_thread()` is called to 
 *   dispatch that task for execution on the specified CPU.
 */
void BPF_STRUCT_OPS(serialise_dispatch, s32 cpu, struct task_struct *p)
{
	u32 eid = dequeue_eid_for_dispatch();
	if (!eid)
		return;

	struct tctx_callback_ctx tcallbackctx = {
		.highest_priority_pid = -1,
		.highest_priority = S32_MIN,
		.eid = eid,
	};

	if (bpf_for_each_map_elem(&task_ctx_map, get_highest_priority, &tcallbackctx, 0) == -EINVAL) {
		bpf_printk("[dispatch] failed to iterate over task_ctx_map\n");
		return;
	}

	dispatch_highest_priority_thread(&tcallbackctx);
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

/*
 * A task is exiting. Update the statistics required for the scheduling algorithm.
 */
void BPF_STRUCT_OPS(serialise_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	if (!is_sched_ext(p))
		return;

	pid_t pid = p->pid;
	struct task_ctx* tctx = bpf_map_lookup_elem(&task_ctx_map, &pid);
	if (!tctx) {
		bpf_printk("[exit_task] task %d not found\n", p->pid);
		return;
	}

	struct sched_job* job = bpf_map_lookup_elem(&sched_job_map, &tctx->eid);
	if (!job) {
		bpf_printk("[exit_task] sched_job %d not found\n", tctx->eid);
		return;
	}
	
	bpf_spin_lock(&job->lock);
	job->num_alive--;
	bpf_spin_unlock(&job->lock);
	
	if (job->num_alive == 0)
		bpf_map_delete_elem(&sched_job_map, &tctx->eid);

	if (bpf_map_delete_elem(&task_ctx_map, &pid) < 0)
		bpf_printk("[exit_task] fail to delete task context\n");
}

/*
 * Initialize our scheduler
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(serialise_init)
{
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
	.yield = (void *)serialise_yield,
	.exit_task = (void *)serialise_exit_task,
	.init = (void *)serialise_init,
	.exit = (void *)serialise_exit,
	.flags = SCX_OPS_ENQ_LAST | SCX_OPS_SWITCH_PARTIAL,
	.timeout_ms = 30000,
	.name = "serialise",
};


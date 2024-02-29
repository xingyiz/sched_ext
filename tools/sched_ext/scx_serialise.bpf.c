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

char _license[] SEC("license") = "GPL";

struct user_exit_info uei;

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

/* The number used in the Linux kernel for the sched_ext scheduling policy */
#define SCHED_EXT 7

/*
 * The maximum number of threads that is supported by the scheduler.
 *
 * This value defines the size of the map used to store the priorities 
 * and enqueued status of each thread. Adjust this value according to 
 * how many threads you expect the program-under-test to create.
 */
#define MAX_THREADS 50

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
bool yield_flag = false;

/*
 * Task context that is used to store the priority and enqueued status of
 * each task. These variables are protected by a spin lock to sieve out
 * concurrent updates.
 */
struct task_ctx {
	s32 priority;
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
	status = bpf_timer_start(timer, 5 * NSEC_PER_SEC, 0);
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
	status = bpf_timer_start(timer, NSEC_PER_SEC, 0);
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

/*
 * Variables for PCT implementation
 *
 * The following variables are set in the corresponding C program
 * based on user-defined parameters.
 * 
 * @depth: the depth of the concurrency bug to find (i.e., the number of
 * 	   interleavings that would trigger the bug)
 * @seed: the seed for the random number generator
 * @use_pct: flag to indicate whether to use PCT
 * 
 * The following variables are set by the BPF program.
 * 
 * @iterations: the number of times the main thread has exited
 * @max_num_events: the maximum number of enqueue()s that have occurred
 * 		over one iteration. 
 * @num_events: the number of enqueue()s that have occurred
 */
const volatile u32 depth = 3, seed = 0xdeadbeef;
const volatile int use_pct = 1;
u32 iterations, initial_max_num_events, task_count, strata, max_num_events, num_events;

/* xorshift random generator */
struct xorshift32_state {
	u32 a;
} rng_state;

/* The state must be initialized to non-zero */
u32 xorshift32(struct xorshift32_state *state)
{
	u32 x = state->a;
	x ^= x << 13;
	x ^= x >> 17;
	x ^= x << 5;
	return state->a = x;
}

/*
 * Map to store the pre-determined priorities for each thread.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, MAX_THREADS);
} pct_priorities SEC(".maps");

/* Swaps two elements in an array */
static inline void swap(u32 *a, u32 *b)
{
	u32 temp = *a;
	*a = *b;
	*b = temp;
}

/* 
 * Shuffle the priorities in the pct_priorities map. This function is called
 * during init() of the scheduler, and after each iteration.
 */
static void shuffle_prios(struct xorshift32_state *state)
{
	u32 *prio_value, *value_i, *value_j;
	u32 index, i, actual_i, actual_j;

	/* Reset the priorities for the new iteration */
	bpf_for(i, depth, depth + MAX_THREADS)
	{
		index = i - depth;
		prio_value = bpf_map_lookup_elem(&pct_priorities, &index);
		if (prio_value)
			*prio_value = get_strata_base() + i;
	}

	/* Shuffle the resetted priorities using Fisher–Yates algorithm */
	bpf_for(i, 1, MAX_THREADS)
	{
		actual_i = MAX_THREADS - i;
		actual_j = xorshift32(state) % actual_i;
		value_i = bpf_map_lookup_elem(&pct_priorities, &actual_i);
		value_j = bpf_map_lookup_elem(&pct_priorities, &actual_j);
		if (value_i && value_j) {
			swap(value_i, value_j);
		} else {
			warn("[shuffle_prios] failed to swap values at index: %d and %d\n",
			     actual_i, actual_j);
		}
	}
}

/* 
 * Assign the priority for a thread based on the pre-determined priorities
 * in the pct_priorities map.
 * 
 * We use % MAX_THREADS to ensure that the index is within the range of the
 * map, and also allow for subsequent processes to get different priorities.
 */
s32 assign_pct_priority(pid_t pid)
{
	u32 index = (u32)pid % MAX_THREADS;
	s32 *prio_value = bpf_map_lookup_elem(&pct_priorities, &index);
	if (prio_value)
		return *prio_value;

	return -1;
}

/*
 * Update the priority of a thread in the pct_priorities map.
 */
static void update_pct_priority(pid_t pid, s32 new_prio)
{
	u32 index = (u32)pid % MAX_THREADS;
	u32 *prio_value = bpf_map_lookup_elem(&pct_priorities, &index);
	if (prio_value)
		*prio_value = new_prio;
}

/*
 * Map to store the pre-determined change points for each iteration.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries,
	       MAX_THREADS); // should be depth - 1 tho, but this needs a constant
} pct_change_points SEC(".maps");

/*
 * Choose the change points for the next iteration. This function is called
 * during init() of the scheduler, and after each iteration.
 */
static void choose_change_points(struct xorshift32_state *state)
{
	/* 
	 * This occurs in a multi-process environment, where the main threads
	 * of each process exit one after another, with no enqueue()s called
	 * in between.
	 */
	if (max_num_events == 0) {
		/*
		 * If no events have occurred for the prev iteration, we don't make
		 * any assumptions about num_events and set the change points to 1, 
		 * 2, ... for the next iteration. TODO: this may not be the best approach.
		 */
		u32 i, n = depth - 1;
		bpf_for(i, 0, n)
		{
			u32 change_point = i;
			long status = bpf_map_update_elem(
				&pct_change_points, &i, &change_point, BPF_ANY);
			if (status)
				warn("[choose_change_points] failed to update change_point[%d]: %d\n",
				     i, change_point);
		}
		return;
	}

	u32 i, n, change_point;
	long status;

	n = depth - 1;
	if (n > MAX_THREADS) {
		scx_bpf_error("[choose_change_points] n: %d, MAX_THREADS: %d\n",
			      n, MAX_THREADS);
		return;
	}

	bpf_for(i, 0, n)
	{
		/* NOTE: THERE MAY BE DUPLICATE CHANGE POINTS */
		change_point = (xorshift32(state) % max_num_events) +
			       1; // [1, max_num_events]
		status = bpf_map_update_elem(&pct_change_points, &i,
					     &change_point, BPF_ANY);
		if (status)
			warn("[choose_change_points] failed to update change_point[%d]: %d\n",
			     i, change_point);

		dbg("[choose_change_points] change_point[%d]: %d\n", i,
		    change_point);
	}
}

/* 
 * Random Walk implementation. @use_random_walk is set in the corresponding
 * C program based on user-defined parameters.
 */
const volatile int use_random_walk = 0;
const volatile int use_random_walk_2 = 0;

/*
 * Assign the priority for a thread based on a completely random number.
 */
static inline s32 assign_rw_priority(pid_t pid)
{
	s32 priority = bpf_get_prandom_u32() % MAX_THREADS;
	return priority;
}

/* 
 * Combines all implemented scheduling algorithms and chooses
 * the appropriate priority to assign to a thread.
 */
s32 assign_priority(pid_t pid)
{
	if (use_random_walk || use_random_walk_2)
		return assign_rw_priority(pid);

	if (use_pct)
		return assign_pct_priority(pid);

	/* should not reach here */
	scx_bpf_error(
		"[assign_priority] ERROR: no scheduling algorithm chosen\n");
	return -2;
}

/*
 * Callback function to update all priorities in tctx_map for random_walk_2
 */
static __u64 update_all_prios(struct bpf_map *map, pid_t *key,
			      struct task_ctx *tctx,
			      struct tctx_callback_ctx *tcallbackctx)
{
	/* Use highest_priority_pid to indicate the pid of the task we have already updated */
	pid_t pid_to_avoid = tcallbackctx->highest_priority_pid;
	s32 new_priority;
	if (*key != pid_to_avoid) {
		new_priority = assign_priority(*key);
		bpf_spin_lock(&tctx->lock);
		tctx->priority = new_priority;
		bpf_spin_unlock(&tctx->lock);
	}
	return 0;
}

// static __u64 dump_error(struct bpf_map *map, pid_t *key, struct task_ctx *tctx, struct tctx_callback_ctx *tcallbackctx) {
//     dbg("[dump_error] pid: %d, priority: %d, enqueued: %d\n", *key, tctx->priority, tctx->enqueued);
//     return 0;
// }

/*
 * Task @p becomes ready to run. We update the task's priority and 
 * the task context to indicate that the task is enqueued.
 */
void BPF_STRUCT_OPS(serialise_enqueue, struct task_struct *p, u64 enq_flags)
{
	pid_t pid = p->pid, tgid = p->tgid;
	dbg("[enqueue] pid: %d, tgid: %d, enq_flags: %d\n", pid, tgid,
	    enq_flags);

		// READ TASK SLICE
		// Is there something on the task struct that will tell us we are in a spin lock?
	  // Need to investigate other fields. Can comment out
		struct sched_entity se;
		if (p != NULL) {
	    long status = bpf_probe_read_kernel(&se, sizeof(se), &p->se);
			if (status) {
				dbg("[enqueue] task_struct read status %ld\n", status);
			} else {
				dbg("[enqueue] %d total exec time\n", se.sum_exec_runtime);
			}
		}

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

	s32 priority = -1;

	/* 
	 * For PCT, check if a change_point is incurred. If so, update the
	 * priority of the task.
	 */
	if (use_pct) {
		u32 n = depth - 1, i;

		if (n > MAX_THREADS) {
			warn("[enqueue] n: %d, MAX_THREADS: %d\n", n,
			     MAX_THREADS);
			return;
		}

		bpf_for(i, 0, n)
		{
			u32 *change_point =
				bpf_map_lookup_elem(&pct_change_points, &i);
			if (change_point) {
				dbg("[enqueue] %d until change \n", *change_point - (num_events % initial_max_num_events) );
				if ((num_events % initial_max_num_events ) == *change_point) {
					// If we have observed more events than expected, resume PCT with a
					// new "strata" -- this allows for threads set to low priority to recover
					if (initial_max_num_events * (strata + 1) < num_events) {
						dbg("[enqueue] NEW STRATA %d\n", strata);
						strata += 1;
					}

					priority = get_strata_base() + i + 1;
					update_pct_priority(pid, priority);
					dbg("[enqueue] UPDATE pid: %d, priority: %d\n",
					    pid, priority);
					break;
				}
			}
		}
	}

	/* Assign priority to the task based on scheduling algo */
	priority = assign_priority(pid);
	if (priority < 0) {
		warn("[enqueue] failed to assign priority for pid: %d, priority: %d\n",
		     pid, priority);
		return;
	}

	/*
	 * Update the task context.
	 *
	 * Since we cannot assure that the task should exist (as new tasks may
	 * get enqueued), we set should_exist to false.
	 */
	tctx_map_insert(pid, priority, true, false);

	if (use_random_walk_2) {
		/* Update the priorities of the rest of the threads as well */
		struct tctx_callback_ctx tcallbackctx = {
			.highest_priority_pid = pid,
		};

		bpf_for_each_map_elem(&task_ctx_map, update_all_prios,
				      &tcallbackctx, 0);
	}
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
		dbg("[dispatch] %d / %d (enqd / aliv) of %d \n", num_threads_alive, tcallbackctx.num_enqueued, task_count);


		dispatch_highest_priority_thread(&tcallbackctx);

	}
	/* 
	 * If a previous task has yielded and not yet returned to enqueue(),
	 * dispatch the next highest priority thread 
	 */
	else if (yield_flag) {
		// dbg("[dispatch] yield_flag: %d\n", yield_flag);
		yield_flag = false;
		dispatch_highest_priority_thread(&tcallbackctx);
	}

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
	yield_flag = true;

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

	task_count += 1;

	dbg("[init_task] pid: %d\n", p->pid);
	return 0;
}

/*
 * A task is exiting. Update the statistics required for the scheduling algorithm.
 *
 * We need to modify this to handle multi-processes properly.
 */
void BPF_STRUCT_OPS(serialise_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	if (!is_sched_ext(p))
		return;

	task_count -= 1;

	struct task_struct *ptask;
  pid_t ppid = 0;

  long status = bpf_probe_read_kernel(&ptask, sizeof(ptask), &p->real_parent);
	bool is_root_proc = false;
  if (status == 0) {
		status = bpf_probe_read_kernel(&ppid, sizeof(ppid), &ptask->pid);
		is_root_proc = !is_sched_ext(ptask);
  } else {
      dbg("[do_exit] status failed on read parent task: %ld\n", status);
  }

	if (p->pid != p->tgid) {
		dbg("[exit_task] THREAD pid: %d, tgid: %d\n", p->pid, p->tgid);
	} else if (!is_root_proc) {
		dbg("[exit_task] VANILLA PROCESS pid: %d, tgid: %d\n", p->pid, p->tgid);
	} else {
		dbg("[exit_task] ROOT PROCESS pid: %d, tgid: %d\n", p->pid, p->tgid);

		if (use_pct) {
			__sync_fetch_and_add(&iterations, 1);

			if (num_events > max_num_events)
				max_num_events = num_events;
			else if ((num_events - max_num_events) > 0 &&
				 (num_events - max_num_events) > 18)
				max_num_events = num_events;
			else if ((num_events - max_num_events) < 0 &&
				 (num_events - max_num_events) < -18)
				max_num_events = num_events;

			dbg("[exit_task] iterations: %d, max_num_events: %d\n",
			    iterations, max_num_events);

			initial_max_num_events = max_num_events;

			num_events = 0;
			strata = 0;

			shuffle_prios(&rng_state);
			choose_change_points(&rng_state);
		}
	}
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

	/* Initialise PCT variables */
	if (use_pct) {
		dbg("[init] depth: %d, seed: %d\n", depth, seed);
		rng_state.a = seed;
		iterations = 0;
		max_num_events = 0;
		strata = 0; 
		initial_max_num_events = depth * 10;
		task_count = 0;
		num_events = 0;
		shuffle_prios(&rng_state);
		choose_change_points(&rng_state);
	}

	return 0;
}

inline s32 get_strata_base() {
	// return 0;
	return S32_MAX - ((strata + 2) * MAX_THREADS);
}

/*
 * Unregister our scheduler
 */
void BPF_STRUCT_OPS(serialise_exit, struct scx_exit_info *ei)
{
	uei_record(&uei, ei);
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
	.flags = SCX_OPS_ENQ_LAST,
	.timeout_ms = 30000,
	.name = "serialise",
};

/* =================================
 * Hooks
 * ================================= */
/*
 * Udelay is called too often to trigger a reschedule every time it is called.
 * Instead, we trigger a reschedule every 300 calls to udelay.
 */

// u32 udelay_schedule_counter = 0;
// SEC("kprobe/__udelay")
// int BPF_KPROBE(udelay_probe)
// {
// 	struct task_struct *p = (struct task_struct *)bpf_get_current_task();
// 	if (!is_sched_ext(p))
// 		return 0;

// 	__sync_fetch_and_add(&udelay_schedule_counter, 1);
// 	if (udelay_schedule_counter == 300) {
// 		udelay_schedule_counter = 0;
// 		dbg("[udelay_probe] bpf schedule called\n");
// 		bpf_schedule();
// 	}
// 	return 0;
// }

u32 kmalloc_schedule_counter = 0;
SEC("kprobe/__kmalloc")
int BPF_KPROBE(kmalloc_probe)
{
	struct task_struct *p = (struct task_struct *)bpf_get_current_task();
	if (!is_sched_ext(p))
		return 0;

	__sync_fetch_and_add(&kmalloc_schedule_counter, 1);
	dbg("[kmalloc_probe] pid: %d\n", (u32)bpf_get_current_pid_tgid());

	if (kmalloc_schedule_counter == 5) {
		kmalloc_schedule_counter = 0;
		dbg("[kmalloc_probe] bpf schedule called\n");
		bpf_schedule();
	}

	return 0;
}

u32 kfree_schedule_counter = 0;
SEC("kprobe/kfree")
int BPF_KPROBE(kfree_probe)
{
	struct task_struct *p = (struct task_struct *)bpf_get_current_task();
	if (!is_sched_ext(p))
		return 0;

	__sync_fetch_and_add(&kfree_schedule_counter, 1);
	dbg("[kfree_probe] pid: %d\n", (u32)bpf_get_current_pid_tgid());

	if (kfree_schedule_counter == 8) {
		kfree_schedule_counter = 0;
		dbg("[kfree_probe] bpf schedule called\n");
		bpf_schedule();
	}
	return 0;
}

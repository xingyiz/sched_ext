#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <scx/common.bpf.h>
#include "scx_simple_signal.h"

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;

static u64 vtime_now;
UEI_DEFINE(uei);

#define SHARED_DSQ 0
#define MAX_THREADS 50
#define TASK_COMM_LEN 16 

static inline bool vtime_before(u64 a, u64 b)
{
	return (s64)(a - b) < 0;
}

/*  
 * The overall workflow of scheduling:
 * 1. Before the executor runs syscalls, it sends a `scehd_req` to the 
 * kernel-space scheduler via `kernel_ringbuf`. The request is then stored 
 * in `sched_req_map` and awaits the arrival of tasks.
 * 2. Now, as the executor runs system calls, tasks begin to flow in. 
 * When a task is enqueued, scheduling is initiated if all the required 
 * tasks are in place. If not, we place the task in `task_ctx_map` and keeps waiting.
 */

/* The number used in the Linux kernel for the sched_ext scheduling policy */
#define SCHED_EXT 7

struct {
	__uint(type, BPF_MAP_TYPE_USER_RINGBUF);
	__uint(max_entries, 256 * 1024);
} user_ringbuf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} kernel_ringbuf SEC(".maps");

struct task_ctx {
	s32 priority;
	u32 id; // id of executor
	bool enqueued;
	struct bpf_spin_lock lock;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key, pid_t);
	__uint(value, struct task_ctx);
	__uint(max_entries, MAX_THREADS);
} task_ctx_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key, u32);
	__uint(value, struct sched_req);
	__uint(max_entries, 10);
} sched_req_map SEC(".maps");

static int insert_sched_req_map() 
{
}

static long receive_req(struct bpf_dynptr *dynptr, void *context)
{
	struct sched_req req;
	int *task_ctx_map;

	if (bpf_dynptr_read(&req, sizeof(req), dynptr, 0, 0) < 0) {
		bpf_printk("[receive_req] error reading dynptr data");
		return 0;
	}

	insert_sched_req_map();

	return 0;
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

static int insert_task_ctx_map()
{

}

s32 BPF_STRUCT_OPS(simple_signal_init_task, struct task_struct *p,
		   struct scx_init_task_args *args)
{
	if (!is_sched_ext(p))
		return 0;

	// bpf_printk("[init_task] pid: %d\n", p->pid);

	return 0;
}

static u32 get_executor_id(const struct task_struct *p) {
	char comm[TASK_COMM_LEN];
	u16 id;
	long status;

	status = bpf_probe_read_kernel(&comm, sizeof(comm), p->comm);
	// comm: `syz-executor.X`
	id = (u32)comm[13];
	return id;
}

void BPF_STRUCT_OPS(simple_signal_enqueue, struct task_struct *p, u64 enq_flags)
{
	struct event *e;
	// bpf_printk("[enqueue] pid: %d\n", p->pid);

	if (is_sched_ext(p) && (bpf_user_ringbuf_drain(&user_ringbuf, receive_req, NULL, 0) > 0)) {
		e = bpf_ringbuf_reserve(&kernel_ringbuf, sizeof(*e), 0);
		if (e) {
			e->pid = p->pid;
			bpf_printk("[bpf_ringbuf_submit] pid: %d\n", p->pid);
			/* send data to user-space for post-processing */
			bpf_ringbuf_submit(e, 0);
		}
	}

	if (is_sched_ext(p)) {
		insert_task_ctx_map();
		// Start scheduling if condition is satisfied
	}

	if (fifo_sched) {
		scx_bpf_dispatch(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	} else {
		u64 vtime = p->scx.dsq_vtime;

		/*
		 * Limit the amount of budget that an idling task can accumulate
		 * to one slice.
		 */
		if (vtime_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;

		scx_bpf_dispatch_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime,
				       enq_flags);
	}
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_signal_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

/*  end of core code for communication  */

void BPF_STRUCT_OPS(simple_signal_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_consume(SHARED_DSQ);
}


void BPF_STRUCT_OPS(simple_signal_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(simple_signal_ops, 
		   .init_task = (void *)simple_signal_init_task,
	       .enqueue = (void *)simple_signal_enqueue,
	       .dispatch = (void *)simple_signal_dispatch,
	       .init = (void *)simple_signal_init, 
		   .exit = (void *)simple_signal_exit,
	       .name = "simple_signal");

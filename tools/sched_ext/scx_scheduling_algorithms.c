
/* The following variables are set by the BPF program.
 * 
 * @iterations: the number of times the main thread has exited
 * @max_num_events: the maximum number of enqueue()s that have occurred
 * 		over one iteration. 
 * @num_events: the number of enqueue()s that have occurred
 */

u32 iterations, initial_max_num_events, task_count, max_num_events,
	num_events;

#include "pct.c"
#include "random-walk.c"
#include "random-priority.c"

s32 assign_priority(pid_t pid) {
	s32 priority;
	
	if (use_pct) {
		priority = assign_pct_priority(pid);
	} else if (use_random_walk) {
		priority = assign_rw_priority();		
	} else if (use_random_priority_walk) {
		priority = assign_priorities_rp();
	}
	if (priority < 0) {
		bpf_printk("[enqueue] failed to assign priority for pid: %d, priority: %d\n",pid, priority);
		return -1;
	}

	return priority;
}

int init_scheduling_algo() {
	if (use_pct) {
		return init_pct();
	} else if (use_random_walk) {
		return init_rw();			
	} else if (use_random_priority_walk) {
		return init_rp();
	}

	return -1;
}

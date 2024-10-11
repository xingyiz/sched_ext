
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

s32 update_priorities(pid_t pid) {
	if (use_pct) {
		return update_priorities_pct(pid);
	} else if (use_random_walk) {
		return update_priorities_rw(pid);			
	} else if (use_random_priority_walk) {
		return update_priorities_rp(pid);
	}

	return -1;
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

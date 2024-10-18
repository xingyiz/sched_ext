
/* 
 * Random Priority Walk implementation. @use_random_walk is set in the corresponding
 * C program based on user-defined parameters.
 */

/*
 * Assign the priority for a thread based on a completely random number.
 */
static inline int update_priorities_rp(pid_t pid)
{
	s32 priority = xorshift32(&rng_state) % 2147483647;
	dbg("prio new %d", priority);

	if (priority < 0) {
		bpf_printk("[enqueue] failed to assign priority for pid: %d, priority: %d\n",
		     pid, priority);
		return -1;
	}

	/*
	 * Update the task context.
	 *
	 * Since we cannot assure that the task should exist (as new tasks may
	 * get enqueued), we set should_exist to false.
	 */
	tctx_map_insert(pid, priority, true, false);
}

static inline s32 init_rp() {
	  return 0;
}

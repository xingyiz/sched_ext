
/* 
 * Random Walk implementation. @use_random_walk is set in the corresponding
 * C program based on user-defined parameters.
 */

/*
 * Assign the priority for a thread based on a completely random number.
 */
static inline s32 assign_rw_priority()
{
	s32 priority = xorshift32(&rng_state) % 2147483647;
	dbg("prio new %d", priority);
	return priority;
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
		new_priority = assign_rw_priority();
		bpf_spin_lock(&tctx->lock);
		tctx->priority = new_priority;
		bpf_spin_unlock(&tctx->lock);
	}
	return 0;
}

static s32 update_priorities_rw(pid_t pid) {
		s32 priority = assign_rw_priority();

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

		/* Update the priorities of all threads */
		struct tctx_callback_ctx tcallbackctx = {
			.highest_priority_pid = pid,
		};

		bpf_for_each_map_elem(&task_ctx_map, update_all_prios,
				      &tcallbackctx, 0);

		return 0;
}

static inline s32 init_rw() {
	  return 0;
}



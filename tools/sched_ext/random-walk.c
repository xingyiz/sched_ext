
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
	// dbg("[assign_rw_priority] prio new %d", priority);
	return priority;
}


/*
 * Callback function to update all priorities in tctx_map for random_walk_2
 */
static int update_all_prios(struct bpf_map *map, pid_t *pid,
			      struct task_ctx *tctx,
			      struct tctx_callback_ctx *tcallbackctx)
{
	if (tctx->eid != tcallbackctx->eid)
		return 0;
	
	s32 priority = assign_rw_priority();
	// bpf_printk("[update_all_prios] pid: %d, priority: %d", *pid, priority);
	update_priority(*pid, priority);
	return 0;
}

static s32 update_priorities_rw(u32 eid) {
	/* Update the priorities of all threads */
	struct tctx_callback_ctx tcallbackctx = {
		.eid = eid
	};

	bpf_for_each_map_elem(&task_ctx_map, update_all_prios,
		&tcallbackctx, 0);

	return 0;
}

static inline s32 init_rw() {
	  return 0;
}



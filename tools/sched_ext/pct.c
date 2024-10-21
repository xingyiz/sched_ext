
/*
 * Variables for PCT implementation
 *
 * The following variables are set in the corresponding C program
 * based on user-defined parameters.
 * 
 * @depth: the depth of the concurrency bug to find (i.e., the number of
 * 	   interleavings that would trigger the bug)
 * @use_pct: flag to indicate whether to use PCT
 */ 

const volatile u32 depth = 3;
u32 strata;

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

/* Get strata base for PCT */
inline s32 get_strata_base()
{
	return S32_MAX - ((strata + 2) * MAX_THREADS);
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

s32 init_pct() {
	/* Initialise PCT variables */
	if (use_pct) {
		dbg("[init] depth: %d\n", depth);
		iterations = 0;
		max_num_events = 0;
		strata = 0;
		initial_max_num_events = depth * 10;
		task_count = 0;
		num_events = 0;
		shuffle_prios(&rng_state);
		choose_change_points(&rng_state);
		strata = 0;
	}
	return 0;
}

static s32 update_priorities_pct(u32 eid) {
	s32 priority = -1;
	/* 
	 * For PCT, check if a change_point is incurred. If so, update the
	 * priority of the task.
	 */
	u32 n = depth - 1, i;

	if (n > MAX_THREADS) {
		bpf_printk("[enqueue] n: %d, MAX_THREADS: %d\n", n,
			   MAX_THREADS);
		return -1;
	}

	bpf_for(i, 0, n)
	{
		u32 *change_point = bpf_map_lookup_elem(&pct_change_points, &i);
		if (change_point) {
			// dbg("[enqueue] %d until change \n",
			//     *change_point - (num_events %
			// 		     initial_max_num_events));
			if ((num_events % initial_max_num_events) ==
			    *change_point) {
				// If we have observed more events than expected, resume PCT with a
				// new "strata" -- this allows for threads set to low priority to recover
				if (num_events >
				    initial_max_num_events * (strata + 1)) {
					strata += 1;
					dbg("[enqueue] NEW STRATA %d\n",
					    strata);
				}

				priority = get_strata_base() + i + 1;
				update_priority(pid, priority);
				dbg("[enqueue] UPDATE pid: %d, priority: %d\n",
				    pid, priority);
				break;
			}
		}
	}
}

#include <bpf/bpf.h>
#include <libgen.h>
#include <sched.h>
#include <scx/common.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

struct xorshift32_state {
	u32 a;
};

#include "scx_serialise.bpf.skel.h"

const char help_fmt[] =
	"A scheduler to serialise the thread schedules of a process.\n"
	"\n"
	"See the top-level comment in .bpf.c for more details.\n"
	"\n"
	"Usage: %s [-s SEED] [-d DEPTH]\n"
	"\n"
	"  -s            Enter seed for the RNG. Default: 0xdeadbeef.\n"
	"  -d            Enter depth of bug to search for. Default: 3.\n"
	"  -h            Display this help and exit\n"
	"  -r            Use random walk instead of PCT. 1 for random walk, 2 for random walk 2\n";

static volatile int exit_req;

static void sigint_handler(int simple)
{
	exit_req = 1;
}

// static __u64 random_number(__u64 min_num, __u64 max_num) {
//     return (rand() % (max_num - min_num + 1)) + min_num;
// }

static void read_stats(struct scx_serialise *skel, __u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 cnts[2][nr_cpus];
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * 2);

	for (idx = 0; idx < 2; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &idx,
					  cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

int main(int argc, char **argv)
{
	struct scx_serialise *skel;
	struct bpf_link *link;
	__u32 opt;

	srand(time(NULL));

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	skel = scx_serialise__open();
	SCX_BUG_ON(!skel, "Failed to open skel");

	while ((opt = getopt(argc, argv, "s:d:hr:")) != -1) {
		unsigned long v;

		switch (opt) {
		case 's':
			v = strtoul(optarg, NULL, 10);
			if (v) {
				printf("seed: %lu\n", v);
				skel->rodata->seed = (__u32)v;
			}
			break;
		case 'd':
			v = strtoul(optarg, NULL, 10);
			if (v) {
				printf("depth: %lu\n", v);
				skel->rodata->depth = (__u32)v;
			}
			break;
		case 'r':
			v = strtoul(optarg, NULL, 10);
			if (v) {
				printf("use random walk: %lu\n", v);
				skel->rodata->use_pct = 0;

				if (v == 1)
					skel->rodata->use_random_walk = 1;
				else if (v == 2)
					skel->rodata->use_random_walk_2 = 1;
				else
					SCX_BUG_ON(1, "Invalid option for -r");
			}
			break;
		case 'h':
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_BUG_ON(scx_serialise__load(skel), "Failed to load skel");

	link = bpf_map__attach_struct_ops(skel->maps.serialise_ops);
	SCX_BUG_ON(!link, "Failed to attach struct_ops");

	SCX_BUG_ON(scx_serialise__attach(skel), "Failed to attach skel");

	while (!exit_req && !uei_exited(&skel->bss->uei)) {
		__u64 stats[2];
		read_stats(skel, stats);
		printf("main=%llu thread=%llu\n", stats[0], stats[1]);
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	uei_print(&skel->bss->uei);
	scx_serialise__detach(skel);
	scx_serialise__destroy(skel);
	return 0;
}

#include <bpf/bpf.h>
#include <libgen.h>
#include <sched.h>
#include <scx/common.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <pthread.h>
#include <unistd.h>

#include "scx_simple_signal.h"
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
	"  -r            (PCT disabled) 1 for random priority walk, 2 for random walk 2, Default: 2. \n"
	"  -u            Use udelay. 0 for no, 1 for yes. (Deprecated) Default: 0.\n";


#define SCHED_SHM "/sched_shared_memory"
#define SHM_SIZE 1024

typedef struct {
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	int available;
	int num_call;
	unsigned long long pid;
} sched_shm;

static int schedShmFd;

sched_shm *shm_ptr;

static volatile int exit_req;

static void sigint_handler(int simple)
{
	exit_req = 1;
}

// static __u64 random_number(__u64 min_num, __u64 max_num) {
//     return (rand() % (max_num - min_num + 1)) + min_num;
// }



static void setup_shm()
{
	schedShmFd = shm_open(SCHED_SHM, O_CREAT | O_RDWR, 0666);
	if (schedShmFd < 0) {
		fprintf(stderr, "shm_open(SCHED_SHM,  O_CREAT | O_RDWR, 0666) fail");
		exit(1);

	}

	if (ftruncate(schedShmFd, SHM_SIZE) < 0) {
		fprintf(stderr, "ftruncate(schedShmFd, SHM_SIZE) fail");
		exit(1);
	};

	shm_ptr = (sched_shm *)mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE,
				    MAP_SHARED, schedShmFd, 0);
	if (shm_ptr == MAP_FAILED) {
		fprintf(stderr, "mmap shm_ptr fail");
		exit(1);
	}

	fprintf(stderr, "MEMSET\n");
	memset(shm_ptr, 0, SHM_SIZE);

	pthread_mutexattr_t mutex_attr;
	pthread_mutexattr_init(&mutex_attr);
	pthread_mutexattr_setpshared(&mutex_attr, PTHREAD_PROCESS_SHARED);
	pthread_mutex_init(&shm_ptr->mutex, &mutex_attr);

	pthread_condattr_t cond_attr;
	pthread_condattr_init(&cond_attr);
	pthread_condattr_setpshared(&cond_attr, PTHREAD_PROCESS_SHARED);
	pthread_cond_init(&shm_ptr->cond, &cond_attr);

	pthread_mutexattr_destroy(&mutex_attr);
	pthread_condattr_destroy(&cond_attr);

	shm_ptr->available = 0;
}

static int send_sched_req(struct user_ring_buffer *ringbuf)
{
	int err = 0;
	struct sched_req *req;

	req = user_ring_buffer__reserve(ringbuf, sizeof(*req));
	if (!req) {
		err = -errno;
		return err;
	}

	req->num_call = shm_ptr->num_call;
	req->pid = shm_ptr->pid;
	user_ring_buffer__submit(ringbuf, req);
	printf("[send_sched_req] sched request has been sent\n");
	return 0;
}

static int handle_kernel_reply(void *ctx, void *data, size_t data_sz)
{
	struct event *e = (struct event*)data;
	printf("[handle_kernel_event] e->pid: %d\n", e->pid);
	return 0;
}


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

	while ((opt = getopt(argc, argv, "s:d:hr:u:")) != -1) {
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
		case 'u':
			v = strtoul(optarg, NULL, 10);
			if (v) {
				printf("use udelay: %lu\n", v);
				skel->rodata->use_udelay = 1;
			} else {
				printf("use udelay: 0\n");
				skel->rodata->use_udelay = 0;
			}
			break;
		case 'h':
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_OPS_LOAD(skel, serialise_ops, scx_serialise, uei);
	link = SCX_OPS_ATTACH(skel, serialise_ops);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		__u64 stats[2];
		read_stats(skel, stats);
		printf("main=%llu thread=%llu\n", stats[0], stats[1]);
		fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	UEI_REPORT(skel, uei);
	scx_serialise__destroy(skel);
	return 0;
}



// cleanup:
// 	// /* Clean up */
// 	munmap(shm_ptr, SHM_SIZE);
//     close(schedShmFd);

// 	ring_buffer__free(rb);
// 	user_ring_buffer__free(user_rb);

// 	bpf_link__destroy(link);
// 	UEI_REPORT(skel, uei);
// 	scx_serialise__destroy(skel);
// 	return 0;
// }

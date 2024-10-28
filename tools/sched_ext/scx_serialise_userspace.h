#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>

#define SCHED_SHM "/sched_shared_memory"
#define SHM_SIZE 1024

typedef uint32_t u32;

#define debug(fmt, args...)            \
	do {                                 \
		if (debug)                         \
			fprintf(stderr, fmt, ##args);    \
	} while (0)


#define fail(fmt, args...)             \
	do {                                 \
		fprintf(stderr, fmt, ##args);      \
		exit(1);                           \
	} while (0)

// For communication from e.g. syzkaller to scx_serialise userspace
struct sched_shm {
	pthread_mutex_t mutex;
  pthread_cond_t cond_ready;
	pthread_cond_t cond_done;
  int ready;
	int done;

	int num_call;
	u32 rng_seed;
	unsigned long long pid;
};

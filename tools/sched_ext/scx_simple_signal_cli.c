#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>

#define SCHED_SHM "/sched_shared_memory"
#define SHM_SIZE 1024

bool debug = true;

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

void setup_sched_shm() 
{
	schedShmFd = shm_open(SCHED_SHM,  O_CREAT | O_RDWR, 0666);
	if (schedShmFd < 0) {
		fail("shm_open(SCHED_SHM,  O_CREAT | O_RDWR, 0666) fail");
	}
	if (ftruncate(schedShmFd, SHM_SIZE) < 0) {
		fail("ftruncate(schedShmFd, SHM_SIZE) fail");
	};
	shm_ptr = (sched_shm*)mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, schedShmFd, 0);
	if (shm_ptr == MAP_FAILED) {
		fail("mmap shm_ptr fail");
	}

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
}

void send_sched_req()
{
	debug("[send_sched_req] sending sched requestion\n");
	pthread_mutex_lock(&shm_ptr->mutex);
	debug("[send_sched_req] acquired lock\n");
	// send data here
	shm_ptr->available = 1;
	shm_ptr->num_call = 1;
	shm_ptr->pid = 100;
	
	pthread_cond_signal(&shm_ptr->cond);
	debug("[send_sched_req] signaled cond wait\n");
	pthread_mutex_unlock(&shm_ptr->mutex);
}

int main() {
  setup_sched_shm();
  send_sched_req();
}

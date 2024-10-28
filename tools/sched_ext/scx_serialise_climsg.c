#include <unistd.h>
#include <pthread.h>
#include <sys/mman.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>

#include "scx_serialise_userspace.h"

bool debug = true;

static int schedShmFd;
struct sched_shm *shm_ptr;

static volatile int exit_req;

static void sigint_handler(int simple)
{
	exit_req = 1;
}

void setup_sched_shm() 
{
	schedShmFd = shm_open(SCHED_SHM,  O_RDWR, 0666);
	if (schedShmFd < 0) {
		fail("shm_open(SCHED_SHM,  O_RDWR, 0666) fail");
	}
	if (ftruncate(schedShmFd, SHM_SIZE) < 0) {
		fail("ftruncate(schedShmFd, SHM_SIZE) fail");
	};
	shm_ptr = (struct sched_shm*)mmap(0, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, schedShmFd, 0);
	if (shm_ptr == MAP_FAILED) {
		fail("mmap shm_ptr fail");
	}
}

void send_sched_req()
{
	debug("[send_sched_req] sending sched request\n");
	pthread_mutex_lock(&shm_ptr->mutex);
	debug("[send_sched_req] acquired lock\n");
	// send data here
	shm_ptr->ready = 1;
	shm_ptr->done = 0;

	shm_ptr->num_call = 0;
	shm_ptr->rng_seed = 999;
	shm_ptr->pid = 0;
	
	pthread_cond_signal(&shm_ptr->cond_ready);
	debug("[send_sched_req] signaled cond wait\n");
	pthread_mutex_unlock(&shm_ptr->mutex);
}

int main() {
  setup_sched_shm();
  send_sched_req();
}

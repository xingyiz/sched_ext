/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <pthread.h>
#include <scx/common.h>
#include "scx_simple_signal.h"
#include "scx_simple_signal.bpf.skel.h"

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

int main(int argc, char **argv)
{
	struct scx_simple_signal *skel;
	struct bpf_link *link;
	struct ring_buffer *rb = NULL;
	struct user_ring_buffer *user_rb = NULL;
	int err;

	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	skel = scx_simple_signal__open();
	SCX_BUG_ON(!skel, "Failed to open skel");

	SCX_OPS_LOAD(skel, simple_signal_ops, scx_simple_signal, uei);
	link = SCX_OPS_ATTACH(skel, simple_signal_ops);

	setup_shm();

	rb = ring_buffer__new(bpf_map__fd(skel->maps.kernel_ringbuf),
			      handle_kernel_reply, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	user_rb = user_ring_buffer__new(bpf_map__fd(skel->maps.user_ringbuf),
					NULL);
	if (!user_rb) {
		fprintf(stderr, "Failed to create user_ring_buffer\n");
		goto cleanup;
	}

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		pthread_mutex_lock(&shm_ptr->mutex);

		// wait for the request from executor
		while (!shm_ptr->available) {
			pthread_cond_wait(&shm_ptr->cond, &shm_ptr->mutex);
		}

		if (send_sched_req(user_rb) < 0) {
			fprintf(stderr, "Failed to send request to user_ring_buffer\n");
			break;
		}

		// keep waiting
		err = ring_buffer__poll(rb, -1);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling ring buffer: %d\n", err);
			break;
		}

		shm_ptr->available = 0;

		pthread_mutex_unlock(&shm_ptr->mutex);
	}

cleanup:
	// /* Clean up */
	munmap(shm_ptr, SHM_SIZE);
    close(schedShmFd);

	ring_buffer__free(rb);
	user_ring_buffer__free(user_rb);

	bpf_link__destroy(link);
	UEI_REPORT(skel, uei);
	scx_simple_signal__destroy(skel);
	return 0;
}

/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

struct event {
	int pid;
};

struct sched_req {
	int pid;
    int num_call;
};

struct xorshift32_state {
       u32 a;
};

#endif /* __BOOTSTRAP_H */

/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Define struct user_exit_info which is shared between BPF and userspace parts
 * to communicate exit status and other information.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#ifndef __USER_EXIT_INFO_H
#define __USER_EXIT_INFO_H

enum uei_sizes {
	UEI_REASON_LEN		= 128,
	UEI_MSG_LEN		= 1024,
	UEI_DUMP_DFL_LEN	= 32768,
};

struct user_exit_info {
	int		kind;
	s64		exit_code;
	char		reason[UEI_REASON_LEN];
	char		msg[UEI_MSG_LEN];
};

#ifdef __bpf__

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>

#define UEI_DEFINE(__name)							\
	char RESIZABLE_ARRAY(data, __name##_dump);				\
	const volatile u32 __name##_dump_len;					\
	struct user_exit_info __name SEC(".data")

#define UEI_RECORD(__uei_name, __ei) ({						\
	bpf_probe_read_kernel_str(__uei_name.reason,				\
				  sizeof(__uei_name.reason), (__ei)->reason);	\
	bpf_probe_read_kernel_str(__uei_name.msg,				\
				  sizeof(__uei_name.msg), (__ei)->msg);		\
	bpf_probe_read_kernel_str(__uei_name##_dump,				\
				  __uei_name##_dump_len, (__ei)->dump);		\
	if (bpf_core_field_exists((__ei)->exit_code))				\
		__uei_name.exit_code = (__ei)->exit_code;			\
	/* use __sync to force memory barrier */				\
	__sync_val_compare_and_swap(&__uei_name.kind, __uei_name.kind,		\
				    (__ei)->kind);				\
})

#else	/* !__bpf__ */

#include <stdio.h>
#include <stdbool.h>

/* no need to call the following explicitly if SCX_OPS_LOAD() is used */
#define UEI_SET_SIZE(__skel, __ops_name, __uei_name) ({				\
	u32 __len = (__skel)->struct_ops.__ops_name->exit_dump_len ?: UEI_DUMP_DFL_LEN; \
	(__skel)->rodata->__uei_name##_dump_len = __len;			\
	RESIZE_ARRAY(data, __uei_name##_dump, __len);				\
})

#define UEI_EXITED(__skel, __uei_name) ({					\
	/* use __sync to force memory barrier */				\
	__sync_val_compare_and_swap(&(__skel)->data->__uei_name.kind, -1, -1);	\
})

#define UEI_KIND(__skel, __uei_name) ((__skel)->data->__uei_name.kind)

#define ECODE_USER_MASK		((1LLU << 32) - 1)
#define ECODE_SYS_ACT_MASK	(((1LLU << 48) - 1) ^ ECODE_USER_MASK)
#define ECODE_SYS_RSN_MASK	(~0LLU ^ (ECODE_SYS_ACT_MASK | ECODE_USER_MASK))

#define UEI_ECODE(__skel, __uei_name) (__skel)->data->__uei_name.exit_code
#define UEI_ECODE_SYS_ACT(__skel, __uei_name) (UEI_ECODE(__skel, __uei_name) & ECODE_SYS_ACT_MASK)
#define UEI_ECODE_SYS_RSN(__skel, __uei_name) (UEI_ECODE(__skel, __uei_name) & ECODE_SYS_RSN_MASK)
#define UEI_ECODE_USER(__skel, __uei_name) (UEI_ECODE(__skel, __uei_name) & ECODE_USER_MASK)

#define UEI_REPORT(__skel, __uei_name) ({					\
	struct user_exit_info *__uei = &(__skel)->data->__uei_name;		\
	char *__uei_dump = (__skel)->data_##__uei_name##_dump->__uei_name##_dump; \
	if (__uei_dump[0] != '\0') {						\
		fputs("\nDEBUG DUMP\n", stderr);				\
		fputs("================================================================================\n\n", stderr); \
		fputs(__uei_dump, stderr);					\
		fputs("\n================================================================================\n\n", stderr); \
	}									\
	fprintf(stderr, "EXIT: %s", __uei->reason);				\
	if (__uei->msg[0] != '\0')						\
		fprintf(stderr, " (%s)", __uei->msg);				\
	fputs("\n", stderr);							\
})

#define UEI_RESET(__skel, __uei_name) ({					\
	struct user_exit_info *__uei = &(__skel)->data->__uei_name;		\
	char *__uei_dump = (__skel)->data_##__uei_name##_dump->__uei_name##_dump; \
	size_t __uei_dump_len = (__skel)->rodata->__uei_name##_dump_len;	\
										\
	memset(__uei, 0, sizeof(struct user_exit_info));			\
	memset(__uei_dump, 0, __uei_dump_len);					\
})

#endif	/* __bpf__ */
#endif	/* __USER_EXIT_INFO_H */

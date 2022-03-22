// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kprobe.h"

#define __user
#define U_HOOK_POINT commit_creds
#define U_ARGS struct cred *new
#define U_KPROBE "kprobe/commit_creds"
#define U_TYPE int

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


SEC(U_KPROBE)
U_TYPE BPF_KPROBE(U_HOOK_POINT, U_ARGS)
{
	struct event *e;
	pid_t pid;
	int err;	
	int now_uid;
	struct task_struct *task;

	task = (struct task_struct *)bpf_get_current_task;

	// now_uid = real_cred->uid.val;
	now_uid = BPF_CORE_READ(task, real_cred, uid.val);

	/* Fetch kernel data here */

        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if(!e)
		return 0;
	/* Fill event content here */
        pid = bpf_get_current_pid_tgid() >> 32;
	e->pid = pid;
	bpf_get_current_comm(&e->task_name, sizeof(e->task_name));
	
	e->now_uid = now_uid;
	
        bpf_ringbuf_submit(e, 0);
end:
	return 0;
}


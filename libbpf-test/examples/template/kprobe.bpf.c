// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kprobe.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


#define __user
#define U_HOOK_POINT [HOOK-POINT]
#define U_ARGS [HP-ARGS]

SEC("kprobe/[HOOK-POINT]");
int BPF_KPROBE(U_HOOK_POINT, U_ARGS)
{
	struct event *e;
	pid_t pid;
	int err;

        pid = bpf_get_current_pid_tgid() >> 32;

	/* Fetch kernel data here */

        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if(!e)
		return 0;
	/* Fill event content here */
	e->pid = pid;
	
        bpf_ringbuf_submit(e, 0);
end:
	return 0;
}


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
	struct cred *credentials = new;
	/* Fetch kernel data here */
        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if(!e)
		return 0;
	/* Fill event content here */
	bpf_probe_read(&e->credentials.uid, sizeof(e->credentials.uid), &credentials->uid);
	bpf_probe_read(&e->credentials.gid, sizeof(e->credentials.gid), &credentials->gid);
	bpf_probe_read(&e->credentials.euid, sizeof(e->credentials.euid), &credentials->euid);
	bpf_probe_read(&e->credentials.egid, sizeof(e->credentials.egid), &credentials->egid);
	bpf_probe_read(&e->credentials.fsuid, sizeof(e->credentials.fsuid), &credentials->fsuid);
	bpf_probe_read(&e->credentials.fsgid, sizeof(e->credentials.fsgid), &credentials->fsgid);
	bpf_probe_read(&e->credentials.cap_effective, sizeof(e->credentials.cap_effective), &credentials->cap_effective);
	bpf_probe_read(&e->credentials.cap_permitted, sizeof(e->credentials.cap_permitted), &credentials->cap_permitted);

	e->pid = pid;
	bpf_get_current_comm(&e->task_name, sizeof(e->task_name));
	
        bpf_ringbuf_submit(e, 0);
end:
	return 0;
}


// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kprobe.h"
#include "dentry_resolver.h"

#define __user
#define U_HOOK_POINT vfs_unlink
#define U_ARGS struct inode *dir, struct dentry *dentry, struct inode **delegated_inode
#define U_KPROBE "kprobe/vfs_unlink"
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

    pid = bpf_get_current_pid_tgid() >> 32;

	
	// resolve_dentry(ctx, DR_KPROBE);
	//kprobe_dentry_resolver_kern(ctx);
	dentry_resolver_kern(ctx, &dentry_resolver_kprobe_progs, &dentry_resolver_kprobe_callbacks, DR_KPROBE_DENTRY_RESOLVER_KERN_KEY);
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


// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kprobe.h"

#define __user
#define U_HOOK_POINT security_inode_create
#define U_ARGS struct inode *dir, struct dentry *dentry, umode_t mode
// #define U_KPROBE "kprobe/security_inode_create"
#define U_KPROBE "fentry/security_inode_create"
#define U_TYPE int

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


SEC(U_KPROBE)
// U_TYPE BPF_KPROBE(U_HOOK_POINT, U_ARGS)
U_TYPE BPF_PROG(U_HOOK_POINT, U_ARGS)
{
	struct event *e;
	pid_t pid;
	struct task_struct *task;
	struct files_struct *files;
	struct fdtable *fdt;
	struct file **fp;
	struct file *f = NULL;
	struct path path;
	struct dentry *d;

	int max_fds;
	int err;

        pid = bpf_get_current_pid_tgid() >> 32;
	task = (struct task_struct *)bpf_get_current_task();
	files = BPF_CORE_READ(task, files);
	if(!files)
		return 0;
	fdt = BPF_CORE_READ(files, fdt);
	if(!fdt)
		return 0;
		
	max_fds = BPF_CORE_READ(fdt, max_fds);
		
	fp = BPF_CORE_READ(fdt, fd);
	if(max_fds > 3)
		f = fp[3];
	if(f){
		// path = BPF_CORE_READ(f, f_path);
		d = BPF_CORE_READ(f, f_path.dentry);
	}


        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if(!e)
		return 0;
	/* Fill event content here */
	e->pid = pid;
	e->max_fds = max_fds;
	
        bpf_ringbuf_submit(e, 0);
end:
	return 0;
}


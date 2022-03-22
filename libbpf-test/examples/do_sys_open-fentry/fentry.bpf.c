// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fentry.h"

#define __user
#define U_HOOK_POINT do_sys_open
#define U_ARGS int dfd, const char __user *filename, int flags, umode_t mode
#define U_FENTRY "fentry/do_sys_open"
#define U_TYPE long

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


SEC(U_FENTRY)
U_TYPE BPF_PROG(U_HOOK_POINT, U_ARGS)
{
	struct event *e;
	pid_t pid;
	int err;

	char buff[128];

	struct task_struct *task;
	struct mm_struct *mm;
	struct file *exe_file;
	
	task = (void *)bpf_get_current_task();
	mm = BPF_CORE_READ(task, mm);
	if(!mm)
		return 0;
	exe_file = BPF_CORE_READ(mm, exe_file);
	bpf_d_path(&exe_file->f_path, buff, 128);

        pid = bpf_get_current_pid_tgid() >> 32;

        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if(!e)
		return 0;
	/* Fill event content here */
	e->pid = pid;
	//bpf_d_path(&nd->path, buff, 128);
	bpf_probe_read_str(e->filename, 128, filename);
	
        bpf_ringbuf_submit(e, 0);
end:
	return 0;
}


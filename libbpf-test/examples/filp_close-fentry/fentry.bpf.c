// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include "fentry.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
      __uint(type, BPF_MAP_TYPE_RINGBUF);
      __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

static void m_get_task_file_path(struct task_struct *task, char *buff)
{
        struct file *file;
        struct mm_struct *mm;
	
	char tmp[128];
        if(!task)
                goto out;
	bpf_probe_read(&mm, sizeof(mm), &(task->mm));
	if(!mm)
		goto out;
	bpf_probe_read(&file, sizeof(file), &(mm->exe_file));
	if(!file)
		goto out;
        bpf_d_path(&file->f_path, tmp, 128);
out:
        return;
}

SEC("fentry/filp_close")
int BPF_PROG(filp_close, struct file *file, void *id)
{
	pid_t pid;
	struct event *e;
	int ret;
	char path[128] = {};
	char task_path[128] = {};
	pid = bpf_get_current_pid_tgid() >> 32;

	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if(!e)      // 没有这个检测过不了 verifier
		return 0;
	e->pid = pid;
#if 0
	bpf_get_current_comm(&e->task_name, sizeof(e->task_name));
#else
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	m_get_task_file_path(task, task_path);
	bpf_probe_read_str(e->task_name, 128, task_path);
#endif
        bpf_d_path(&file->f_path, path, 128);
	bpf_probe_read_str(e->filename, 128, path);
	bpf_ringbuf_submit(e, 0);
	return 0;
}


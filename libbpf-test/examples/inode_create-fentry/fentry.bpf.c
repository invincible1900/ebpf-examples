// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fentry.h"

#define __user
#define U_HOOK_POINT security_inode_create
#define U_ARGS struct inode *dir, struct dentry *dentry, umode_t mode
#define U_FENTRY "fentry/security_inode_create"
#define U_TYPE int

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


static struct file * u_get_task_file(struct task_struct *task){
	struct file *file = NULL;
	struct mm_struct *mm;

	if(!task)
		goto out;
	mm = BPF_CORE_READ(task, mm);
	if(!mm)
		goto out;
	file = BPF_CORE_READ(mm, exe_file);
out:
	return file;
}

static const unsigned char *u_get_file_name(struct file *file){
	struct dentry *dentry;
	dentry = BPF_CORE_READ(file, f_path.dentry);
	if(dentry)
		return BPF_CORE_READ(dentry, d_name.name);
	else
		return NULL;
}

static struct file *u_task_lookup_fd(struct task_struct *task, int fd){
        struct files_struct *files;
        struct file *file;
        struct fdtable *fdt;
        struct file **farr;
        const unsigned char *fname;
        unsigned int max_fds;

        files = BPF_CORE_READ(task, files);
        if(!files)
                goto out;

        fdt = BPF_CORE_READ(files, fdt);
        if(!fdt)
                goto out;

	max_fds = BPF_CORE_READ(fdt, max_fds);
        farr = BPF_CORE_READ(fdt, fd);

	//if(fd < max_fds)
	bpf_probe_read(&file, 8, farr + fd);
out:
	return file;
}


SEC(U_FENTRY)
U_TYPE BPF_PROG(U_HOOK_POINT, U_ARGS)
{
	struct event *e;
	pid_t pid;
	int err;
	char buff[MAX_LEN];

	const unsigned char *pname;
	struct file *exe;
	struct task_struct *task;
	task = (struct task_struct *)bpf_get_current_task();
	exe = u_get_task_file(task);

	/* API */
        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if(!e)
		return 0;
	/* USER CODE START: fill event content here*/
	
	/* get pid */
	pid = bpf_get_current_pid_tgid() >> 32;
	e->pid = pid;

	/* get task name */
#if 1
	bpf_get_current_comm(&e->task_name, sizeof(e->task_name));
#else
	bpf_probe_read_str(e->task_name, sizeof(e->task_name), get_file_name(exe));
#endif

	/* get inode create name */
	pname = BPF_CORE_READ(dentry, d_name.name);
	bpf_probe_read_str(e->filename, sizeof(e->filename), pname);

	/* get file tables */
	struct file *file;
	const unsigned char *fname;
	for(int fd = 3; fd<10; fd++){
		file = u_task_lookup_fd(task, fd);
		if(!file)
			goto submit;
		fname = u_get_file_name(file);

		if(!fname)	
			goto submit;
		bpf_probe_read_str(e->files[fd], 128, fname);
	}
	
	/* USER CODE END */
submit:	
	/* API: submit */
        bpf_ringbuf_submit(e, 0);
end:
	return 0;
}


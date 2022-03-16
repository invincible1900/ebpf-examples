// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "mkprobe.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("kprobe/security_mmap_file")
int BPF_KPROBE(security_mmap_file, struct file *file, unsigned long prot, unsigned long flags)
{
	struct event *e;
	struct task_struct *task;
	int err;

        pid_t pid;
	struct dentry *dentry = NULL;
	const unsigned char *path = NULL;

// 这两个 Macro 不知道怎么导
#define VM_EXEC         0x00000004  
#define MAP_EXECUTABLE 0x1000	
	// 过滤掉非可执行文件
	if(!(prot & VM_EXEC))
		goto end;

#if 0
	// 过滤掉 .so 文件
	if(!(flags & MAP_EXECUTABLE))
		goto end;
#endif		
        pid = bpf_get_current_pid_tgid() >> 32;

	if(file){
		dentry = BPF_CORE_READ(file, f_path.dentry); 
		// dentry = file->f_path.dentry; not work
		if(dentry)
			path = (const unsigned char *)BPF_CORE_READ(dentry, d_name.name);
			// path = dentry->d_name.name; not work
	}

        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if(!e)
		return 0;
	e->pid = pid;
        
	task = (struct task_struct *)bpf_get_current_task();
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);

        bpf_get_current_comm(&e->comm, sizeof(e->comm));

	if(path)
	        bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)path);
        	// bpf_printk("KPROBE ENTRY pid = %d, %s\n", pid, path);
        bpf_ringbuf_submit(e, 0);
end:
	return 0;
}


// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kprobe.h"

#define TEST0 0
#define TEST 1
#define TEST2 2
#define TEST3 3

#define __stringify_1(x...)	#x
#define __stringify(x...)	__stringify_1(x)
#define PROG(F) SEC("kprobe/"__stringify(F)) int bpf_func_##F

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 8);
} jmp_table SEC(".maps");

struct ctx {
	struct event *e;
	struct dentry *dentry;
};

struct {
        __uint(type, BPF_MAP_TYPE_RINGBUF);
        __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 8192);
        __type(key, int);
        __type(value, int);
} hash_map SEC(".maps");

// 这两个 Macro 不知道怎么导
#define VM_EXEC         0x00000004  
#define MAP_EXECUTABLE 0x1000	

SEC("kprobe/security_mmap_file")
int BPF_KPROBE(security_mmap_file, struct file *file, unsigned long prot, unsigned long flags)
{
	struct event *e;
	struct task_struct *task;
	int err;

        pid_t pid;
	struct dentry *dentry = NULL;
	const unsigned char *path = NULL;

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
#if 1
	int hmk = 0;
	int *pval;
	int val;
	pval = bpf_map_lookup_elem(&hash_map, &hmk);
	if(pval){
		e->test = *pval;
		val = *pval + 1;
		// bpf_map_update_elem(&hash_map, &hmk, &val, BPF_ANY);
	}else{
		val = 1;
		e->test = val;
		bpf_map_update_elem(&hash_map, &hmk, &val, BPF_ANY);
	}

    bpf_ringbuf_submit(e, 0);

	bpf_tail_call(ctx, &jmp_table, TEST);
#else
    bpf_ringbuf_submit(e, 0);
#endif
end:
	return 0;
}


PROG(TEST0)(void *ctx){	
	int key = 0, value = 10;
#if 0
	int *tmp;
    tmp = bpf_map_lookup_elem(&hash_map, &key);
	if(tmp)
		value = *tmp + 1;
#endif
	bpf_map_update_elem(&hash_map, &key, &value, BPF_ANY);

	// c->e->test = (unsigned long)(c->dentry);
    // bpf_ringbuf_submit(c->e, 0);
	return 0;
}


PROG(TEST)(void *ctx){	
	int key = 0, value = 10;
#if 0
	int *tmp;
    tmp = bpf_map_lookup_elem(&hash_map, &key);
	if(tmp)
		value = *tmp + 1;
#endif
	bpf_map_update_elem(&hash_map, &key, &value, BPF_ANY);

	// c->e->test = (unsigned long)(c->dentry);
    // bpf_ringbuf_submit(c->e, 0);
	return 0;
}

PROG(TEST2)(void *ctx){	
	int key = 0, value = 12;
#if 0
	int *tmp;
    tmp = bpf_map_lookup_elem(&hash_map, &key);
	if(tmp)
		value = *tmp + 1;
#endif
	bpf_map_update_elem(&hash_map, &key, &value, BPF_ANY);

	// c->e->test = (unsigned long)(c->dentry);
    // bpf_ringbuf_submit(c->e, 0);
	return 0;
}

PROG(TEST3)(void *ctx){	
	int key = 0, value = 13;
#if 0
	int *tmp;
    tmp = bpf_map_lookup_elem(&hash_map, &key);
	if(tmp)
		value = *tmp + 1;
#endif
	bpf_map_update_elem(&hash_map, &key, &value, BPF_ANY);

	// c->e->test = (unsigned long)(c->dentry);
    // bpf_ringbuf_submit(c->e, 0);
	return 0;
}


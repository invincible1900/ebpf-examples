// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "kprobe.h"

#define U_HOOK_POINT do_init_module
#define U_KPROBE "kprobe/do_init_module"
#define U_ARGS struct module *mod
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
	const char *mname;
	int err;

        e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if(!e)
		return 0;

	/* Fill event content here */
        pid = bpf_get_current_pid_tgid() >> 32;
	e->pid = pid;

	mname = BPF_CORE_READ(mod, mkobj.kobj.name);
	if(mname)
		bpf_probe_read_str(&e->mod_name, sizeof(e->mod_name), mname);	

	bpf_get_current_comm(&e->task_name, sizeof(e->task_name));
        bpf_ringbuf_submit(e, 0);
end:
	return 0;
}


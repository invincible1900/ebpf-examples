// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
// #include "kprobe.h"
#include "kprobe.skel.h"

#define MAX_LEN 128
#define _KERNEL_CAPABILITY_U32S 2
typedef struct kernel_cap_struct {
        __u32 cap[_KERNEL_CAPABILITY_U32S];
} kernel_cap_t;

typedef struct {
        uid_t val;
} kuid_t;

typedef struct {
        gid_t val;
} kgid_t;

struct credentials {
    kuid_t uid;
    kgid_t gid;
    kuid_t suid;
    kgid_t sgid;
    kuid_t euid;
    kgid_t egid;
    kuid_t fsuid;
    kgid_t fsgid;
    unsigned securebits;
    kernel_cap_t cap_inheritable;
    kernel_cap_t cap_permitted;
    kernel_cap_t cap_effective;
    kernel_cap_t cap_bset;
    kernel_cap_t cap_ambient;
};

struct event {
        // event data here
        int pid;
        char task_name[MAX_LEN];
        struct credentials credentials;
};

static volatile sig_atomic_t stop;
static void sig_int(int signo){	stop = 1; }

static int handle_event_cb(void *ctx, void *data, size_t data_sz)
{
        const struct event *e = data;
	printf("%s, %d, %d, %d,  %d, %d,  %d, %d,  %d, %d, %d\n", e->task_name, e->pid, 
		e->credentials.uid.val,
		e->credentials.gid.val,
		e->credentials.suid.val,
		e->credentials.sgid.val,
		e->credentials.euid.val,
		e->credentials.egid.val,
		e->credentials.fsuid.val,
		e->credentials.fsgid.val,
		e->credentials.securebits
	);	
	
        return 0;
}

int main(int argc, char **argv)
{
        struct ring_buffer *rb = NULL;
	struct kprobe_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	/* Open load and verify BPF application */
	skel = kprobe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = kprobe_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

        rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event_cb, NULL, NULL);

	printf("Successfully started! \n");

	while (!stop) {
		ring_buffer__poll(rb, 100 /* timeout, ms */);
	}


cleanup:
        ring_buffer__free(rb);
	kprobe_bpf__destroy(skel);
	return -err;
}

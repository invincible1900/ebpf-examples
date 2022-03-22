// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <time.h>
#include "kprobe.h"
#include "kprobe.skel.h"

static volatile sig_atomic_t stop;
static void sig_int(int signo){	stop = 1; }

#if 0
static int handle_event_cb(void *ctx, void *data, size_t data_sz)
{
        const struct event *e = data;

        printf("%-5s %-16s %-7d %-7d %s\n",
                       "[security_mmap_file]", e->comm, e->pid, e->ppid, e->filename);
        return 0;
}
#endif

int main(int argc, char **argv)
{
        struct ring_buffer *rb = NULL;
	struct kprobe_bpf *skel;
	int err;

	int key = 0;
	int next_key = 0;
	// int v = 0;
	struct event e = {};
	int ret = 0;
	int map_fd;
	struct event value = {};

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	/* Open load and verify BPF application */
	skel = kprobe_bpf__open_and_load();
	//if (!skel) {
	//	fprintf(stderr, "Failed to open BPF skeleton\n");
	//	return 1;
	//}

	/* Attach tracepoint handler */
	err = kprobe_bpf__attach(skel);
	//if (err) {
	//	fprintf(stderr, "Failed to attach BPF skeleton\n");
	//	goto cleanup;
	//}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

        // rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event_cb, NULL, NULL);

	printf("Successfully started! \n");
	map_fd = bpf_map__fd(skel->maps.hash_map);
#if 0
	while(!stop){
		ret = bpf_map_get_next_key(map_fd, &key, &next_key);
		if(key != next_key)
			printf("%d, %d, %d\n", key, next_key, ret);
		if(ret){
			// sleep(1);
			continue;
		}
		key = next_key;
		// next_key = 0;
		ret = bpf_map_lookup_elem(map_fd, &key, &value);
		printf("[+] %d, %d, %d\n", key, value.pid, ret);
		sleep(1);
	}
#else
	while(!stop){
		ret = bpf_map_lookup_elem(map_fd, &key, &e);
		if(!ret)
		// printf("[ ] hit %d times\n", v.pid);
			printf("[ ]  %s \n", e.comm);
		// sleep(1);
	}
#endif
#if 0
        printf("%-20s %-16s %-7s %-7s %s\n",
		"Hook", "comm", "pid", "ppid", "filename");

	while (!stop) {
		ring_buffer__poll(rb, 100 /* timeout, ms */);
	}
#endif


cleanup:
//        ring_buffer__free(rb);
	kprobe_bpf__destroy(skel);
	return -err;
}

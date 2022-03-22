// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "fentry.h"
#include "fentry.skel.h"

static volatile sig_atomic_t stop;
static void sig_int(int signo){	stop = 1; }

static int handle_event_cb(void *ctx, void *data, size_t data_sz)
{
        const struct event *e = data;
	printf("%s, %d, %s\n", e->task_name, e->pid, e->mod_name);
        return 0;
}

int main(int argc, char **argv)
{
        struct ring_buffer *rb = NULL;
	struct fentry_bpf *skel;
	int err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

	/* Open load and verify BPF application */
	skel = fentry_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	err = fentry_bpf__attach(skel);
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
	fentry_bpf__destroy(skel);
	return -err;
}

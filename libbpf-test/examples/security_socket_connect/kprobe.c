// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2021 Sartura
 * Based on minimal.c by Facebook */

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "kprobe.h"
#include "kprobe.skel.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

static volatile sig_atomic_t stop;
static void sig_int(int signo){	stop = 1; }

static void handle_event(void *ctx, int cpu, void *data, __u32 size) {
	// struct event *e = data;
	struct ipv4_event_t *e = data;
	char laddr_str[40];
	char daddr_str[40];
	struct in_addr ina = {.s_addr = e->laddr};
	sprintf(laddr_str, "%s", inet_ntoa(ina));

	ina.s_addr = e->daddr;
	sprintf(daddr_str, "%s", inet_ntoa(ina));

/* skc_dport 是 be16
 162 struct sock_common {
 ...
 180                 struct {
 181                         __be16  skc_dport;
 182                         __u16   skc_num;
 183                 };
*/	
	printf("%s, %d, %s, %d, %s, %d, %d\n", e->task ,e->pid, laddr_str, e->lport, daddr_str, ntohs(e->dport), e->af);
}


int main(int argc, char **argv)
{
        // struct ring_buffer *rb = NULL;
	struct kprobe_bpf *skel;
	int err;

	struct perf_buffer_opts pb_opts = {};
	struct perf_buffer *pb;

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
#if 1
        // rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event_cb, NULL, NULL);
	
	// pb_opts.sample_cb = print_bpf_output;
	pb_opts.sample_cb = handle_event;
	pb = perf_buffer__new(bpf_map__fd(skel->maps.ipv4_events), 8 /* 32KB per CPU */, &pb_opts);

	//pb = perf_buffer__new(map_fd, 8, print_bpf_output, NULL, NULL, &pb_opts);
	if (libbpf_get_error(pb)) {
		fprintf(stderr, "Failed to create perf buffer\n");
		goto cleanup;
	}
	printf("Successfully started! \n");
#endif
	while (!stop) {
		perf_buffer__poll(pb, 1000);
		// ring_buffer__poll(rb, 100 /* timeout, ms */);
	}


cleanup:
        //ring_buffer__free(rb);
	kprobe_bpf__destroy(skel);
	return -err;
}


// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <arpa/inet.h>
#include <assert.h>
#include <bpf/libbpf.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
#include "bootstrap.h"
#include "bootstrap.skel.h"

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"BPF bootstrap demo application.\n"
"\n"
"It traces process start and exits and shows associated \n"
"information (filename, process duration, PID and PPID, etc).\n"
"\n"
"USAGE: ./bootstrap [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static inline void ltoa(uint32_t addr, char *dst)
{
	snprintf(dst, 16, "%u.%u.%u.%u", (addr >> 24) & 0xFF, (addr >> 16) & 0xFF,
		 (addr >> 8) & 0xFF, (addr & 0xFF));
}

static inline void print_l4_proto(uint8_t proto)
{
	switch (proto)
	{
	case IPPROTO_TCP:
		printf("TCP");
		break;
	case IPPROTO_UDP:
		printf("UDP");
		break;
	default:
		printf("Unknown");
		break;
	}
}

static inline void print_tls_content_type(uint8_t content_type)
{
	switch (content_type)
	{
	case 20:
		printf("Change Cipher Spec: ");
		break;
	case 21:
		printf("Alert");
		break;
	case 22:
		printf("Handshake");
		break;
	case 23:
		printf("Application Data");
		break;
	case 24:
		printf("Heartbeat");
		break;
	default:
		printf("Unknown");
		break;
	}
}

static inline void print_tls_message_type(uint8_t message_type)
{
	switch (message_type)
	{
	case 0:
		printf("Hello Request");
		break;
	case 1:
		printf("Client Hello");
		break;
	case 2:
		printf("Server Hello");
		break;
	case 3:
		printf("Hello Verify Request");
		break;
	case 4:
		printf("New Session Ticket");
		break;
	case 8:
		printf("Encrypted Extensions");
		break;
	case 11:
		printf("Certificate");
		break;
	case 12:
		printf("Server Key Exchange");
		break;
	case 13:
		printf("Certificate Request");
		break;
	case 14:
		printf("Server Hello Done");
		break;
	case 15:
		printf("Certificate Verify");
		break;
	case 16:
		printf("Client Key Exchange");
		break;
	case 20:
		printf("Finished");
		break;
	default:
		printf("Unknown or Encrypted");
		break;
	}
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct so_event *e = data;

	char sstr[16] = {}, dstr[16] = {};


	ltoa(e->fl.src_addr, sstr);
	ltoa(e->fl.dst_addr, dstr);

	printf("src ip: %s\nsrc port: %d\ndst ip: %s\ndst port: %d\nprotocol: ", sstr, e->fl.src_port, dstr, e->fl.dst_port);

	print_l4_proto(e->fl.l4_proto);

	if(e->tls.content_type == 0)
	{
		printf("\nNo TLS content\n\n");
		return 0;
	}

	printf("\ntls content type: ");
	print_tls_content_type(e->tls.content_type);

	printf("\ntls message type: ");
	print_tls_message_type(e->tls.message_type);

	printf("\n\n");
	
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct bootstrap_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = bootstrap_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	//skel->links.xdp_parser_func = bpf_program__attach_xdp(skel->progs.xdp_parser_func, 2);
	/* Parameterize BPF code with minimum duration parameter 
	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;*/

	/* Load & verify BPF programs */
	err = bootstrap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	skel->links.xdp_parser_func = bpf_program__attach_xdp(skel->progs.xdp_parser_func, 2);

	/* Attach BPF programs */
	err = bootstrap_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}
	
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
		
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	bootstrap_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}

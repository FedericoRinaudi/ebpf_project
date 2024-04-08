/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

typedef union {
    __be32 ipv4;
    struct in6_addr ipv6;
} ip_address;

struct flow {
	ip_address src_addr;
	ip_address dst_addr;
	__be16 src_port;
	__be16 dst_port;
	__be16 l3_proto;
	__u8 l4_proto;
};

struct tls_info {
	__u8 content_type; // 0 if no tls
	__u8 message_type; //may be encrypted
	//TODO: add other fields as needed (message type length and data)
};

struct so_event {
	struct flow fl;
	struct tls_info tls;
};

#endif /* __BOOTSTRAP_H */

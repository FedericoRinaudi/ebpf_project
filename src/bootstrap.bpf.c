#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "bootstrap.h"
#include "flags.h"

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define TC_ACT_OK 0
#define ETH_P_IP 0x0800 /* Internet Protocol packet */
#define ETH_HLEN 14


struct
{
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct flow);
    __type(value, __u8);
} flow_map SEC(".maps");


SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *) (long) ctx->data_end;
	void *data = (void*) (long)ctx->data;
	struct so_event *e;
	struct ethhdr *eth = data;
	struct iphdr *ip_v4;
	struct tcphdr *tcp;
	struct udphdr *udp;
	void *l3_start = data + ETH_HLEN;
	void *l4_start; 
	void *tls_start;
	__u16 h_proto, frag_off, ip_len;
	__be16 l4_len;
	__be16 tcp_len;
	__u8 *value, l4_protocol;
	struct flow fl = {};
	struct tls_info tls = {};


	if (data + sizeof(struct ethhdr) > data_end)
		return XDP_PASS;

	h_proto = bpf_ntohs(eth->h_proto);

	

	if (h_proto != ETH_P_IP)
	{
		return XDP_PASS;
	}

	//l3 management
	//TODO: ipv6 support
	ip_v4 = (struct iphdr *) l3_start;
	if ((void*) ip_v4 + sizeof(struct iphdr) > data_end){
		bpf_printk("No IP packet\n");
		return XDP_PASS;
	}

	frag_off = bpf_ntohs(ip_v4->frag_off);

	//TODO: fragmented packets support
	if (frag_off & (IP_MF | IP_OFFSET))
	{
		bpf_printk("Fragmented IP packet\n");
		return XDP_PASS;
	}
	ip_len = ip_v4->ihl << 2;
	l4_protocol = ip_v4->protocol;
	fl.src_addr = bpf_ntohl(ip_v4->saddr);
	fl.dst_addr = bpf_ntohl(ip_v4->daddr);

	//l4 management
	l4_start = l3_start + ip_len;

	switch (l4_protocol)
	{
		case IPPROTO_TCP:

			tcp = (struct tcphdr *) l4_start;

			if ((void*) tcp + sizeof(struct tcphdr) > data_end)
				return XDP_PASS;

			fl.src_port = bpf_ntohs(tcp->source);
			fl.dst_port = bpf_ntohs(tcp->dest);
			fl.ip_proto = IPPROTO_TCP;

			l4_len = (__be16)(tcp->doff);
			l4_len <<= 2;

			break;

		case IPPROTO_UDP:

			udp = (struct udphdr *) l4_start;

			if ((void*) udp + sizeof(struct udphdr) > data_end)
				return XDP_PASS;

			fl.src_port = bpf_ntohs(udp->source);
			fl.dst_port = bpf_ntohs(udp->dest);
			fl.ip_proto = IPPROTO_UDP;

			l4_len = 8;

			break;
		default:
			return XDP_PASS;
	}
	

	#if FIRST_PACKET_OF_FLOW_ONLY
	//check if flow already exists
	value = bpf_map_lookup_elem(&flow_map, &fl);

	if (value) 
	{
		bpf_printk("Flow already exists\n");
    	return XDP_PASS;
	} 
	else 
	{
		__u8 val = 1;
		bpf_map_update_elem(&flow_map, &fl, &val, BPF_ANY);
	}
	#endif
	//tls management
	tls_start = l4_start + l4_len;

	//This check does not guarantee that the packet is a TLS packet
	if (tls_start + 6 > data_end || *((__u8*)tls_start) < 20 || *((__u8*)tls_start) > 24)
	{
		tls.content_type = 0;
		goto send;
	}

	tls.content_type = *((__u8*)tls_start);
	tls.message_type = *((__u8*)tls_start + 5);
	

send:
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);

	if (!e)
		return 0;

	e->fl = fl;
	e->tls = tls;

	bpf_ringbuf_submit(e, 0);

	return XDP_PASS;
}


char __license[] SEC("license") = "GPL";

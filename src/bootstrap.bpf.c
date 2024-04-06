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

static inline int ip_is_fragment(struct iphdr *iph)
{
	return bpf_ntohs(iph->frag_off) & (IP_MF | IP_OFFSET);
}

static inline void* manage_ethernet(void* data, void* data_end, struct flow *fl)
{
	struct ethhdr *eth = data;

	if (data + sizeof(struct ethhdr) > data_end)
		return NULL;

	fl->l3_proto = bpf_ntohs(eth->h_proto);

	//TODO: add ipv6 support
	if (fl->l3_proto != ETH_P_IP)
	{
		return NULL;
	}

	return data + ETH_HLEN;
}

static inline void* manage_ipv4(void* data, void* data_end, struct flow *fl)
{

	__u8 ip_len;
	struct iphdr *ip_v4 = (struct iphdr *) data;
	if ((void*) ip_v4 + sizeof(struct iphdr) > data_end){
		bpf_printk("No IP packet\n");
		return NULL;
	}

	if (ip_is_fragment(ip_v4))
	{
		bpf_printk("Fragmented IP packet\n");
		return NULL;
	}
	ip_len = ip_v4->ihl << 2;
	fl->l4_proto = ip_v4->protocol;
	fl->src_addr = bpf_ntohl(ip_v4->saddr);
	fl->dst_addr = bpf_ntohl(ip_v4->daddr);

	return data + ip_len;
}

static inline void* manage_tcp(void* data, void* data_end, struct flow *fl)
{
	struct tcphdr *tcp = (struct tcphdr *) data;

	if ((void*) tcp + sizeof(struct tcphdr) > data_end)
		return NULL;

	fl->src_port = bpf_ntohs(tcp->source);
	fl->dst_port = bpf_ntohs(tcp->dest);

	return data + (tcp->doff << 2);
}

static inline void* manage_udp(void* data, void* data_end, struct flow *fl)
{
	struct udphdr *udp = (struct udphdr *) data;

	if ((void*) udp + sizeof(struct udphdr) > data_end)
		return NULL;

	fl->src_port = bpf_ntohs(udp->source);
	fl->dst_port = bpf_ntohs(udp->dest);

	return data + 8;
}

static inline void manage_tls(void* data, void* data_end, struct tls_info *tls)
{
	if (data + 6 > data_end || *((__u8*)data) < 20 || *((__u8*)data) > 24)
	{
		tls->content_type = 0;
		return;
	}

	tls->content_type = *((__u8*)data);
	tls->message_type = *((__u8*)data + 5);

	return;

}

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *) (long) ctx->data_end;
	void *data = (void*) (long)ctx->data;
	struct so_event *e;
	__u8 *value;
	struct flow fl = {};
	struct tls_info tls = {};

	//l2 management

	data = manage_ethernet(data, data_end, &fl);

	if (!data)
		return XDP_PASS;

	//l3 management
	//TODO: ipv6 support

	data = manage_ipv4(data, data_end, &fl);

	if (!data)
		return XDP_PASS;

	//l4 management

	switch (fl.l4_proto)
	{
		case IPPROTO_TCP:

			data = manage_tcp(data, data_end, &fl);

			break;

		case IPPROTO_UDP:

			data = manage_udp(data, data_end, &fl);

			break;
		default:
			return XDP_PASS;
	}
	
	if (!data)
		return XDP_PASS;

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
	manage_tls(data, data_end, &tls);

	//put event in ring buffer
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);

	if (!e)
		return 0;

	e->fl = fl;
	e->tls = tls;

	bpf_ringbuf_submit(e, 0);

	return XDP_PASS;
}


char __license[] SEC("license") = "GPL";

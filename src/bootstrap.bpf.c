#include <vmlinux.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "bootstrap.h"
#include "flags.h"
#include "const.h"

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

static inline int is_little_endian() {
    int num = 1;
    return *(char *)&num == 1;
}

static inline int ip_is_fragment(struct iphdr *iph)
{
	return bpf_ntohs(iph->frag_off) & (IP_MF | IP_OFFSET);
}

static inline void* manage_ethernet(void* data, void* data_end, struct flow *fl)
{
	struct ethhdr *eth = data;

	if (data + ETH_HLEN > data_end)
		return NULL;

	fl->l3_proto = bpf_ntohs(eth->h_proto);

	return data + ETH_HLEN;
}

static inline void* manage_ipv4(void* data, void* data_end, struct flow *fl)
{

	__u8 ip_len;
	struct iphdr *ip_v4 = (struct iphdr *) data;
	if (data + IPV4_MIN_HLEN > data_end){
		bpf_printk("No IP packet\n");
		return NULL;
	}

	if (ip_is_fragment(ip_v4))
	{
		bpf_printk("Fragmented IP packet\n");
		return NULL;
	}
	
	ip_len = ip_v4->ihl << 2;
	
	if (data + ip_len > data_end)
		return NULL;

	fl->l4_proto = ip_v4->protocol;
	fl->src_addr.ipv4 = bpf_ntohl(ip_v4->saddr);
	fl->dst_addr.ipv4 = bpf_ntohl(ip_v4->daddr);

	return data + ip_len;
}

static inline struct in6_addr ntohin6_addr(struct in6_addr ipv6)
{
	struct in6_addr ret;
	__u64 *src = (__u64 *)&ipv6;
	__u64 *dst = (__u64 *)&ret;

	if(is_little_endian())
	{
		dst[0] = bpf_ntohl(src[3]);
		dst[1] = bpf_ntohl(src[2]);
		dst[2] = bpf_ntohl(src[1]);
		dst[3] = bpf_ntohl(src[0]);
	}
	else
	{
		ret = ipv6;
	}

	return ret;
}

//TODO: at the moment we are not managing extension headers. while cycle nedeed and it creates me problem with the verifier
static inline void* manage_ipv6(void* data, void* data_end, struct flow *fl)
{
	struct ipv6hdr *ip_v6 = (struct ipv6hdr *) data;

	if ((void*) ip_v6 + IPV6_HLEN > data_end)
		return NULL;
	
	if(ip_v6->nexthdr != IPPROTO_TCP && ip_v6->nexthdr != IPPROTO_UDP)
	{
		bpf_printk("IPV6 extensione header not supported\n");
		return NULL;
	}

	fl->l4_proto = ip_v6->nexthdr;
	fl->src_addr.ipv6 = ntohin6_addr(ip_v6->saddr);
	fl->dst_addr.ipv6 = ntohin6_addr(ip_v6->daddr);

	return data + IPV6_HLEN;
}

static inline void* manage_tcp(void* data, void* data_end, struct flow *fl)
{
	struct tcphdr *tcp = (struct tcphdr *) data;
	__u16 tcp_hlen;

	if (data + TCP_MIN_HLEN > data_end)
		return NULL;

	tcp_hlen = tcp->doff << 2;

	if (data + tcp_hlen > data_end)
		return NULL;

	fl->src_port = bpf_ntohs(tcp->source);
	fl->dst_port = bpf_ntohs(tcp->dest);

	return data + tcp_hlen;
}

static inline void* manage_udp(void* data, void* data_end, struct flow *fl)
{
	struct udphdr *udp = (struct udphdr *) data;

	if (data + 8 > data_end)
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
	switch(fl.l3_proto)
	{
		case ETH_P_IPV4:
			data = manage_ipv4(data, data_end, &fl);
			break;
		/*case ETH_P_IPV6:
			data = manage_ipv6(data, data_end, &fl);
			break;*/
		default:
			return XDP_PASS;
	}

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

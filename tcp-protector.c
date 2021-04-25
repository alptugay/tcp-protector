#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#define PROTO_TCP 6
struct hdr_cursor {
        void *pos;
};


static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
                                        void *data_end,
                                        struct ethhdr **ethhdr)
{
        struct ethhdr *eth = nh->pos;
        int hdrsize = sizeof(*eth);

        /* Byte-count bounds check; check if current pointer + size of header
         * is after data_end.
         */
        if (nh->pos + hdrsize > data_end)
                return -1;

        nh->pos += hdrsize;
        *ethhdr = eth;


        return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
                                       void *data_end,
                                       struct iphdr **iphdr)
{
        struct iphdr *iph = nh->pos;
        int hdrsize;

        if (iph + 1 > data_end)
                return -1;

        hdrsize = iph->ihl * 4;
        /* Sanity check packet field is valid */
        if(hdrsize < sizeof(*iph))
                return -1;

        /* Variable-length IPv4 header, need to use byte-based arithmetic */
        if (nh->pos + hdrsize > data_end)
                return -1;

        nh->pos += hdrsize;
        *iphdr = iph;

        return iph->protocol;
}



static __always_inline int parse_tcphdr(struct hdr_cursor *nh,
                                          void *data_end,
                                          struct tcphdr **tcphdr)
{
        int len;
        struct tcphdr *h = nh->pos;

        if (h + 1 > data_end)
                return -1;

        len = h->doff * 4;
        /* Sanity check packet field is valid */
        if(len < sizeof(*h))
                return -1;

        /* Variable-length TCP header, need to use byte-based arithmetic */
        if (nh->pos + len > data_end)
                return -1;

        nh->pos += len;
        *tcphdr = h;

        return len;

}
// define output data structure in C
struct data_t {
    int srcip;
    int data;
    int issyn;
    int isfin;
};
BPF_PERF_OUTPUT(events);

BPF_TABLE("percpu_hash", uint32_t, uint32_t, iplist, 6524288);
int xdp_prog(struct xdp_md *ctx) {



        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;
        struct ethhdr *eth;
        struct iphdr *ip4h;
        struct icmphdr *icmp4h;
	struct tcphdr *tcph;

        /* Default action XDP_PASS, imply everything we couldn't parse, or that
         * we don't want to deal with, we just pass up the stack and let the
         * kernel deal with it.
         */
        __u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
        struct hdr_cursor nh;
        int nh_type;

        /* Start next header cursor position at data start */
        nh.pos = data;

        /* Packet parsing in steps: Get each header one at a time, aborting if
         * parsing fails. Each helper function does sanity checking (is the
         * header type in the packet correct?), and bounds checking.
         */
        nh_type = parse_ethhdr(&nh, data_end, &eth);
        if(nh_type == bpf_htons(ETH_P_IP)){
                nh_type = parse_iphdr(&nh, data_end, &ip4h);
		if (nh_type >= 0){
			uint32_t * value;
			value = iplist.lookup(&(ip4h->saddr));
                	if(value){
                		return XDP_DROP;
                	}
		
			if (nh_type == PROTO_TCP){
				if (parse_tcphdr(&nh, data_end, &tcph) > 0){
					uint32_t payload_offset = sizeof(*eth) + sizeof(*ip4h) + sizeof(*tcph);
					uint32_t payload_length = ntohs(ip4h->tot_len) - (ip4h->ihl << 2) - (tcph->doff << 2);
					struct data_t data = {};
                                        if (tcph->syn == 1){
                                                data.srcip = ip4h->saddr;
						data.issyn = 1;
						if (tcph->fin == 1){
							data.isfin = 1;
						}
						if (payload_length >= 0){
							data.data = payload_length;
						}
						events.perf_submit(ctx, &data, sizeof(data));
                                        }

				}
			}

        	}
	}

    return XDP_PASS;
}

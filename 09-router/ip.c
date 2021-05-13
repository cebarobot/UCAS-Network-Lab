#include "ip.h"
#include "arp.h"
#include "icmp.h"
#include "rtable.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>

// handle ip packet
//
// If the packet is ICMP echo request and the destination IP address is equal to
// the IP address of the iface, send ICMP echo reply; otherwise, forward the
// packet.
void handle_ip_packet(iface_info_t *iface, char *packet, int len)
{
	// TODO:
	fprintf(stderr, "TODO: handle ip packet.\n");

	// parse ip packet header
	struct iphdr * ip_hdr = packet_to_ip_hdr(packet);
	char * ip_data = IP_DATA(ip_hdr);
	u32 daddr = ntohl(ip_hdr->daddr);

	// check dest
	if (daddr == iface->ip) {
		switch (ip_hdr->protocol) {
			case IPPROTO_ICMP:
				handle_icmp_packet(packet, len);
				break;
			default:
				log(ERROR, "Unknown ip protocol 0x%04hx, ingore it.", \
						ip_hdr->protocol);
				free(packet);
				break;
		}
	}
	
	// handle TTL
	ip_hdr->ttl -= 1;
	if (ip_hdr->ttl <= 0) {
		icmp_send_packet(packet, len, ICMP_TIME_EXCEEDED, ICMP_EXC_TTL);
		free(packet);
		return;
	}
	ip_hdr->checksum = ip_checksum(ip_hdr);

	// search in route table
	rt_entry_t * p_rt = longest_prefix_match(daddr);
	if (!p_rt) {
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_NET_UNREACH);
		free(packet);
		return ;
	}
	// get next hop
	u32 next_hop = p_rt->gw ? p_rt->gw : daddr;

	// check dest
	if (daddr == p_rt->iface->ip) {
		switch (ip_hdr->protocol) {
			case IPPROTO_ICMP:
				handle_icmp_packet(packet, len);
				break;
			default:
				log(ERROR, "Unknown ip protocol 0x%04hx, ingore it.", \
						ip_hdr->protocol);
				free(packet);
				break;
		}
		return;
	}

	// forward packet
	iface_send_packet_by_arp(p_rt->iface, next_hop, packet, len);
}

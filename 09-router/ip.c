#include "ip.h"
#include "arp.h"

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

	// TODO: parse ip packet header

	// TODO: handle TTL
	
	// TODO: if TTL <= 0:
	if (0) {
		// TODO: drop packet & send ICMP info.
		return;
	}

	// TODO: search in route table

	// TODO: if found:
	// TODO check ICMP echo request (ping).
	if (0) {
		// TODO: send ICMP reply.
		return;
	}
	// TODO: forward (IP) packet through arpcache lookup 
	// iface_send_packet_by_arp(xxx, xxxxxx, packet, len);

	// TODO: if not found: 
	// TODO: send ICMP info.
}

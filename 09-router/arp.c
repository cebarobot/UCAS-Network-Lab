#include "arp.h"
#include "base.h"
#include "types.h"
#include "ether.h"
#include "arpcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "log.h"

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	// fprintf(stderr, "TODO: send arp request when lookup failed in arpcache.\n");
	
	char * packet = malloc(ETHER_HDR_SIZE + ETHER_ARP_SIZE);
	struct ether_header * eth_hdr = (void *) packet;
	struct ether_arp * req_hdr = (void *)(packet + ETHER_HDR_SIZE);

	// prepare ether_header
	memcpy(eth_hdr->ether_shost, iface->mac, ETH_ALEN);
	memset(eth_hdr->ether_dhost, 0xFF, ETH_ALEN);
	eth_hdr->ether_type = ETH_P_ARP;

	// prepare ether_arp
	req_hdr->arp_hrd = htons(ARPHRD_ETHER);
	req_hdr->arp_pro = htons(ETH_P_IP);
	req_hdr->arp_hln = ETH_ALEN;
	req_hdr->arp_pln = 4;
	req_hdr->arp_op = htons(ARPOP_REQUEST);
	memcpy(req_hdr->arp_sha, iface->mac, ETH_ALEN);
	req_hdr->arp_spa = htonl(iface->ip);
	memset(req_hdr->arp_tha, 0x00, ETH_ALEN);
	req_hdr->arp_tpa = htonl(dst_ip);

	// send packet (auto free packet space)
	iface_send_packet(iface, packet, ETHER_HDR_SIZE + ETHER_ARP_SIZE);
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	// fprintf(stderr, "TODO: send arp reply when receiving arp request.\n");
	char * packet = malloc(ETHER_HDR_SIZE + ETHER_ARP_SIZE);
	struct ether_header * eth_hdr = (void *) packet;
	struct ether_arp * rply_hdr = (void *)(packet + ETHER_HDR_SIZE);

	// prepare ether_header
	memcpy(eth_hdr->ether_shost, iface->mac, ETH_ALEN);
	memcpy(eth_hdr->ether_dhost, req_hdr->arp_sha, ETH_ALEN);
	eth_hdr->ether_type = ETH_P_ARP;

	// prepare ether_arp
	rply_hdr->arp_hrd = htons(ARPHRD_ETHER);
	rply_hdr->arp_pro = htons(ETH_P_IP);
	rply_hdr->arp_hln = ETH_ALEN;
	rply_hdr->arp_pln = 4;
	rply_hdr->arp_op = htons(ARPOP_REPLY);
	memcpy(rply_hdr->arp_sha, iface->mac, ETH_ALEN);
	rply_hdr->arp_spa = htonl(iface->ip);
	memcpy(rply_hdr->arp_tha, req_hdr->arp_sha, ETH_ALEN);
	rply_hdr->arp_tpa = req_hdr->arp_spa;

	// send packet (auto free packet space)
	iface_send_packet(iface, packet, ETHER_HDR_SIZE + ETHER_ARP_SIZE);
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	// TODO:
	fprintf(stderr, "TODO: process arp packet: arp request & arp reply.\n");
	struct ether_arp * arp_hdr = (void *)(packet + ETHER_HDR_SIZE);

	u32 arp_spa = ntohl(arp_hdr->arp_spa);
	u32 arp_tpa = ntohl(arp_hdr->arp_tpa);

	// check arp packet op
	if (arp_hdr->arp_op == ARPOP_REPLY) {
		// check arp packet target
		if (arp_tpa == iface->ip && memcmp(iface->mac, arp_hdr->arp_tha, ETH_ALEN) == 0) {
			// insert info into arpcache
			arpcache_insert(arp_spa, arp_hdr->arp_sha);
		}
	} else if (arp_hdr->arp_op == ARPOP_REQUEST) {
		// check arp packet target
		if (arp_tpa == iface->ip) {
			// send reply
			arp_send_reply(iface, arp_hdr);
		}
	}

	free(packet);
}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		// log(DEBUG, "found the mac of %x, send this packet", dst_ip);
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
	}
	else {
		// log(DEBUG, "lookup %x failed, pend this packet", dst_ip);
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}

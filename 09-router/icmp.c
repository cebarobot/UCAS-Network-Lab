#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"

#include "log.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	// fprintf(stderr, "TODO: malloc and send icmp packet.\n");
	log(DEBUG, "malloc and send icmp packet.");
	// prase in_pkt
	struct iphdr * in_ip_hdr = packet_to_ip_hdr(in_pkt);
	char * in_ip_data = IP_DATA(in_ip_hdr);

	char * out_pkt = NULL;
	int out_len = 0, icmp_len = 0;

	// calculate packet length
	if (type == ICMP_ECHOREPLY) {
		icmp_len = ntohs(in_ip_hdr->tot_len) - IP_HDR_SIZE(in_ip_hdr);
		out_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + icmp_len;
	} else if (type == ICMP_DEST_UNREACH || type == ICMP_TIME_EXCEEDED) {
		int icmp_len = ICMP_HDR_SIZE + IP_HDR_SIZE(in_ip_hdr) + ICMP_COPIED_DATA_LEN;
		out_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + icmp_len;
	}

	// allocate packet
	out_pkt = malloc(out_len);
	memset(out_pkt, 0x00, out_len);

	// init out_ip_hdr
	struct iphdr * out_ip_hdr = packet_to_ip_hdr(out_pkt);
	if (type == ICMP_ECHOREPLY) {
		ip_init_hdr(out_ip_hdr, ntohl(in_ip_hdr->daddr), ntohl(in_ip_hdr->saddr), 
				IP_BASE_HDR_SIZE + icmp_len, IPPROTO_ICMP);
	} else if (type == ICMP_DEST_UNREACH || type == ICMP_TIME_EXCEEDED) {
		rt_entry_t *rt_entry = longest_prefix_match(ntohl(in_ip_hdr->saddr));
		if (!rt_entry) {
			free(out_pkt);
			return;
		}
		ip_init_hdr(out_ip_hdr, rt_entry->iface->ip, ntohl(in_ip_hdr->saddr), 
				IP_BASE_HDR_SIZE + icmp_len, IPPROTO_ICMP);
	}

	// init icmp
	char * out_ip_data = IP_DATA(out_ip_hdr);
	struct icmphdr * out_icmp_hdr = (void *)out_ip_data;
	if (type == ICMP_ECHOREPLY) {
		memcpy(out_ip_data, in_ip_data, icmp_len);
	} else if (type == ICMP_DEST_UNREACH || type == ICMP_TIME_EXCEEDED) {
		out_icmp_hdr->icmp_identifier = 0;
		out_icmp_hdr->icmp_sequence = 0;
		memcpy(out_ip_data + ICMP_HDR_SIZE, in_ip_hdr, icmp_len - ICMP_HDR_SIZE);
	}
	out_icmp_hdr->type = type;
	out_icmp_hdr->code = code;
	out_icmp_hdr->checksum = icmp_checksum(out_icmp_hdr, icmp_len);
	
	// ip send packet
	if (out_pkt) {
		ip_send_packet(out_pkt, out_len);
	}
}

void handle_icmp_packet(char *packet, int len) {
	struct iphdr * ip_hdr = packet_to_ip_hdr(packet);
	struct icmphdr * icmp_hdr = (void *)IP_DATA(ip_hdr);
	if (icmp_hdr->type == ICMP_ECHOREQUEST) {
		icmp_send_packet(packet, len, ICMP_ECHOREPLY, 0);
	}

	free(packet);
}
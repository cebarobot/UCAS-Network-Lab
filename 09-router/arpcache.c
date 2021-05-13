#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "icmp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweeping thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// lookup the IP->mac mapping
//
// traverse the table to find whether there is an entry with the same IP
// and mac address with the given arguments
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	// fprintf(stderr, "TODO: lookup ip address in arp cache.\n");
	pthread_mutex_lock(&arpcache.lock);

	for (int i = 0; i < MAX_ARP_SIZE; i++) {
		if (arpcache.entries[i].valid && arpcache.entries[i].ip4 == ip4) {
			memcpy(mac, arpcache.entries[i].mac, ETH_ALEN);
			
			pthread_mutex_unlock(&arpcache.lock);
			return 1;
		}
	}
	
	pthread_mutex_unlock(&arpcache.lock);
	return 0;
}

// append the packet to arpcache
//
// Lookup in the list which stores pending packets, if there is already an
// entry with the same IP address and iface (which means the corresponding arp
// request has been sent out), just append this packet at the tail of that entry
// (the entry may contain more than one packet); otherwise, malloc a new entry
// with the given IP address and iface, append the packet, and send arp request.
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	// fprintf(stderr, "TODO: append the ip address if lookup failed, and send arp request if necessary.\n");
	pthread_mutex_lock(&arpcache.lock);

	struct cached_pkt * cached_packet = malloc(sizeof(struct cached_pkt));
	cached_packet->packet = packet;
	cached_packet->len = len;

	int found = 0;
	struct arp_req * one_entry = NULL;
	list_for_each_entry(one_entry, &arpcache.req_list, list) {
		if (one_entry->ip4 == ip4 && one_entry->iface == iface) {
			found = 1;
			break;
		}
	}

	if (!found) {
		// alloc new arp_req 
		one_entry = malloc(sizeof(struct arp_req));
		list_add_tail(&one_entry->list, &arpcache.req_list);

		one_entry->iface = iface;
		one_entry->ip4 = ip4;
		one_entry->sent = time(NULL);
		one_entry->retries = 0;
		init_list_head(&one_entry->cached_packets);
		arp_send_request(iface, ip4);
	}
	// insert into cached_packets
	list_add_tail(&cached_packet->list, &one_entry->cached_packets);

	pthread_mutex_unlock(&arpcache.lock);
}

// insert the IP->mac mapping into arpcache, if there are pending packets
// waiting for this mapping, fill the ethernet header for each of them, and send
// them out
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	// fprintf(stderr, "TODO: insert ip->mac entry, and send all the pending packets.\n");
	pthread_mutex_lock(&arpcache.lock);
	time_t now = time(NULL);

	// insert into arpcache
	// random an entry
	int pos = now % MAX_ARP_SIZE;
	// find invalid entry
	for (int i = 0; i < MAX_ARP_SIZE; i++) {
		if (!arpcache.entries[i].valid) {
			pos = i;
			break;
		}
	}
	// find same entry
	for (int i = 0; i < MAX_ARP_SIZE; i++) {
		if (arpcache.entries[i].valid && arpcache.entries[i].ip4 == ip4) {
			pos = i;
			break;
		}
	}
	// inerst into arpcache
	arpcache.entries[pos].valid = 1;
	arpcache.entries[pos].added = now;
	memcpy(arpcache.entries[pos].mac, mac, ETH_ALEN);
	arpcache.entries[pos].ip4 = ip4;
	
	// send out pending packets
	struct arp_req * p_req = NULL, * q_req = NULL;
	list_for_each_entry_safe(p_req, q_req, &arpcache.req_list, list) {
		if (p_req->ip4 == ip4) {
			struct cached_pkt * p_pkt = NULL, * q_pkt = NULL;
			list_for_each_entry_safe(p_pkt, q_pkt, &p_req->cached_packets, list) {
				struct ether_header *eth_hdr = (void *)p_pkt->packet;
				memcpy(eth_hdr->ether_dhost, mac, ETH_ALEN);
				iface_send_packet(p_req->iface, p_pkt->packet, p_pkt->len);

				list_delete_entry(&p_pkt->list);
				free(p_pkt);
			}
		}
		list_delete_entry(&p_req->list);
		free(p_req);
	}

	pthread_mutex_unlock(&arpcache.lock);
}

// sweep arpcache periodically
//
// For the IP->mac entry, if the entry has been in the table for more than 15
// seconds, remove it from the table.
// For the pending packets, if the arp request is sent out 1 second ago, while 
// the reply has not been received, retransmit the arp request. If the arp
// request has been sent 5 times without receiving arp reply, for each
// pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these
// packets.
void *arpcache_sweep(void *arg) 
{
	while (1) {
		sleep(1);
		// fprintf(stderr, "TODO: sweep arpcache periodically: remove old entries, resend arp requests .\n");
		
		struct list_head unreachable_list;
		init_list_head(&unreachable_list);

		pthread_mutex_lock(&arpcache.lock);
		time_t now = time(NULL);

		// sweep IP->mac entry
		for (int i = 0; i < MAX_ARP_SIZE; i++) {
			if (now - arpcache.entries[i].added >= ARP_ENTRY_TIMEOUT) {
				arpcache.entries[i].valid = 0;
			}
		}

		// sweep pending packets
		struct arp_req * p_req = NULL, * q_req = NULL;
		list_for_each_entry_safe(p_req, q_req, &arpcache.req_list, list) {
			if (p_req->retries < ARP_REQUEST_MAX_RETRIES) {
				if (now - p_req->sent >= 1) {
					p_req->retries += 1;
					p_req->sent = now;
					arp_send_request(p_req->iface, p_req->ip4);
				}
			} else {
				list_delete_entry(&p_req->list);
				list_add_tail(&p_req->list, &unreachable_list);
			}
		}

		pthread_mutex_unlock(&arpcache.lock);

		// send icmp packet
		p_req = NULL, q_req = NULL;
		list_for_each_entry_safe(p_req, q_req, &unreachable_list, list) {
			struct cached_pkt * p_pkt = NULL, * q_pkt = NULL;
			list_for_each_entry_safe(p_pkt, q_pkt, &p_req->cached_packets, list) {
				icmp_send_packet(p_pkt->packet, p_pkt->len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
				free(p_pkt->packet);

				list_delete_entry(&p_pkt->list);
				free(p_pkt);
			}
			
			list_delete_entry(&p_req->list);
			free(p_req);
		}
		
	}

	return NULL;
}

#include "base.h"
#include "ether.h"
#include "mac.h"
#include "utils.h"

#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// handle packet
// 1. if the dest mac address is found in mac_port table, forward it; otherwise, 
// broadcast it.
// 2. put the src mac -> iface mapping into mac hash table.
void handle_packet(iface_info_t *iface, char *packet, int len)
{
	// implement the packet forwarding process here

	struct ether_header *eh = (struct ether_header *)packet;
	// log(INFO, "Receive packet from " ETHER_STRING " at %s.", ETHER_FMT(eh->ether_shost), iface->name);
	// log(INFO, "The dst mac address is " ETHER_STRING ".", ETHER_FMT(eh->ether_dhost));
	
	iface_info_t * dest_iface = lookup_port(eh->ether_dhost);
	if (dest_iface) {
		// log(DEBUG, "Send this packet to %s.", dest_iface->name);
		iface_send_packet(dest_iface, packet, len);
	} else {
		// log(DEBUG, "Broadcast this packet.");
		broadcast_packet(iface, packet, len);
	}

	// log(DEBUG, "Insert into mac_port_map: " ETHER_STRING " -> %s.", ETHER_FMT(eh->ether_shost), iface->name);
	insert_mac_port(eh->ether_shost, iface);

	// log(DEBUG, "Finished.\n");
	free(packet);
}

// run user stack, receive packet on each interface, and handle those packet
// like normal switch
void ustack_run()
{
	struct sockaddr_ll addr;
	socklen_t addr_len = sizeof(addr);
	char buf[ETH_FRAME_LEN];
	int len;

	while (1) {
		int ready = poll(instance->fds, instance->nifs, -1);
		if (ready < 0) {
			perror("Poll failed!");
			break;
		}
		else if (ready == 0)
			continue;

		for (int i = 0; i < instance->nifs; i++) {
			if (instance->fds[i].revents & POLLIN) {
				len = recvfrom(instance->fds[i].fd, buf, ETH_FRAME_LEN, 0, \
						(struct sockaddr*)&addr, &addr_len);
				if (len <= 0) {
					log(ERROR, "receive packet error: %s", strerror(errno));
				}
				else if (addr.sll_pkttype == PACKET_OUTGOING) {
					// XXX: Linux raw socket will capture both incoming and
					// outgoing packets, while we only care about the incoming ones.

					// log(DEBUG, "received packet which is sent from the "
					// 		"interface itself, drop it.");
				}
				else {
					iface_info_t *iface = fd_to_iface(instance->fds[i].fd);
					if (!iface) 
						continue;

					char *packet = malloc(len);
					if (!packet) {
						log(ERROR, "malloc failed when receiving packet.");
						continue;
					}
					memcpy(packet, buf, len);
					handle_packet(iface, packet, len);
				}
			}
		}
	}
}

int main(int argc, const char **argv)
{
	if (getuid() && geteuid()) {
		printf("Permission denied, should be superuser!\n");
		exit(1);
	}

	init_ustack();
	init_mac_port_table();

	ustack_run();

	return 0;
}

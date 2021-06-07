#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_daemon.h"
#include "ip.h"
#include "base.h"
#include <stdio.h>
#include <stdlib.h>

int aging_mospf_nbr() {
	int nbr_changed = 0;

	iface_info_t * iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		mospf_nbr_t * nbr_p = NULL, * nbr_q = NULL;
		list_for_each_entry_safe(nbr_p, nbr_q, &iface->nbr_list, list) {
			nbr_p->alive -= 1;
			if (nbr_p->alive <= 0) {
				list_delete_entry(&nbr_p->list);
				free(nbr_p);

				iface->num_nbr -= 1;
				nbr_changed = 1;
			}
		}
	}

	return nbr_changed;
}

int update_mospf_nbr(iface_info_t *iface, const char *packet) {
	int nbr_changed = 0;
	
	struct ether_header * eth_hdr = (void *) packet;
	struct iphdr * ip_hdr = packet_to_ip_hdr(packet);
	char * mospf_msg = IP_DATA(ip_hdr);

	struct mospf_hdr * pkt_hdr = (void *) IP_DATA(ip_hdr);
	struct mospf_hello * pkt_hello = (void *) (IP_DATA(ip_hdr) + MOSPF_HDR_SIZE);

	u32 mospf_rid = ntohl(pkt_hdr->rid);

	mospf_nbr_t * nbr_p = NULL, * nbr_match = NULL;
	list_for_each_entry(nbr_p, &iface->nbr_list, list) {
		if (nbr_p->nbr_id == mospf_rid) {
			nbr_match = nbr_p;
			break;
		}
	}

	if (!nbr_match) {
		nbr_match = malloc(sizeof(mospf_nbr_t));
		list_add_tail(&nbr_match->list, &iface->nbr_list);
		nbr_match->nbr_id = mospf_rid;

		iface->num_nbr += 1;
		nbr_changed = 1;
	}

	nbr_match->alive = 3 * iface->helloint;
	nbr_match->nbr_ip = ntohl(ip_hdr->saddr);
	nbr_match->nbr_mask = ntohl(pkt_hello->mask);

	return nbr_changed;
}

void print_nbr_list() {

	printf("=========================== NBR LIST ===========================\n");

	iface_info_t * iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		printf("iface: %s, %s\n", iface->name, iface->ip_str);
		mospf_nbr_t * nbr_p = NULL;
		list_for_each_entry(nbr_p, &iface->nbr_list, list) {
			printf("\tnbr "IP_FMT ":\t", HOST_IP_FMT_STR(nbr_p->nbr_id));
			printf(IP_FMT ",\t", HOST_IP_FMT_STR(nbr_p->nbr_ip));
			printf(IP_FMT ",\t", HOST_IP_FMT_STR(nbr_p->nbr_mask));
			printf("%d\n", nbr_p->alive);
		}
	}
	printf("================================================================\n");
}
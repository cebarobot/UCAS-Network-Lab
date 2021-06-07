#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "mospf_database.h"

#include "ip.h"

#include "list.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

extern ustack_t *instance;

pthread_mutex_t mospf_lock;

void mospf_init()
{
	pthread_mutex_init(&mospf_lock, NULL);

	instance->area_id = 0;
	// get the ip address of the first interface
	iface_info_t *iface = list_entry(instance->iface_list.next, iface_info_t, list);
	instance->router_id = iface->ip;
	instance->sequence_num = 0;
	instance->lsuint = MOSPF_DEFAULT_LSUINT;

	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		iface->helloint = MOSPF_DEFAULT_HELLOINT;
		init_list_head(&iface->nbr_list);
	}

	init_mospf_db();
}

void *sending_mospf_hello_thread(void *param);
void *sending_mospf_lsu_thread(void *param);
void *checking_nbr_thread(void *param);
void *checking_database_thread(void *param);

void print_nbr_list();
void print_mospf_db();

void mospf_run()
{
	pthread_t hello, lsu, nbr, db;
	pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
	pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
	pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
	pthread_create(&db, NULL, checking_database_thread, NULL);
}

void *sending_mospf_hello_thread(void *param)
{
	// fprintf(stdout, "TODO: send mOSPF Hello message periodically.\n");

	while (1) {
		sleep(MOSPF_DEFAULT_HELLOINT);
		time_t now = time(NULL);

		iface_info_t *iface = NULL;
		list_for_each_entry(iface, &instance->iface_list, list) {
			char * pkt = NULL;
			int pkt_len = mospf_prepare_hello(&pkt, iface);
			iface_send_packet(iface, pkt, pkt_len);
		}
	}

	return NULL;
}

void *checking_nbr_thread(void *param)
{
	// TODO:
	fprintf(stdout, "TODO: neighbor list timeout operation.\n");
	while (1) {
		sleep(1);
		// print_nbr_list();
		pthread_mutex_lock(&mospf_lock);

		iface_info_t * iface = NULL;
		list_for_each_entry(iface, &instance->iface_list, list) {
			mospf_nbr_t * nbr_p = NULL, * nbr_q = NULL;
			list_for_each_entry_safe(nbr_p, nbr_q, &iface->nbr_list, list) {
				nbr_p->alive -= 1;
				if (nbr_p->alive <= 0) {
					list_delete_entry(&nbr_p->list);
					iface->num_nbr -= 1;
					// TODO: update database & send lsu;
				}
			}
		}

		pthread_mutex_unlock(&mospf_lock);
	}

	return NULL;
}

void *checking_database_thread(void *param)
{
	// TODO:
	fprintf(stdout, "TODO: link state database timeout operation.\n");

	return NULL;
}

void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{
	// TODO:
	fprintf(stdout, "TODO: handle mOSPF Hello message.\n");

	struct ether_header * eth_hdr = (void *) packet;
	struct iphdr * ip_hdr = (void *) (packet + ETHER_HDR_SIZE);
	struct mospf_hdr * pkt_hdr = (void *) IP_DATA(ip_hdr);
	struct mospf_hello * pkt_hello = (void *) (IP_DATA(ip_hdr) + MOSPF_HDR_SIZE);

	u32 mospf_rid = ntohl(pkt_hdr->rid);

	time_t now = time(NULL);
	pthread_mutex_lock(&mospf_lock);

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
	}

	nbr_match->alive = 3 * iface->helloint;
	nbr_match->nbr_ip = ntohl(ip_hdr->saddr);
	nbr_match->nbr_mask = ntohl(pkt_hello->mask);

	pthread_mutex_unlock(&mospf_lock);
}

void *sending_mospf_lsu_thread(void *param)
{
	// TODO:
	fprintf(stdout, "TODO: send mOSPF LSU message periodically.\n");

	return NULL;
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
{
	// TODO:
	fprintf(stdout, "TODO: handle mOSPF LSU message.\n");

}

void handle_mospf_packet(iface_info_t *iface, char *packet, int len)
{
	struct iphdr *ip = (struct iphdr *)(packet + ETHER_HDR_SIZE);
	struct mospf_hdr *mospf = (struct mospf_hdr *)((char *)ip + IP_HDR_SIZE(ip));

	if (mospf->version != MOSPF_VERSION) {
		log(ERROR, "received mospf packet with incorrect version (%d)", mospf->version);
		return ;
	}
	if (mospf->checksum != mospf_checksum(mospf)) {
		log(ERROR, "received mospf packet with incorrect checksum");
		return ;
	}
	if (ntohl(mospf->aid) != instance->area_id) {
		log(ERROR, "received mospf packet with incorrect area id");
		return ;
	}

	switch (mospf->type) {
		case MOSPF_TYPE_HELLO:
			handle_mospf_hello(iface, packet, len);
			break;
		case MOSPF_TYPE_LSU:
			handle_mospf_lsu(iface, packet, len);
			break;
		default:
			log(ERROR, "received mospf packet with unknown type (%d).", mospf->type);
			break;
	}
}

void print_nbr_list() {
	
	pthread_mutex_lock(&mospf_lock);

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

	pthread_mutex_unlock(&mospf_lock);
}

void print_mospf_db() {

}
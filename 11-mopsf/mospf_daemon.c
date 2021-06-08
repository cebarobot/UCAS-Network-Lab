#include "mospf_daemon.h"
#include "mospf_proto.h"
#include "mospf_database.h"
#include "mospf_nbr.h"
#include "mospf_route.h"

#include "ip.h"

#include "list.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

extern ustack_t *instance;

pthread_mutex_t mospf_lock;
pthread_cond_t lsu_send_cond;

void mospf_init()
{
	pthread_mutex_init(&mospf_lock, NULL);
	pthread_cond_init(&lsu_send_cond, NULL);

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


void mospf_run()
{
	pthread_t hello, lsu, nbr, db;
	pthread_create(&hello, NULL, sending_mospf_hello_thread, NULL);
	pthread_create(&lsu, NULL, sending_mospf_lsu_thread, NULL);
	pthread_create(&nbr, NULL, checking_nbr_thread, NULL);
	pthread_create(&db, NULL, checking_database_thread, NULL);
}

void send_mospf_hello() {
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		char * pkt = NULL;
		int pkt_len = mospf_prepare_hello_pkt(&pkt, iface);
		iface_send_packet(iface, pkt, pkt_len);
	}
}

void *sending_mospf_hello_thread(void *param)
{
	// fprintf(stdout, "TODO: send mOSPF Hello message periodically.\n");

	while (1) {
		sleep(MOSPF_DEFAULT_HELLOINT);

		send_mospf_hello();
	}

	return NULL;
}

void *checking_nbr_thread(void *param)
{
	fprintf(stdout, "TODO: neighbor list timeout operation.\n");
	while (1) {
		sleep(1);
		pthread_mutex_lock(&mospf_lock);
		print_nbr_list();

		if (aging_mospf_nbr()) {
			// trigger lsu send
			pthread_cond_signal(&lsu_send_cond);
		}

		pthread_mutex_unlock(&mospf_lock);
	}

	return NULL;
}

void *checking_database_thread(void *param)
{
	fprintf(stdout, "TODO: link state database timeout operation.\n");
	while (1) {
		sleep(1);
		pthread_mutex_lock(&mospf_lock);

		if (aging_mospf_db()) {
			// TODO: upate rtable
			update_rtable_from_database();
		}
		print_mospf_db();

		pthread_mutex_unlock(&mospf_lock);
	}

	return NULL;
}

void handle_mospf_hello(iface_info_t *iface, const char *packet, int len)
{
	fprintf(stdout, "TODO: handle mOSPF Hello message.\n");
	// struct mospf_hdr * pkt_hdr = (void *) IP_DATA(ip_hdr);
	// struct mospf_hello * pkt_hello = (void *) (IP_DATA(ip_hdr) + MOSPF_HDR_SIZE);

	pthread_mutex_lock(&mospf_lock);

	if (update_mospf_nbr(iface, packet)) {
		// trigger lsu send
		pthread_cond_signal(&lsu_send_cond);
	}

	pthread_mutex_unlock(&mospf_lock);
}

void send_mospf_lsu(const char * lsu_msg, int lsu_msg_len, iface_info_t * ignore) {
	iface_info_t * iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (iface == ignore) {
			continue;
		}
		printf("send to %s, %s\n", iface->name, iface->ip_str);
		mospf_nbr_t * nbr_p = NULL, * nbr_q = NULL;
		list_for_each_entry_safe(nbr_p, nbr_q, &iface->nbr_list, list) {
			int lsu_pkt_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + lsu_msg_len;
			char * lsu_pkt = malloc(lsu_pkt_len);
			struct ether_header * eth_hdr = (void *) lsu_pkt;
			struct iphdr * ip_hdr = packet_to_ip_hdr(lsu_pkt);
			char * pkt_data = IP_BASE_DATA(ip_hdr);

			ip_init_hdr(ip_hdr, iface->ip, nbr_p->nbr_ip, IP_BASE_HDR_SIZE + lsu_msg_len, IPPROTO_MOSPF);

			memcpy(pkt_data, lsu_msg, lsu_msg_len);

			ip_send_packet(lsu_pkt, lsu_pkt_len);
		}
	}

}

void *sending_mospf_lsu_thread(void *param)
{
	fprintf(stdout, "TODO: send mOSPF LSU message periodically.\n");
	pthread_mutex_lock(&mospf_lock);

	while (1) {
		struct timespec to_time;
		clock_gettime(CLOCK_REALTIME, &to_time);
		to_time.tv_sec += instance->lsuint;
		pthread_cond_timedwait(&lsu_send_cond, &mospf_lock, &to_time);

		printf("send mospf lsu\n");
		char * lsu_msg = NULL;
		int lsu_msg_len = mospf_prepare_lsu_msg(&lsu_msg);
		
		update_mospf_db(lsu_msg);
		send_mospf_lsu(lsu_msg, lsu_msg_len, NULL);

		printf("before seq: %d\n", instance->sequence_num);
		instance->sequence_num += 1;
		printf("after seq: %d\n", instance->sequence_num);
	}

	pthread_mutex_unlock(&mospf_lock);
	return NULL;
}

void handle_mospf_lsu(iface_info_t *iface, char *packet, int len)
{
	fprintf(stdout, "handle mOSPF LSU message.\n");

	struct ether_header * eth_hdr = (void *) packet;
	struct iphdr * ip_hdr = packet_to_ip_hdr(packet);
	char * mospf_msg = IP_DATA(ip_hdr);
	// struct mospf_hdr * pkt_hdr = (void *) IP_DATA(ip_hdr);
	// struct mospf_lsa * pkt_lsa_arr = (void *) (IP_DATA(ip_hdr) + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE);

	pthread_mutex_lock(&mospf_lock);

	if (update_mospf_db(mospf_msg)) {
		printf("update_db\n");
		// transfer lsu msg
		struct mospf_hdr * pkt_hdr = (void *) mospf_msg;
		struct mospf_lsu * pkt_lsu = (void *) (mospf_msg + MOSPF_HDR_SIZE);
		pkt_lsu->ttl -= 1;
		pkt_hdr->checksum = mospf_checksum(pkt_hdr);
		if (pkt_lsu > 0) {
			printf("forward lsu msg from " IP_FMT "\n", NET_IP_FMT_STR(pkt_hdr->rid));
			send_mospf_lsu(mospf_msg, len - ETHER_HDR_SIZE - IP_HDR_SIZE(ip_hdr), iface);
		}

		// TODO: update rtable
		update_rtable_from_database();
	}
	print_mospf_db();

	pthread_mutex_unlock(&mospf_lock);
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
		printf(IP_FMT, NET_IP_FMT_STR(mospf->rid));
		return ;
	}
	if (ntohl(mospf->aid) != instance->area_id) {
		log(ERROR, "received mospf packet with incorrect area id");
		return ;
	}
	if (ntohl(mospf->rid) == instance->router_id) {
		log(DEBUG, "received mospf packet of this router");
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
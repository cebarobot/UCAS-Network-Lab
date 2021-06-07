#include "mospf_proto.h"
#include "mospf_nbr.h"
#include "base.h"
#include "ip.h"
#include "log.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

extern ustack_t *instance;

void mospf_init_hdr(struct mospf_hdr *mospf, u8 type, u16 len, u32 rid, u32 aid)
{
	mospf->version = MOSPF_VERSION;
	mospf->type = type;
	mospf->len = htons(len);
	mospf->rid = htonl(rid);
	mospf->aid = htonl(aid);
	mospf->padding = 0;
}

void mospf_init_hello(struct mospf_hello *hello, u32 mask)
{
	hello->mask = htonl(mask);
	hello->helloint = htons(MOSPF_DEFAULT_HELLOINT);
	hello->padding = 0;
}

void mospf_init_lsu(struct mospf_lsu *lsu, u32 nadv)
{
	lsu->seq = htons(instance->sequence_num);
	lsu->unused = 0;
	lsu->ttl = MOSPF_MAX_LSU_TTL;
	lsu->nadv = htonl(nadv);
}

int mospf_prepare_hello_pkt(char ** pkt, iface_info_t * iface) {
	int msg_len = MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE;
	int len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + msg_len;
	char * hello_pkt = malloc(len);
	struct ether_header * eth_hdr = (void *) hello_pkt;
	struct iphdr * ip_hdr = packet_to_ip_hdr(hello_pkt);
	struct mospf_hdr * pkt_hdr = (void *) IP_BASE_DATA(ip_hdr);
	struct mospf_hello * pkt_hello = (void *) (IP_BASE_DATA(ip_hdr) + MOSPF_HDR_SIZE);

	memcpy(eth_hdr->ether_shost, iface->mac, ETH_ALEN);
	mac_assign(eth_hdr->ether_dhost, 0x01, 0x00, 0x5e, 0x00, 0x00, 0x05);
	eth_hdr->ether_type = htons(ETH_P_IP);

	ip_init_hdr(ip_hdr, iface->ip, MOSPF_ALLSPFRouters, IP_BASE_HDR_SIZE + msg_len, IPPROTO_MOSPF);
	ip_hdr->ttl = 1;	// ttl of ip packets sent to local network control block should always be 1

	mospf_init_hdr(pkt_hdr, MOSPF_TYPE_HELLO, msg_len, instance->router_id, instance->area_id);

	mospf_init_hello(pkt_hello, iface->mask);

	pkt_hdr->checksum = mospf_checksum(pkt_hdr);

	*pkt = hello_pkt;
	return len;
}

int mospf_prepare_lsu_msg(char ** msg) {
	int num_nbr = 0;

	iface_info_t * iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		num_nbr += (iface->num_nbr > 0) ? iface->num_nbr : 1;
	}

	int len = MOSPF_HDR_SIZE + MOSPF_LSU_SIZE + MOSPF_LSA_SIZE * num_nbr;
	char * lsu_msg = malloc(len);

	struct mospf_hdr * pkt_hdr = (void *) lsu_msg;
	struct mospf_lsu * pkt_lsu = (void *) (lsu_msg + MOSPF_HDR_SIZE);
	struct mospf_lsa * pkt_lsa_arr = (void *) (lsu_msg + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE);

	mospf_init_hdr(pkt_hdr, MOSPF_TYPE_LSU, len, instance->router_id, instance->area_id);

	mospf_init_lsu(pkt_lsu, num_nbr);

	int lsa_i = 0;
	iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (list_empty(&iface->nbr_list)) {
			pkt_lsa_arr[lsa_i].mask = htonl(iface->mask);
			pkt_lsa_arr[lsa_i].network = htonl(iface->ip & iface->mask);
			pkt_lsa_arr[lsa_i].rid = 0;

			if (lsa_i < num_nbr) {
				lsa_i += 1;
			} else {
				log(ERROR, "Too many lsa when preparing lsu message");
			}
		} else {
			mospf_nbr_t * nbr_p = NULL;
			list_for_each_entry(nbr_p, &iface->nbr_list, list) {
				pkt_lsa_arr[lsa_i].mask = htonl(iface->mask);
				pkt_lsa_arr[lsa_i].network = htonl(iface->ip & iface->mask);
				pkt_lsa_arr[lsa_i].rid = htonl(nbr_p->nbr_id);
				
				if (lsa_i < num_nbr) {
					lsa_i += 1;
				} else {
					log(ERROR, "Too many lsa when preparing lsu message");
				}
			}
		}
	}
	
	pkt_hdr->checksum = mospf_checksum(pkt_hdr);

	*msg = lsu_msg;
	return len;
}
#include "mospf_proto.h"
#include "base.h"
#include "ip.h"
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

int mospf_prepare_hello(char ** pkt, iface_info_t * iface) {
	int len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE;
	char * hello_pkt = malloc(len);
	struct ether_header * eth_hdr = (void *) hello_pkt;
	struct iphdr * ip_hdr = (void *) (hello_pkt + ETHER_HDR_SIZE);
	struct mospf_hdr * pkt_hdr = (void *) (hello_pkt + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE);
	struct mospf_hello * pkt_hello = (void *) (hello_pkt + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE);

	memcpy(eth_hdr->ether_shost, iface->mac, ETH_ALEN);
	mac_assign(eth_hdr->ether_dhost, 0x01, 0x00, 0x5e, 0x00, 0x00, 0x05);
	eth_hdr->ether_type = htons(ETH_P_IP);

	ip_init_hdr(ip_hdr, iface->ip, MOSPF_ALLSPFRouters, IP_BASE_HDR_SIZE + MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, IPPROTO_MOSPF);
	ip_hdr->ttl = 1;	// ttl of ip packets sent to local network control block should always be 1

	mospf_init_hdr(pkt_hdr, MOSPF_TYPE_HELLO, MOSPF_HDR_SIZE + MOSPF_HELLO_SIZE, instance->router_id, instance->area_id);

	mospf_init_hello(pkt_hello, iface->mask);

	pkt_hdr->checksum = mospf_checksum(pkt_hdr);

	*pkt = hello_pkt;
	return len;
}
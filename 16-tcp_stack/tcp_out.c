#include "tcp.h"
#include "tcp_sock.h"
#include "ip.h"
#include "ether.h"

#include "log.h"
#include "list.h"

#include <stdlib.h>
#include <string.h>

void send_buf_insert(struct tcp_sock *tsk, char *packet, int len, u32 seq, u32 seq_end) {
	pthread_mutex_lock(&tsk->send_buf_lock);

	struct pend_pkt * new_pend = malloc(sizeof(struct pend_pkt));

	char * pkt_in_buf = malloc(len);
	memcpy(pkt_in_buf, packet, len);
	new_pend->packet = pkt_in_buf;
	new_pend->packet_len = len;

	new_pend->retrans_times = 0;
	new_pend->seq = seq;
	new_pend->seq_end = seq_end;

	if (list_empty(&tsk->send_buf)) {
		tcp_set_retrans_timer(tsk);
	}
	log(INFO, "checkpoint 1");

	list_add_tail(&new_pend->list, &tsk->send_buf);

	log(INFO, "checkpoint 1");

	pthread_mutex_unlock(&tsk->send_buf_lock);
}

void send_buf_sweep(struct tcp_sock *tsk) {
	pthread_mutex_lock(&tsk->send_buf_lock);

	struct pend_pkt *p = NULL, *q = NULL;
	list_for_each_entry_safe(p, q, &tsk->send_buf, list) {
		// if (p->seq_end <= tsk->snd_una) {
		if (less_or_equal_32b(p->seq_end, tsk->snd_una)) {
			free(p->packet);
			list_delete_entry(&p->list);
			free(p);

		} else {
			break;
		}
	}

	if (list_empty(&tsk->send_buf)) {
		tcp_unset_retrans_timer(tsk);
	} else {
		tcp_set_retrans_timer(tsk);
	}

	pthread_mutex_unlock(&tsk->send_buf_lock);
}

int send_buf_retrans(struct tcp_sock *tsk) {
	int ret = 0;

	pthread_mutex_lock(&tsk->send_buf_lock);

	struct pend_pkt * p = list_entry(tsk->send_buf.next, struct pend_pkt, list);

	if (p->retrans_times >= TCP_MAX_RETRANS_TIMES) {
		log(ERROR, "TCP retransmission timeout, close this sock.");
		tcp_send_control_packet(tsk, TCP_RST);
		tcp_set_state(tsk, TCP_CLOSED);
		
		ret = -1;

	} else if (tcp_update_retrans_timer(tsk, p->retrans_times + 1)) {
		p->retrans_times += 1;

		char *packet = malloc(p->packet_len);
		memcpy(packet, p->packet, p->packet_len);
		
		log(INFO, "retrans packet");
		ip_send_packet(packet, p->packet_len);
	}

	pthread_mutex_unlock(&tsk->send_buf_lock);

	return ret;
}

// initialize tcp header according to the arguments
static void tcp_init_hdr(struct tcphdr *tcp, u16 sport, u16 dport, u32 seq, u32 ack,
		u8 flags, u16 rwnd)
{
	memset((char *)tcp, 0, TCP_BASE_HDR_SIZE);

	tcp->sport = htons(sport);
	tcp->dport = htons(dport);
	tcp->seq = htonl(seq);
	tcp->ack = htonl(ack);
	tcp->off = TCP_HDR_OFFSET;
	tcp->flags = flags;
	tcp->rwnd = htons(rwnd);
}

// send a tcp packet
//
// Given that the payload of the tcp packet has been filled, initialize the tcp 
// header and ip header (remember to set the checksum in both header), and emit 
// the packet by calling ip_send_packet.
void tcp_send_packet(struct tcp_sock *tsk, char *packet, int len) 
{
	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

	int ip_tot_len = len - ETHER_HDR_SIZE;
	int tcp_data_len = ip_tot_len - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE;

	u32 saddr = tsk->sk_sip;
	u32	daddr = tsk->sk_dip;
	u16 sport = tsk->sk_sport;
	u16 dport = tsk->sk_dport;

	u32 seq = tsk->snd_nxt;
	u32 ack = tsk->rcv_nxt;
	u16 rwnd = tsk->rcv_wnd;

	tcp_init_hdr(tcp, sport, dport, seq, ack, TCP_PSH|TCP_ACK, rwnd);
	ip_init_hdr(ip, saddr, daddr, ip_tot_len, IPPROTO_TCP); 

	tcp->checksum = tcp_checksum(ip, tcp);

	ip->checksum = ip_checksum(ip);

	tsk->snd_nxt += tcp_data_len;

	send_buf_insert(tsk, packet, len, seq, tsk->snd_nxt);

	ip_send_packet(packet, len);
}

// send a tcp control packet
//
// The control packet is like TCP_ACK, TCP_SYN, TCP_FIN (excluding TCP_RST).
// All these packets do not have payload and the only difference among these is 
// the flags.
void tcp_send_control_packet(struct tcp_sock *tsk, u8 flags)
{
	int pkt_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
	char *packet = malloc(pkt_size);
	if (!packet) {
		log(ERROR, "malloc tcp control packet failed.");
		return ;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

	u16 tot_len = IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;

	ip_init_hdr(ip, tsk->sk_sip, tsk->sk_dip, tot_len, IPPROTO_TCP);
	tcp_init_hdr(tcp, tsk->sk_sport, tsk->sk_dport, tsk->snd_nxt, \
			tsk->rcv_nxt, flags, tsk->rcv_wnd);

	tcp->checksum = tcp_checksum(ip, tcp);

	if (flags & (TCP_SYN|TCP_FIN)) {
		u32 seq = tsk->snd_nxt;
		tsk->snd_nxt += 1;
		
		send_buf_insert(tsk, packet, pkt_size, seq, tsk->snd_nxt);
	}

	ip_send_packet(packet, pkt_size);
}

// send tcp reset packet
//
// Different from tcp_send_control_packet, the fields of reset packet is 
// from tcp_cb instead of tcp_sock.
void tcp_send_reset(struct tcp_cb *cb)
{
	int pkt_size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
	char *packet = malloc(pkt_size);
	if (!packet) {
		log(ERROR, "malloc tcp control packet failed.");
		return ;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	struct tcphdr *tcp = (struct tcphdr *)((char *)ip + IP_BASE_HDR_SIZE);

	u16 tot_len = IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
	ip_init_hdr(ip, cb->daddr, cb->saddr, tot_len, IPPROTO_TCP);
	tcp_init_hdr(tcp, cb->dport, cb->sport, 0, cb->seq_end, TCP_RST|TCP_ACK, 0);
	tcp->checksum = tcp_checksum(ip, tcp);

	ip_send_packet(packet, pkt_size);
}

// send tcp data packet
int tcp_send_data(struct tcp_sock *tsk, char *buf, int len) {
	len = min(len, ETH_FRAME_LEN - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE - TCP_BASE_HDR_SIZE);
	
	int data_pkt_len = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE + len;
	char * data_pkt = malloc(data_pkt_len);
	char * pkt_payload = data_pkt + ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + TCP_BASE_HDR_SIZE;
	memcpy(pkt_payload, buf, len);

	while (tsk->snd_wnd < len) {
		log(DEBUG, "send windows %d but want to send %d.", tsk->snd_wnd, len);
		tsk->snd_wnd = 0;
		sleep_on(tsk->wait_send);
	}

	tcp_send_packet(tsk, data_pkt, data_pkt_len);

	return len;
}
#include "tcp.h"
#include "tcp_sock.h"
#include "tcp_timer.h"

#include "log.h"
#include "ring_buffer.h"

#include <stdlib.h>
// update the snd_wnd of tcp_sock
//
// if the snd_wnd before updating is zero, notify tcp_sock_send (wait_send)
static inline void tcp_update_window(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u16 old_snd_wnd = tsk->snd_wnd;
	tsk->snd_wnd = cb->rwnd;
	if (old_snd_wnd == 0)
		wake_up(tsk->wait_send);
}

// update the snd_wnd safely: cb->ack should be between snd_una and snd_nxt
static inline void tcp_update_window_safe(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	if (less_or_equal_32b(tsk->snd_una, cb->ack) && less_or_equal_32b(cb->ack, tsk->snd_nxt))
		tcp_update_window(tsk, cb);
}

#ifndef max
#	define max(x,y) ((x)>(y) ? (x) : (y))
#endif

// check whether the sequence number of the incoming packet is in the receiving
// window
static inline int is_tcp_seq_valid(struct tcp_sock *tsk, struct tcp_cb *cb)
{
	u32 rcv_end = tsk->rcv_nxt + max(tsk->rcv_wnd, 1);
	if (less_than_32b(cb->seq, rcv_end) && less_or_equal_32b(tsk->rcv_nxt, cb->seq_end)) {
		return 1;
	}
	else {
		log(ERROR, "received packet with invalid seq, drop it.");
		return 0;
	}
}

static void handle_syn(struct tcp_sock *tsk, struct tcp_cb *cb) {
	if (tsk->state == TCP_LISTEN) {
		// LISTEN --SYN/SYN+ACK-> SYN_RECV
		// alloc child sock
		struct tcp_sock * child_tsk = alloc_tcp_sock();
		child_tsk->parent = tsk;
		tsk->ref_cnt += 1;

		child_tsk->local.ip = cb->daddr;
		child_tsk->local.port = cb->dport;
		child_tsk->peer.ip = cb->saddr;
		child_tsk->peer.port = cb->sport;

		child_tsk->iss = tcp_new_iss();
		child_tsk->snd_nxt = child_tsk->iss;
		child_tsk->rcv_nxt = cb->seq_end;

		tcp_set_state(child_tsk, TCP_SYN_RECV);

		tcp_hash(child_tsk);
		init_list_head(&child_tsk->bind_hash_list);
		
		log(DEBUG, "Pass " IP_FMT ":%hu <-> " IP_FMT ":%hu from process to listen_queue", 
				HOST_IP_FMT_STR(child_tsk->sk_sip), child_tsk->sk_sport,
				HOST_IP_FMT_STR(child_tsk->sk_dip), child_tsk->sk_dport);
		list_add_tail(&child_tsk->list, &tsk->listen_queue);

		// send SYN + ACK
		tcp_send_control_packet(child_tsk, TCP_SYN | TCP_ACK);

	} else if (tsk->state == TCP_SYN_SENT) {
		if (cb->flags & TCP_ACK) {
			// SYN_SENT --SYN+ACK/ACK-> ESTABLISHED
			tsk->rcv_nxt = cb->seq_end;

			tcp_update_window_safe(tsk, cb);
			tsk->snd_una = cb->ack;

			tcp_set_state(tsk, TCP_ESTABLISHED);

			tcp_send_control_packet(tsk, TCP_ACK);
			
			wake_up(tsk->wait_connect);

		} else {
			// SYN_SENT --SYN/SYN+ACK-> SYN_RCVD
			tsk->rcv_nxt = cb->seq_end;
			
			tcp_set_state(tsk, TCP_SYN_RECV);
			
			tcp_send_control_packet(tsk, TCP_SYN | TCP_ACK);
		}

	} else {
		tcp_send_control_packet(tsk, TCP_ACK);
	}
}

static void handle_ack_packet(struct tcp_sock *tsk, struct tcp_cb * cb) {
	if (cb->ack > tsk->snd_una) {
		struct pend_pkt *pkt_p = NULL, *pkt_q = NULL;
		list_for_each_entry_safe(pkt_p, pkt_q, &tsk->send_buf, list) {
			if (cb->ack >= pkt_p->seq_end) {

			} else {
				break;
			}
		}
		tsk->snd_una = cb->ack;
	}

	return;
}

static int handle_ack_control(struct tcp_sock *tsk, struct tcp_cb * cb) {
	// checking whether all send packets have been acked.
	if (tsk->snd_nxt != tsk->snd_una) {
		return 0;
	}

	if (tsk->state == TCP_SYN_RECV) {
		if (tsk->parent) {
			if (tcp_sock_accept_queue_full(tsk->parent)) {
				tcp_set_state(tsk, TCP_CLOSED);
				// send RST
				tcp_send_control_packet(tsk, TCP_RST);

				tcp_unhash(tsk);
				tcp_bind_unhash(tsk);

				// remove from listen list
				list_delete_entry(&tsk->list);
				free_tcp_sock(tsk);
				log(DEBUG, "The tsk should be freed.");
				return 1;

			} else {
				tcp_set_state(tsk, TCP_ESTABLISHED);
				tcp_sock_accept_enqueue(tsk);

				// wake up user process for accept
				wake_up(tsk->parent->wait_accept);
			}
		} else {
			tcp_set_state(tsk, TCP_ESTABLISHED);
			wake_up(tsk->parent->wait_connect);
		}
	} else if (tsk->state == TCP_FIN_WAIT_1) {
		tcp_set_state(tsk, TCP_FIN_WAIT_2);

	} else if (tsk->state == TCP_CLOSING) {
		tcp_set_state(tsk, TCP_TIME_WAIT);
		tcp_set_timewait_timer(tsk);

	} else if (tsk->state == TCP_LAST_ACK) {
		tcp_set_state(tsk, TCP_CLOSED);

		// release the sock
		tcp_unhash(tsk);
		tcp_bind_unhash(tsk);
		return 1;
	}
	return 0;
}

// handle the recv data from TCP packet
static int handle_tcp_recv_data(struct tcp_sock *tsk, struct tcp_cb * cb) {
	if (cb->pl_len <= 0) {
		return 0;
	}

	pthread_mutex_lock(&tsk->rcv_buf_lock);

	if (cb->pl_len > ring_buffer_free(tsk->rcv_buf)) {
		log(DEBUG, "receive packet is larger than rcv_buf_free, drop it.");

		pthread_mutex_unlock(&tsk->rcv_buf_lock);
		return 0;
	}
	write_ring_buffer(tsk->rcv_buf, cb->payload, cb->pl_len);

	tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);

	wake_up(tsk->wait_recv);

	pthread_mutex_unlock(&tsk->rcv_buf_lock);

	return 1;
}

static void handle_fin(struct tcp_sock *tsk, struct tcp_cb *cb) {
	if (tsk->state == TCP_ESTABLISHED) {
		tcp_set_state(tsk, TCP_CLOSE_WAIT);

		// wake up receiving process as the sock is closed.
		wake_up(tsk->wait_recv);

	} else if (tsk->state == TCP_FIN_WAIT_1) {
		tcp_set_state(tsk, TCP_CLOSING);

	} else if (tsk->state == TCP_FIN_WAIT_2) {
		tcp_set_state(tsk, TCP_TIME_WAIT);

		tcp_set_timewait_timer(tsk);
	}
}

// Process the incoming packet according to TCP state machine. 
void tcp_process(struct tcp_sock *tsk, struct tcp_cb *cb, char *packet)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

	if (tsk == NULL) {
		// no process listening 
		// send RST;
		tcp_send_reset(cb);
		return;
	}

	if (cb->flags & TCP_RST) {
		tcp_set_state(tsk, TCP_CLOSED);
		// release TCP socket

		tcp_unhash(tsk);
		tcp_bind_unhash(tsk);

		// just leave closed socks in list/user
		return;
	}

	if (tsk->state == TCP_CLOSED) {
		log(DEBUG, "this socket is closed");

		// release the sock
		tcp_unhash(tsk);
		tcp_bind_unhash(tsk);

		// send RST
		tcp_send_reset(cb);
		return;
	}

	// establish connection control, part1
	if (cb->flags & TCP_SYN) {
		handle_syn(tsk, cb);
		return;
	}

	// checking seq
	if (!is_tcp_seq_valid(tsk, cb)) {
		return;
	}

	// checking new ack
	if (cb->flags & TCP_ACK) {
		handle_ack_packet(tsk, cb);

		tcp_update_window_safe(tsk, cb);

		if (handle_ack_control(tsk, cb)) {
			return;
		}
	}

	// checking new data or control
	if (cb->seq == cb->seq_end) {
		return;
	}

	// checking out of order
	if (cb->seq < tsk->rcv_nxt) {
		log(DEBUG, "received packet had been received before, drop it.");
		return;
	} else if (cb->seq > tsk->rcv_nxt) {
		log(DEBUG, "received packet out of order.");
		// TODO: insert_rcv_ofo_buf();
		return;
	}

	// checking new data
	if (handle_tcp_recv_data(tsk, cb)) {
		tsk->rcv_nxt = cb->seq_end;
	}

	// close connection control start
	if (cb->flags & TCP_FIN) {
		handle_fin(tsk, cb);
	}

	tcp_send_control_packet(tsk, TCP_ACK);

	if (tsk->state == TCP_TIME_WAIT) {
		log(DEBUG, "receive a packet of a TCP_TIME_WAIT sock.");
		// do something but not this stage

	} else if (tsk->state == TCP_CLOSE_WAIT) {
		log(DEBUG, "receive a packet of a TCP_CLOSE_WAIT sock.");
		// nothing to do;

	}
}

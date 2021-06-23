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

	if (tsk->state == TCP_LISTEN) {
		if (cb->flags == TCP_SYN) {
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
		}

	} else if (tsk->state == TCP_SYN_SENT) {
		if (cb->flags == (TCP_SYN | TCP_ACK)) {
			tsk->rcv_nxt = cb->seq_end;
			tsk->snd_una = cb->ack;

			tcp_set_state(tsk, TCP_ESTABLISHED);

			// send ACK;
			tcp_send_control_packet(tsk, TCP_ACK);
			
			wake_up(tsk->wait_connect);

		} else if (cb->flags == TCP_SYN) {
			tsk->rcv_nxt = cb->seq_end;

			tcp_set_state(tsk, TCP_SYN_RECV);
			// send SYN + ACK;
			tcp_send_control_packet(tsk, TCP_SYN | TCP_ACK);
		}

	} else if (tsk->state == TCP_SYN_RECV) {
		if (cb->flags == TCP_ACK) {
			if (!is_tcp_seq_valid(tsk, cb)) {
				return;
			}
			tsk->rcv_nxt = cb->seq_end;
			tsk->snd_una = cb->ack;

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
		}

	} else if (tsk->state == TCP_ESTABLISHED) {
		if (!is_tcp_seq_valid(tsk, cb)) {
			return;
		}
		tsk->rcv_nxt = cb->seq_end;

		if (cb->flags & TCP_ACK) {
			tsk->snd_una = cb->ack;
			// do something but not this stage
		}

		if (cb->flags & TCP_FIN) {
			tcp_set_state(tsk, TCP_CLOSE_WAIT);
			// send ACK;
			tcp_send_control_packet(tsk, TCP_ACK);
		}

	} else if (tsk->state == TCP_FIN_WAIT_1) {
		if (!is_tcp_seq_valid(tsk, cb)) {
			return;
		}

		// do something but not this stage
		tsk->rcv_nxt = cb->seq_end;

		if (cb->flags & TCP_ACK) {
			tsk->snd_una = cb->ack;
			// do something but not this stage
		}

		if ((cb->flags & TCP_FIN) && (cb->flags & TCP_ACK) && tsk->snd_nxt == tsk->snd_una) {
			tcp_set_state(tsk, TCP_TIME_WAIT);
			tcp_set_timewait_timer(tsk);

			// send ACK;
			tcp_send_control_packet(tsk, TCP_ACK);

		} else if ((cb->flags & TCP_ACK) && tsk->snd_nxt == tsk->snd_una) {
			tcp_set_state(tsk, TCP_FIN_WAIT_2);

		} else if (cb->flags & TCP_FIN) {
			tcp_set_state(tsk, TCP_CLOSING);

			// send ACK;
			tcp_send_control_packet(tsk, TCP_ACK);
		}

	} else if (tsk->state == TCP_FIN_WAIT_2) {
		if (!is_tcp_seq_valid(tsk, cb)) {
			return;
		}

		// do something but not this stage
		tsk->rcv_nxt = cb->seq_end;

		if (cb->flags & TCP_ACK) {
			tsk->snd_una = cb->ack;
			// do something but not this stage
		}

		if (cb->flags & TCP_FIN) {
			tcp_set_state(tsk, TCP_TIME_WAIT);
			tcp_set_timewait_timer(tsk);

			// send ACK;
			tcp_send_control_packet(tsk, TCP_ACK);
		}

	} else if (tsk->state == TCP_CLOSING) {
		if (!is_tcp_seq_valid(tsk, cb)) {
			return;
		}

		tsk->rcv_nxt = cb->seq_end;

		if (cb->flags & TCP_ACK) {
			tsk->snd_una = cb->ack;
			// do something but not this stage
		}

		if ((cb->flags & TCP_ACK) && tsk->snd_nxt == tsk->snd_una) {
			tcp_set_state(tsk, TCP_TIME_WAIT);
			tcp_set_timewait_timer(tsk);
		}

	} else if (tsk->state == TCP_TIME_WAIT) {
		log(DEBUG, "receive a packet of a TCP_TIME_WAIT sock.");
		// do something but not this stage

	} else if (tsk->state == TCP_CLOSE_WAIT) {
		log(DEBUG, "receive a packet of a TCP_CLOSE_WAIT sock.");
		// nothing to do;

	} else if (tsk->state == TCP_LAST_ACK) {
		if (!is_tcp_seq_valid(tsk, cb)) {
			return;
		}

		tsk->rcv_nxt = cb->seq_end;

		if (cb->flags & TCP_ACK) {
			tsk->snd_una = cb->ack;
			// do something but not this stage
		}

		if ((cb->flags & TCP_ACK) && tsk->snd_nxt == tsk->snd_una) {
			tcp_set_state(tsk, TCP_CLOSED);

			// release the sock
			tcp_unhash(tsk);
			tcp_bind_unhash(tsk);

			// just leave the closed sock in accept_queue/user
		}

	} else if (tsk->state == TCP_CLOSED) {
		log(DEBUG, "this socket is closed");

		// release the sock
		tcp_unhash(tsk);
		tcp_bind_unhash(tsk);
	}

}

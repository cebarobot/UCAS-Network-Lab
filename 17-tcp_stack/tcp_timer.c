#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"
#include "log.h"

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

static struct list_head timer_list;
static pthread_mutex_t timer_list_lock;

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	static struct tcp_sock * retrans_sks[10];
	static int retrans_sks_cnt;

	retrans_sks_cnt = 0;

	pthread_mutex_lock(&timer_list_lock);

	struct tcp_timer * timer_p = NULL, * timer_q = NULL;
	list_for_each_entry_safe(timer_p, timer_q, &timer_list, list) {
		if (timer_p->enable) {
			timer_p->timeout -= TCP_TIMER_SCAN_INTERVAL;
			if (timer_p->timeout <= 0) {
				struct tcp_sock * tsk = NULL;
				if (timer_p->type == TIMER_TYPE_TIME_WAIT) {
					// do TCP_TIME_WAIT to TCP_CLOSED
					timer_p->enable = 0;

					tsk = timewait_to_tcp_sock(timer_p);
					assert(tsk->state == TCP_TIME_WAIT);
					tcp_set_state(tsk, TCP_CLOSED);

					tcp_unhash(tsk);
					tcp_bind_unhash(tsk);
					
					// remove reference from timewait list
					list_delete_entry(&timer_p->list);
					free_tcp_sock(tsk);

					// just leave the closed sock in accept_queue/user
				} else if (timer_p->type == TIMER_TYPE_RETRANS) {
					// record all sock needed be retrans
					tsk = retranstimer_to_tcp_sock(timer_p);
					
					retrans_sks[retrans_sks_cnt] = tsk;
					retrans_sks_cnt += 1;
				}
			}
		}
	}

	pthread_mutex_unlock(&timer_list_lock);

	// retrans first packet
	for (int i = 0; i < retrans_sks_cnt; i++) {
		struct tcp_sock * tsk = retrans_sks[i];
		if (send_buf_retrans(tsk)) {
			tcp_unhash(tsk);
			tcp_bind_unhash(tsk);

			tcp_unset_retrans_timer(tsk);
		}
	}
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	// fprintf(stdout, "implement %s please.\n", __FUNCTION__);
	pthread_mutex_lock(&timer_list_lock);

	if (tsk->timewait.enable) {
		tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;
	} else {
		tsk->timewait.enable = 1;
		tsk->timewait.type = TIMER_TYPE_TIME_WAIT;
		tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;

		// refer to this sock in timewait list
		tsk->ref_cnt += 1;
		log(DEBUG, "insert " IP_FMT ":%hu <-> " IP_FMT ":%hu to timewait, ref_cnt += 1", 
				HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport,
				HOST_IP_FMT_STR(tsk->sk_dip), tsk->sk_dport);

		list_add_tail(&tsk->timewait.list, &timer_list);
	}
	pthread_mutex_unlock(&timer_list_lock);
}

// set the retrans timer of a tcp sock, by adding the timer into timer_list
void tcp_set_retrans_timer(struct tcp_sock *tsk) {
	pthread_mutex_lock(&timer_list_lock);

	if (tsk->retrans_timer.enable) {
		tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;
	} else {
		tsk->retrans_timer.enable = 1;
		tsk->retrans_timer.type = TIMER_TYPE_RETRANS;
		tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL;

		// refer to this sock in timewait list
		tsk->ref_cnt += 1;
		log(DEBUG, "insert " IP_FMT ":%hu <-> " IP_FMT ":%hu to retrans_timer, ref_cnt += 1", 
				HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport,
				HOST_IP_FMT_STR(tsk->sk_dip), tsk->sk_dport);

		log(INFO, "timer_list");
		log(INFO, "timer_list: %p %p", timer_list.prev, timer_list.next);
		list_add_tail(&tsk->retrans_timer.list, &timer_list);
		log(INFO, "checkpoint 5");
	}

	pthread_mutex_unlock(&timer_list_lock);
}

int tcp_update_retrans_timer(struct tcp_sock *tsk, int retrans_times) {
	int ret = 0;
	pthread_mutex_lock(&timer_list_lock);

	if (tsk->retrans_timer.enable && tsk->retrans_timer.timeout <= 0) {
		tsk->retrans_timer.timeout = TCP_RETRANS_INTERVAL_INITIAL << retrans_times;
		ret = 1;
	}

	pthread_mutex_unlock(&timer_list_lock);
	return ret;
}

void tcp_unset_retrans_timer(struct tcp_sock *tsk) {
	pthread_mutex_lock(&timer_list_lock);

	if (tsk->retrans_timer.enable) {
		list_delete_entry(&tsk->retrans_timer.list);
		tsk->retrans_timer.enable = 0;

		free_tcp_sock(tsk);
	}

	pthread_mutex_unlock(&timer_list_lock);
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}

void tcp_timer_init() {
	init_list_head(&timer_list);
	log(INFO, "timer_list: %p %p", timer_list.prev, timer_list.next);
	pthread_mutex_init(&timer_list_lock, NULL);
}
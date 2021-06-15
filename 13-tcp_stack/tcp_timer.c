#include "tcp.h"
#include "tcp_timer.h"
#include "tcp_sock.h"

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>

static struct list_head timer_list;
static pthread_mutex_t timer_list_lock = PTHREAD_MUTEX_INITIALIZER;

// scan the timer_list, find the tcp sock which stays for at 2*MSL, release it
void tcp_scan_timer_list()
{
	// fprintf(stdout, "implement %s please.\n", __FUNCTION__);

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
					tsk = retranstimer_to_tcp_sock(timer_p);
					// nothing to do in this version
				}
			}
		}
	}

	pthread_mutex_unlock(&timer_list_lock);
}

// set the timewait timer of a tcp sock, by adding the timer into timer_list
void tcp_set_timewait_timer(struct tcp_sock *tsk)
{
	// fprintf(stdout, "implement %s please.\n", __FUNCTION__);

	tsk->timewait.enable = 1;
	tsk->timewait.type = TIMER_TYPE_TIME_WAIT;
	tsk->timewait.timeout = TCP_TIMEWAIT_TIMEOUT;

	// refer to this sock in timewait list
	tsk->ref_cnt += 1;
	pthread_mutex_lock(&timer_list_lock);
	list_add_tail(&tsk->timewait.list, &timer_list);
	pthread_mutex_unlock(&timer_list_lock);
}

// scan the timer_list periodically by calling tcp_scan_timer_list
void *tcp_timer_thread(void *arg)
{
	init_list_head(&timer_list);
	while (1) {
		usleep(TCP_TIMER_SCAN_INTERVAL);
		tcp_scan_timer_list();
	}

	return NULL;
}

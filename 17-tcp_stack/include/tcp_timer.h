#ifndef __TCP_TIMER_H__
#define __TCP_TIMER_H__

#include "list.h"

#include <stddef.h>

struct tcp_timer {
	int type;	// time-wait: 0		retrans: 1
#define TIMER_TYPE_TIME_WAIT 0
#define TIMER_TYPE_RETRANS 1

	int timeout;	// in micro second
	struct list_head list;
	int enable;
};

struct tcp_sock;
#define timewait_to_tcp_sock(t) \
	(struct tcp_sock *)((char *)(t) - offsetof(struct tcp_sock, timewait))

#define retranstimer_to_tcp_sock(t) \
	(struct tcp_sock *)((char *)(t) - offsetof(struct tcp_sock, retrans_timer))
#define TCP_TIMER_SCAN_INTERVAL 100000
#define TCP_MSL			1000000
#define TCP_TIMEWAIT_TIMEOUT	(2 * TCP_MSL)
#define TCP_RETRANS_INTERVAL_INITIAL 200000

// init sources of tcp_timer
void tcp_timer_init();
// the thread that scans timer_list periodically
void *tcp_timer_thread(void *arg);
// add the timer of tcp sock to timer_list
void tcp_set_timewait_timer(struct tcp_sock *);

void tcp_set_retrans_timer(struct tcp_sock *tsk);
int tcp_update_retrans_timer(struct tcp_sock *tsk, int retrans_times);
void tcp_unset_retrans_timer(struct tcp_sock *tsk);

#endif

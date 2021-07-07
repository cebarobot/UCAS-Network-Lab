#include "tcp.h"
#include "tcp_hash.h"
#include "tcp_sock.h"
#include "tcp_timer.h"
#include "ip.h"
#include "rtable.h"
#include "log.h"

// TCP socks should be hashed into table for later lookup: Those which
// occupy a port (either by *bind* or *connect*) should be hashed into
// bind_table, those which listen for incoming connection request should be
// hashed into listen_table, and those of established connections should
// be hashed into established_table.

struct tcp_hash_table tcp_sock_table;
#define tcp_established_sock_table	tcp_sock_table.established_table
#define tcp_listen_sock_table		tcp_sock_table.listen_table
#define tcp_bind_sock_table			tcp_sock_table.bind_table

inline void tcp_set_state(struct tcp_sock *tsk, int state)
{
	log(DEBUG, IP_FMT":%hu switch state, from %s to %s.", \
			HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport, \
			tcp_state_str[tsk->state], tcp_state_str[state]);
	tsk->state = state;
}

// init tcp hash table and tcp timer
// used by stack
void init_tcp_stack()
{
	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_established_sock_table[i]);

	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_listen_sock_table[i]);

	for (int i = 0; i < TCP_HASH_SIZE; i++)
		init_list_head(&tcp_bind_sock_table[i]);

	pthread_t timer;
	pthread_create(&timer, NULL, tcp_timer_thread, NULL);
}

// allocate tcp sock, and initialize all the variables that can be determined
// now
// Used by user & stack
struct tcp_sock *alloc_tcp_sock()
{
	struct tcp_sock *tsk = malloc(sizeof(struct tcp_sock));

	memset(tsk, 0, sizeof(struct tcp_sock));

	tsk->state = TCP_CLOSED;
	tsk->rcv_wnd = TCP_DEFAULT_WINDOW;

	init_list_head(&tsk->list);
	init_list_head(&tsk->listen_queue);
	init_list_head(&tsk->accept_queue);

	tsk->rcv_buf = alloc_ring_buffer(tsk->rcv_wnd);
	pthread_mutex_init(&tsk->rcv_buf_lock, NULL);

	tsk->wait_connect = alloc_wait_struct();
	tsk->wait_accept = alloc_wait_struct();
	tsk->wait_recv = alloc_wait_struct();
	tsk->wait_send = alloc_wait_struct();

	log(DEBUG, "alloc a new tcp sock, ref_cnt = 1");
	tsk->ref_cnt += 1;
	return tsk;
}

// release all the resources of tcp sock
//
// To make the stack run safely, each time the tcp sock is refered (e.g. hashed), 
// the ref_cnt is increased by 1. each time free_tcp_sock is called, the ref_cnt
// is decreased by 1, and release the resources practically if ref_cnt is
// decreased to zero.
// used by stack
void free_tcp_sock(struct tcp_sock *tsk)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

	tsk->ref_cnt -= 1;
	if (tsk->ref_cnt <= 0) {
		log(DEBUG, "Do free " IP_FMT ":%hu <-> " IP_FMT ":%hu.", 
				HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport,
				HOST_IP_FMT_STR(tsk->sk_dip), tsk->sk_dport);
		
		if (tsk->parent) {
			free_tcp_sock(tsk->parent);
		}

		free_ring_buffer(tsk->rcv_buf);

		free_wait_struct(tsk->wait_connect);
		free_wait_struct(tsk->wait_accept);
		free_wait_struct(tsk->wait_recv);
		free_wait_struct(tsk->wait_send);

		free(tsk);
	} else {
		log(DEBUG, "Try to free " IP_FMT ":%hu <-> " IP_FMT ":%hu, but ref_cnt = %d", 
				HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport,
				HOST_IP_FMT_STR(tsk->sk_dip), tsk->sk_dport, tsk->ref_cnt);
	}
}

// lookup tcp sock in established_table with key (saddr, daddr, sport, dport)
// used by stack
struct tcp_sock *tcp_sock_lookup_established(u32 saddr, u32 daddr, u16 sport, u16 dport)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	
	int value = tcp_hash_function(saddr, daddr, sport, dport);
	struct list_head *list = &tcp_established_sock_table[value];

	struct tcp_sock *sock_p;
	list_for_each_entry(sock_p, list, hash_list) {
		if (
			saddr == sock_p->sk_sip && daddr == sock_p->sk_dip &&
			sport == sock_p->sk_sport && dport == sock_p->sk_dport
		) {
			return sock_p;
		}
	}

	return NULL;
}

// lookup tcp sock in listen_table with key (sport)
//
// In accordance with BSD socket, saddr is in the argument list, but never used.
// used by stack
struct tcp_sock *tcp_sock_lookup_listen(u32 saddr, u16 sport)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

	int value = tcp_hash_function(0, 0, sport, 0);
	struct list_head *list = &tcp_listen_sock_table[value];

	struct tcp_sock *sock_p;
	list_for_each_entry(sock_p, list, hash_list) {
		if (sport == sock_p->sk_sport) {
			return sock_p;
		}
	}

	return NULL;
}

// lookup tcp sock in both established_table and listen_table
// used by stack
struct tcp_sock *tcp_sock_lookup(struct tcp_cb *cb)
{
	u32 saddr = cb->daddr,
		daddr = cb->saddr;
	u16 sport = cb->dport,
		dport = cb->sport;

	struct tcp_sock *tsk = tcp_sock_lookup_established(saddr, daddr, sport, dport);
	if (!tsk)
		tsk = tcp_sock_lookup_listen(saddr, sport);

	return tsk;
}

// hash tcp sock into bind_table, using sport as the key
// used by stack
static int tcp_bind_hash(struct tcp_sock *tsk)
{
	int bind_hash_value = tcp_hash_function(0, 0, tsk->sk_sport, 0);
	struct list_head *list = &tcp_bind_sock_table[bind_hash_value];
	list_add_head(&tsk->bind_hash_list, list);

	log(DEBUG, "insert " IP_FMT ":%hu <-> " IP_FMT ":%hu to bind_hash_list, ref_cnt += 1", 
			HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport,
			HOST_IP_FMT_STR(tsk->sk_dip), tsk->sk_dport);
	tsk->ref_cnt += 1;

	return 0;
}

// unhash the tcp sock from bind_table
// used by stack
void tcp_bind_unhash(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->bind_hash_list)) {
		list_delete_entry(&tsk->bind_hash_list);
		free_tcp_sock(tsk);
	}
}

// lookup bind_table to check whether sport is in use
// used by stack
static int tcp_port_in_use(u16 sport)
{
	int value = tcp_hash_function(0, 0, sport, 0);
	struct list_head *list = &tcp_bind_sock_table[value];
	struct tcp_sock *tsk;
	list_for_each_entry(tsk, list, hash_list) {
		if (tsk->sk_sport == sport)
			return 1;
	}

	return 0;
}

// find a free port by looking up bind_table
// used by stack
static u16 tcp_get_port()
{
	time_t t;
	srand((unsigned) time(&t));
	int r = rand();

	for (u16 i = 0; i < PORT_MAX - PORT_MIN; i++) {
		u16 port = (i + r) % (PORT_MAX - PORT_MIN) + PORT_MIN;
		if (!tcp_port_in_use(port))
			return port;
	}

	return 0;
}

// tcp sock tries to use port as its source port
// used by stack
static int tcp_sock_set_sport(struct tcp_sock *tsk, u16 port)
{
	if ((port && tcp_port_in_use(port)) ||
			(!port && !(port = tcp_get_port())))
		return -1;

	tsk->sk_sport = port;

	tcp_bind_hash(tsk);

	return 0;
}

// hash tcp sock into either established_table or listen_table according to its
// TCP_STATE
// used by stack
int tcp_hash(struct tcp_sock *tsk)
{
	struct list_head *list;
	int hash;

	if (tsk->state == TCP_CLOSED)
		return -1;

	if (tsk->state == TCP_LISTEN) {
		hash = tcp_hash_function(0, 0, tsk->sk_sport, 0);
		list = &tcp_listen_sock_table[hash];
	}
	else {
		int hash = tcp_hash_function(tsk->sk_sip, tsk->sk_dip, \
				tsk->sk_sport, tsk->sk_dport); 
		list = &tcp_established_sock_table[hash];

		struct tcp_sock *tmp;
		list_for_each_entry(tmp, list, hash_list) {
			if (tsk->sk_sip == tmp->sk_sip &&
					tsk->sk_dip == tmp->sk_dip &&
					tsk->sk_sport == tmp->sk_sport &&
					tsk->sk_dport == tmp->sk_dport)
				return -1;
		}
	}

	list_add_head(&tsk->hash_list, list);
	tsk->ref_cnt += 1;
	
	log(DEBUG, "insert " IP_FMT ":%hu <-> " IP_FMT ":%hu to hash_list, ref_cnt += 1", 
			HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport,
			HOST_IP_FMT_STR(tsk->sk_dip), tsk->sk_dport);

	return 0;
}

// unhash tcp sock from established_table or listen_table
// used by stack
void tcp_unhash(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->hash_list)) {
		list_delete_entry(&tsk->hash_list);
		free_tcp_sock(tsk);
	}
}

// XXX: skaddr here contains network-order variables
// used by user
int tcp_sock_bind(struct tcp_sock *tsk, struct sock_addr *skaddr)
{
	int err = 0;
	log(DEBUG, "binding port %hu.", skaddr->port);

	// omit the ip address, and only bind the port
	err = tcp_sock_set_sport(tsk, ntohs(skaddr->port));

	return err;
}

// connect to the remote tcp sock specified by skaddr
//
// XXX: skaddr here contains network-order variables
// 1. initialize the four key tuple (sip, sport, dip, dport);
// 2. hash the tcp sock into bind_table;
// 3. send SYN packet, switch to TCP_SYN_SENT state, wait for the incoming
//    SYN packet by sleep on wait_connect;
// 4. if the SYN packet of the peer arrives, this function is notified, which
//    means the connection is established.
// used by user
int tcp_sock_connect(struct tcp_sock *tsk, struct sock_addr *skaddr)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	int err = 0;

	tsk->sk_dip = ntohl(skaddr->ip);
	tsk->sk_dport = ntohs(skaddr->port);

	rt_entry_t * rt = longest_prefix_match(tsk->sk_dip);
	if (!rt) {
		log(ERROR, "cannot find route to daddr.");
		return -1;
	}
	tsk->sk_sip = rt->iface->ip;

	err = tcp_sock_set_sport(tsk, 0);
	if (err) {
		log(ERROR, "setting sport failed.");
		return err;
	}

	tcp_set_state(tsk, TCP_SYN_SENT);
	err = tcp_hash(tsk);
	if (err) {
		log(ERROR, "hashing into hash_table failed.");
		return err;
	}

	tcp_send_control_packet(tsk, TCP_SYN);

	err = sleep_on(tsk->wait_connect);
	if (err) {
		return err;
	}

	return 0;
}

// set backlog (the maximum number of pending connection requst), switch the
// TCP_STATE, and hash the tcp sock into listen_table
// used by user
int tcp_sock_listen(struct tcp_sock *tsk, int backlog)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);

	int err = 0;
	log(DEBUG, "listening port %hu.", tsk->sk_sport);

	tsk->backlog = backlog;
	tcp_set_state(tsk, TCP_LISTEN);
	err = tcp_hash(tsk);

	return err;
}

// check whether the accept queue is full
// used by stack
inline int tcp_sock_accept_queue_full(struct tcp_sock *tsk)
{
	if (tsk->accept_backlog >= tsk->backlog) {
		log(ERROR, "tcp accept queue (%d) is full.", tsk->accept_backlog);
		return 1;
	}

	return 0;
}

// push the tcp sock into accept_queue
// used by stack
inline void tcp_sock_accept_enqueue(struct tcp_sock *tsk)
{
	if (!list_empty(&tsk->list)) {
		list_delete_entry(&tsk->list);
		tsk->ref_cnt -= 1;
		log(DEBUG, "remove " IP_FMT ":%hu <-> " IP_FMT ":%hu from list, ref_cnt -= 1", 
				HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport,
				HOST_IP_FMT_STR(tsk->sk_dip), tsk->sk_dport);
	}
	list_add_tail(&tsk->list, &tsk->parent->accept_queue);
	tsk->parent->accept_backlog += 1;
	tsk->ref_cnt += 1;
	log(DEBUG, "add " IP_FMT ":%hu <-> " IP_FMT ":%hu to accept_list, ref_cnt += 1", 
			HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport,
			HOST_IP_FMT_STR(tsk->sk_dip), tsk->sk_dport);
}

// pop the first tcp sock of the accept_queue
// used by stack
inline struct tcp_sock *tcp_sock_accept_dequeue(struct tcp_sock *tsk)
{
	struct tcp_sock *new_tsk = list_entry(tsk->accept_queue.next, struct tcp_sock, list);
	list_delete_entry(&new_tsk->list);
	init_list_head(&new_tsk->list);
	tsk->accept_backlog -= 1;

	log(DEBUG, "pass " IP_FMT ":%hu <-> " IP_FMT ":%hu from accept_list, ref_cnt ===", 
			HOST_IP_FMT_STR(new_tsk->sk_sip), new_tsk->sk_sport,
			HOST_IP_FMT_STR(new_tsk->sk_dip), new_tsk->sk_dport);
	return new_tsk;
}

// if accept_queue is not emtpy, pop the first tcp sock and accept it,
// otherwise, sleep on the wait_accept for the incoming connection requests
// used by user
struct tcp_sock *tcp_sock_accept(struct tcp_sock *tsk)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	while (list_empty(&tsk->accept_queue)) {
		sleep_on(tsk->wait_accept);
	}

	return tcp_sock_accept_dequeue(tsk);
}

// close the tcp sock, by releasing the resources, sending FIN/RST packet
// to the peer, switching TCP_STATE to closed
// used by user
void tcp_sock_close(struct tcp_sock *tsk)
{
	// fprintf(stdout, "TODO: implement %s please.\n", __FUNCTION__);
	log(DEBUG, "close sock " IP_FMT ":%hu <-> " IP_FMT ":%hu, state %s", 
			HOST_IP_FMT_STR(tsk->sk_sip), tsk->sk_sport,
			HOST_IP_FMT_STR(tsk->sk_dip), tsk->sk_dport, tcp_state_str[tsk->state]);

	if (tsk->state == TCP_LISTEN) {
		tcp_set_state(tsk, TCP_CLOSED);

		tcp_unhash(tsk);
		tcp_bind_unhash(tsk);

	} else if (tsk->state == TCP_SYN_SENT) {
		tcp_set_state(tsk, TCP_CLOSED);
		
		tcp_unhash(tsk);
		tcp_bind_unhash(tsk);

	} else if (tsk->state == TCP_SYN_RECV) {
		tcp_set_state(tsk, TCP_FIN_WAIT_1);
		tcp_send_control_packet(tsk, TCP_FIN | TCP_ACK);
		
	} else if (tsk->state == TCP_ESTABLISHED) {
		tcp_set_state(tsk, TCP_FIN_WAIT_1);
		tcp_send_control_packet(tsk, TCP_FIN | TCP_ACK);

	} else if (tsk->state == TCP_CLOSE_WAIT) {
		tcp_set_state(tsk, TCP_LAST_ACK);
		tcp_send_control_packet(tsk, TCP_FIN | TCP_ACK);

	}

	free_tcp_sock(tsk);
}

int tcp_sock_read(struct tcp_sock *tsk, char *buf, int len) {
	pthread_mutex_lock(&tsk->rcv_buf_lock);

	while (ring_buffer_empty(tsk->rcv_buf)) {
		if (tsk->state == TCP_CLOSED || tsk->state == TCP_LAST_ACK || tsk->state == TCP_CLOSE_WAIT) {
			pthread_mutex_unlock(&tsk->rcv_buf_lock);
			return 0;
		} else {
			pthread_mutex_unlock(&tsk->rcv_buf_lock);
			sleep_on(tsk->wait_recv);
			pthread_mutex_lock(&tsk->rcv_buf_lock);
		}
	}

	int read_len = min(len, ring_buffer_used(tsk->rcv_buf));
	read_ring_buffer(tsk->rcv_buf, buf, read_len);

	tsk->rcv_wnd = ring_buffer_free(tsk->rcv_buf);

	pthread_mutex_unlock(&tsk->rcv_buf_lock);
	return read_len;
}

int tcp_sock_write(struct tcp_sock *tsk, char *buf, int len) {
	while (len > 0) {
		int write_len = tcp_send_data(tsk, buf, len);
		buf += write_len;
		len -= write_len;
	}
	return len;
}
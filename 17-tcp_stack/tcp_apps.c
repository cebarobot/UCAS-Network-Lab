#include "tcp_sock.h"

#include "log.h"

#include <stdlib.h>
#include <unistd.h>

char filename[100];

// tcp server application, listens to port (specified by arg) and serves only one
// connection request
void *tcp_server(void *arg)
{
	u16 port = *(u16 *)arg;
	struct tcp_sock *tsk = alloc_tcp_sock();

	struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = port;
	if (tcp_sock_bind(tsk, &addr) < 0) {
		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
		exit(1);
	}

	if (tcp_sock_listen(tsk, 3) < 0) {
		log(ERROR, "tcp_sock listen failed");
		exit(1);
	}

	log(DEBUG, "listen to port %hu.", ntohs(port));

	struct tcp_sock *csk = tcp_sock_accept(tsk);

	log(DEBUG, "accept a connection.");

	char rbuf[1001];
	char wbuf[1024];
	int rlen = 0;
	while (1) {
		rlen = tcp_sock_read(csk, rbuf, 1000);
		if (rlen == 0) {
			log(DEBUG, "tcp_sock_read return 0, finish transmission.");
			break;
		} 
		else if (rlen > 0) {
			rbuf[rlen] = '\0';
			sprintf(wbuf, "server echoes: %s", rbuf);
			if (tcp_sock_write(csk, wbuf, strlen(wbuf)) < 0) {
				log(DEBUG, "tcp_sock_write return negative value, something goes wrong.");
				exit(1);
			}
		}
		else {
			log(DEBUG, "tcp_sock_read return negative value, something goes wrong.");
			exit(1);
		}
	}

	log(DEBUG, "close this connection.");

	tcp_sock_close(csk);
	
	tcp_sock_close(tsk);
	
	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), each
// time sends one bulk of data and receives one bulk of data 
void *tcp_client(void *arg)
{
	struct sock_addr *skaddr = arg;

	struct tcp_sock *tsk = alloc_tcp_sock();

	if (tcp_sock_connect(tsk, skaddr) < 0) {
		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}

	log(DEBUG, "connect success.");

	char *data = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	int dlen = strlen(data);
	char *wbuf = malloc(dlen+1);
	char rbuf[1001];
	int rlen = 0;

	int n = 10;
	for (int i = 0; i < n; i++) {
		memcpy(wbuf, data+i, dlen-i);
		if (i > 0) memcpy(wbuf+(dlen-i), data, i);

		if (tcp_sock_write(tsk, wbuf, dlen) < 0)
			break;

		log(DEBUG, "send packet");

		rlen = tcp_sock_read(tsk, rbuf, 1000);
		if (rlen == 0) {
			log(DEBUG, "tcp_sock_read return 0, finish transmission.");
			break;
		}
		else if (rlen > 0) {
			rbuf[rlen] = '\0';
			fprintf(stdout, "%s\n", rbuf);
		}
		else {
			log(DEBUG, "tcp_sock_read return negative value, something goes wrong.");
			exit(1);
		}
	}

	tcp_sock_close(tsk);

	free(wbuf);

	return NULL;
}


// tcp server application, listens to port (specified by arg) and serves only one
// connection request
void *tcp_server_file(void *arg)
{
	FILE * f = fopen(filename, "wb");
	if (!f) {
		log(ERROR, "cannot open file");
	}
	log(DEBUG, "open file %s", filename);

	u16 port = *(u16 *)arg;
	struct tcp_sock *tsk = alloc_tcp_sock();

	struct sock_addr addr;
	addr.ip = htonl(0);
	addr.port = port;
	if (tcp_sock_bind(tsk, &addr) < 0) {
		log(ERROR, "tcp_sock bind to port %hu failed", ntohs(port));
		exit(1);
	}

	if (tcp_sock_listen(tsk, 3) < 0) {
		log(ERROR, "tcp_sock listen failed");
		exit(1);
	}

	log(DEBUG, "listen to port %hu.", ntohs(port));

	struct tcp_sock *csk = tcp_sock_accept(tsk);

	log(DEBUG, "accept a connection.");

	char data_buf[1030];
	int data_len = 0;
	while (1) {
		data_len = tcp_sock_read(csk, data_buf, 1024);
		if (data_len > 0) {
			fwrite(data_buf, 1, data_len, f);
		} else {
			log(DEBUG, "peer closed.");
			break;
		}
	}

	fclose(f);
	log(DEBUG, "close this connection.");

	tcp_sock_close(csk);
	
	tcp_sock_close(tsk);
	
	return NULL;
}

// tcp client application, connects to server (ip:port specified by arg), each
// time sends one bulk of data and receives one bulk of data 
void *tcp_client_file(void *arg)
{
	FILE * f = fopen(filename, "rb");
	if (!f) {
		log(ERROR, "cannot open file");
	}
	log(DEBUG, "open file %s", filename);

	struct sock_addr *skaddr = arg;

	struct tcp_sock *tsk = alloc_tcp_sock();

	if (tcp_sock_connect(tsk, skaddr) < 0) {
		log(ERROR, "tcp_sock connect to server ("IP_FMT":%hu)failed.", \
				NET_IP_FMT_STR(skaddr->ip), ntohs(skaddr->port));
		exit(1);
	}

	log(DEBUG, "connect success.");

	char data_buf[1030];
	int data_len = 0;

	int send_size = 0;
	while (1) {
		data_len = fread(data_buf, 1, 1024, f);
		if (data_len > 0) {
			send_size += data_len;
			printf("sent %d Bytes\n", send_size);
			tcp_sock_write(tsk, data_buf, data_len);
		} else {
			log(DEBUG, "the file is end.");
			break;
		}
		usleep(100);
	}

	fclose(f);
	tcp_sock_close(tsk);

	return NULL;
}

/* A simple http server */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>
#include <pthread.h>

#include "tcp_sock.h"
// #include "log.h"

#define MAX_THREAD 5

struct ThreadInfo {
    pthread_t pthread_id;
    int is_busy;
    // struct sockaddr_in client;
    int addr_len;
    struct tcp_sock *csk;
} t_info[MAX_THREAD];

struct ResponseInfo {
    int status_code;
    const char * reason_message;
    int content_length;
    FILE * response_file;
};

int genResponseHeader(struct ResponseInfo * r_info, char * buff) {
    int len = 0;
    len += sprintf(buff + len, "HTTP/1.1 %d %s\r\n", r_info->status_code, r_info->reason_message);
    len += sprintf(buff + len, "Content-Type: %s\r\n", "text/plain");
    len += sprintf(buff + len, "Content-Length: %d\r\n", r_info->content_length);
    len += sprintf(buff + len, "Server: %s\r\n", "simple-http-server/0.1 ceba");
    len += sprintf(buff + len, "\r\n");
    return len;
}

void * handleRequest(void * arg) {
    pthread_detach(pthread_self());
    struct ThreadInfo * this_info = arg;

    char * recv_buff = malloc(2000);
    int recv_len = tcp_sock_read(this_info->csk, recv_buff, 2000);
    if (recv_len < 0) {
        fprintf(stderr, "Recv failed.");
        this_info->is_busy = 0;
        return NULL;
    }

    char * line_start = recv_buff;
    // char * line_end = strstr(line_start, "\r\n");

    char method[10];
    char path[100];
    char http_version[10];
    sscanf(line_start, "%s %s %s", method, path, http_version);

    struct ResponseInfo r_info;
    char * send_buff = malloc(6000);
    char * file_buff = malloc(4000);

    FILE * req_file = fopen(path + 1, "r");
    if (req_file == NULL) {
        r_info.status_code = 404;
        r_info.reason_message = "Not Found";
        r_info.content_length = 0;
    } else {
        r_info.status_code = 200;
        r_info.reason_message = "OK";

        char ch;
        int len = 0;
        while ((ch = fgetc(req_file)) != EOF && len < 4000)  {
            file_buff[len] = ch;
            len ++;
        }
        file_buff[len] = 0;
        r_info.content_length = len;
    }

    int send_len = 0;
    send_len += genResponseHeader(&r_info, send_buff + send_len);
    send_len += sprintf(send_buff + send_len, "%s", file_buff);

    if (tcp_sock_write(this_info->csk, send_buff, send_len) < 0) {
        fprintf(stderr, "send failed");
        return NULL;
    }
    printf(IP_FMT " - ", HOST_IP_FMT_STR(this_info->csk->peer.ip));
    printf("\"%s %s %s\"", method, path, http_version);
    printf(" - %d\n", r_info.status_code);
    
    free(recv_buff);
    free(send_buff);
    free(file_buff);
    this_info->is_busy = 0;

	tcp_sock_close(this_info->csk);

    return NULL;
}

void *http_server(void *arg) {
    int port = 80;
	struct sock_addr addr;

    char** argv = arg;

    int ret = sscanf(argv[1], "%d", &port);
    if (ret < 1) {
        fprintf(stderr, "Invalid Port, use 80 instead");
        port = 80;
    }

    struct tcp_sock *tsk = alloc_tcp_sock();
    if (tsk == NULL) {
        perror("Create socket failed");
		exit(1);
    }

	addr.ip = htonl(0);
    addr.port = htons(port);

    if (tcp_sock_bind(tsk, &addr) < 0) {
        perror("bind failed");
        exit(1);
    }

    if (tcp_sock_listen(tsk, 3) < 0) {
        perror("listen failed");
        exit(1);
	}
    printf("Servering HTTP on 0.0.0.0 port %d ...\n", port);
    
    while (1) {
        for (int i = 0; i < MAX_THREAD; i++) {
            if (!t_info[i].is_busy) {
                t_info[i].csk = tcp_sock_accept(tsk);
                // t_info[i].request = accept(sockfd, (struct sockaddr *)&t_info[i].client, (socklen_t *)&t_info[i].addr_len);
                t_info[i].is_busy = 1;
                pthread_create(&t_info[i].pthread_id, NULL, handleRequest, t_info + i);
            }
        }
    }

    return 0;
}
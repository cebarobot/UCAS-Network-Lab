/* A simple http client */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <regex.h>

#include "tcp_sock.h"
// #include "log.h"

struct UrlInfo {
    char ip_addr[16];
    char protocol[8];
    char port[8];
    char path[64];
};

struct RequestInfo {
    struct UrlInfo url_info;
    int port_int;
};

int parseUrl(const char * url, struct UrlInfo * url_info) {
    int ret;
    regex_t url_reg;
    char error_buff[256];
    regmatch_t matches[7];

    ret = regcomp(&url_reg, "((http)://)?([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})(:([0-9]{1,5}))?(\\S+)?", REG_EXTENDED | REG_ICASE);
    if (ret) {
        regerror(ret, &url_reg, error_buff, 256);
        fprintf(stderr, "Failed to parse URL: %s\n", error_buff);
        return -1;
    }

    ret = regexec(&url_reg, url, 7, matches, 0);
    if (ret) {
        regerror(ret, &url_reg, error_buff, 256);
        fprintf(stderr, "Failed to parse URL: %s\n", error_buff);
        return -1;
    }

    memset(url_info, 0, sizeof(struct UrlInfo));
    memcpy(url_info->protocol, url + matches[2].rm_so, matches[2].rm_eo - matches[2].rm_so);
    memcpy(url_info->ip_addr, url + matches[3].rm_so, matches[3].rm_eo - matches[3].rm_so);
    memcpy(url_info->port, url + matches[5].rm_so, matches[5].rm_eo - matches[5].rm_so);
    memcpy(url_info->path, url + matches[6].rm_so, matches[6].rm_eo - matches[6].rm_so);

    regfree(&url_reg);
    return 0;
}

int genRequestHeader(struct RequestInfo * r_info, char * buff) {
    int len = 0;
    len += sprintf(buff + len, "GET %s HTTP/1.1\r\n", r_info->url_info.path);
    len += sprintf(buff + len, "User-Agent: %s\r\n", "simple-http-client/0.1 ceba");
    len += sprintf(buff + len, "Host: %s\r\n", r_info->url_info.ip_addr);
    len += sprintf(buff + len, "\r\n");
    return len;
}

void *http_client(void *arg) {
    struct RequestInfo r_info;
	struct sock_addr addr;

    char** argv = arg;

    if (parseUrl(argv[1], &r_info.url_info)) {
        exit(1);
    }

    if (r_info.url_info.port[0]) {
        sscanf(r_info.url_info.port, "%d", &r_info.port_int);
    } else {
        r_info.port_int = 80;
    }
    if (!r_info.url_info.path[0]) {
        r_info.url_info.path[0] = '/';
    }

    addr.ip = inet_addr(r_info.url_info.ip_addr);
    addr.port = htons(r_info.port_int);

    printf("Connecting to %s:%d...", r_info.url_info.ip_addr, r_info.port_int);

    // int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct tcp_sock *tsk = alloc_tcp_sock();
    if (tsk == NULL) {
        fprintf(stderr, "Create socket failed.\n");
		exit(1);
    }

	if (tcp_sock_connect(tsk, &addr) < 0) {
        perror("Connect failed\n");
        exit(1);
    }

    printf("Success.\n");

    char * send_buff = malloc(500);
    int send_len = genRequestHeader(&r_info, send_buff);

    if (tcp_sock_write(tsk, send_buff, send_len) < 0) {
        fprintf(stderr, "send failed");
        exit(1);
    }
    printf("HTTP request sent, awaiting response...\n");
    
    char * recv_buff = malloc(2000);
    memset(recv_buff, 0, 2000);
    int recv_len = tcp_sock_read(tsk, recv_buff, 2000);
    // printf("===========%s\n", recv_buff);
    if (recv_len < 0) {
        fprintf(stderr, "Recv failed.");
        exit(1);
    }

    if (recv_len < 30) {
        int new_recv_len = tcp_sock_read(tsk, recv_buff + recv_len, 2000 - recv_len);
        recv_len += new_recv_len;
        printf("new_recv_len: %d\n", new_recv_len);
    }

    printf("recv_len: %d\n", recv_len);

    char * http_head_end = strstr(recv_buff, "\r\n\r\n");
    if (http_head_end == NULL) {
        http_head_end = recv_buff + recv_len;
        // fprintf(stderr, "HTTP parse failed.");
        // exit(1);
    }

    char * line_start = recv_buff;
    // char * line_end = strstr(line_start, "\r\n");

    char http_version[10];
    int status_code;
    char reason_message[30];
    sscanf(line_start, "%s %d %[^\n]", http_version, &status_code, reason_message);

    printf("%d %s\n", status_code, reason_message);

    printf("%s\n", http_head_end + 4);

    if (status_code == 200) {
        char * file_name_start = strrchr(r_info.url_info.path, '/') + 1;
        char file_name[50];
        sprintf(file_name, "save-%s", *file_name_start ? file_name_start : "index.html");
        FILE * resp_file = fopen(file_name, "w");
        fprintf(resp_file, "%s", http_head_end + 4);
        printf("File \"%s\" saved.\n", file_name);
        fclose(resp_file);
    }

	tcp_sock_close(tsk);

    free(send_buff);
    free(recv_buff);
    return 0;
}

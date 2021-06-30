#ifndef __TCP_APPS_H__
#define __TCP_APPS_H__

extern char filename[100];

void *tcp_server(void *arg);
void *tcp_client(void *arg);

void *tcp_server_file(void *arg);
void *tcp_client_file(void *arg);

#endif

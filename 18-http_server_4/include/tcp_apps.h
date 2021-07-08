#ifndef __TCP_APPS_H__
#define __TCP_APPS_H__

extern char filename[100];

void *http_server(void *arg);
void *http_client(void *arg);


#endif

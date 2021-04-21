/* A simple http client */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <regex.h>

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

int main(int argc, char* argv[]) {
    struct RequestInfo r_info;
 0Â­öiU
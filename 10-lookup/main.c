#include "binary.h"
#include "ip.h"
#include "trie.h"

#include <stdio.h>
#include <sys/time.h>
#include <time.h>

struct TrieNode * table_root;

#define FORW_TABLE_SIZE 700000
uint32_t ip_table[FORW_TABLE_SIZE];
uint32_t prefix_table[FORW_TABLE_SIZE];
int port_table[FORW_TABLE_SIZE];
int table_size;

void read_all_data(const char * filename) {
    FILE * file = fopen(filename, "r");

    uint32_t ip;
    uint32_t prefix;
    int port;

    table_size = 0;
    while (fscanf(file, IP_FMT " %u %d", IP_SCAN_STR(ip), &prefix, &port) == 6) {
        ip_table[table_size] = ip;
        prefix_table[table_size] = prefix;
        port_table[table_size] = port;
        table_size += 1;
    }

    fclose(file);
}

static inline long diff_us(struct timeval * tv1, struct timeval * tv2) {
    return (((tv2->tv_sec - tv1->tv_sec) * 1000000) + (tv2->tv_usec - tv1->tv_usec));
}

int main(int argc, char *argv[]) {
    // int pppp = 32;
    // uint32_t ip;
    // sscanf("5.34.183.151", IP_FMT, IP_SCAN_STR(ip));
    // printf("0x%08x\n", ( ~ 0U ) >> (pppp) );
    // ip = PREFIX_OF(ip, pppp);
    // printf(IP_FMT "\n", IP_FMT_STR(ip));
    // return 0;
    if (argc < 3) {
        return -1;
    }
    unsigned opt = 0;
    sscanf(argv[1], "%u", &opt);

    read_all_data(argv[2]);

    table_root = trie_init();
    for (int i = 0; i < table_size; i++) {
        if (BIT_OF(opt, 3)) {
            trie_insert_compress(table_root, ip_table[i], prefix_table[i], port_table[i]);
        } else {
            trie_insert(table_root, ip_table[i], prefix_table[i], port_table[i]);
        }
    }
    
    if (BIT_OF(opt, 0)) {
        print_trie(table_root);
    }

    struct timeval tv1, tv2;
    int res_port = 0;

    gettimeofday(&tv1, NULL);
    for (int i = 0; i < table_size; i++) {
        res_port = trie_lookup(table_root, ip_table[i]);
        
        // if (BIT_OF(opt, 1)) {
        //     printf("%d\n", res_port);
        // }
    }
    gettimeofday(&tv2, NULL);

    long total_time = diff_us(&tv1, &tv2);

    if (BIT_OF(opt, 2)) {
        printf("mem: %lu Bytes\n", memory_measure);
        printf("time: %ld us\n", total_time);
        printf("table size: %d\n", table_size);
        printf("time per lookup: %f us\n", (double)total_time / table_size);
    }
    
    // print_trie(table_root);

    return 0;
}
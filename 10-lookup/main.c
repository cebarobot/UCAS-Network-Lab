#include "binary.h"
#include "ip.h"
#include "trie.h"

#include <stdio.h>
#include <sys/time.h>
#include <time.h>

const char * table_filename = "forwarding-table.txt";
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

int main() {
    read_all_data(table_filename);

    table_root = trie_init();
    for (int i = 0; i < table_size; i++) {
        trie_insert(table_root, ip_table[i], prefix_table[i], port_table[i]);
    }
    struct timeval tv1, tv2;
    int res_port = 0;

    gettimeofday(&tv1, NULL);
    for (int i = 0; i < table_size; i++) {
        res_port = trie_lookup(table_root, ip_table[i]);
        // printf("%d\n", res_port);
    }
    gettimeofday(&tv2, NULL);

    long total_time = diff_us(&tv1, &tv2);

    printf("mem: %lu Bytes\n", memory_measure);
    printf("time: %ld us\n", total_time);
    printf("table size: %d\n", table_size);
    printf("time per lookup: %f us\n", (double)total_time / table_size);

    
    // print_trie(table_root);

    return 0;
}
#include <stdio.h>

#include "trie.h"
#include "binary.h"
#include "ip.h"

size_t memory_measure = 0;

static inline void *measure_malloc(size_t size) 
{
	void *ptr = malloc(size);
    memory_measure += size;
	return ptr;
}

struct TrieNode * trie_init() {
    struct TrieNode * root = measure_malloc(sizeof(struct TrieNode));
    root->ip = 0;
    root->prefix = 0;
    root->valid = false;
    // root->parent = NULL:
    root->children[0] = NULL;
    root->children[1] = NULL;

    return root;
}

int trie_lookup(struct TrieNode * root, uint32_t ip) {
    struct TrieNode * match_node = NULL;
    struct TrieNode * pos = root; 
    while (pos) {
        if (pos->valid && pos->ip == PREFIX_OF(ip, pos->prefix)) {
            match_node = pos;
        }
        int nxt_prefix = pos->prefix + 1;
        int nxt_bit = BIT_OF(ip, 32 - nxt_prefix);
        pos = pos->children[nxt_bit];
    }
    return match_node ? match_node->port : -1;
}

void trie_insert(struct TrieNode * root, uint32_t ip, uint32_t prefix, int port) {
    struct TrieNode * pos = root;
    while (pos && pos->prefix < prefix) {
        int nxt_prefix = pos->prefix + 1;
        int nxt_bit = BIT_OF(ip, 32 - nxt_prefix);
        struct TrieNode * nxt = pos->children[nxt_bit];
        if (!nxt) {
            nxt = measure_malloc(sizeof(struct TrieNode));

            nxt->ip = PREFIX_OF(ip, nxt_prefix);
            nxt->prefix = nxt_prefix;
            nxt->valid = false;

            // nxt->parent = pos;
            nxt->children[0] = NULL;
            nxt->children[1] = NULL;

            pos->children[nxt_bit] = nxt;
        }
        pos = nxt;
    }
    if (pos) {
        pos->port = port;
        pos->valid = true;
    }
}

void print_trie(struct TrieNode * root) {
    if (root) {
        printf(IP_FMT "/%d:%d\n", IP_FMT_STR(root->ip), root->prefix, root->valid);
        print_trie(root->children[0]);
        print_trie(root->children[1]);
    } else {
        printf("NULL\n");
    }
}
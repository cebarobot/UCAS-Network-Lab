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
    root->match = false;
    root->port = 0;
    // root->parent = NULL:
    root->children[0] = NULL;
    root->children[1] = NULL;

    return root;
}

int trie_lookup(struct TrieNode * root, uint32_t ip) {
    struct TrieNode * match_node = NULL;
    struct TrieNode * pos = root; 
    while (pos) {
        if (pos->match && pos->ip == PREFIX_OF(ip, pos->prefix)) {
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
    struct TrieNode * nxt = root;
    int nxt_bit = 0;
    while (pos && pos->prefix < prefix) {
        nxt_bit = BIT_OF(ip, 31 - pos->prefix);
        nxt = pos->children[nxt_bit];
        if (!nxt) {
            nxt = measure_malloc(sizeof(struct TrieNode));

            int nxt_prefix = pos->prefix + 1;
            nxt->prefix = nxt_prefix;
            nxt->ip = PREFIX_OF(ip, nxt_prefix);
            nxt->match = false;
            nxt->port = 0;
            // nxt->parent = pos;
            nxt->children[0] = NULL;
            nxt->children[1] = NULL;

            pos->children[nxt_bit] = nxt;
        }
        pos = nxt;
    }
    if (pos) {
        pos->port = port;
        pos->match = true;
    }
}

// void trie_insert_compress(struct TrieNode * root, uint32_t ip, uint32_t prefix, int port) {
//     struct TrieNode * pos = root;
//     struct TrieNode * nxt = root;
//     int nxt_bit = 0;
//     do {
//         pos = nxt;
//         nxt_bit = BIT_OF(ip, 31 - pos->prefix);
//         nxt = pos->children[nxt_bit];
//     } while (nxt && nxt->prefix < prefix);

//     if (nxt && nxt->prefix == prefix) {
//         nxt->ip = ip;
//         nxt->match = true;
//         nxt->port = port;
//     } else {
//         struct TrieNode * mid = measure_malloc(sizeof(struct TrieNode));
//         pos->children[nxt_bit] = mid;
        
//         mid->match = true;
//         mid->port = port;
//         mid->prefix = prefix;
//         mid->ip = ip;

//         // mid->parent = pos;
//         mid->children[0] = NULL;
//         mid->children[1] = NULL;
//         if (nxt) {
//             nxt_bit = BIT_OF(nxt->ip, 31 - prefix);
//             mid->children[nxt_bit] = nxt;
//         }
//     }
// }

void trie_insert_compress(struct TrieNode * root, uint32_t ip, uint32_t prefix, int port) {
    if (root->prefix >= prefix) {
        return;
    }
    int new_bit = BIT_OF(ip, 31 - root->prefix);
    struct TrieNode ** sel_child = &root->children[new_bit];
    if (*sel_child) {
        int max_prefix = root->prefix;
        for (int i = max_prefix + 1; i <= prefix && i <= (*sel_child)->prefix; i++) {
            if (PREFIX_OF(ip, i) != PREFIX_OF((*sel_child)->ip, i)) {
                break;
            }
            max_prefix = i;
        }

        if (max_prefix == (*sel_child)->prefix) {
            trie_insert_compress(*sel_child, ip, prefix, port);
        } else if (max_prefix == prefix) {
            struct TrieNode * old_node = *sel_child;
            (*sel_child) = measure_malloc(sizeof(struct TrieNode));

            (*sel_child)->match = true;
            (*sel_child)->port = port;
            (*sel_child)->ip = PREFIX_OF(ip, prefix);
            (*sel_child)->prefix = prefix;
            (*sel_child)->children[0] = NULL;
            (*sel_child)->children[1] = NULL;

            int old_bit = BIT_OF(old_node->ip, 31 - prefix);
            (*sel_child)->children[old_bit] = old_node;
        } else {
            struct TrieNode * old_node = *sel_child;
            struct TrieNode * new_node = measure_malloc(sizeof(struct TrieNode));
            (*sel_child) = measure_malloc(sizeof(struct TrieNode));

            new_node->match = true;
            new_node->port = port;
            new_node->ip = PREFIX_OF(ip, prefix);
            new_node->prefix = prefix;
            new_node->children[0] = NULL;
            new_node->children[1] = NULL;

            (*sel_child)->match = false;
            (*sel_child)->port = 0;
            (*sel_child)->ip = PREFIX_OF(ip, max_prefix);
            (*sel_child)->prefix = max_prefix;

            int old_bit = BIT_OF(old_node->ip, 31 - max_prefix);
            int new_bit = BIT_OF(new_node->ip, 31 - max_prefix);
            (*sel_child)->children[old_bit] = old_node;
            (*sel_child)->children[new_bit] = new_node;
        }
    } else {
        (*sel_child) = measure_malloc(sizeof(struct TrieNode));

        (*sel_child)->match = true;
        (*sel_child)->port = port;
        (*sel_child)->ip = PREFIX_OF(ip, prefix);
        (*sel_child)->prefix = prefix;
        (*sel_child)->children[0] = NULL;
        (*sel_child)->children[1] = NULL;
    }
}

void print_trie(struct TrieNode * root) {
    if (root) {
        printf(IP_FMT "/%d:%d:%d\n", IP_FMT_STR(root->ip), root->prefix, root->match, root->port);
        print_trie(root->children[0]);
        print_trie(root->children[1]);
    } else {
        printf("NULL\n");
    }
}
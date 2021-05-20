#ifndef __TRIE_H__
#define __TRIE_H__

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

extern size_t memory_measure;

struct TrieNode {
    // struct TrieNode * parent;   // for struct changing
    struct TrieNode * children[2];

    // route info
    uint32_t ip;
    uint32_t prefix;
    bool match;
    int port;
};

struct TrieNode * trie_init();
int trie_lookup(struct TrieNode * root, uint32_t ip);
void trie_insert(struct TrieNode * root, uint32_t ip, uint32_t prefix, int port);
void trie_insert_compress(struct TrieNode * root, uint32_t ip, uint32_t prefix, int port);

void print_trie(struct TrieNode * root);

#endif
#ifndef TRIE_H
#define TRIE_H

#include <unistd.h>
#include <stdint.h>

struct trie;

struct trie *trie_create();

void trie_add(struct trie *t, struct route_table_entry *entry);

struct route_table_entry * trie_find(struct trie *t, uint32_t ip_addr);

#endif

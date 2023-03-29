#ifndef TRIE_H
#define TRIE_H

#include <unistd.h>
#include <stdint.h>

struct trie;

/* create an empty trie */
struct trie *trie_create();

/* insert an element fron the routing table in the trie */
void trie_add(struct trie *t, struct route_table_entry *entry);

/* return the entry that corresponds with the longest prefix
match of the given ip address searched*/
struct route_table_entry * trie_find(struct trie *t, uint32_t ip_addr);

#endif

#include "lib.h"

#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>


struct node
{
    struct route_table_entry *entry;
    struct node *child[1];
};

struct trie
{
    struct node *head;
};

struct trie *trie_create()
{
    struct trie *t = malloc(sizeof(struct trie));
    t->head = NULL;

    return t;
}

void trie_add(struct trie *t, struct route_table_entry *entry)
{
    if (t->head == NULL)
        t->head = malloc(sizeof(struct node *));

    struct node *curr_node = t->head;

    uint32_t mask = ntohl(entry->mask);
    uint32_t pref = ntohl(entry->prefix);
    // printf("mask=%u prefix=%u\n", mask, pref);
    int curr_bit_idx = 31;
    while ((mask >> curr_bit_idx) & 1 && curr_bit_idx) {
        int curr_bit = (pref >> curr_bit_idx) & 1;

        if(curr_node->child[curr_bit] == NULL) {
            curr_node->child[curr_bit] = malloc(sizeof(struct node *));
        }

        curr_node = curr_node->child[curr_bit];
        curr_bit_idx--;
    }

    curr_node->entry = entry;
}

struct route_table_entry * trie_find(struct trie *t, uint32_t ip_addr)
{
    struct node *curr_node = t->head;
    struct route_table_entry *entry = NULL;

    int curr_bit_idx = 31;
    while (curr_bit_idx) {
        int curr_bit = (ip_addr >> curr_bit_idx) & 1;

        if(curr_node->child[curr_bit] == NULL)
            break;

        curr_node = curr_node->child[curr_bit];
        if(curr_node->entry != NULL)
            entry = curr_node->entry;

        curr_bit_idx--;
    }

    return entry;
}

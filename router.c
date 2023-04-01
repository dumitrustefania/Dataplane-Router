#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "trie.h"
#include <arpa/inet.h>
#include <string.h>

// Constants
#define IPv4 0x0800
#define ARP 0x0806
#define ARP_REQ 1
#define ARP_REP 2
#define ICMP 1
#define MAC_SIZE 6
#define IP_SIZE 4

// Transform an IP address from dotted decimal notation (char*) to uint32_t
uint32_t get_int_ip_addr(char *ip_addr)
{
	uint8_t bytes[4];
	sscanf(ip_addr, "%hhu.%hhu.%hhu.%hhu", &bytes[0], &bytes[1], &bytes[2], &bytes[3]);

	uint32_t int_ip_addr = (bytes[0] << 24) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3];
	return int_ip_addr;
}

// Loop through all the routing table entries and add them one
// by one in the trie
struct trie *create_rtable_trie(char *rtable_path)
{
	// Populate routing table
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 80000);
	int rtable_size = read_rtable(rtable_path, rtable);

	// Create and populate trie
	struct trie *t = trie_create();
	for (int i = 0; i < rtable_size; i++)
		trie_add(t, &rtable[i]);

	return t;
}

void send_icmp_message(struct ether_header *eth_hdr, struct iphdr *ip_hdr, int type, int code, int interface, int len)
{
	// Swap ethernet physical addresses
	uint8_t *aux = malloc(MAC_SIZE);
	memcpy(aux, eth_hdr->ether_dhost, MAC_SIZE);
	memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, MAC_SIZE);
	memcpy(eth_hdr->ether_shost, aux, MAC_SIZE);

	// Save old IP header and its next 64 bits of payload
	struct iphdr *old_ip_hdr_and_bits = malloc(sizeof(struct iphdr) + 64);
	memcpy(old_ip_hdr_and_bits, ip_hdr, sizeof(struct iphdr) + 64);

	// Swap ip addresses
	uint32_t aux2 = ip_hdr->saddr;
	ip_hdr->saddr = ip_hdr->daddr;
	ip_hdr->daddr = aux2;
	// Set ip protocol to ICMP
	ip_hdr->protocol = ICMP;

	// Create the new packet
	char package[MAX_PACKET_LEN];
	memcpy(package, eth_hdr, sizeof(struct ether_header));

	// If ICMP type is time exceeded or dest unreachable
	if (type)
	{
		// Recompute IP len and checksum
		ip_hdr->tot_len = htons(2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 64);
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
		memcpy(package + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));

		// Create ICMP header structure with given type and code
		struct icmphdr *icmp_hdr = malloc(sizeof(struct icmphdr));
		icmp_hdr->type = type;
		icmp_hdr->code = code;
		icmp_hdr->checksum = 0;
		icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

		// Copy the new ICMP header
		memcpy(package + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));
		len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

		// Copy the old ip header and the next 64 bits of payload
		memcpy(package + len, old_ip_hdr_and_bits, sizeof(struct iphdr) + 64);
		len += sizeof(struct iphdr) + 64;
	}
	else
	{ // Recompute len and checksum
		ip_hdr->tot_len = htons(len - sizeof(struct ether_header));
		ip_hdr->check = 0;
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
		memcpy(package + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));

		// Modify icmp header structure with given type and code
		struct icmphdr *icmp_hdr = (struct icmphdr *)(ip_hdr + sizeof(struct iphdr));
		icmp_hdr->type = type;
		icmp_hdr->code = code;
		icmp_hdr->checksum = 0;
		icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

		// Copy the ICMP header and whatever was after it
		memcpy(package + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, len - sizeof(struct ether_header) - sizeof(struct iphdr));
	}

	send_to_link(interface, package, len);
}

void send_arp(uint8_t *mac_src, uint8_t *mac_dst, uint32_t ip_src, uint32_t ip_dst, int interface, int type)
{ // Create eth header structure and populate it
	struct ether_header *eth_hdr = malloc(sizeof(struct ether_header));
	memcpy(eth_hdr->ether_shost, mac_src, MAC_SIZE);
	memcpy(eth_hdr->ether_dhost, mac_dst, MAC_SIZE);
	eth_hdr->ether_type = htons(ARP);

	// Create arp header structure and populate it
	struct arp_header *arp_hdr = malloc(sizeof(struct arp_header));
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(IPv4);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(type);
	memcpy(arp_hdr->sha, mac_src, MAC_SIZE);
	memcpy(arp_hdr->tha, mac_dst, MAC_SIZE);
	arp_hdr->spa = ip_src;
	arp_hdr->tpa = ip_dst;

	// Create the new package and send it
	char package[MAX_PACKET_LEN];
	memcpy(package, eth_hdr, sizeof(struct ether_header));
	memcpy(package + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));

	send_to_link(interface, package, sizeof(struct ether_header) + sizeof(struct arp_header));
}

// Structure that stores the important elements of the current packet in a queue
struct queue_entry
{
	char *buf;
	int buf_len;
	struct route_table_entry *rtable_entry;
};

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Create the routing table trie
	struct trie *t = create_rtable_trie(argv[1]);

	// Create an empty ARP table structure
	struct arp_entry *arptable = malloc(sizeof(struct arp_entry) * 100);
	int arptable_size = 0;

	// Create the queue
	queue q = queue_create();

	while (1)
	{
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		// Exctract the ethernet header from the buffer
		struct ether_header *eth_hdr = (struct ether_header *)buf;

		// Determine the interface IP
		uint32_t interface_ip = get_int_ip_addr(get_interface_ip(interface));

		// If received packet is IPv4 packet
		if (ntohs(eth_hdr->ether_type) == IPv4)
		{ // Exctract the IP header from the buffer
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			// Check if packet destination is this router
			if (ntohl(ip_hdr->daddr) == interface_ip)
			{ // Send back ICMP message type 0 code 0 - ping reply
				send_icmp_message(eth_hdr, ip_hdr, 0, 0, interface, len);
				continue;
			}

			// Compute checksum and throw packet if it is wrong
			int check = ntohs(ip_hdr->check);
			ip_hdr->check = 0;
			if (check != checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)))
				continue;

			// Check if ttl expired (ttl < 2)
			if (ip_hdr->ttl == 0 || ip_hdr->ttl == 1)
			{ // Send back ICMP message type 11 code 0 - time exceeded
				send_icmp_message(eth_hdr, ip_hdr, 11, 0, interface, len);
				continue;
			}

			// Find an entry in the routing table to determine the next hop
			struct route_table_entry *rtable_entry = trie_find(t, ntohl(ip_hdr->daddr));

			// Check if the entry was found
			if (rtable_entry == NULL)
			{
				// Send back ICMP message type 3 code 0 - destination unreachable
				send_icmp_message(eth_hdr, ip_hdr, 3, 0, interface, len);
				continue;
			}

			// Descrease TTL and recompute checksum
			ip_hdr->ttl--;
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

			// Determine the interface MAC
			uint8_t *interface_mac = malloc(MAC_SIZE);
			get_interface_mac(rtable_entry->interface, interface_mac);

			// Set source MAC to sender interface MAC
			memcpy(eth_hdr->ether_shost, interface_mac, MAC_SIZE);

			// Search the ARP table for the next hop ip address
			int found_mac = 0;
			for (int i = 0; i < arptable_size; i++)
				if (arptable[i].ip == rtable_entry->next_hop)
				{
					// If the entry is present, set destination MAC to the entry found
					found_mac = 1;
					memcpy(eth_hdr->ether_dhost, arptable[i].mac, MAC_SIZE);
					break;
				}

			// If the ARP table doesn't contain the next hop, send ARP request
			if (!found_mac)
			{ // Create a new queue entry structure and populate it with data
				// about the current packet (buffer, its length, routing table entry found)
				struct queue_entry *q_entry = malloc(sizeof(struct queue_entry));
				q_entry->buf = malloc(len);
				memcpy(q_entry->buf, buf, len);
				q_entry->rtable_entry = rtable_entry;
				q_entry->buf_len = len;
				queue_enq(q, (void *)q_entry);

				// Set broadcast MAC to 0xffffffffffff
				uint8_t *broadcast = malloc(MAC_SIZE);
				for (int i = 0; i < MAC_SIZE; i++)
					broadcast[i] = 0xff;

				// Determine the new interface IP
				interface_ip = get_int_ip_addr(get_interface_ip(rtable_entry->interface));

				// Send ARP request
				send_arp(interface_mac, broadcast, htonl(interface_ip),
						 rtable_entry->next_hop, rtable_entry->interface, ARP_REQ);
				continue;
			}
			else
				send_to_link(rtable_entry->interface, buf, len);
		}

		// If received packet is ARP packet
		else if (ntohs(eth_hdr->ether_type) == ARP)
		{ // Extract the ARP header from the buffer
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

			// Determine the MAC of the current interface
			uint8_t *interface_mac = malloc(MAC_SIZE);
			get_interface_mac(interface, interface_mac);

			// If the router received an ARP REQUEST, send an ARP REPLY
			if (ntohs(arp_hdr->op) == ARP_REQ)
			{ // Check if the router is the final destination
				if (ntohl(arp_hdr->tpa) == interface_ip)
					send_arp(interface_mac, eth_hdr->ether_shost, arp_hdr->tpa, arp_hdr->spa, interface, ARP_REP);
				else
					continue;
			}
			// If the router received an ARP REPLY, store its response
			// and send certain IP packets stored
			else if (ntohs(arp_hdr->op) == ARP_REP)
			{ // Store the ARP reply in the ARP table
				arptable[arptable_size].ip = arp_hdr->spa;
				memcpy(arptable[arptable_size].mac, arp_hdr->sha, MAC_SIZE);
				arptable_size++;

				queue aux_q = queue_create();
				while (!queue_empty(q))
				{ // Extract the buffer from the queue
					struct queue_entry *q_entry = (struct queue_entry *)queue_deq(q);
					// Extract the ethernet header from the queue
					struct ether_header *q_eth_hdr = (struct ether_header *)(q_entry->buf);

					// If the current packet was waiting for this reply, send it now
					if (q_entry->rtable_entry->next_hop == arp_hdr->spa)
					{ // Set the destination MAC to the one received
						memcpy(q_eth_hdr->ether_dhost, arp_hdr->sha, MAC_SIZE);
						// Send the packet
						send_to_link(q_entry->rtable_entry->interface, q_entry->buf, q_entry->buf_len);
					}
					else // Keep the packet in the queue and keep waiting
						queue_enq(aux_q, q_entry);
				}
				q = aux_q;
			}
		}
	}
}

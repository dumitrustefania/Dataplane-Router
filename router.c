#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "trie.h"
#include <arpa/inet.h>
#include <string.h>

#define IPv4 0x0800
#define ARP 0x0806
#define ARP_REQ 1
#define ARP_REP 2
#define ICMP 1
#define MAC_SIZE 6
#define IP_SIZE 4

char *get_dotted_ip_addr(uint32_t ip_addr)
{
	char *dotted_ip_addr = malloc(16);
	uint8_t bytes[4];

	bytes[0] = (ip_addr >> 24) & 0xFF;
	bytes[1] = (ip_addr >> 16) & 0xFF;
	bytes[2] = (ip_addr >> 8) & 0xFF;
	bytes[3] = ip_addr & 0xFF;

	sprintf(dotted_ip_addr, "%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
	return dotted_ip_addr;
}

uint32_t get_int_ip_addr(char *ip_addr)
{
	uint8_t bytes[4];
	sscanf(ip_addr, "%hhu.%hhu.%hhu.%hhu", &bytes[0], &bytes[1], &bytes[2], &bytes[3]);

	uint32_t int_ip_addr = (bytes[0] << 24) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3];
	return int_ip_addr;
}

struct trie *create_rtable_trie(char *rtable_path)
{
	// populate routing table
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 80000);
	int rtable_size = read_rtable(rtable_path, rtable);

	struct trie *t = trie_create();

	for (int i = 0; i < rtable_size; i++)
		trie_add(t, &rtable[i]);

	return t;
}
void print_mac(uint8_t *mac)
{
	for (int i = 0; i < 6; i++)
		printf("%x:", mac[i]);
	printf("\n");
}
void send_icmp_message(struct ether_header *eth_hdr, struct iphdr *ip_hdr, int type, int code, int interface)
{	printf("Trimit ICMP\n");
	for (int i = 0; i < 6; i++)
	{
		uint8_t aux = eth_hdr->ether_dhost[i];
		eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
		eth_hdr->ether_shost[i] = aux;
	}

	uint32_t aux = ip_hdr->saddr;
	ip_hdr->saddr = ip_hdr->daddr;
	ip_hdr->daddr = aux;
	ip_hdr->protocol = ICMP;
	ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	struct icmphdr *icmp_hdr = malloc(sizeof(struct icmphdr));
	icmp_hdr->type = type;
	icmp_hdr->code = code;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

	char package[MAX_PACKET_LEN];
	memcpy(package, eth_hdr, sizeof(struct ether_header));
	memcpy(package + sizeof(struct ether_header), ip_hdr, sizeof(struct iphdr));
	memcpy(package + sizeof(struct ether_header) + sizeof(struct iphdr), icmp_hdr, sizeof(struct icmphdr));

	send_to_link(interface, package, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr));
}

void send_arp(uint8_t *mac_src, uint8_t *mac_dst, uint32_t ip_src, uint32_t ip_dst, int interface, int type)
{	printf("Trimit ARP de tip %d (req=1, rep=2)\n", type);

	struct ether_header *eth_hdr = malloc(sizeof(struct ether_header));
	memcpy(eth_hdr->ether_shost, mac_src, MAC_SIZE);
	memcpy(eth_hdr->ether_dhost, mac_dst, MAC_SIZE);
	eth_hdr->ether_type = htons(ARP);

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

	printf("Acest ARP va fi trimis cu IP_SRC %s, IP_DST %s, MAC_SRC ", get_dotted_ip_addr(ip_src), get_dotted_ip_addr(ip_dst));
	print_mac(mac_src);
	printf("si MAC_DST");
	print_mac(mac_dst);

	char package[MAX_PACKET_LEN];
	memcpy(package, eth_hdr, sizeof(struct ether_header));
	memcpy(package + sizeof(struct ether_header), arp_hdr, sizeof(struct arp_header));
	send_to_link(interface, package, sizeof(struct ether_header) + sizeof(struct arp_header));
}
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

	// create_rtable_trie
	struct trie *t = create_rtable_trie(argv[1]);

	struct arp_entry *arptable = malloc(sizeof(struct arp_entry) * 100);
	int arptable_size = 0;

	queue q = queue_create();

	while (1)
	{
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		printf("\n----------------------------\nPachet primit pe interfata %d\n", interface);

		// ip ul de pe interfara routerului unde s a primit pachetul
		char *interface_ip = get_interface_ip(interface);
		// macul de pe interfata routerului unde s a primit pachetul
		uint8_t *interface_mac = malloc(MAC_SIZE);
		get_interface_mac(interface, interface_mac);
		printf("IP interfata = %s, MAC interfata = ", interface_ip);
		print_mac(interface_mac);

		if (ntohs(eth_hdr->ether_type) == IPv4)
		{	
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));
			printf("E pachet IP cu id %u\n", ip_hdr->id);
			// verific daca destinatia cautata e routerul
			if (ntohl(ip_hdr->daddr) == get_int_ip_addr(interface_ip))
			{
				printf("destinatia e chiar routerul\n");
				send_icmp_message(eth_hdr, ip_hdr, 0, 0, interface);
				continue;
			}

			// compute checksum and check
			int check = ntohs(ip_hdr->check);
			ip_hdr->check = 0;

			if (check != checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)))
			{
				printf("suma e gresita!\n");
				continue;
			}

			// verific ttl
			if (ip_hdr->ttl == 0 || ip_hdr->ttl == 1)
			{
				printf("ttl expirat\n");
				send_icmp_message(eth_hdr, ip_hdr, 11, 0, interface);
				continue;
			}

			// find entry corresponding to next hop
			struct route_table_entry *rtable_entry = trie_find(t, ntohl(ip_hdr->daddr));

			if (rtable_entry == NULL)
			{
				printf("nu are destinatar\n");
				send_icmp_message(eth_hdr, ip_hdr, 3, 0, interface);
				continue;
			}

			// descrease ttl and recompute checksum
			ip_hdr->ttl--;
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

			// rescrie mac
			memcpy(eth_hdr->ether_shost, interface_mac, MAC_SIZE);

			int found_mac = 0;
			for (int i = 0; i < arptable_size; i++)
			{
				if (arptable[i].ip == rtable_entry->next_hop)
				{	printf("Am gasit MAC in arptable pt IP %s:", get_dotted_ip_addr(ntohl(rtable_entry->next_hop)));
					print_mac(arptable[i].mac);

					found_mac = 1;
					memcpy(eth_hdr->ether_dhost, arptable[i].mac, MAC_SIZE);
					break;
				}
			}

			if (!found_mac)
			{	printf("Nu am gasit MAC in arptable pt IP %s\n", get_dotted_ip_addr(ntohl(rtable_entry->next_hop)));
				
				struct queue_entry *q_entry = malloc(sizeof(struct queue_entry));
				q_entry->buf = malloc(len);
				memcpy(q_entry->buf, buf, len);
				q_entry->rtable_entry = rtable_entry;
				q_entry->buf_len = len;
				queue_enq(q, (void *)q_entry);

				printf("Am bagat in coada pachetul curent cu id %u\n", ip_hdr->id);

				uint8_t *broadcast = malloc(MAC_SIZE);
				for (int i = 0; i < MAC_SIZE; i++)
					broadcast[i] = 0xff;

				send_arp(interface_mac, broadcast, htonl(get_int_ip_addr(interface_ip)),
						 rtable_entry->next_hop, rtable_entry->interface, ARP_REQ);
				continue;
			}
			else
			{	printf("Trimit pachetul pe interfata %d\n", rtable_entry->interface);
				send_to_link(rtable_entry->interface, buf, len);
			}
		}

		else if (ntohs(eth_hdr->ether_type) == ARP)
		{	
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));
			printf("E pachet ARP ");
			if (ntohs(arp_hdr->op) == ARP_REQ)
			{	printf("request cu IP_SRC %s, IP_DST %s\n", get_dotted_ip_addr(arp_hdr->spa), get_dotted_ip_addr(arp_hdr->tpa));
				// eu sunt destinatarul arp req
				if (ntohl(arp_hdr->tpa) == get_int_ip_addr(interface_ip))
					send_arp(interface_mac, eth_hdr->ether_shost, arp_hdr->tpa, arp_hdr->spa, interface, ARP_REP);
			}
			else if (ntohs(arp_hdr->op) == ARP_REP)
			{					
				printf("reply cu IP_SRC %s, IP_DST %s\n", get_dotted_ip_addr(arp_hdr->spa), get_dotted_ip_addr(arp_hdr->tpa));
				// if (ntohl(arp_hdr->tpa) != get_int_ip_addr(interface_ip)) {
				// 	printf("HOPA! Nu eu sunt destinatia\n");
				// 	continue;
				// }
				arptable[arptable_size].ip = arp_hdr->spa;
				memcpy(arptable[arptable_size].mac, arp_hdr->sha, MAC_SIZE);
				arptable_size++;

				printf("Am adaugat in ARP table intrarea, acum arata asa:\n");
				for(int i= 0 ;i < arptable_size;i++) {
					printf("%s - ", get_dotted_ip_addr(arptable[i].ip));
					print_mac(arptable[i].mac);
				}

				queue aux_q = queue_create();
				while (!queue_empty(q))
				{	
					struct queue_entry *q_entry = (struct queue_entry *)queue_deq(q);
					struct ether_header *q_eth_hdr = (struct ether_header *)(q_entry->buf);
					struct iphdr *q_ip_hdr = (struct iphdr *)(q_entry->buf + sizeof(struct ether_header));
					printf("Am scos din coada pachetul de tip %x, cu id %d. El astepta ca next hop IP-ul %s\n",
							q_eth_hdr->ether_type, q_ip_hdr->id, get_dotted_ip_addr(q_entry->rtable_entry->next_hop));
					
					if (q_entry->rtable_entry->next_hop == arp_hdr->spa)
					{	
							memcpy(q_eth_hdr->ether_dhost, arp_hdr->sha, MAC_SIZE);

							printf("Acum sursa si destinatia mac a pachetului sunt:");
							print_mac(q_eth_hdr->ether_shost);
							print_mac(q_eth_hdr->ether_dhost);

							printf("Acum trimit pachetul pe interfata %d\n", q_entry->rtable_entry->interface);
							send_to_link(q_entry->rtable_entry->interface, q_entry->buf, q_entry->buf_len);
						
					}
					else
						queue_enq(aux_q, q_entry);
				}
				q = aux_q;
			}
		}
	}
}

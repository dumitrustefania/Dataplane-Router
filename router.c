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

void send_icmp_message(struct ether_header *eth_hdr, struct iphdr *ip_hdr, int type, int code, int interface)
{
	for (int i = 0; i < 6; i++)
	{
		uint8_t aux = eth_hdr->ether_dhost[i];
		eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
		eth_hdr->ether_shost[i] = aux;
	}

	uint32_t aux = ip_hdr->saddr;
	ip_hdr->saddr = ip_hdr->daddr;
	ip_hdr->daddr = aux;
	ip_hdr->protocol = 1;
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

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// create_rtable_trie
	struct trie *t = create_rtable_trie(argv[1]);

	while (1)
	{
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *)buf;
		printf("interfata recv=%d, ethertype=%x\n", interface, ntohs(eth_hdr->ether_type));
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		// ip ul de pe interfara routerului unde s a primit pachetul
		char *interface_ip = get_interface_ip(interface);
		// macul de pe interfata routerului unde s a primit pachetul
		uint8_t *interface_mac = malloc(6);
		get_interface_mac(interface, interface_mac);

		if (ntohs(eth_hdr->ether_type) == IPv4)
		{
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			// transformam ip dest din nr pe 32 de biti in format dotted
			char *dotted_ip_addr_dest = get_dotted_ip_addr(ntohl(ip_hdr->daddr));

			// verific daca destinatia cautat e routerul
			// todo icmp
			if (!strcmp(dotted_ip_addr_dest, interface_ip))
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
			struct route_table_entry *entry = trie_find(t, ntohl(ip_hdr->daddr));
			// printf("id=%s prefix=%s mask=%s hop=%s interf=%d\n",
			// 	   get_dotted_ip_addr(ntohl(ip_hdr->daddr)),
			// 	   get_dotted_ip_addr(ntohl(entry->prefix)),
			// 	   get_dotted_ip_addr(ntohl(entry->mask)),
			// 	   get_dotted_ip_addr(ntohl(entry->next_hop)),
			// 	   entry->interface);

			if (entry == NULL)
			{
				printf("nu are destinatar\n");
				send_icmp_message(eth_hdr, ip_hdr, 3, 0, interface);
				continue;
			}

			// descrease ttl and recompute checksum
			ip_hdr->ttl--;
			ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

			// rescrie mac

			for (int i = 0; i < 6; i++)
			{
				eth_hdr->ether_shost[i] = interface_mac[i];
				printf("%x ", interface_mac[i]);
			}
			printf("\n");

			struct arp_entry *arptable = malloc(sizeof(struct arp_entry) * 100);
			int arptable_size = parse_arp_table("arp_table.txt", arptable);

			for (int i = 0; i < arptable_size; i++)
			{
				if ((arptable[i]).ip == entry->next_hop)
				{
					for (int j = 0; j < 6; j++)
					{
						printf("%x ", (arptable[i]).mac[j]);
						eth_hdr->ether_dhost[j] = (arptable[i]).mac[j];
					}
					printf("\n");
					break;
				}
			}

			char package[MAX_PACKET_LEN];
			memcpy(package, eth_hdr, sizeof(struct ether_header));
			memcpy(package + sizeof(struct ether_header), ip_hdr, len - sizeof(struct ether_header));

			send_to_link(entry->interface, package, len);
		}

		// else if (ntohs(eth_hdr->ether_type) == ARP)
		// {
		// 	struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

		// 	if (ntohs(arp_hdr->op) == ARP_REQ)
		// 	{	printf("e arp request\n");

		// 		char *dotted_ip_addr_dest = get_dotted_ip_addr(ntohl(arp_hdr->tpa));
		// 		printf("arp dest=%s my ip=%s\n", dotted_ip_addr_dest, interface_ip);
		// 		if(!strcmp(dotted_ip_addr_dest, interface_ip)) {
		// 			printf("eu sunt destinatia\n");

		// 			for (int i = 0; i < 6; i++) {
		// 				eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
		// 				arp_hdr->tha[i] = eth_hdr->ether_shost[i];
		// 			}

		// 			for (int i = 0; i < 6; i++) {
		// 				eth_hdr->ether_shost[i] = interface_mac[i];
		// 				arp_hdr->sha[i] = eth_hdr->ether_shost[i];
		// 			}

		// 			arp_hdr->op = htons(ARP_REP);

		// 			uint32_t aux = arp_hdr->tpa;
		// 			arp_hdr->tpa = arp_hdr->spa;
		// 			arp_hdr->spa = aux;

		// 			char package[MAX_PACKET_LEN];
		// 			memcpy(package, eth_hdr, sizeof(struct ether_header));
		// 			memcpy(package + sizeof(struct ether_header), arp_hdr, len - sizeof(struct ether_header));

		// 			int res = send_to_link(interface, buf, len);
		// 		}
		// 		else {
		// 			printf("nu eu sunt destinatia\n");
		// 		}
		// 	}
		// 	else {
		// 		printf("e arp reply\n");
		// 	}
		// }
	}
}

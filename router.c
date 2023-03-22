#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include "trie.h"
#include <arpa/inet.h>
#include <string.h>

#define IPv4 0x0800
#define ARP 0x0806

char *get_dotted_ip_addr(uint32_t ip_addr)
{
	char *dotted_ip_addr = malloc(16);
	uint8_t bytes[4];

	bytes[0] = (ip_addr >> 24) & 0xFF;
	bytes[1] = (ip_addr >> 16) & 0xFF;
	bytes[2] = (ip_addr >> 8) & 0xFF;
	bytes[3] = ip_addr & 0xFF;

	sprintf(dotted_ip_addr, "%d.%d.%d.%d\n", bytes[0], bytes[1], bytes[2], bytes[3]);
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

		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		if (ntohs(eth_hdr->ether_type) == IPv4)
		{
			struct iphdr *ip_hdr = (struct iphdr *)(buf + sizeof(struct ether_header));

			// ip ul de pe interfara routerului unde s a primit pachetul
			char *interface_ip = get_interface_ip(interface);

			// transformam ip dest din nr pe 32 de biti in format dotted
			char *dotted_ip_addr_dest = get_dotted_ip_addr(ntohl(ip_hdr->daddr));

			// verific daca destinatia cautat e routerul
			// todo icmp
			if (!strcmp(dotted_ip_addr_dest, interface_ip))
			{
				printf("destinatia e chiar routerul\n");
				continue;
			}

			// compute checksum and check
			int check = ntohs(ip_hdr->check);
			ip_hdr->check = 0;

			if (check != checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)))
			{
				printf("suma e gresita!\n");
				break;
			}

			// verific ttl
			if (ip_hdr->ttl == 0 || ip_hdr->ttl == 1)
			{
				printf("ttl expirat\n");
				break;
			}

			// find entry corresponding to next hop
			struct route_table_entry *entry = trie_find(t, ntohl(ip_hdr->daddr));
			printf("id=%s prefix=%s mask=%s hop=%s interf=%d\n",
				   get_dotted_ip_addr(ntohl(ip_hdr->daddr)),
				   get_dotted_ip_addr(ntohl(entry->prefix)),
				   get_dotted_ip_addr(ntohl(entry->mask)),
				   get_dotted_ip_addr(ntohl(entry->next_hop)),
				   entry->interface);

			if (entry == NULL)
			{
				printf("nu are destinatar");
				break;
			}

			// descrease ttl and recompute checksum
			ip_hdr->ttl--;
			ip_hdr->check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));

			// rescrie mac
			uint8_t *router_mac = malloc(6);
			get_interface_mac(interface, router_mac);
			for (int i = 0; i < 6; i++)
			{
				eth_hdr->ether_shost[i] = router_mac[i];
				// printf("%d ", router_mac[i]);
			}
			// printf("\n");

			struct arp_entry *arptable = malloc(sizeof(struct arp_entry) * 100);
			int arptable_size = parse_arp_table("arp_table.txt", arptable);
			for (int i = 0; i < arptable_size; i++)
			{
				if ((arptable[i]).ip == entry->next_hop)
				{
					for (int j = 0; j < 6; j++)
					{
						// printf("%d ", (arptable[i]).mac[j]);
						eth_hdr->ether_dhost[j] = (arptable[i]).mac[j];
					}
					// printf("\n");
					break;
				}
			}
			
			// printf("hdrsize=%ld ipsize=%ld totalip=%d payloadip=%ld\n", sizeof(struct ether_header), sizeof(struct iphdr),
			// 			ip_hdr->tot_len, ip_hdr->tot_len - sizeof(struct iphdr));
			// char package[MAX_PACKET_LEN];
			strncpy(buf, (char *)eth_hdr, sizeof(struct ether_header));
			strncpy(buf + sizeof(struct ether_header), (char *)ip_hdr, sizeof(struct iphdr));
			// strncat(package, buf + sizeof(struct ether_header) + sizeof(struct iphdr), ip_hdr->tot_len - sizeof(struct iphdr));
			printf("len=%ld\n", len);
			int res = send_to_link(entry->interface, buf, len);
		}
	}
}

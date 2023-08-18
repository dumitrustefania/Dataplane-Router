# DATAPLANE ROUTER

March 2023
----------------------------------------------------------------------------------------------------
## Introduction

* Dataplane router
  *  The program implements a dataplane router in Linux.
  * The main purpose is to route IP packets between hosts.
  * The router also implements sending ICMP packets when necessary.
  * Determination of neighbor MAC addresses is done using the ARP protocol.

## How it works?

### Initialization

During initialization, the router allocates memory for the ARP table to be populated and creates the trie that ensures efficient longest prefix match lookup with a given IP in the routing table.

### Reception

A packet is received on one of the router's interfaces. The Ethernet header of the received packet is extracted, and the respective interface's IP is determined. It is checked whether the packet uses the IPv4 protocol or ARP.

### IPv4 Protocol

The router extracts the IP header of the packet and performs certain checks:
* If the router is the intended recipient of the packet, an ICMP echo reply packet is sent back.
The checksum is verified. If the packet is corrupted, the router discards it.
* It is checked whether TTL > 2. If not, an ICMP time exceeded packet is sent back.
After these checks, the router determines the next hop to the destination. This is achieved by querying the previously created trie, which returns the correct entry from the routing table. If no matching entry for the given destination exists, the router sends an ICMP destination unreachable packet.

The TTL is then decremented, and the checksum is recalculated. In the Ethernet header, the source MAC is set to the interface's MAC where the packet is to be sent.

The router looks up the MAC of the next hop in the local ARP table. If it is already there, the packet is successfully forwarded. Otherwise, the packet is added to a queue to be revisited later, and the router performs an ARP request to determine the MAC address of the next hop.

### ARP Protocol

When it is determined that the received packet follows the ARP protocol, the ARP header is extracted from the buffer, and it is checked whether the packet is an ARP request or ARP reply.

In the case of an ARP request, the router checks if it is the intended recipient and sends a reply, notifying the sender of its MAC address.

In the case of an ARP reply, the router receives a response to a previously made request within the processing of IPv4 packets. The received ARP reply is stored in the local ARP table, and the queue is traversed, searching for all IPv4 packets that were waiting for this reply. Those packets are now forwarded.

### ICMP Protocol

ICMP packets consist of Ethernet, IP, and ICMP headers.

### Resources

Networking tutorial - https://youtube.com/playlist?list=PLowKtXNTBypH19whXTVoG3oKSuOcw_XeW






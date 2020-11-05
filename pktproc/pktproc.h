#pragma once

#include <iostream>
#include <stdio.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <bitset>
#include <string.h>
#include "structs.h"



char* tomac(void* mac);
char* toip(const uint32_t* ip);
const char* toip6(const in6_addr* ip, char* buf);




namespace protocols {
    void UDP(uint8_t* buf);
    void TCP(uint8_t* buf, const ip_hdr* iphdr);
    void TCP(uint8_t* buf, const ip6_hdr* iphdr);
    void ICMP(uint8_t* buf, const ip_hdr* iphdr);
    void ICMP(uint8_t* buf, const ip6_hdr* iphdr);
    void IPv4(uint8_t* buf);
    void IPv6(uint8_t* buf);
    void ARP(uint8_t* buf);
    void EtherII(uint8_t* buf);
}
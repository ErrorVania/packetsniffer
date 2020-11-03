#pragma once
#include <iostream>


struct eth_hdr
{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t ethertype;
    uint8_t payload[];
};

struct arp_hdr {
    uint16_t htype;
    uint16_t ptype;
    
    uint8_t hlen;
    uint8_t plen;

    uint16_t oper;
    uint8_t senderhardwareaddr[6];
    uint8_t senderprotoaddr[4];

    uint8_t targethardwareaddr[6];
    uint8_t targetprotoaddr[4];

};

struct ip_hdr {
#if (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
	uint8_t ihl : 4,
		version : 4;

#elif (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
	uint8_t version : 4,
		    ihl : 4;
#else
#error "fix endianness defines"
#endif
	uint8_t tos;
	uint16_t total_len, ident;
	uint16_t flag_frag;
	uint8_t ttl, proto;
	uint16_t header_chksum;
	uint32_t src, dst;
};
struct ip6_hdr {
    uint32_t version : 4,
       traffic_class : 8,
          flow_label : 20;

    uint16_t length;
    uint8_t next_header;
    uint8_t ttl;
    in6_addr src, dst;
};



struct udp_hdr {
    uint16_t srcport;
    uint16_t dstport;
    uint16_t length;
    uint16_t chksum;
    uint8_t payload[];
};

struct tcp_hdr {
    uint16_t src_port, dst_port;
    uint32_t seq, ack;
    uint8_t data_offset, flags;
    uint16_t window_size, chksum, urgentptr;
};

struct icmp_hdr {
    uint8_t type, code;
    uint16_t chksum;
    uint32_t rest;
};
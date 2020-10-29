#pragma once
#include <iostream>
#include "endianness.h"


struct eth_hdr
{
    unsigned char dmac[6];
    unsigned char smac[6];
    uint16_t ethertype;
    unsigned char payload[];
};

struct udp_hdr {
    uint16_t srcport;
    uint16_t dstport;
    uint16_t length;
    uint16_t chksum;
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
#ifdef LITTLEENDIAN
	uint8_t ihl : 4,
		version : 4;

#elif defined(BIGENDIAN)
	uint8_t version : 4,
		ihl : 4;
#endif

	uint8_t tos;

	uint16_t total_len, ident;

	uint16_t flag_frag;


	uint8_t ttl, proto;

	uint16_t header_chksum;
	uint32_t src, dst;
};

struct tcp_hdr { //needs work!
    uint16_t srcport, dstport;
    uint32_t seq, ack_num;
    uint8_t size; //in 32-bit words
    uint8_t flags;


    uint16_t window_size, chksum, urgent_ptr;

};

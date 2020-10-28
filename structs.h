#pragma once
#include <iostream>



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
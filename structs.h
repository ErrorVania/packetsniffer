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
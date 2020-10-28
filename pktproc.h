#pragma once

#include <iostream>
#include <stdio.h>
#include <inttypes.h>
#include <limits.h>
#include <iomanip>
#include <string.h>
#include <ostream>
#include "netincl.h"
#include "structs.h"
#include "protos.h"
using namespace std;



char* tomac(const uint8_t* mac)
{
    ether_addr ea;
    memcpy(ea.ether_addr_octet,mac,6);
    return ether_ntoa(&ea);
}
char* toip(const uint32_t* ip) {
    in_addr i;
    memcpy(&i.s_addr,ip,32/8);
    return inet_ntoa(i);
}




namespace protocols {

    void IPv4(uint8_t* buf) {

        ip_hdr* iphdr = (ip_hdr*)buf;
        cout << " IPv4 " << toip(&iphdr->src) << "->" << toip(&iphdr->dst) << " proto:" << (int)iphdr->proto;

    }


    void ARP(uint8_t* buf) {
        arp_hdr* arphdr = (arp_hdr*)buf;
        //cout << " ARP " << htons(arphdr->htype) << " " << htons(arphdr->oper);
        cout << " ARP ";
        if (htons(arphdr->htype) == 1)
            cout << "Ethernet ";
        if (htons(arphdr->oper) == 1)
            cout << "Request";
        else
            cout << "Reply";

        cout << " SPA:" << toip((uint32_t*)&arphdr->senderprotoaddr);
    }


    void EtherII(uint8_t* buf) {
        eth_hdr* ethernet_header = (eth_hdr*)buf;
        uint16_t ethtype = ntohs(ethernet_header->ethertype);
        cout << "EtherII " << tomac(ethernet_header->smac) << "->" << tomac(ethernet_header->dmac);

        if (ethtype <= 1500) { //ethtype is size
            return;
        }


        if (ethtype >= 1536) { //ethtype is proto
            if (ethtype == ETHERTYPE_IP) {
                IPv4((uint8_t*)&ethernet_header->payload);
            }
            if (ethtype == ETHERTYPE_ARP) {
                ARP((uint8_t*)&ethernet_header->payload);
            }
        }
        cout << endl;
    
    
    }
}
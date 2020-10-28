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

using namespace std;



char* tomac(const uint8_t* mac)
{
    ether_addr ea;
    memcpy(ea.ether_addr_octet,mac,6);
    return ether_ntoa(&ea);
}


void procpkt(uint8_t* buf,int siz) {
    eth_hdr* ethernet_header = (eth_hdr*)buf;
    uint16_t ethtype = ntohs(ethernet_header->ethertype);
    if (ethtype <= 1500) { //ethtype is size
        cout << "EtherSize: " << ethtype << endl;
    } else if (ethtype >= 1536) { //ethtype is proto
        cout << "EtherType: " << ethtype << endl;
    }
    
    
}
#pragma once


#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <iostream>


//writes and returns index of interface into ifstr
int getIfaceIndex(int sock, const char* ifacename, ifreq* ifstr) {
    strncpy(ifstr->ifr_ifrn.ifrn_name,ifacename,IFNAMSIZ-1);

    if (ioctl(sock,SIOCGIFINDEX,ifstr) == -1) {
        std::cerr << "IOCTL could not get interface index of " << ifacename << ": " << strerror(errno) << " (" << errno << ")" << std::endl;
        exit(1);
    }
    return ifstr->ifr_ifru.ifru_ivalue;
}
void getIfaceFlags(int sock, ifreq* ifstr) {
    if (ioctl(sock,SIOCGIFFLAGS,ifstr) == -1) {
        std::cerr << "IOCTL could not get interface flags: " << strerror(errno) << " (" << errno << ")" << std::endl;
        exit(1);
    }
}
void setIfaceFlags(int sock, ifreq* ifstr) {
    if (ioctl(sock,SIOCSIFFLAGS,ifstr) == -1) {
        std::cerr << "IOCTL could not set interface flags: " << strerror(errno) << " (" << errno << ")" << std::endl;
        exit(1);
    }
}

void BindToInterface(int sock, ushort fam, ushort proto, int idex) {
    sockaddr_ll sll;
    sll.sll_family = fam;
    sll.sll_protocol = proto;
    sll.sll_ifindex = idex;
    if (bind(sock,(sockaddr*)&sll,sizeof(sll)) == -1) {
        std::cerr << "Could not bind socket to interface: " << strerror(errno) << " (" << errno << ")" << std::endl;
        exit(1);
    }
}
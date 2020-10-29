#include <iostream>
#include <cstdlib>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <fstream>
#include "pcapmaker.h"
#include "pktproc.h"
#include "netincl.h"
#include "pcapmaker.h"


using namespace std;

void err(const char* extra) {
    cerr << errno << " " << strerror(errno) << " " << extra << endl;
    exit(errno);
}

int main() {
    const int bufsiz = 0xffff;
    uint8_t* buffer = (uint8_t*)malloc(bufsiz);
    if (buffer <= 0) {
        err("malloc");
    }



    int s = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if (s == -1) {
        err("socket");
    }


    ifreq ifstr;
    memset(&ifstr,0,sizeof(ifreq));
    strncpy(ifstr.ifr_ifrn.ifrn_name,"wlan0",IFNAMSIZ-1);


    if (ioctl(s,SIOCGIFINDEX,&ifstr) == -1) {
        err("ioctl");
    }
    int ifidex = ifstr.ifr_ifru.ifru_ivalue;
    cout << "iface id: " << ifidex << endl;
    

    sockaddr_ll sll;
    sll.sll_family = PF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifidex;
    if (bind(s,(sockaddr*)&sll,sizeof(sll)) == -1) {
        err("bind");
    }


    if (ioctl(s,SIOCGIFFLAGS,&ifstr) == -1) {
        err("ioctl");
    }
    auto orig_flags = ifstr.ifr_ifru.ifru_flags;
    ifstr.ifr_ifru.ifru_flags = orig_flags | IFF_PROMISC | IFF_UP;
    if (ioctl(s,SIOCSIFFLAGS,&ifstr) == -1) {
        err("ioctl");
    }


    int slctVal, ret;
    timeval tv;
    sockaddr_in sin;
    uint siz = sizeof(sin);
    //netcode

#define LOGGING 1
#ifdef LOGGING
    PcapFile pfile;
    pfile.open("log.pcap");

    for (int i = 0; i < 0xffff; i++) {
        ret = recvfrom(s,buffer,bufsiz,0,(sockaddr*)&sin,&siz);
        if (ret > 0) {
            pfile.write_pkt(buffer,ret);
            protocols::EtherII(buffer);
        }
    }
#else
    for (int i = 0; i < 0xffff; i++) {
        ret = recvfrom(s,buffer,bufsiz,0,(sockaddr*)&sin,&siz);
        if (ret > 0) {
            protocols::EtherII(buffer);
        }
    }
#endif
    //netcode end

    ifreq a;
    memset(&a,0,sizeof(a));
    a.ifr_ifru.ifru_flags = orig_flags;
    a.ifr_ifru.ifru_ivalue = ifidex;
    if (ioctl(s,SIOCSIFFLAGS,&ifstr) == -1) {
        err("ioctl");
    }
    free(buffer);
    close(s);
}
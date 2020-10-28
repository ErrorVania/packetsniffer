#include <iostream>
#include <cstdlib>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <fstream>
#include "pcapmaker.h"
#include "netincl.h"
#include "pktproc.h"
#include <chrono>


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


#if defined(LOGGING)
    ofstream pcap("sniffer.pcap",ios::binary | ios::out);
    pcap_write_glob_hdr(pcap);

    auto start = chrono::steady_clock::now();

    for (int i = 0; i < 0xffff; i++) {
        ret = recvfrom(s,buffer,bufsiz,0,(sockaddr*)&sin,&siz);
        if (ret > 0) {
            pcap_pak_hdr hdr;
            auto end = chrono::steady_clock::now();
            hdr.ts_sec = chrono::duration_cast<chrono::seconds>(end-start).count();
            hdr.ts_usec = chrono::duration_cast<chrono::microseconds>(end-start).count();
            hdr.incl_len = hdr.orig_len = ret;
            pcap_write_pkt(pcap,&hdr,buffer,ret);


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
    if (ioctl(s,SIOCSIFFLAGS,&ifstr) == -1) {
        err("ioctl");
    }
    free(buffer);
    close(s);
}
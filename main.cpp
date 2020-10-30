#include "netincl.h"
#include "pcapmaker.h"
#include "pktproc.h"
#include "pcapmaker.h"
#include <iostream>
#include <cstdlib>
#include <sys/ioctl.h>
#include <unistd.h>
#include "helpers.h"
#include <signal.h>


#define bufsiz 0xffff


uint32_t captured;
void sHandle(int s) {
    std::cout << "\rCaptured " << captured << " Frames" << std::endl;
    exit(0);
}

int main(int argc, char **argv) {

    //Gather arguments

    bool flag_iface = false;
    bool flag_logfile = false;
    char ifacename[IFNAMSIZ-1];
    char logfile[PATH_MAX];

    for (int c = -2; c != -1; c = getopt(argc,argv,"i:l:h")) {
        switch (c) {
            case 'i':
                strcpy(ifacename,optarg);
                flag_iface = true;
                break;
            case 'l':
                strcpy(logfile,optarg);
                flag_logfile = true;
                break;
            case 'h':
                std::cout << "i --- Sets target interface" << std::endl << "l --- Enable logging" << std::endl << "h --- display this message" << std::endl << "o --- filter only outgoing frames" << std::endl << "r --- filter only incoming frames" << std::endl;
                break;
            case '?':
                return 1;

        }
    }

    if (!flag_iface) {
        std::cerr << "No interface specified." << std::endl;
        exit(1);
    }





    //setup socket and hardware
    int s = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if (s == -1) {
        std::cerr << "Could not create raw socket: " << strerror(errno) << " (" << errno << ")" << std::endl;
        return 1;
    }


    ifreq ifstr;
    memset(&ifstr,0,sizeof(ifreq));
    
    int ifidex = getIfaceIndex(s,ifacename,&ifstr);
    
    BindToInterface(s,PF_PACKET,htons(ETH_P_ALL),ifidex);
    getIfaceFlags(s,&ifstr);

    
    auto orig_flags = ifstr.ifr_ifru.ifru_flags;
    ifstr.ifr_ifru.ifru_flags = orig_flags | IFF_PROMISC | IFF_UP;
    setIfaceFlags(s,&ifstr);


    uint8_t* buffer = (uint8_t*)malloc(bufsiz);
    if (buffer <= 0) {
        std::cout << "Could not allocate " << bufsiz << " bytes of memory" << std::endl;
        return 1;
    }

    int ret;
    

    //Start sniffing

    signal(SIGINT,sHandle);

    if (flag_logfile) {
        PcapFile pfile;
        pfile.open(logfile);

        for (captured = 0;;captured++) {
            ret = recv(s,buffer,bufsiz,0);
            if (ret > 0) {
                pfile.write_pkt(buffer,ret);
                //protocols::EtherII(buffer);
            }
        }
    } else {
        for (captured = 0;;captured++) {
            ret = recv(s,buffer,bufsiz,0);
            if (ret > 0) {
                protocols::EtherII(buffer);
            }
        }
    }


    ifstr.ifr_ifru.ifru_flags = orig_flags;
    setIfaceFlags(s,&ifstr);


    free(buffer);
    close(s);
    return 0;
}

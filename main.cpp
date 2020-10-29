#include "netincl.h"
#include "pcapmaker.h"
#include "pktproc.h"
#include "pcapmaker.h"
#include <iostream>
#include <cstdlib>
#include <sys/ioctl.h>
#include <unistd.h>

using namespace std;


#define minimum_args 2
/*
-i
interface
-l
name
*/


int main(int argc, char **argv) {

    if (argc-1 < minimum_args) {
        int spaces = strlen(argv[0]) + 8;
        std::cout << "Insufficient Argmuents" << std::endl
        << "Usage: " << argv[0] << " -i [interface]" << std::endl;
        
        for (int i = 0; i < spaces; i++) {
            std::cout << " ";
        }
        std::cout << "-l {log file}" << std::endl;
        return argc-1;
    }


    //get iface

    char ifacename[IFNAMSIZ-1];
    char logfile[PATH_MAX];
    memset(ifacename,0,IFNAMSIZ-1);
    memset(logfile,0,PATH_MAX);

    bool flag_iface = false;
    bool flag_logfile = false;

    for (int i = 0; i < argc; i++) {
        if (!strcmp(argv[i],"-i")) {
            if (i + 1 < argc) {
                strcpy(ifacename, argv[i + 1]);
                flag_iface = true;
            }
        }
        if (!strcmp(argv[i],"-l")) {
            if (i + 1 < argc) {
                strcpy(logfile, argv[i+1]);
                //strcat(logfile,".pcap");
                flag_logfile = true;
            }
        }
    }

    if (!flag_iface) {
        std::cout << "Missing Interface" << std::endl;
        return argc-1;
    }







    int s = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if (s == -1) {
        std::cout << "Could not create raw socket: " << strerror(errno) << " (" << errno << ")" << std::endl;
        return 1;
    }


    ifreq ifstr;
    memset(&ifstr,0,sizeof(ifreq));
    strncpy(ifstr.ifr_ifrn.ifrn_name,ifacename,IFNAMSIZ-1);


    if (ioctl(s,SIOCGIFINDEX,&ifstr) == -1) {
        std::cout << "IOCTL could not get interface index: " << strerror(errno) << " (" << errno << ")" << std::endl;
        return 1;
    }

    
    int ifidex = ifstr.ifr_ifru.ifru_ivalue;
    
    sockaddr_ll sll;
    sll.sll_family = PF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ifidex;
    if (bind(s,(sockaddr*)&sll,sizeof(sll)) == -1) {
        std::cout << "Could not bind socket to interface '" << ifacename << "' " << strerror(errno) << " (" << errno << ")" << std::endl;
        return 1;
    }


    if (ioctl(s,SIOCGIFFLAGS,&ifstr) == -1) {
        std::cout << "IOCTL could not get interface flags from: '" << ifacename << "' " << strerror(errno) << " (" << errno << ")" << std::endl;
        return 1;

    }
    auto orig_flags = ifstr.ifr_ifru.ifru_flags;
    ifstr.ifr_ifru.ifru_flags = orig_flags | IFF_PROMISC | IFF_UP;
    if (ioctl(s,SIOCSIFFLAGS,&ifstr) == -1) {
        std::cout << "IOCTL could not set interface flags from: '" << ifacename << "' " << strerror(errno) << " (" << errno << ")" << std::endl;
        return 1;
    }


    const int bufsiz = 0xffff;
    uint8_t* buffer = (uint8_t*)malloc(bufsiz);
    if (buffer <= 0) {
        std::cout << "Could not allocate " << bufsiz << " bytes of memory" << std::endl;
        return 1;
    }

    int ret;
    sockaddr_in sin;
    uint siz = sizeof(sin);
    //netcode









    if (flag_logfile) {
        PcapFile pfile;
        pfile.open(logfile);

        while (1) {
            ret = recvfrom(s,buffer,bufsiz,0,(sockaddr*)&sin,&siz);
            if (ret > 0) {
                pfile.write_pkt(buffer,ret);
                protocols::EtherII(buffer);
            }
        }
    } else {
        for (int i = 0; i < 0xffff; i++) {
            ret = recvfrom(s,buffer,bufsiz,0,(sockaddr*)&sin,&siz);
            if (ret > 0) {
                protocols::EtherII(buffer);
            }
        }
    }



    //netcode end

    ifreq a;
    memset(&a,0,sizeof(a));
    a.ifr_ifru.ifru_flags = orig_flags;
    a.ifr_ifru.ifru_ivalue = ifidex;
    if (ioctl(s,SIOCSIFFLAGS,&ifstr) == -1) {
        std::cout << "IOCTL could not set interface flags from: '" << ifacename << "' " << strerror(errno) << " (" << errno << ")" << std::endl;
    }
    free(buffer);
    close(s);
    return 0;
}

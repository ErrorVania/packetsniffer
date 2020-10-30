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
#define minimum_args 2
/*
-i
interface
-l
name
*/


uint32_t captured;
void sHandle(int s) {
    std::cout << "\rCaptured " << captured << " Frames" << std::endl;
    exit(0);
}

int main(int argc, char **argv) {

    //Gather arguments
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
                flag_logfile = true;
            }
        }
    }

    if (!flag_iface) {
        std::cout << "No interface specified" << std::endl;
        return argc-1;
    }





    //setup socket and hardware
    int s = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if (s == -1) {
        std::cout << "Could not create raw socket: " << strerror(errno) << " (" << errno << ")" << std::endl;
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

#include "pktproc.h"


char* tomac(void* mac) {
    ether_addr ea;
    memcpy(ea.ether_addr_octet,mac,6);
    return ether_ntoa(&ea);
}
char* toip(const uint32_t* ip) {
    in_addr i;
    memcpy(&i.s_addr,ip,32/8);
    return inet_ntoa(i);
}
const char* toip6(const in6_addr* ip, char* buf) {
    inet_ntop(AF_INET6,&ip->__in6_u,buf,INET6_ADDRSTRLEN);
    return buf;
}




namespace protocols {

    void UDP(uint8_t* buf) {
        udp_hdr* udphdr = (udp_hdr*)buf;
        std::cout << "(UDP: Port " << ntohs(udphdr->srcport) << " > " << ntohs(udphdr->dstport) << ", Payload: " << ntohs(udphdr->length) - sizeof(udp_hdr) << " bytes)";
    }
    void TCP(uint8_t* buf, const ip_hdr* iphdr) {
        tcp_hdr* tcphdr = (tcp_hdr*)buf;
        uint hdrlen = (tcphdr->data_offset >> 4)*4;
        std::bitset<8> fl(tcphdr->flags);
        std::cout << "(TCP: Port " << ntohs(tcphdr->src_port) << " > " << ntohs(tcphdr->dst_port) << " Header Length: " << hdrlen << ", Flags:[" << fl << "], Payload: " << (ntohs(iphdr->total_len) - iphdr->ihl*4 - hdrlen) << " bytes)";

    }
    void TCP(uint8_t* buf, const ip6_hdr* iphdr) {
        tcp_hdr* tcphdr = (tcp_hdr*)buf;
        uint hdrlen = (tcphdr->data_offset >> 4)*4;
        std::bitset<8> fl(tcphdr->flags);
        std::cout << "(TCP: Port " << ntohs(tcphdr->src_port) << " > " << ntohs(tcphdr->dst_port) << ", Flags:[" << fl << "], Payload: " << (ntohs(iphdr->length) - hdrlen) << " bytes)";

    }


    void ICMP(uint8_t* buf, const ip_hdr* iphdr) {
        icmp_hdr* icmphdr = (icmp_hdr*)buf;
        std::cout << "(ICMP: Type " << (int)icmphdr->type << " Code " << (int)icmphdr->code << ", Rest: " << ntohl(icmphdr->rest) << ", Payload: " << (ntohs(iphdr->total_len) - iphdr->ihl*4 - sizeof(icmp_hdr)) << " bytes)";
    }
    void ICMP(uint8_t* buf, const ip6_hdr* iphdr) {
        icmp_hdr* icmphdr = (icmp_hdr*)buf;
        std::cout << "(ICMP: Type " << (int)icmphdr->type << " Code " << (int)icmphdr->code << ", Rest: " << ntohl(icmphdr->rest) << ", Payload: " << (ntohs(iphdr->length) - sizeof(icmp_hdr)) << " bytes)";
    }

    void IPv4(uint8_t* buf) {

        ip_hdr* iphdr = (ip_hdr*)buf;
        std::cout << "(IPv4: " << toip(&iphdr->src) << " > " << toip(&iphdr->dst) << ")";

        switch (iphdr->proto) {
            case IPPROTO_UDP:
                std::cout << "|";
                UDP(buf + iphdr->ihl*4);
                break;
            case IPPROTO_TCP:
                std::cout << "|";
                TCP(buf + iphdr->ihl*4, iphdr);
                break;
            case IPPROTO_ICMP:
                std::cout << "|";
                ICMP(buf + iphdr->ihl*4,iphdr);
                break;
            default:
                std::cout << "| " << iphdr->proto;
                break;
        }

    }
    void IPv6(uint8_t* buf) {
        ip6_hdr* iphdr = (ip6_hdr*)buf;
        char b[INET6_ADDRSTRLEN];

        std::cout << "(IPv6: " << toip6(&iphdr->src,b) << " > " << toip6(&iphdr->dst,b) << ")";

        switch (iphdr->next_header) {
            case IPPROTO_UDP:
                std::cout << "|";
                UDP(buf + sizeof(ip6_hdr));
                break;
            case IPPROTO_TCP:
                std::cout << "|";
                TCP(buf + sizeof(ip6_hdr), iphdr);
                break;
            case IPPROTO_ICMPV6:
                std::cout << "|";
                ICMP(buf + sizeof(ip6_hdr), iphdr);
                break;
            default:
                std::cout << "| " << iphdr->next_header;
                break;
        }
    }


    void ARP(uint8_t* buf) {
        arp_hdr* arphdr = (arp_hdr*)buf;
        std::cout << "(ARP: ";
        if (htons(arphdr->htype) == 1)
            std::cout << "Ethernet "; //all other are irrelevant
        if (htons(arphdr->oper) == 1)
            std::cout << "Request, ";
        else
            std::cout << "Reply,   ";

        std::cout << tomac(arphdr->senderhardwareaddr) << "/" << toip((uint32_t*)&arphdr->senderprotoaddr) << " > " << tomac(arphdr->targethardwareaddr) << "/" << toip((uint32_t*)&arphdr->targetprotoaddr) << ")";
    }





    void EtherII(uint8_t* buf) {
        eth_hdr* ethernet_header = (eth_hdr*)buf;
        uint16_t ethtype = ntohs(ethernet_header->ethertype);
        std::cout << "(Ether: " << tomac(ethernet_header->smac) << " > " << tomac(ethernet_header->dmac) << ")";

        if (ethtype <= 1500) { //ethtype is size
            std::cout << "|" << "(Raw: " << ethtype << " bytes)";
            return;
        }


        if (ethtype >= 1536) { //ethtype is proto
            if (ethtype == ETHERTYPE_IP) {
                std::cout << "|";
                IPv4((uint8_t*)&ethernet_header->payload);
            } else
            if (ethtype == ETHERTYPE_ARP) {
                std::cout << "|";
                ARP((uint8_t*)&ethernet_header->payload);
            } else
            if (ethtype == ETHERTYPE_IPV6) {
                std::cout << "|";
                IPv6((uint8_t*)&ethernet_header->payload);
            }
        }
        std::cout << std::endl;
    
    
    }
}
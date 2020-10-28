#pragma once


#include <fstream>
#include <iostream>
#include <stdio.h>

struct pcap_global_hdr {

    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;

};
struct pcap_pak_hdr {

    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;

};

struct pcap_pak {
    pcap_pak_hdr hdr;
    uint8_t packet[];
};



void pcap_write_glob_hdr(std::ofstream& file) {

    pcap_global_hdr a;
    a.magic = 0xA1B2C3D4;
    a.version_major = 2;
    a.version_minor = 4;
    a.thiszone = 0;
    a.sigfigs = 0;
    a.snaplen = 0xffff;
    a.network = 1;

    file.write((const char*)&a,sizeof(a));


}

void pcap_write_pkt(std::ofstream& file, pcap_pak_hdr* hdr, void* buf,int siz) {

    file.write((const char*)hdr,sizeof(pcap_pak_hdr));
    file.write((const char*)buf,siz);

}



class PcapFile {
private:
    std::ofstream pcapfile;
    bool isopen;

public:

    void open(const char *s) {
        PcapFile(s);
    }

    PcapFile() {
        isopen = false;
    }
    PcapFile(const char* filename) {
        pcapfile.open(filename,std::ios::binary | std::ios::out);
        isopen = true;
        if (pcapfile.fail()) {
            throw std::runtime_error("pcap file couldnt be created");
        }

    }





};
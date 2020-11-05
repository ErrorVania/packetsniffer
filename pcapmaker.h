#pragma once
#include <fstream>
#include <chrono>
#include <iostream>


namespace pcap {
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

    class PcapWriter {
    private:
        std::ofstream pcapfile;
        bool isopen;
        std::chrono::_V2::steady_clock::time_point ts_start;
        void pcap_write_glob_hdr(std::ofstream& file);
        void pcap_write_pkt(std::ofstream& file, pcap::pcap_pak_hdr* hdr, void* buf,int siz);
    public:
        PcapWriter();
        void open(const char* filename);
        void write_pkt(void* buf, int len);
        ~PcapWriter();
    };
}
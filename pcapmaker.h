#pragma once


#include <fstream>
//#include <stdio.h>
//#include <chrono>
#include <sys/time.h>
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
        //std::chrono::_V2::steady_clock::time_point ts_start;

        void pcap_write_glob_hdr(std::ofstream& file) {
            pcap::pcap_global_hdr a;
            a.magic = 0xA1B2C3D4;
            a.version_major = 2;
            a.version_minor = 4;
            a.thiszone = 0;
            a.sigfigs = 0;
            a.snaplen = 0xffff;
            a.network = 1;

            file.write((const char*)&a,sizeof(a));
        }

        void pcap_write_pkt(std::ofstream& file, pcap::pcap_pak_hdr* hdr, void* buf,int siz) {
            file.write((const char*)hdr,sizeof(pcap::pcap_pak_hdr));
            file.write((const char*)buf,siz);
        }
    public:
        PcapWriter() {
            isopen = false;
        }
        void open(const char* filename) {
            pcapfile.open(filename,std::ios::binary | std::ios::out);
            if (pcapfile.fail()) {
                throw std::runtime_error("pcap file couldnt be created");
            }
            isopen = true;

            //ts_start = std::chrono::steady_clock::now();
            pcap_write_glob_hdr(pcapfile);
        }

        void write_pkt(void* buf, int len) {
            pcap::pcap_pak_hdr hdr;
            /*auto ts_end = std::chrono::steady_clock::now();
            hdr.ts_sec = std::chrono::duration_cast<std::chrono::seconds>(ts_end-ts_start).count();
            hdr.ts_usec = std::chrono::duration_cast<std::chrono::microseconds>(ts_end-ts_start).count();*/
            struct timeval tv;
            gettimeofday(&tv,0);

            hdr.ts_sec = tv.tv_sec;
            hdr.ts_usec = tv.tv_usec;


            hdr.incl_len = hdr.orig_len = len;
            pcap_write_pkt(pcapfile,&hdr,buf,len);
        }

        ~PcapWriter() {
            if (isopen) pcapfile.close();
        }
    };
}
#include "pcapmaker.h"

namespace pcap {

    void PcapWriter::pcap_write_glob_hdr(std::ofstream& file) {
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

    void PcapWriter::pcap_write_pkt(std::ofstream& file, pcap::pcap_pak_hdr* hdr, void* buf,int siz) {
        file.write((const char*)hdr,sizeof(pcap::pcap_pak_hdr));
        file.write((const char*)buf,siz);
    }
    PcapWriter::PcapWriter() {
        isopen = false;
    }
    void PcapWriter::open(const char* filename) {
        pcapfile.open(filename,std::ios::binary | std::ios::out);
        if (pcapfile.fail()) {
            throw std::runtime_error("pcap file couldnt be created");
        }
        isopen = true;

        ts_start = std::chrono::steady_clock::now();
        PcapWriter::pcap_write_glob_hdr(pcapfile);
    }

    void PcapWriter::write_pkt(void* buf, int len) {
        pcap::pcap_pak_hdr hdr;
        auto ts_end = std::chrono::steady_clock::now();
        hdr.ts_sec = std::chrono::duration_cast<std::chrono::seconds>(ts_end-ts_start).count();
        hdr.ts_usec = std::chrono::duration_cast<std::chrono::microseconds>(ts_end-ts_start).count();
        hdr.incl_len = hdr.orig_len = len;
        PcapWriter::pcap_write_pkt(pcapfile,&hdr,buf,len);
    }

    PcapWriter::~PcapWriter() {
        if (isopen) pcapfile.close();
    }
}
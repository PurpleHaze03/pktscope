#include "pktscope/capture.hpp"

#include <pcap/pcap.h>

#include <cstring>

namespace pktscope {

static pcap_t* as_pcap(void* h) { return static_cast<pcap_t*>(h); }

Capture Capture::live(const std::string& iface, bool promiscuous) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    // 65535 snaplen (full frames), promiscuous, 100 ms read timeout.
    pcap_t* h = pcap_open_live(iface.c_str(), 65535, promiscuous ? 1 : 0, 100, errbuf);
    if (!h) throw CaptureError("cannot open interface '" + iface + "': " + errbuf);

    Capture c;
    c.handle_ = h;
    c.linktype_ = pcap_datalink(h);
    c.live_ = true;
    return c;
}

Capture Capture::offline(const std::string& path) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* h = pcap_open_offline(path.c_str(), errbuf);
    if (!h) throw CaptureError("cannot open capture file '" + path + "': " + errbuf);

    Capture c;
    c.handle_ = h;
    c.linktype_ = pcap_datalink(h);
    c.live_ = false;
    return c;
}

Capture::~Capture() {
    if (handle_) pcap_close(as_pcap(handle_));
}

Capture::Capture(Capture&& o) noexcept {
    handle_ = o.handle_; linktype_ = o.linktype_; live_ = o.live_; stop_ = o.stop_;
    o.handle_ = nullptr;
}

Capture& Capture::operator=(Capture&& o) noexcept {
    if (this != &o) {
        if (handle_) pcap_close(as_pcap(handle_));
        handle_ = o.handle_; linktype_ = o.linktype_; live_ = o.live_; stop_ = o.stop_;
        o.handle_ = nullptr;
    }
    return *this;
}

void Capture::set_filter(const std::string& bpf) {
    bpf_program prog;
    if (pcap_compile(as_pcap(handle_), &prog, bpf.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0)
        throw CaptureError("bad BPF filter: " + std::string(pcap_geterr(as_pcap(handle_))));
    if (pcap_setfilter(as_pcap(handle_), &prog) < 0) {
        pcap_freecode(&prog);
        throw CaptureError("cannot install filter: " + std::string(pcap_geterr(as_pcap(handle_))));
    }
    pcap_freecode(&prog);
}

std::uint64_t Capture::run(const Callback& cb, long max) {
    stop_ = false;
    std::uint64_t count = 0;
    pcap_pkthdr* hdr = nullptr;
    const std::uint8_t* data = nullptr;

    while (!stop_) {
        int rc = pcap_next_ex(as_pcap(handle_), &hdr, &data);
        if (rc == 1) {
            double ts = hdr->ts.tv_sec + hdr->ts.tv_usec / 1e6;
            Bytes frame(data, hdr->caplen);
            Packet p = dissect(frame, linktype_, ts, hdr->len);
            cb(p);
            if (++count == static_cast<std::uint64_t>(max) && max > 0) break;
        } else if (rc == 0) {
            continue;  // live read timeout, no packet this round
        } else if (rc == -2) {
            break;     // end of a savefile
        } else {
            throw CaptureError("read error: " + std::string(pcap_geterr(as_pcap(handle_))));
        }
    }
    return count;
}

void Capture::stop() { stop_ = true; }

}  // namespace pktscope

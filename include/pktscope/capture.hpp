// libpcap wrapper: opens a live interface or an offline .pcap, applies an
// optional BPF filter, and delivers dissected packets to a callback.
#pragma once

#include <functional>
#include <string>

#include "pktscope/dissector.hpp"

namespace pktscope {

struct CaptureError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

class Capture {
public:
    using Callback = std::function<void(const Packet&)>;

    // Open a live interface (needs CAP_NET_RAW / root).
    static Capture live(const std::string& iface, bool promiscuous = true);
    // Open a saved capture file.
    static Capture offline(const std::string& path);

    ~Capture();
    Capture(Capture&&) noexcept;
    Capture& operator=(Capture&&) noexcept;
    Capture(const Capture&) = delete;
    Capture& operator=(const Capture&) = delete;

    // Compile+install a BPF filter (e.g. "tcp port 80"). Throws on bad syntax.
    void set_filter(const std::string& bpf);

    // Loop delivering packets until the file ends, `max` packets are seen, or
    // stop() is called. max <= 0 means unlimited. Returns packets processed.
    std::uint64_t run(const Callback& cb, long max = 0);
    void stop();

    int linktype() const { return linktype_; }
    bool is_live() const { return live_; }

private:
    Capture() = default;
    void* handle_ = nullptr;  // pcap_t*
    int linktype_ = 0;
    bool live_ = false;
    bool stop_ = false;
};

}  // namespace pktscope

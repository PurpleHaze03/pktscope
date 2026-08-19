// Detection engine: stateful heuristics run over the packet stream.
//
// All time windows use the packet's own capture timestamp (not wall clock),
// so results are deterministic and identical whether a .pcap is replayed at
// full speed or analyzed live.
#pragma once

#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "pktscope/dissector.hpp"

namespace pktscope {

enum class Severity { Info, Warning, Critical };
const char* severity_name(Severity s);

struct Alert {
    double timestamp = 0.0;
    Severity severity = Severity::Warning;
    std::string kind;     // "port-scan", "arp-spoof", ...
    std::string source;   // offending IP/MAC
    std::string detail;   // human-readable explanation
};

// Tunable thresholds (defaults chosen to fire on typical nmap/hping defaults
// without tripping on normal browsing).
struct DetectorConfig {
    // Port scan: one source touching this many distinct dst ports within window.
    int port_scan_threshold = 15;
    double port_scan_window = 5.0;   // seconds

    // SYN flood: this many SYNs to a single dst:port within window without
    // matching handshake completion.
    int syn_flood_threshold = 100;
    double syn_flood_window = 2.0;

    // DNS tunneling: qname longer than this, or more labels than this.
    std::size_t dns_name_len = 50;
    int dns_label_count = 6;
};

class Detector {
public:
    explicit Detector(DetectorConfig cfg = {}) : cfg_(cfg) {}

    // Feed one dissected packet; returns any alerts newly raised by it.
    std::vector<Alert> inspect(const Packet& p);

    const std::vector<Alert>& all_alerts() const { return alerts_; }

private:
    void check_port_scan(const Packet& p, std::vector<Alert>& out);
    void check_arp_spoof(const Packet& p, std::vector<Alert>& out);
    void check_syn_flood(const Packet& p, std::vector<Alert>& out);
    void check_stealth_scan(const Packet& p, std::vector<Alert>& out);
    void check_dns_tunnel(const Packet& p, std::vector<Alert>& out);

    DetectorConfig cfg_;
    std::vector<Alert> alerts_;

    // port-scan state: per source IP, recent (timestamp, dst:port) touches
    struct PortHit { double ts; std::uint32_t dst_port_key; };
    std::unordered_map<std::string, std::deque<PortHit>> scan_hits_;
    std::unordered_set<std::string> scan_reported_;

    // arp-spoof state: IP -> MAC binding first learned
    std::unordered_map<std::uint32_t, MacAddr> arp_bindings_;

    // syn-flood state: per dst:port, recent SYN timestamps
    std::unordered_map<std::string, std::deque<double>> syn_times_;
    std::unordered_set<std::string> flood_reported_;
};

}  // namespace pktscope

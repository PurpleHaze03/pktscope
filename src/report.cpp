#include "pktscope/report.hpp"

#include <algorithm>
#include <cstdio>
#include <iomanip>
#include <utility>
#include <vector>

namespace pktscope {

static std::string pct(std::uint64_t n, std::uint64_t total) {
    char b[16];
    std::snprintf(b, sizeof(b), "%.1f%%", total ? 100.0 * n / total : 0.0);
    return b;
}

static void bar(std::ostream& os, const char* label, std::uint64_t n,
                std::uint64_t total) {
    int width = total ? static_cast<int>(30.0 * n / total) : 0;
    os << "  " << std::left << std::setw(8) << label << std::right << std::setw(8)
       << n << "  " << std::setw(6) << pct(n, total) << "  ";
    for (int i = 0; i < width; ++i) os << "#";
    os << "\n";
}

void write_report(std::ostream& os, const Stats& s, const FlowTable& flows,
                  const std::vector<Alert>& alerts, const std::string& source) {
    os << "========================================================\n";
    os << " pktscope report -- " << source << "\n";
    os << "========================================================\n";
    os << "Packets     : " << s.packets << "  (" << s.malformed << " malformed)\n";
    os << "Bytes       : " << s.bytes << "\n";
    os << "Duration    : " << std::fixed << std::setprecision(2) << s.duration() << " s\n";
    os << "Throughput  : " << std::setprecision(1) << s.pps() << " pkt/s, "
       << std::setprecision(2) << s.mbps() << " Mbit/s\n";
    os << "Flows       : " << flows.size() << "\n\n";

    os << "Protocol breakdown:\n";
    bar(os, "ARP", s.arp, s.packets);
    bar(os, "IPv4", s.ipv4, s.packets);
    bar(os, "IPv6", s.ipv6, s.packets);
    bar(os, "TCP", s.tcp, s.packets);
    bar(os, "UDP", s.udp, s.packets);
    bar(os, "ICMP", s.icmp, s.packets);
    bar(os, "DNS", s.dns, s.packets);
    os << "\n";

    os << "Top talkers (by bytes):\n";
    auto top = flows.top_by_bytes(10);
    for (const auto& f : top) {
        char line[160];
        std::snprintf(line, sizeof(line), "  %-46s %10llu B  %6llu pkt  %s\n",
                      f.describe().c_str(),
                      static_cast<unsigned long long>(f.bytes),
                      static_cast<unsigned long long>(f.packets),
                      f.proto == 6 ? tcp_state_name(f.state) : "");
        os << line;
    }
    os << "\n";

    os << "Top destination ports:\n";
    // sort port map by count
    std::vector<std::pair<std::uint16_t, std::uint64_t>> ports(
        s.dst_port_counts.begin(), s.dst_port_counts.end());
    std::sort(ports.begin(), ports.end(),
              [](auto& a, auto& b) { return a.second > b.second; });
    for (std::size_t i = 0; i < ports.size() && i < 8; ++i)
        os << "  :" << std::left << std::setw(7) << ports[i].first << std::right
           << ports[i].second << " pkt\n";
    os << "\n";

    os << "Security alerts (" << alerts.size() << "):\n";
    if (alerts.empty()) {
        os << "  (none)\n";
    } else {
        for (const auto& a : alerts) {
            char line[256];
            std::snprintf(line, sizeof(line), "  [%s] %-12s %s\n",
                          severity_name(a.severity), a.kind.c_str(), a.detail.c_str());
            os << line;
        }
    }
    os << "========================================================\n";
}

static std::string esc(const std::string& s) {
    std::string o;
    for (char c : s) {
        if (c == '"' || c == '\\') { o += '\\'; o += c; }
        else if (c == '\n') o += "\\n";
        else o += c;
    }
    return o;
}

void write_json(std::ostream& os, const Stats& s, const FlowTable& flows,
                const std::vector<Alert>& alerts, const std::string& source) {
    os << "{\n  \"source\": \"" << esc(source) << "\",\n";
    os << "  \"packets\": " << s.packets << ", \"bytes\": " << s.bytes
       << ", \"malformed\": " << s.malformed << ",\n";
    os << "  \"duration_s\": " << std::fixed << std::setprecision(3) << s.duration() << ",\n";
    os << "  \"protocols\": {\"arp\": " << s.arp << ", \"ipv4\": " << s.ipv4
       << ", \"ipv6\": " << s.ipv6 << ", \"tcp\": " << s.tcp << ", \"udp\": " << s.udp
       << ", \"icmp\": " << s.icmp << ", \"dns\": " << s.dns << "},\n";
    os << "  \"flows\": " << flows.size() << ",\n";
    os << "  \"alerts\": [\n";
    for (std::size_t i = 0; i < alerts.size(); ++i) {
        const auto& a = alerts[i];
        os << "    {\"ts\": " << std::setprecision(3) << a.timestamp
           << ", \"severity\": \"" << severity_name(a.severity)
           << "\", \"kind\": \"" << esc(a.kind) << "\", \"source\": \"" << esc(a.source)
           << "\", \"detail\": \"" << esc(a.detail) << "\"}"
           << (i + 1 < alerts.size() ? "," : "") << "\n";
    }
    os << "  ]\n}\n";
}

}  // namespace pktscope

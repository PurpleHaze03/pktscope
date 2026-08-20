#include "pktscope/detect.hpp"

#include <algorithm>

namespace pktscope {

const char* severity_name(Severity s) {
    switch (s) {
        case Severity::Info: return "INFO";
        case Severity::Warning: return "WARN";
        case Severity::Critical: return "CRIT";
    }
    return "?";
}

std::vector<Alert> Detector::inspect(const Packet& p) {
    std::vector<Alert> out;
    if (p.malformed) return out;

    if (p.l3 == L3::Arp) {
        check_arp_spoof(p, out);
    } else if (p.l4 == L4::Tcp) {
        check_port_scan(p, out);
        check_stealth_scan(p, out);
        check_syn_flood(p, out);
    }
    if (p.dns) check_dns_tunnel(p, out);

    for (auto& a : out) alerts_.push_back(a);
    return out;
}

// ---- port scan: many distinct destination ports from one source -----------

void Detector::check_port_scan(const Packet& p, std::vector<Alert>& out) {
    // A connection attempt is a lone SYN (no ACK). Completed connections and
    // normal traffic don't look like this.
    if (!(p.tcp_flags.syn && !p.tcp_flags.ack)) return;

    auto& hits = scan_hits_[p.src_ip];
    std::uint32_t key = (static_cast<std::uint32_t>(std::hash<std::string>{}(p.dst_ip) & 0xFFFF) << 16) |
                        p.dst_port;
    hits.push_back({p.timestamp, key});

    // Drop touches older than the window.
    while (!hits.empty() && p.timestamp - hits.front().ts > cfg_.port_scan_window)
        hits.pop_front();

    // Count distinct dst:port within the window.
    std::unordered_set<std::uint32_t> distinct;
    for (const auto& h : hits) distinct.insert(h.dst_port_key);

    if (static_cast<int>(distinct.size()) >= cfg_.port_scan_threshold &&
        !scan_reported_.count(p.src_ip)) {
        scan_reported_.insert(p.src_ip);
        out.push_back({p.timestamp, Severity::Critical, "port-scan", p.src_ip,
                       p.src_ip + " probed " + std::to_string(distinct.size()) +
                           " ports in " + std::to_string((int)cfg_.port_scan_window) +
                           "s (SYN scan)"});
    }
}

// ---- stealth scans: illegal / unusual flag combinations -------------------

void Detector::check_stealth_scan(const Packet& p, std::vector<Alert>& out) {
    const TcpFlags& f = p.tcp_flags;
    // `only()` ignores ECE/CWR, so exclude those here to avoid mislabeling an
    // ECN-negotiating packet (ECE/CWR set) as a flagless NULL scan.
    if (f.ece || f.cwr) return;
    const char* kind = nullptr;
    // NULL scan: no flags set at all.
    if (f.only(false, false, false, false, false, false)) kind = "NULL scan";
    // FIN scan: only FIN.
    else if (f.only(true, false, false, false, false, false)) kind = "FIN scan";
    // Xmas scan: FIN + PSH + URG.
    else if (f.only(true, false, false, true, false, true)) kind = "Xmas scan";
    if (!kind) return;

    out.push_back({p.timestamp, Severity::Warning, "stealth-scan", p.src_ip,
                   std::string(kind) + " packet " + p.src_ip + " -> " + p.dst_ip +
                       ":" + std::to_string(p.dst_port)});
}

// ---- ARP spoofing: an IP suddenly claimed by a different MAC ---------------

void Detector::check_arp_spoof(const Packet& p, std::vector<Alert>& out) {
    // Learn/verify bindings from BOTH replies and requests: ARP cache poisoning
    // is very commonly done with unsolicited/gratuitous ARP *requests* (opcode
    // 1), whose sender IP/MAC fields are fully populated -- checking only
    // replies would miss that entire class of attack.
    if (!p.arp) return;
    std::uint32_t ip = p.arp->sender_ip;
    const MacAddr& mac = p.arp->sender_mac;
    if (ip == 0) return;

    auto it = arp_bindings_.find(ip);
    if (it == arp_bindings_.end()) {
        arp_bindings_[ip] = mac;  // first binding: learn it
        return;
    }
    if (it->second != mac) {
        out.push_back(
            {p.timestamp, Severity::Critical, "arp-spoof", mac_to_string(mac),
             "IP " + ipv4_to_string(ip) + " moved from MAC " +
                 mac_to_string(it->second) + " to " + mac_to_string(mac) +
                 " (possible ARP cache poisoning)"});
        it->second = mac;  // update so we alert again only on the next change
    }
}

// ---- SYN flood: a burst of SYNs at one target -----------------------------

void Detector::check_syn_flood(const Packet& p, std::vector<Alert>& out) {
    if (!(p.tcp_flags.syn && !p.tcp_flags.ack)) return;
    std::string target = p.dst_ip + ":" + std::to_string(p.dst_port);
    auto& times = syn_times_[target];
    times.push_back(p.timestamp);
    while (!times.empty() && p.timestamp - times.front() > cfg_.syn_flood_window)
        times.pop_front();

    if (static_cast<int>(times.size()) >= cfg_.syn_flood_threshold &&
        !flood_reported_.count(target)) {
        flood_reported_.insert(target);
        out.push_back({p.timestamp, Severity::Critical, "syn-flood", p.dst_ip,
                       std::to_string(times.size()) + " SYNs to " + target + " in " +
                           std::to_string((int)cfg_.syn_flood_window) +
                           "s (possible SYN flood / DoS)"});
    }
}

// ---- DNS tunneling / exfiltration heuristic -------------------------------

void Detector::check_dns_tunnel(const Packet& p, std::vector<Alert>& out) {
    // Only inspect queries: the exfil vector is the outbound QNAME, and running
    // on responses would blame the resolver's IP as the "tunneling source".
    if (p.dns->is_response) return;
    const std::string& name = p.dns->first_qname;
    if (name.empty()) return;
    int labels = 1 + static_cast<int>(std::count(name.begin(), name.end(), '.'));
    if (name.size() >= cfg_.dns_name_len || labels >= cfg_.dns_label_count) {
        out.push_back({p.timestamp, Severity::Warning, "dns-tunnel", p.src_ip,
                       "long/complex DNS query (" + std::to_string(name.size()) +
                           " chars, " + std::to_string(labels) +
                           " labels): possible tunneling/exfil"});
    }
}

}  // namespace pktscope

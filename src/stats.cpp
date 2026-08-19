#include "pktscope/stats.hpp"

namespace pktscope {

void Stats::add(const Packet& p) {
    if (packets == 0) first_ts = p.timestamp;
    last_ts = p.timestamp;
    packets += 1;
    bytes += p.wire_len;
    if (p.malformed) { malformed += 1; return; }

    if (p.eth) eth += 1;
    switch (p.l3) {
        case L3::IPv4: ipv4 += 1; break;
        case L3::IPv6: ipv6 += 1; break;
        case L3::Arp: arp += 1; break;
        default: break;
    }
    switch (p.l4) {
        case L4::Tcp: tcp += 1; break;
        case L4::Udp: udp += 1; break;
        case L4::Icmp: icmp += 1; break;
        default: break;
    }
    if (p.dns) dns += 1;
    if (p.l4 == L4::Tcp || p.l4 == L4::Udp) dst_port_counts[p.dst_port] += 1;
}

double Stats::pps() const {
    double d = duration();
    return d > 0 ? packets / d : 0.0;
}

double Stats::mbps() const {
    double d = duration();
    return d > 0 ? (bytes * 8.0) / d / 1e6 : 0.0;
}

}  // namespace pktscope

#include "pktscope/dissector.hpp"

#include <pcap/pcap.h>  // for DLT_* constants

#include <cstdio>
#include <string>

namespace pktscope {

const char* Packet::l4_name() const {
    switch (l4) {
        case L4::Tcp: return "TCP";
        case L4::Udp: return "UDP";
        case L4::Icmp: return "ICMP";
        default: return "";
    }
}

std::string Packet::summary() const {
    if (malformed) return "[malformed] " + note;
    char buf[256];
    if (l3 == L3::Arp && arp) {
        if (arp->is_request()) {
            std::snprintf(buf, sizeof(buf), "ARP who-has %s tell %s",
                          ipv4_to_string(arp->target_ip).c_str(),
                          ipv4_to_string(arp->sender_ip).c_str());
        } else {
            std::snprintf(buf, sizeof(buf), "ARP %s is-at %s",
                          ipv4_to_string(arp->sender_ip).c_str(),
                          mac_to_string(arp->sender_mac).c_str());
        }
        return buf;
    }
    if (l4 == L4::Tcp) {
        std::string extra;
        if (dns) extra = "  DNS " + dns->first_qname;
        std::snprintf(buf, sizeof(buf), "TCP %s:%u > %s:%u [%s] len %u",
                      src_ip.c_str(), src_port, dst_ip.c_str(), dst_port,
                      tcp_flags.to_string().c_str(), payload_len);
        return std::string(buf) + extra;
    }
    if (l4 == L4::Udp) {
        std::string extra;
        if (dns) extra = "  DNS " + (dns->is_response ? std::string("resp ") : std::string("query ")) +
                         dns->first_qname;
        std::snprintf(buf, sizeof(buf), "UDP %s:%u > %s:%u len %u",
                      src_ip.c_str(), src_port, dst_ip.c_str(), dst_port, payload_len);
        return std::string(buf) + extra;
    }
    if (l4 == L4::Icmp) {
        std::snprintf(buf, sizeof(buf), "ICMP %s > %s", src_ip.c_str(), dst_ip.c_str());
        return buf;
    }
    if (l3 == L3::IPv4 || l3 == L3::IPv6) {
        std::snprintf(buf, sizeof(buf), "%s %s > %s", ip_proto_name(ip_proto),
                      src_ip.c_str(), dst_ip.c_str());
        return buf;
    }
    return "non-IP frame";
}

// Parse L4 (TCP/UDP/ICMP) given the L3 protocol number, filling `p`.
static void dissect_l4(Packet& p, ByteReader& r, std::uint8_t proto) {
    if (proto == static_cast<std::uint8_t>(IpProto::TCP)) {
        auto tcp = parse_tcp(r);
        if (!tcp) { p.malformed = true; p.note = "bad TCP"; return; }
        p.l4 = L4::Tcp;
        p.src_port = tcp->src_port;
        p.dst_port = tcp->dst_port;
        p.tcp_flags = tcp->flags;
        p.tcp_seq = tcp->seq;
        p.payload_len = static_cast<std::uint32_t>(r.remaining());
        if (tcp->src_port == 53 || tcp->dst_port == 53) {
            // DNS over TCP is length-prefixed; skip the 2-byte length.
            Bytes rest = r.peek_rest();
            if (rest.size() > 2) p.dns = parse_dns(rest.subspan(2));
        }
    } else if (proto == static_cast<std::uint8_t>(IpProto::UDP)) {
        auto udp = parse_udp(r);
        if (!udp) { p.malformed = true; p.note = "bad UDP"; return; }
        p.l4 = L4::Udp;
        p.src_port = udp->src_port;
        p.dst_port = udp->dst_port;
        p.payload_len = static_cast<std::uint32_t>(r.remaining());
        if (udp->src_port == 53 || udp->dst_port == 53) {
            p.dns = parse_dns(r.peek_rest());
        }
    } else if (proto == static_cast<std::uint8_t>(IpProto::ICMP) ||
               proto == static_cast<std::uint8_t>(IpProto::ICMPv6)) {
        auto icmp = parse_icmp(r);
        if (!icmp) { p.malformed = true; p.note = "bad ICMP"; return; }
        p.l4 = L4::Icmp;
    }
}

Packet dissect(Bytes frame, int linktype, double timestamp, std::uint32_t wire_len) {
    Packet p;
    p.timestamp = timestamp;
    p.wire_len = wire_len;
    p.cap_len = static_cast<std::uint32_t>(frame.size());

    ByteReader r(frame);

    // Link layer: Ethernet (DLT_EN10MB) or raw IP (DLT_RAW). Loopback
    // (DLT_NULL) carries a 4-byte address-family header before the IP packet.
    std::uint16_t ethertype = 0;
    if (linktype == DLT_EN10MB) {
        auto eth = parse_ethernet(r);
        if (!eth) { p.malformed = true; p.note = "bad Ethernet"; return p; }
        p.eth = eth;
        ethertype = eth->ethertype;
    } else if (linktype == DLT_NULL || linktype == DLT_LOOP) {
        try { r.skip(4); } catch (...) { p.malformed = true; p.note = "short loopback"; return p; }
        // Peek IP version to route.
        Bytes rest = r.peek_rest();
        if (rest.empty()) { p.malformed = true; p.note = "empty"; return p; }
        ethertype = (rest[0] >> 4) == 6 ? static_cast<std::uint16_t>(EtherType::IPv6)
                                        : static_cast<std::uint16_t>(EtherType::IPv4);
    } else if (linktype == DLT_RAW) {
        Bytes rest = r.peek_rest();
        if (rest.empty()) { p.malformed = true; p.note = "empty"; return p; }
        ethertype = (rest[0] >> 4) == 6 ? static_cast<std::uint16_t>(EtherType::IPv6)
                                        : static_cast<std::uint16_t>(EtherType::IPv4);
    } else {
        p.malformed = true;
        p.note = "unsupported linktype " + std::to_string(linktype);
        return p;
    }

    if (ethertype == static_cast<std::uint16_t>(EtherType::ARP)) {
        auto arp = parse_arp(r);
        if (!arp) { p.malformed = true; p.note = "bad ARP"; return p; }
        p.arp = arp;
        p.l3 = L3::Arp;
        return p;
    }

    if (ethertype == static_cast<std::uint16_t>(EtherType::IPv4)) {
        auto ip = parse_ipv4(r);
        if (!ip) { p.malformed = true; p.note = "bad IPv4"; return p; }
        p.l3 = L3::IPv4;
        p.src_ip = ipv4_to_string(ip->src);
        p.dst_ip = ipv4_to_string(ip->dst);
        p.ip_proto = ip->protocol;
        p.ttl = ip->ttl;
        dissect_l4(p, r, ip->protocol);
    } else if (ethertype == static_cast<std::uint16_t>(EtherType::IPv6)) {
        auto ip = parse_ipv6(r);
        if (!ip) { p.malformed = true; p.note = "bad IPv6"; return p; }
        p.l3 = L3::IPv6;
        p.src_ip = ipv6_to_string(ip->src);
        p.dst_ip = ipv6_to_string(ip->dst);
        p.ip_proto = ip->next_header;
        p.ttl = ip->hop_limit;
        dissect_l4(p, r, ip->next_header);
    }
    return p;
}

}  // namespace pktscope

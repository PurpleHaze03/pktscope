// Top-level packet dissection: raw bytes -> a flat, display-ready record.
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "pktscope/protocols.hpp"

namespace pktscope {

enum class L3 { None, IPv4, IPv6, Arp };
enum class L4 { None, Tcp, Udp, Icmp };

// A fully dissected packet. Addresses/ports are normalized to strings/ints so
// the flow table, detectors, and TUI never re-parse raw bytes.
struct Packet {
    // timing / sizing (filled by the capture layer)
    double timestamp = 0.0;   // seconds, from the capture
    std::uint32_t wire_len = 0;
    std::uint32_t cap_len = 0;

    // layer 2
    std::optional<EthernetHeader> eth;
    std::optional<ArpHeader> arp;

    // layer 3
    L3 l3 = L3::None;
    std::string src_ip;
    std::string dst_ip;
    std::uint8_t ip_proto = 0;
    std::uint8_t ttl = 0;

    // layer 4
    L4 l4 = L4::None;
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    TcpFlags tcp_flags;
    std::uint32_t tcp_seq = 0;
    std::uint32_t payload_len = 0;

    // application
    std::optional<DnsInfo> dns;

    bool malformed = false;
    std::string note;  // reason when malformed

    std::string summary() const;             // one-line, tcpdump-ish
    const char* l4_name() const;
};

// Dissect one link-layer frame. `linktype` is the pcap DLT_* value.
Packet dissect(Bytes frame, int linktype, double timestamp,
               std::uint32_t wire_len);

}  // namespace pktscope

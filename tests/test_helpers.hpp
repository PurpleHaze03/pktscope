// Helpers to build raw packet byte buffers for parser/detector tests.
#pragma once

#include <cstdint>
#include <vector>

#include "pktscope/dissector.hpp"

namespace pktscope::test {

using Buf = std::vector<std::uint8_t>;

inline void put16(Buf& b, std::uint16_t v) {
    b.push_back(v >> 8);
    b.push_back(v & 0xFF);
}
inline void put32(Buf& b, std::uint32_t v) {
    b.push_back((v >> 24) & 0xFF);
    b.push_back((v >> 16) & 0xFF);
    b.push_back((v >> 8) & 0xFF);
    b.push_back(v & 0xFF);
}
inline void put_mac(Buf& b, std::uint8_t last) {
    for (int i = 0; i < 5; ++i) b.push_back(0xAA);
    b.push_back(last);
}

// Ethernet header with a given ethertype.
inline void eth(Buf& b, std::uint16_t ethertype, std::uint8_t src_last = 0x01) {
    put_mac(b, 0xFF);       // dst
    put_mac(b, src_last);   // src
    put16(b, ethertype);
}

// IPv4 header (20 bytes, no options). Returns nothing; appends to b.
inline void ipv4(Buf& b, std::uint8_t proto, std::uint32_t src, std::uint32_t dst,
                 std::uint16_t total_len = 40) {
    b.push_back(0x45);            // version 4, IHL 5
    b.push_back(0x00);            // dscp/ecn
    put16(b, total_len);
    put16(b, 0x0000);            // id
    put16(b, 0x0000);            // flags/frag
    b.push_back(64);             // ttl
    b.push_back(proto);
    put16(b, 0x0000);            // checksum (unchecked)
    put32(b, src);
    put32(b, dst);
}

// TCP header (20 bytes, no options). flags byte per RFC.
inline void tcp(Buf& b, std::uint16_t sport, std::uint16_t dport,
                std::uint8_t flags, std::uint32_t seq = 1000) {
    put16(b, sport);
    put16(b, dport);
    put32(b, seq);
    put32(b, 0);                 // ack
    b.push_back(0x50);           // data offset 5 words
    b.push_back(flags);
    put16(b, 0xFFFF);            // window
    put16(b, 0x0000);            // checksum
    put16(b, 0x0000);            // urgent
}

inline void udp(Buf& b, std::uint16_t sport, std::uint16_t dport, std::uint16_t len = 8) {
    put16(b, sport);
    put16(b, dport);
    put16(b, len);
    put16(b, 0x0000);
}

// TCP flag bit constants
constexpr std::uint8_t F_FIN = 0x01, F_SYN = 0x02, F_RST = 0x04, F_PSH = 0x08,
                       F_ACK = 0x10, F_URG = 0x20;

// Build a full Ethernet/IPv4/TCP packet and dissect it.
inline Packet make_tcp(std::uint32_t src, std::uint32_t dst, std::uint16_t sport,
                       std::uint16_t dport, std::uint8_t flags, double ts = 0.0) {
    Buf b;
    eth(b, 0x0800);
    ipv4(b, 6, src, dst);
    tcp(b, sport, dport, flags);
    return dissect(Bytes(b.data(), b.size()), 1 /*DLT_EN10MB*/, ts, (std::uint32_t)b.size());
}

}  // namespace pktscope::test

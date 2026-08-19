// Protocol header definitions and bounds-checked parsers (L2-L4 + DNS).
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>

#include "pktscope/byte_reader.hpp"

namespace pktscope {

// ---- address helpers -------------------------------------------------------

using MacAddr = std::array<std::uint8_t, 6>;

std::string mac_to_string(const MacAddr& mac);
std::string ipv4_to_string(std::uint32_t addr_be);          // addr in network order
std::string ipv6_to_string(const std::array<std::uint8_t, 16>& addr);

// ---- EtherType / IP protocol numbers we care about -------------------------

enum class EtherType : std::uint16_t {
    IPv4 = 0x0800,
    ARP = 0x0806,
    IPv6 = 0x86DD,
    VLAN = 0x8100,
};

enum class IpProto : std::uint8_t {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    ICMPv6 = 58,
    Other = 255,
};

// ---- Layer 2 ---------------------------------------------------------------

struct EthernetHeader {
    MacAddr dst{};
    MacAddr src{};
    std::uint16_t ethertype = 0;  // host order
};

struct ArpHeader {
    std::uint16_t hw_type = 0;
    std::uint16_t proto_type = 0;
    std::uint16_t opcode = 0;  // 1 = request, 2 = reply
    MacAddr sender_mac{};
    std::uint32_t sender_ip = 0;  // network order
    MacAddr target_mac{};
    std::uint32_t target_ip = 0;
    bool is_reply() const { return opcode == 2; }
    bool is_request() const { return opcode == 1; }
};

// ---- Layer 3 ---------------------------------------------------------------

struct Ipv4Header {
    std::uint8_t ihl = 0;         // header length in bytes
    std::uint8_t ttl = 0;
    std::uint8_t protocol = 0;
    std::uint16_t total_length = 0;
    std::uint32_t src = 0;        // network order
    std::uint32_t dst = 0;
};

struct Ipv6Header {
    std::uint8_t next_header = 0;
    std::uint8_t hop_limit = 0;
    std::uint16_t payload_length = 0;
    std::array<std::uint8_t, 16> src{};
    std::array<std::uint8_t, 16> dst{};
};

// ---- Layer 4 ---------------------------------------------------------------

struct TcpFlags {
    bool fin = false, syn = false, rst = false, psh = false;
    bool ack = false, urg = false, ece = false, cwr = false;
    std::string to_string() const;  // e.g. "SYN,ACK"
    bool only(bool f, bool s, bool r, bool p, bool a, bool u) const {
        return fin == f && syn == s && rst == r && psh == p && ack == a && urg == u;
    }
};

struct TcpHeader {
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint32_t seq = 0;
    std::uint32_t ack = 0;
    std::uint8_t data_offset = 0;  // header length in bytes
    TcpFlags flags;
    std::uint16_t window = 0;
};

struct UdpHeader {
    std::uint16_t src_port = 0;
    std::uint16_t dst_port = 0;
    std::uint16_t length = 0;
};

struct IcmpHeader {
    std::uint8_t type = 0;
    std::uint8_t code = 0;
};

// ---- DNS (just enough for the tunneling heuristic) -------------------------

struct DnsInfo {
    std::uint16_t id = 0;
    bool is_response = false;
    std::uint16_t qd_count = 0;
    std::string first_qname;  // decoded, dot-separated
    std::uint16_t qtype = 0;
};

// ---- parsers: each returns nullopt on malformed/truncated input ------------
// On success, the ByteReader is advanced to the start of the next layer.

std::optional<EthernetHeader> parse_ethernet(ByteReader& r);
std::optional<ArpHeader> parse_arp(ByteReader& r);
std::optional<Ipv4Header> parse_ipv4(ByteReader& r);
std::optional<Ipv6Header> parse_ipv6(ByteReader& r);
std::optional<TcpHeader> parse_tcp(ByteReader& r);
std::optional<UdpHeader> parse_udp(ByteReader& r);
std::optional<IcmpHeader> parse_icmp(ByteReader& r);
std::optional<DnsInfo> parse_dns(Bytes payload);

const char* ip_proto_name(std::uint8_t proto);

}  // namespace pktscope

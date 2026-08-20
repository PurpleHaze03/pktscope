// Regression tests for issues found in the code-review pass.
#include "doctest.h"
#include "pktscope/detect.hpp"
#include "pktscope/dissector.hpp"
#include "test_helpers.hpp"

using namespace pktscope;
using namespace pktscope::test;

static bool has_kind(const std::vector<Alert>& a, const std::string& kind) {
    for (const auto& x : a) if (x.kind == kind) return true;
    return false;
}

// ---- IPv6 extension headers no longer blind L4 detection ------------------

TEST_CASE("IPv6 with a Destination-Options ext header still finds TCP") {
    Buf b;
    eth(b, 0x86DD);
    // IPv6 fixed header, next_header = 60 (Destination Options)
    put32(b, 0x60000000);
    put16(b, 28);        // payload length (8 ext + 20 tcp)
    b.push_back(60);     // next header = Dest Options
    b.push_back(64);     // hop limit
    for (int i = 0; i < 16; ++i) b.push_back(i == 15 ? 0x01 : 0x20);  // src
    for (int i = 0; i < 16; ++i) b.push_back(i == 15 ? 0x02 : 0x20);  // dst
    // Destination Options ext header: next=6 (TCP), hdr_ext_len=0 -> 8 bytes
    b.push_back(6);      // next header = TCP
    b.push_back(0);      // hdr ext len (0 -> total 8 bytes)
    for (int i = 0; i < 6; ++i) b.push_back(0);  // options padding
    tcp(b, 4444, 443, F_SYN);

    Packet p = dissect(Bytes(b.data(), b.size()), 1, 0.0, (std::uint32_t)b.size());
    REQUIRE(!p.malformed);
    CHECK(p.l3 == L3::IPv6);
    CHECK(p.l4 == L4::Tcp);       // used to be L4::None (evasion)
    CHECK(p.dst_port == 443);
}

TEST_CASE("IPv6 Fragment header is skipped to reach TCP") {
    Buf b;
    eth(b, 0x86DD);
    put32(b, 0x60000000);
    put16(b, 28);
    b.push_back(44);     // next header = Fragment
    b.push_back(64);
    for (int i = 0; i < 16; ++i) b.push_back(0x20);
    for (int i = 0; i < 16; ++i) b.push_back(0x30);
    // Fragment header: 8 bytes fixed
    b.push_back(6);      // next = TCP
    b.push_back(0);      // reserved
    put16(b, 0);         // fragment offset + flags
    put32(b, 0x1234);    // identification
    tcp(b, 1000, 80, F_SYN);
    Packet p = dissect(Bytes(b.data(), b.size()), 1, 0.0, (std::uint32_t)b.size());
    REQUIRE(!p.malformed);
    CHECK(p.l4 == L4::Tcp);
    CHECK(p.dst_port == 80);
}

// ---- ARP spoofing via gratuitous request (not just reply) -----------------

static Packet arp_packet(std::uint16_t opcode, std::uint32_t ip, std::uint8_t mac_last) {
    Buf b;
    eth(b, 0x0806);
    put16(b, 1); put16(b, 0x0800);
    b.push_back(6); b.push_back(4);
    put16(b, opcode);
    put_mac(b, mac_last);   // sender mac
    put32(b, ip);           // sender ip
    put_mac(b, 0x00);
    put32(b, 0);
    return dissect(Bytes(b.data(), b.size()), 1, 0.0, (std::uint32_t)b.size());
}

TEST_CASE("ARP spoof detected via gratuitous REQUEST, not only reply") {
    Detector det;
    // learn binding from a request (opcode 1)
    CHECK_FALSE(has_kind(det.inspect(arp_packet(1, 0xC0A80101, 0x11)), "arp-spoof"));
    // attacker poisons via another request with a different MAC
    CHECK(has_kind(det.inspect(arp_packet(1, 0xC0A80101, 0x99)), "arp-spoof"));
}

// ---- stacked VLAN (QinQ) reaches the inner IP ------------------------------

TEST_CASE("QinQ double-tagged frame is dissected to TCP") {
    Buf b;
    put_mac(b, 0xFF);        // dst
    put_mac(b, 0x01);        // src
    put16(b, 0x88A8);        // outer S-VLAN tag
    put16(b, 0x0064);        // vlan id
    put16(b, 0x8100);        // inner C-VLAN tag
    put16(b, 0x000A);        // vlan id
    put16(b, 0x0800);        // inner ethertype = IPv4
    ipv4(b, 6, 0x0A000001, 0x0A000002);
    tcp(b, 1234, 22, F_SYN);
    Packet p = dissect(Bytes(b.data(), b.size()), 1, 0.0, (std::uint32_t)b.size());
    REQUIRE(!p.malformed);
    CHECK(p.l3 == L3::IPv4);
    CHECK(p.l4 == L4::Tcp);
    CHECK(p.dst_port == 22);
}

// ---- stealth-scan classifier ignores ECN flags ----------------------------

TEST_CASE("ECE-only packet is not misclassified as a NULL scan") {
    Detector det;
    constexpr std::uint8_t F_ECE = 0x40;
    auto alerts = det.inspect(make_tcp(1, 2, 100, 80, F_ECE, 1.0));
    CHECK_FALSE(has_kind(alerts, "stealth-scan"));
}

TEST_CASE("a real NULL scan is still detected") {
    Detector det;
    CHECK(has_kind(det.inspect(make_tcp(1, 2, 100, 80, 0, 1.0)), "stealth-scan"));
}

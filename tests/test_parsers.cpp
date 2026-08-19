#include "doctest.h"
#include "pktscope/dissector.hpp"
#include "pktscope/protocols.hpp"
#include "test_helpers.hpp"

using namespace pktscope;
using namespace pktscope::test;

TEST_CASE("address formatting") {
    CHECK(ipv4_to_string(0xC0A80101) == "192.168.1.1");
    MacAddr m{0xde, 0xad, 0xbe, 0xef, 0x00, 0x01};
    CHECK(mac_to_string(m) == "de:ad:be:ef:00:01");
}

TEST_CASE("dissect Ethernet/IPv4/TCP") {
    Packet p = make_tcp(0xC0A80102, 0xC0A80101, 12345, 80, F_SYN, 1.0);
    REQUIRE(!p.malformed);
    CHECK(p.l3 == L3::IPv4);
    CHECK(p.src_ip == "192.168.1.2");
    CHECK(p.dst_ip == "192.168.1.1");
    CHECK(p.l4 == L4::Tcp);
    CHECK(p.src_port == 12345);
    CHECK(p.dst_port == 80);
    CHECK(p.tcp_flags.syn);
    CHECK_FALSE(p.tcp_flags.ack);
}

TEST_CASE("TCP flag decoding") {
    Packet p = make_tcp(1, 2, 1000, 2000, F_SYN | F_ACK);
    CHECK(p.tcp_flags.syn);
    CHECK(p.tcp_flags.ack);
    CHECK(p.tcp_flags.to_string() == "SYN,ACK");
}

TEST_CASE("UDP + DNS query parsing") {
    Buf b;
    eth(b, 0x0800);
    ipv4(b, 17, 0x0A000001, 0x08080808);
    udp(b, 40000, 53);
    // DNS: id, flags(query), qd=1, an/ns/ar=0, qname "example.com", qtype A
    put16(b, 0x1234);
    put16(b, 0x0100);  // standard query
    put16(b, 1);       // qdcount
    put16(b, 0); put16(b, 0); put16(b, 0);
    const char* labels[] = {"example", "com"};
    for (const char* l : labels) {
        b.push_back((std::uint8_t)std::string(l).size());
        for (char c : std::string(l)) b.push_back((std::uint8_t)c);
    }
    b.push_back(0);    // root
    put16(b, 1);       // qtype A
    put16(b, 1);       // qclass IN

    Packet p = dissect(Bytes(b.data(), b.size()), 1, 0.0, (std::uint32_t)b.size());
    REQUIRE(!p.malformed);
    CHECK(p.l4 == L4::Udp);
    REQUIRE(p.dns.has_value());
    CHECK(p.dns->first_qname == "example.com");
    CHECK_FALSE(p.dns->is_response);
}

TEST_CASE("ARP request/reply") {
    Buf b;
    eth(b, 0x0806);
    put16(b, 1);          // hw type ethernet
    put16(b, 0x0800);     // proto ipv4
    b.push_back(6); b.push_back(4);
    put16(b, 2);          // opcode reply
    put_mac(b, 0x11);     // sender mac
    put32(b, 0xC0A80101); // sender ip
    put_mac(b, 0x22);     // target mac
    put32(b, 0xC0A80102); // target ip

    Packet p = dissect(Bytes(b.data(), b.size()), 1, 0.0, (std::uint32_t)b.size());
    REQUIRE(!p.malformed);
    CHECK(p.l3 == L3::Arp);
    REQUIRE(p.arp.has_value());
    CHECK(p.arp->is_reply());
    CHECK(ipv4_to_string(p.arp->sender_ip) == "192.168.1.1");
}

// The security-critical property: malformed / truncated input must never crash,
// only ever yield malformed==true.
TEST_CASE("truncated packets never crash") {
    Buf full;
    eth(full, 0x0800);
    ipv4(full, 6, 1, 2);
    tcp(full, 1, 2, F_SYN);

    for (std::size_t len = 0; len <= full.size(); ++len) {
        Buf slice(full.begin(), full.begin() + len);
        Packet p = dissect(Bytes(slice.data(), slice.size()), 1, 0.0, (std::uint32_t)len);
        // Either it parsed a prefix cleanly or flagged malformed -- never UB.
        CHECK((p.malformed || p.l3 != L3::None || len < 14));
    }
}

TEST_CASE("garbage bytes never crash") {
    for (int seed = 0; seed < 500; ++seed) {
        Buf b;
        std::uint32_t x = seed * 2654435761u;
        for (int i = 0; i < (seed % 60); ++i) {
            x = x * 1103515245u + 12345u;
            b.push_back((std::uint8_t)(x >> 16));
        }
        Packet p = dissect(Bytes(b.data(), b.size()), 1, 0.0, (std::uint32_t)b.size());
        CHECK((p.malformed || !p.malformed));  // reached here == no crash
    }
}

TEST_CASE("IPv6/TCP dissection") {
    Buf b;
    eth(b, 0x86DD);
    // IPv6 header
    put32(b, 0x60000000);  // version 6
    put16(b, 20);          // payload length
    b.push_back(6);        // next header TCP
    b.push_back(64);       // hop limit
    for (int i = 0; i < 16; ++i) b.push_back(i == 15 ? 0x01 : 0x20);  // src
    for (int i = 0; i < 16; ++i) b.push_back(i == 15 ? 0x02 : 0x20);  // dst
    tcp(b, 1111, 443, F_SYN);
    Packet p = dissect(Bytes(b.data(), b.size()), 1, 0.0, (std::uint32_t)b.size());
    REQUIRE(!p.malformed);
    CHECK(p.l3 == L3::IPv6);
    CHECK(p.l4 == L4::Tcp);
    CHECK(p.dst_port == 443);
}

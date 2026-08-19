#include "doctest.h"
#include "pktscope/detect.hpp"
#include "test_helpers.hpp"

using namespace pktscope;
using namespace pktscope::test;

static bool has_kind(const std::vector<Alert>& alerts, const std::string& kind) {
    for (const auto& a : alerts) if (a.kind == kind) return true;
    return false;
}

TEST_CASE("port scan: many ports from one source triggers alert") {
    Detector det;
    std::uint32_t attacker = 0x0A000001, victim = 0x0A000002;
    bool fired = false;
    for (int port = 1; port <= 20; ++port) {
        Packet p = make_tcp(attacker, victim, 40000, (std::uint16_t)port, F_SYN, port * 0.1);
        auto alerts = det.inspect(p);
        if (has_kind(alerts, "port-scan")) fired = true;
    }
    CHECK(fired);
}

TEST_CASE("normal traffic does not trigger a port scan") {
    Detector det;
    // Repeated full connections to ONE port look nothing like a scan.
    for (int i = 0; i < 30; ++i) {
        double t = i * 0.1;
        det.inspect(make_tcp(0x0A000001, 0x0A000002, 50000 + i, 443, F_SYN, t));
        det.inspect(make_tcp(0x0A000002, 0x0A000001, 443, 50000 + i, F_SYN | F_ACK, t + 0.01));
        det.inspect(make_tcp(0x0A000001, 0x0A000002, 50000 + i, 443, F_ACK, t + 0.02));
    }
    CHECK_FALSE(has_kind(det.all_alerts(), "port-scan"));
}

TEST_CASE("port scan window: slow scan below rate does not fire") {
    DetectorConfig cfg;
    cfg.port_scan_threshold = 15;
    cfg.port_scan_window = 5.0;
    Detector det(cfg);
    // one port every 2 seconds -> never 15 within any 5s window
    for (int port = 1; port <= 20; ++port)
        det.inspect(make_tcp(0x0A000001, 0x0A000002, 40000, (std::uint16_t)port, F_SYN, port * 2.0));
    CHECK_FALSE(has_kind(det.all_alerts(), "port-scan"));
}

TEST_CASE("stealth scans: NULL, FIN, Xmas flag combos") {
    Detector det;
    CHECK(has_kind(det.inspect(make_tcp(1, 2, 100, 80, 0, 1.0)), "stealth-scan"));          // NULL
    CHECK(has_kind(det.inspect(make_tcp(1, 2, 100, 81, F_FIN, 2.0)), "stealth-scan"));       // FIN
    CHECK(has_kind(det.inspect(make_tcp(1, 2, 100, 82, F_FIN | F_PSH | F_URG, 3.0)),
                   "stealth-scan"));                                                          // Xmas
    // a normal SYN is not a stealth scan
    CHECK_FALSE(has_kind(det.inspect(make_tcp(1, 2, 100, 83, F_SYN, 4.0)), "stealth-scan"));
}

TEST_CASE("ARP spoofing: IP moving to a new MAC") {
    Detector det;
    auto arp_reply = [](std::uint32_t ip, std::uint8_t mac_last, double ts) {
        Buf b;
        eth(b, 0x0806);
        put16(b, 1); put16(b, 0x0800);
        b.push_back(6); b.push_back(4);
        put16(b, 2);           // reply
        put_mac(b, mac_last);  // sender mac
        put32(b, ip);
        put_mac(b, 0x00);
        put32(b, 0);
        return dissect(Bytes(b.data(), b.size()), 1, ts, (std::uint32_t)b.size());
    };
    CHECK_FALSE(has_kind(det.inspect(arp_reply(0xC0A80101, 0x11, 1.0)), "arp-spoof"));  // learn
    CHECK_FALSE(has_kind(det.inspect(arp_reply(0xC0A80101, 0x11, 2.0)), "arp-spoof"));  // same
    CHECK(has_kind(det.inspect(arp_reply(0xC0A80101, 0x99, 3.0)), "arp-spoof"));        // moved!
}

TEST_CASE("SYN flood: burst of SYNs to one target") {
    DetectorConfig cfg;
    cfg.syn_flood_threshold = 50;
    cfg.syn_flood_window = 2.0;
    Detector det(cfg);
    bool fired = false;
    for (int i = 0; i < 60; ++i) {
        // many different source ports, same victim:port, tightly packed in time
        Packet p = make_tcp(0x0A000001, 0x0A00000A, (std::uint16_t)(1024 + i), 80, F_SYN,
                            i * 0.01);
        if (has_kind(det.inspect(p), "syn-flood")) fired = true;
    }
    CHECK(fired);
}

TEST_CASE("DNS tunneling: long/complex qname") {
    Detector det;
    Buf b;
    eth(b, 0x0800);
    ipv4(b, 17, 0x0A000001, 0x08080808);
    udp(b, 40000, 53);
    put16(b, 0x1); put16(b, 0x0100); put16(b, 1);
    put16(b, 0); put16(b, 0); put16(b, 0);
    // 8 long labels -> both length and label-count heuristics fire
    for (int i = 0; i < 8; ++i) {
        std::string lbl = "abcdef0123456789seg" + std::to_string(i);
        b.push_back((std::uint8_t)lbl.size());
        for (char c : lbl) b.push_back((std::uint8_t)c);
    }
    b.push_back(0);
    put16(b, 16); put16(b, 1);
    Packet p = dissect(Bytes(b.data(), b.size()), 1, 1.0, (std::uint32_t)b.size());
    REQUIRE(p.dns.has_value());
    CHECK(has_kind(det.inspect(p), "dns-tunnel"));
}

TEST_CASE("normal DNS query does not trigger tunneling alert") {
    Detector det;
    Buf b;
    eth(b, 0x0800);
    ipv4(b, 17, 0x0A000001, 0x08080808);
    udp(b, 40000, 53);
    put16(b, 0x1); put16(b, 0x0100); put16(b, 1);
    put16(b, 0); put16(b, 0); put16(b, 0);
    for (const char* l : {"www", "google", "com"}) {
        b.push_back((std::uint8_t)std::string(l).size());
        for (char c : std::string(l)) b.push_back((std::uint8_t)c);
    }
    b.push_back(0);
    put16(b, 1); put16(b, 1);
    Packet p = dissect(Bytes(b.data(), b.size()), 1, 1.0, (std::uint32_t)b.size());
    CHECK_FALSE(has_kind(det.inspect(p), "dns-tunnel"));
}

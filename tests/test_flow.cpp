#include "doctest.h"
#include "pktscope/flow.hpp"
#include "test_helpers.hpp"

using namespace pktscope;
using namespace pktscope::test;

TEST_CASE("bidirectional packets collapse into one flow") {
    FlowTable ft;
    ft.update(make_tcp(0x0A000001, 0x0A000002, 5000, 80, F_SYN, 1.0));
    ft.update(make_tcp(0x0A000002, 0x0A000001, 80, 5000, F_SYN | F_ACK, 1.1));
    ft.update(make_tcp(0x0A000001, 0x0A000002, 5000, 80, F_ACK, 1.2));
    CHECK(ft.size() == 1);
}

TEST_CASE("distinct conversations are separate flows") {
    FlowTable ft;
    ft.update(make_tcp(0x0A000001, 0x0A000002, 5000, 80, F_SYN, 1.0));
    ft.update(make_tcp(0x0A000001, 0x0A000003, 5000, 80, F_SYN, 1.0));
    CHECK(ft.size() == 2);
}

TEST_CASE("TCP handshake drives state to ESTABLISHED") {
    FlowTable ft;
    ft.update(make_tcp(0x0A000001, 0x0A000002, 5000, 80, F_SYN, 1.0));
    ft.update(make_tcp(0x0A000002, 0x0A000001, 80, 5000, F_SYN | F_ACK, 1.1));
    Flow& f = ft.update(make_tcp(0x0A000001, 0x0A000002, 5000, 80, F_ACK, 1.2));
    CHECK(f.state == TcpState::Established);
    CHECK(ft.active_tcp() == 1);
}

TEST_CASE("RST closes the flow") {
    FlowTable ft;
    ft.update(make_tcp(0x0A000001, 0x0A000002, 5000, 80, F_SYN, 1.0));
    Flow& f = ft.update(make_tcp(0x0A000002, 0x0A000001, 80, 5000, F_RST, 1.1));
    CHECK(f.state == TcpState::Closed);
}

TEST_CASE("top talkers ranked by bytes") {
    FlowTable ft;
    // small flow
    ft.update(make_tcp(0x0A000001, 0x0A000002, 5000, 80, F_SYN, 1.0));
    // big flow: many packets between another pair
    for (int i = 0; i < 50; ++i)
        ft.update(make_tcp(0x0A000005, 0x0A000006, 6000, 443, F_ACK, 2.0 + i));
    auto top = ft.top_by_bytes(2);
    REQUIRE(top.size() == 2);
    CHECK(top[0].bytes > top[1].bytes);
    CHECK(top[0].src_port == 6000);
}

// Running counters for the dashboard and the end-of-run report.
#pragma once

#include <cstdint>
#include <map>
#include <string>

#include "pktscope/dissector.hpp"

namespace pktscope {

struct Stats {
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;
    std::uint64_t malformed = 0;

    std::uint64_t eth = 0, arp = 0, ipv4 = 0, ipv6 = 0;
    std::uint64_t tcp = 0, udp = 0, icmp = 0, dns = 0;

    double first_ts = 0.0;
    double last_ts = 0.0;

    // top L4 destination ports by packet count
    std::map<std::uint16_t, std::uint64_t> dst_port_counts;

    void add(const Packet& p);
    double duration() const { return last_ts > first_ts ? last_ts - first_ts : 0.0; }
    double pps() const;   // packets per second over the capture
    double mbps() const;  // megabits per second over the capture
};

}  // namespace pktscope

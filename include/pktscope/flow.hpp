// Flow table: aggregates packets into bidirectional 5-tuple conversations,
// tracks a simplified TCP state machine, and keeps top-talker statistics.
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "pktscope/dissector.hpp"

namespace pktscope {

enum class TcpState {
    None,        // non-TCP or not yet seen
    SynSent,     // SYN observed
    SynAck,      // SYN-ACK observed
    Established,  // handshake completed (ACK after SYN-ACK, or data seen)
    Closing,     // FIN seen from at least one side
    Closed,      // RST, or FINs both ways
};

const char* tcp_state_name(TcpState s);

// A canonical, direction-independent key so both halves of a conversation map
// to one flow (the endpoint pair is sorted).
struct FlowKey {
    std::string a_ip, b_ip;
    std::uint16_t a_port = 0, b_port = 0;
    std::uint8_t proto = 0;
    bool operator==(const FlowKey& o) const {
        return proto == o.proto && a_port == o.a_port && b_port == o.b_port &&
               a_ip == o.a_ip && b_ip == o.b_ip;
    }
};

struct FlowKeyHash {
    std::size_t operator()(const FlowKey& k) const;
};

struct Flow {
    FlowKey key;
    std::string src_ip, dst_ip;   // as first seen (initiator side)
    std::uint16_t src_port = 0, dst_port = 0;
    std::uint8_t proto = 0;
    std::uint64_t packets = 0;
    std::uint64_t bytes = 0;
    double first_seen = 0.0;
    double last_seen = 0.0;
    TcpState state = TcpState::None;

    std::string proto_name() const;
    std::string describe() const;  // "1.2.3.4:5 -> 6.7.8.9:80 TCP"
};

class FlowTable {
public:
    // Update (or create) the flow for this packet; returns the flow.
    Flow& update(const Packet& p);

    std::size_t size() const { return flows_.size(); }

    // Flows sorted by bytes, descending (top talkers).
    std::vector<Flow> top_by_bytes(std::size_t n) const;

    std::size_t active_tcp() const;

private:
    static FlowKey make_key(const Packet& p);
    std::unordered_map<FlowKey, Flow, FlowKeyHash> flows_;
};

}  // namespace pktscope

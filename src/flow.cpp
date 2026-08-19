#include "pktscope/flow.hpp"

#include <algorithm>
#include <functional>

namespace pktscope {

const char* tcp_state_name(TcpState s) {
    switch (s) {
        case TcpState::SynSent: return "SYN_SENT";
        case TcpState::SynAck: return "SYN_ACK";
        case TcpState::Established: return "ESTABLISHED";
        case TcpState::Closing: return "CLOSING";
        case TcpState::Closed: return "CLOSED";
        default: return "-";
    }
}

std::size_t FlowKeyHash::operator()(const FlowKey& k) const {
    std::size_t h = std::hash<std::string>{}(k.a_ip);
    auto mix = [&h](std::size_t v) { h ^= v + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2); };
    mix(std::hash<std::string>{}(k.b_ip));
    mix(k.a_port);
    mix(k.b_port);
    mix(k.proto);
    return h;
}

std::string Flow::proto_name() const {
    switch (proto) {
        case 6: return "TCP";
        case 17: return "UDP";
        case 1: return "ICMP";
        case 58: return "ICMPv6";
        default: return "IP";
    }
}

std::string Flow::describe() const {
    if (proto == 6 || proto == 17) {
        return src_ip + ":" + std::to_string(src_port) + " -> " + dst_ip + ":" +
               std::to_string(dst_port) + " " + proto_name();
    }
    return src_ip + " -> " + dst_ip + " " + proto_name();
}

FlowKey FlowTable::make_key(const Packet& p) {
    FlowKey k;
    k.proto = p.ip_proto;
    // Sort endpoints so A->B and B->A collapse into one flow.
    bool a_first = std::tie(p.src_ip, p.src_port) <= std::tie(p.dst_ip, p.dst_port);
    if (a_first) {
        k.a_ip = p.src_ip; k.a_port = p.src_port;
        k.b_ip = p.dst_ip; k.b_port = p.dst_port;
    } else {
        k.a_ip = p.dst_ip; k.a_port = p.dst_port;
        k.b_ip = p.src_ip; k.b_port = p.src_port;
    }
    return k;
}

// Advance the simplified TCP state machine on each observed segment.
static TcpState next_state(TcpState cur, const TcpFlags& f) {
    if (f.rst) return TcpState::Closed;
    if (f.syn && !f.ack) return TcpState::SynSent;
    if (f.syn && f.ack) return TcpState::SynAck;
    if (f.fin) return cur == TcpState::Closing ? TcpState::Closed : TcpState::Closing;
    if (f.ack) {
        if (cur == TcpState::SynAck || cur == TcpState::SynSent) return TcpState::Established;
        if (cur == TcpState::None) return TcpState::Established;  // mid-stream capture
    }
    return cur == TcpState::None ? TcpState::Established : cur;
}

Flow& FlowTable::update(const Packet& p) {
    FlowKey key = make_key(p);
    auto it = flows_.find(key);
    if (it == flows_.end()) {
        Flow f;
        f.key = key;
        f.src_ip = p.src_ip; f.src_port = p.src_port;
        f.dst_ip = p.dst_ip; f.dst_port = p.dst_port;
        f.proto = p.ip_proto;
        f.first_seen = p.timestamp;
        it = flows_.emplace(key, std::move(f)).first;
    }
    Flow& f = it->second;
    f.packets += 1;
    f.bytes += p.wire_len;
    f.last_seen = p.timestamp;
    if (p.l4 == L4::Tcp) f.state = next_state(f.state, p.tcp_flags);
    return f;
}

std::vector<Flow> FlowTable::top_by_bytes(std::size_t n) const {
    std::vector<Flow> v;
    v.reserve(flows_.size());
    for (const auto& [_, f] : flows_) v.push_back(f);
    std::partial_sort(
        v.begin(), v.begin() + std::min(n, v.size()), v.end(),
        [](const Flow& a, const Flow& b) { return a.bytes > b.bytes; });
    if (v.size() > n) v.resize(n);
    return v;
}

std::size_t FlowTable::active_tcp() const {
    std::size_t n = 0;
    for (const auto& [_, f] : flows_)
        if (f.proto == 6 && f.state == TcpState::Established) ++n;
    return n;
}

}  // namespace pktscope

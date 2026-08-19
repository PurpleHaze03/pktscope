#include "pktscope/protocols.hpp"

#include <array>
#include <cstdio>

namespace pktscope {

// ---- address formatting ----------------------------------------------------

std::string mac_to_string(const MacAddr& mac) {
    char buf[18];
    std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                  mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

std::string ipv4_to_string(std::uint32_t addr_be) {
    // addr_be holds the four octets in network order (first octet in the MSB).
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  (addr_be >> 24) & 0xFF, (addr_be >> 16) & 0xFF,
                  (addr_be >> 8) & 0xFF, addr_be & 0xFF);
    return buf;
}

std::string ipv6_to_string(const std::array<std::uint8_t, 16>& a) {
    // Not RFC 5952 canonical (no "::" compression) but unambiguous and cheap.
    char buf[40];
    std::snprintf(buf, sizeof(buf),
                  "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                  "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                  a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
                  a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);
    return buf;
}

// ---- Layer 2 ---------------------------------------------------------------

static MacAddr read_mac(ByteReader& r) {
    Bytes b = r.take(6);
    MacAddr m{};
    for (int i = 0; i < 6; ++i) m[i] = b[i];
    return m;
}

std::optional<EthernetHeader> parse_ethernet(ByteReader& r) {
    try {
        EthernetHeader h;
        h.dst = read_mac(r);
        h.src = read_mac(r);
        h.ethertype = r.u16();
        // Skip a single 802.1Q VLAN tag if present, exposing the inner type.
        if (h.ethertype == static_cast<std::uint16_t>(EtherType::VLAN)) {
            r.skip(2);           // priority/VLAN id
            h.ethertype = r.u16();
        }
        return h;
    } catch (const ShortBuffer&) {
        return std::nullopt;
    }
}

std::optional<ArpHeader> parse_arp(ByteReader& r) {
    try {
        ArpHeader h;
        h.hw_type = r.u16();
        h.proto_type = r.u16();
        r.skip(2);  // hw len + proto len
        h.opcode = r.u16();
        h.sender_mac = read_mac(r);
        h.sender_ip = r.u32();
        h.target_mac = read_mac(r);
        h.target_ip = r.u32();
        return h;
    } catch (const ShortBuffer&) {
        return std::nullopt;
    }
}

// ---- Layer 3 ---------------------------------------------------------------

std::optional<Ipv4Header> parse_ipv4(ByteReader& r) {
    try {
        const std::size_t start = r.offset();
        std::uint8_t ver_ihl = r.u8();
        if ((ver_ihl >> 4) != 4) return std::nullopt;   // not IPv4
        std::uint8_t ihl_words = ver_ihl & 0x0F;
        if (ihl_words < 5) return std::nullopt;          // header < 20 bytes: invalid

        Ipv4Header h;
        h.ihl = static_cast<std::uint8_t>(ihl_words * 4);
        r.skip(1);                                       // DSCP/ECN
        h.total_length = r.u16();
        r.skip(2);                                       // identification
        r.skip(2);                                       // flags + fragment offset
        h.ttl = r.u8();
        h.protocol = r.u8();
        r.skip(2);                                       // header checksum
        h.src = r.u32();
        h.dst = r.u32();
        // Advance past any IP options to the L4 header.
        std::size_t consumed = r.offset() - start;
        if (h.ihl > consumed) r.skip(h.ihl - consumed);
        return h;
    } catch (const ShortBuffer&) {
        return std::nullopt;
    }
}

static std::array<std::uint8_t, 16> read_v6addr(ByteReader& r) {
    Bytes b = r.take(16);
    std::array<std::uint8_t, 16> a{};
    for (int i = 0; i < 16; ++i) a[i] = b[i];
    return a;
}

std::optional<Ipv6Header> parse_ipv6(ByteReader& r) {
    try {
        std::uint32_t vtf = r.u32();
        if ((vtf >> 28) != 6) return std::nullopt;
        Ipv6Header h;
        h.payload_length = r.u16();
        h.next_header = r.u8();
        h.hop_limit = r.u8();
        h.src = read_v6addr(r);
        h.dst = read_v6addr(r);
        return h;  // extension headers not walked; next_header used as-is
    } catch (const ShortBuffer&) {
        return std::nullopt;
    }
}

// ---- Layer 4 ---------------------------------------------------------------

std::string TcpFlags::to_string() const {
    std::string s;
    auto add = [&](bool set, const char* name) {
        if (set) { if (!s.empty()) s += ','; s += name; }
    };
    add(syn, "SYN"); add(ack, "ACK"); add(fin, "FIN");
    add(rst, "RST"); add(psh, "PSH"); add(urg, "URG");
    add(ece, "ECE"); add(cwr, "CWR");
    return s.empty() ? "none" : s;
}

std::optional<TcpHeader> parse_tcp(ByteReader& r) {
    try {
        const std::size_t start = r.offset();
        TcpHeader h;
        h.src_port = r.u16();
        h.dst_port = r.u16();
        h.seq = r.u32();
        h.ack = r.u32();
        std::uint8_t offset_reserved = r.u8();
        std::uint8_t data_off_words = (offset_reserved >> 4) & 0x0F;
        if (data_off_words < 5) return std::nullopt;
        h.data_offset = static_cast<std::uint8_t>(data_off_words * 4);
        std::uint8_t flags = r.u8();
        h.flags.fin = flags & 0x01;
        h.flags.syn = flags & 0x02;
        h.flags.rst = flags & 0x04;
        h.flags.psh = flags & 0x08;
        h.flags.ack = flags & 0x10;
        h.flags.urg = flags & 0x20;
        h.flags.ece = flags & 0x40;
        h.flags.cwr = flags & 0x80;
        h.window = r.u16();
        r.skip(2);  // checksum
        r.skip(2);  // urgent pointer
        std::size_t consumed = r.offset() - start;
        if (h.data_offset > consumed) r.skip(h.data_offset - consumed);  // TCP options
        return h;
    } catch (const ShortBuffer&) {
        return std::nullopt;
    }
}

std::optional<UdpHeader> parse_udp(ByteReader& r) {
    try {
        UdpHeader h;
        h.src_port = r.u16();
        h.dst_port = r.u16();
        h.length = r.u16();
        r.skip(2);  // checksum
        return h;
    } catch (const ShortBuffer&) {
        return std::nullopt;
    }
}

std::optional<IcmpHeader> parse_icmp(ByteReader& r) {
    try {
        IcmpHeader h;
        h.type = r.u8();
        h.code = r.u8();
        return h;
    } catch (const ShortBuffer&) {
        return std::nullopt;
    }
}

// ---- DNS -------------------------------------------------------------------

std::optional<DnsInfo> parse_dns(Bytes payload) {
    try {
        ByteReader r(payload);
        DnsInfo d;
        d.id = r.u16();
        std::uint16_t flags = r.u16();
        d.is_response = (flags & 0x8000) != 0;
        d.qd_count = r.u16();
        r.skip(6);  // an/ns/ar counts
        if (d.qd_count == 0) return d;

        // Decode the first QNAME (labels), guarding against loops/overrun.
        std::string name;
        for (int guard = 0; guard < 128; ++guard) {
            std::uint8_t len = r.u8();
            if (len == 0) break;
            if ((len & 0xC0) == 0xC0) {  // compression pointer: stop, not expected in a query
                r.skip(1);
                break;
            }
            if (len > 63) return std::nullopt;
            Bytes label = r.take(len);
            if (!name.empty()) name += '.';
            for (std::uint8_t b : label) {
                name += (b >= 32 && b < 127) ? static_cast<char>(b) : '.';
            }
        }
        d.first_qname = name;
        d.qtype = r.u16();
        return d;
    } catch (const ShortBuffer&) {
        return std::nullopt;
    }
}

const char* ip_proto_name(std::uint8_t proto) {
    switch (proto) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        case 58: return "ICMPv6";
        default: return "other";
    }
}

}  // namespace pktscope

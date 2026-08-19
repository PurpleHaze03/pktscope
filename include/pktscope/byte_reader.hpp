// Bounds-checked, big-endian byte reader over a non-owning view of packet data.
//
// Every protocol parser reads through a ByteReader so that a truncated or
// malformed packet can NEVER cause an out-of-bounds read -- the whole point of
// a security tool is that it must not itself be exploitable by the hostile
// input it inspects. Reads past the end throw ShortBuffer, which parsers turn
// into a clean "malformed" result instead of undefined behavior.
#pragma once

#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>

namespace pktscope {

using Bytes = std::span<const std::uint8_t>;

struct ShortBuffer : std::runtime_error {
    explicit ShortBuffer(const std::string& what) : std::runtime_error(what) {}
};

class ByteReader {
public:
    explicit ByteReader(Bytes data) : data_(data) {}

    std::size_t offset() const noexcept { return pos_; }
    std::size_t remaining() const noexcept { return data_.size() - pos_; }
    bool empty() const noexcept { return remaining() == 0; }

    std::uint8_t u8() {
        auto b = need(1);
        pos_ += 1;
        return b[0];
    }

    std::uint16_t u16() {  // network byte order (big-endian)
        auto b = need(2);
        pos_ += 2;
        return static_cast<std::uint16_t>((b[0] << 8) | b[1]);
    }

    std::uint32_t u32() {
        auto b = need(4);
        pos_ += 4;
        return (std::uint32_t(b[0]) << 24) | (std::uint32_t(b[1]) << 16) |
               (std::uint32_t(b[2]) << 8) | std::uint32_t(b[3]);
    }

    // Return a view of the next n bytes and advance past them.
    Bytes take(std::size_t n) {
        auto b = need(n);
        pos_ += n;
        return b;
    }

    // Skip n bytes (e.g. options we don't parse).
    void skip(std::size_t n) { (void)need(n); pos_ += n; }

    // The rest of the buffer as a view, consuming it.
    Bytes rest() {
        Bytes r = data_.subspan(pos_);
        pos_ = data_.size();
        return r;
    }

    // A view of the rest WITHOUT consuming (for payload inspection).
    Bytes peek_rest() const { return data_.subspan(pos_); }

private:
    Bytes need(std::size_t n) {
        if (n > remaining()) {
            throw ShortBuffer("need " + std::to_string(n) + " bytes, have " +
                              std::to_string(remaining()));
        }
        return data_.subspan(pos_, n);
    }

    Bytes data_;
    std::size_t pos_ = 0;
};

}  // namespace pktscope

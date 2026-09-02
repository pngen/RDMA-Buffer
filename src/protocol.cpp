// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "rdmabuffer/protocol.hpp"

#include <cstring>

namespace rdmabuffer {
namespace protocol {

namespace {
void put32(std::vector<std::uint8_t>& v, std::uint32_t x) {
    for (int i = 0; i < 4; ++i) v.push_back(static_cast<std::uint8_t>((x >> (8 * i)) & 0xFF));
}
void put64(std::vector<std::uint8_t>& v, std::uint64_t x) {
    for (int i = 0; i < 8; ++i) v.push_back(static_cast<std::uint8_t>((x >> (8 * i)) & 0xFF));
}
bool get32(std::span<const std::uint8_t> d, std::size_t& p, std::uint32_t& x) {
    if (p + 4 > d.size()) return false;
    x = 0;
    for (int i = 0; i < 4; ++i) x |= static_cast<std::uint32_t>(d[p++]) << (8 * i);
    return true;
}
bool get64(std::span<const std::uint8_t> d, std::size_t& p, std::uint64_t& x) {
    if (p + 8 > d.size()) return false;
    x = 0;
    for (int i = 0; i < 8; ++i) x |= static_cast<std::uint64_t>(d[p++]) << (8 * i);
    return true;
}
} // namespace

std::vector<std::uint8_t> encode_frame(MessageKind kind, std::uint64_t seq,
                                       std::span<const std::uint8_t> payload) {
    if (payload.size() > max_payload) return {};

    std::vector<std::uint8_t> frame;
    frame.reserve(header_size + payload.size() + 4);
    put32(frame, frame_magic);
    put32(frame, frame_version);
    put32(frame, static_cast<std::uint32_t>(kind));
    put64(frame, seq);
    put64(frame, static_cast<std::uint64_t>(payload.size()));
    for (auto b : payload) frame.push_back(b);
    const std::uint32_t crc = crc32(frame.data(), frame.size());
    put32(frame, crc);
    return frame;
}

bool decode_frame(std::span<const std::uint8_t> data, Frame& out, std::size_t& consumed,
                  std::string& err) {
    consumed = 0;
    if (data.size() < header_size) {
        err = "TRUNCATED";
        return false;
    }
    std::size_t p = 0;
    std::uint32_t magic = 0, version = 0, kindu = 0;
    std::uint64_t seq = 0, len = 0;
    if (!get32(data, p, magic) || !get32(data, p, version) || !get32(data, p, kindu) ||
        !get64(data, p, seq) || !get64(data, p, len)) {
        err = "TRUNCATED";
        return false;
    }
    if (magic != frame_magic) {
        err = "BAD_MAGIC";
        return false;
    }
    if (version != frame_version) {
        err = "BAD_VERSION";
        return false;
    }
    if (kindu >= static_cast<std::uint32_t>(MessageKind::MAX) || kindu == 0) {
        err = "INVALID_ENUM";
        return false;
    }
    if (len > max_payload) {
        err = "OVERSIZED";
        return false;
    }
    const std::size_t total = header_size + static_cast<std::size_t>(len) + 4;
    if (data.size() < total) {
        err = "TRUNCATED";
        return false;
    }
    out.kind = static_cast<MessageKind>(kindu);
    out.seq = seq;
    out.payload.assign(data.begin() + header_size, data.begin() + header_size + static_cast<std::size_t>(len));

    // Verify CRC over the entire frame (header + payload) against the trailer.
    std::size_t crcpos = header_size + static_cast<std::size_t>(len);
    std::uint32_t expected = 0;
    std::size_t crcRead = crcpos;
    {
        // read trailer
        std::uint32_t trailer = 0;
        std::size_t q = crcpos;
        if (!get32(data, q, trailer)) { err = "TRUNCATED"; return false; }
        expected = trailer;
        (void)crcRead;
    }
    const std::uint32_t actual = crc32(data.data(), crcpos);
    if (actual != expected) {
        err = "CHECKSUM_MISMATCH";
        return false;
    }
    consumed = total;
    return true;
}

std::vector<std::uint8_t> payload_string(std::string_view s) {
    std::vector<std::uint8_t> v;
    v.reserve(s.size());
    for (char c : s) v.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(c)));
    return v;
}

bool parse_payload_string(std::span<const std::uint8_t> payload, std::string& out) {
    out.assign(reinterpret_cast<const char*>(payload.data()), payload.size());
    return true;
}

} // namespace protocol
} // namespace rdmabuffer

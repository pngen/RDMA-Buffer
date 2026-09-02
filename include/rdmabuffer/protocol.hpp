// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Bounded, typed, versioned framed-TCP protocol. Every frame carries magic,
// protocol version, message kind, payload length, and a CRC-32 trailer. The
// decoder rejects bad magic, unsupported version, oversized payload,
// truncation, checksum mismatch, invalid enum, impossible generation, duplicate
// ids, malformed ranges, and trailing garbage.

#pragma once

#include "crc32.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace rdmabuffer {
namespace protocol {

constexpr std::uint32_t frame_magic = 0x52444246u; // "RDBF"
constexpr std::uint32_t frame_version = 1u;
constexpr std::uint64_t max_payload = 16ull * 1024ull * 1024ull; // 16 MiB bound.
constexpr std::size_t header_size = 28; // magic4 + version4 + kind4 + seq8 + len8

enum class MessageKind : std::uint32_t {
    UNKNOWN = 0,
    HELLO = 1,
    HELLO_ACK = 2,
    WORKER_BOOT = 3,
    WORKER_BOOT_ACK = 4,
    CREATE_DOMAIN = 5,
    CREATE_DOMAIN_ACK = 6,
    REGISTER_BUFFER = 7,
    REGISTER_BUFFER_ACK = 8,
    REQUEST_ACCESS = 9,
    REQUEST_ACCESS_ACK = 10,
    RELEASE_LEASE = 11,
    RELEASE_LEASE_ACK = 12,
    REVOKE = 13,
    REVOKE_ACK = 14,
    DEREGISTER = 15,
    DEREGISTER_ACK = 16,
    PERSIST = 17,
    PERSIST_ACK = 18,
    RECOVER = 19,
    RECOVER_ACK = 20,
    WORKER_LOST = 21,
    ERROR = 22,
    OK = 23,
    KEEPALIVE = 24,
    MAX = 25,
};

struct Frame {
    MessageKind kind{MessageKind::UNKNOWN};
    std::uint64_t seq{0};
    std::vector<std::uint8_t> payload;
};

// Encode a single frame. The returned vector is exactly one frame.
std::vector<std::uint8_t> encode_frame(MessageKind kind, std::uint64_t seq,
                                       std::span<const std::uint8_t> payload);

// Decode the first frame in the buffer. `consumed` is the number of bytes the
// frame occupies. On failure `err` is set and `ok` false.
bool decode_frame(std::span<const std::uint8_t> data, Frame& out, std::size_t& consumed,
                  std::string& err);

// Frame payload convenience builders for string text and integer fields.
std::vector<std::uint8_t> payload_string(std::string_view s);
bool parse_payload_string(std::span<const std::uint8_t> payload, std::string& out);

} // namespace protocol
} // namespace rdmabuffer

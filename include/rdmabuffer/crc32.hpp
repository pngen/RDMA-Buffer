// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// CRC-32 (IEEE 802.3) used for persistence and framed-protocol integrity.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace rdmabuffer {

// Standard CRC-32 (polynomial 0xEDB88320). Returns 0 for an empty range.
std::uint32_t crc32(const std::uint8_t* data, std::size_t len) noexcept;
inline std::uint32_t crc32(std::span<const std::uint8_t> data) noexcept {
    return crc32(data.data(), data.size());
}

} // namespace rdmabuffer

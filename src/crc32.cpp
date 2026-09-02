// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "rdmabuffer/crc32.hpp"

namespace rdmabuffer {

std::uint32_t crc32(const std::uint8_t* data, std::size_t len) noexcept {
    if (data == nullptr || len == 0) return 0;
    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < len; ++i) {
        crc ^= static_cast<std::uint32_t>(data[i]);
        for (int k = 0; k < 8; ++k) {
            const std::uint32_t mask = static_cast<std::uint32_t>(-static_cast<std::int32_t>(crc & 1u));
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return crc ^ 0xFFFFFFFFu;
}

} // namespace rdmabuffer

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Buffer descriptor and associated validation. A remote-accessible buffer is
// governed state with identity, memory domain, registration lifetime, access
// rights, generation, ownership, transport capability, remote-key semantics,
// locality, freshness, provenance, and authority.

#pragma once

#include "config.hpp"
#include "enums.hpp"
#include "generation.hpp"
#include "identity.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace rdmabuffer {

// The kind of address a buffer points at. A numeric address is only ever
// revalidated under live authority; it is never persisted as authoritative.
enum class PointerKind : std::uint8_t {
    VIRTUAL = 0,
    DEVICE = 1,
    SHARED = 2,
    FILE = 3,
    SYNTHETIC = 4,
    UNKNOWN = 5,
};

inline constexpr std::string_view pointer_kind_name(PointerKind v) noexcept {
    switch (v) {
        case PointerKind::VIRTUAL: return "VIRTUAL";
        case PointerKind::DEVICE: return "DEVICE";
        case PointerKind::SHARED: return "SHARED";
        case PointerKind::FILE: return "FILE";
        case PointerKind::SYNTHETIC: return "SYNTHETIC";
        case PointerKind::UNKNOWN: return "UNKNOWN";
    }
    return "UNKNOWN";
}

// A value-only abstraction of a base pointer. Live memory actually backing a
// registration is tracked separately (registration record, not persisted).
struct BufferPointer {
    std::uintptr_t address{0};
    PointerKind kind{PointerKind::UNKNOWN};

    constexpr bool is_valid() const noexcept { return address != 0; }
    constexpr std::uint64_t address_value() const noexcept { return static_cast<std::uint64_t>(address); }
};

// The full governing description of a memory buffer eligible for registration.
struct BufferDescriptor {
    BufferId id;
    BufferGeneration generation;
    MemoryDomain domain{MemoryDomain::UNKNOWN};
    BufferPointer base;
    std::uint64_t byte_length{0};
    std::uint64_t alignment{1};
    std::uint64_t page_size{0}; // 0 means unknown.
    OwnerId owner;
    ProcessId process;
    WorkerId worker;
    NodeId node;
    DeviceId device;                 // where applicable.
    TransferDirection direction{TransferDirection::NONE};
    AccessMask requested_access{0};
    RegistrationMode registration_mode{RegistrationMode::ANY};
    LifetimePolicy lifetime{LifetimePolicy::TRANSACTIONAL};
    Provenance provenance{Provenance::UNKNOWN};
    Freshness freshness{Freshness::UNKNOWN};
    PolicyGeneration policy_generation;
};

// Deterministic validation of a descriptor's range math. Never trusts caller
// arithmetic; overflow and zero-length are rejected.
struct BufferValidation {
    bool ok{false};
    std::string code;
};

inline bool checked_add(std::uint64_t a, std::uint64_t b, std::uint64_t& out) noexcept {
    if (a > UINT64_MAX - b) return false;
    out = a + b;
    return true;
}

inline BufferValidation validate_range(const BufferDescriptor& d) noexcept {
    if (d.byte_length == 0) {
        return {false, "ZERO_LENGTH"};
    }
    if (!d.base.is_valid() && d.domain != MemoryDomain::SYNTHETIC_REMOTE_CAPABLE &&
        d.domain != MemoryDomain::FILE_BACKED) {
        return {false, "NULL_OR_INVALID_POINTER"};
    }
    if (d.alignment == 0) {
        return {false, "ZERO_ALIGNMENT"};
    }
    if (d.alignment != 0 && d.base.address % d.alignment != 0) {
        return {false, "MISALIGNED_BASE"};
    }
    std::uint64_t end = 0;
    if (!checked_add(d.base.address, d.byte_length, end)) {
        return {false, "OVERFLOW"};
    }
    if (d.domain == MemoryDomain::CUDA_DEVICE || d.domain == MemoryDomain::CUDA_MANAGED ||
        d.domain == MemoryDomain::SYNTHETIC_REMOTE_CAPABLE) {
        // Device/synthetic ranges may use a synthetic address space; overflow
        // still checked above.
    }
    return {true, "OK"};
}

// True when `sub` (offset,length) lies fully inside `d`.
inline bool range_inside(const BufferDescriptor& d, std::uint64_t offset, std::uint64_t length) noexcept {
    if (offset > d.byte_length) return false;
    std::uint64_t requested_end = 0;
    if (!checked_add(offset, length, requested_end)) return false;
    return requested_end <= d.byte_length;
}

} // namespace rdmabuffer

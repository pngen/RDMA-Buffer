// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Strong generation types. Generations are monotonic, incarnation-scoped
// counters. A numerically larger generation from an old incarization (an old
// WorkerBootId or CoordinatorEpoch) must never fence a fresh incarnation.
// Authoritative comparison is therefore always done through an explicit
// authority envelope that binds a generation to its incarnation (see
// authority.hpp). The raw ordering operators here describe natural-number
// order only; they are not by themselves an authorization decision.

#pragma once

#include <cstdint>

namespace rdmabuffer {
namespace detail {

template <typename Tag>
struct StrongGeneration {
    std::uint64_t value_{0};

    constexpr StrongGeneration() noexcept = default;
    constexpr explicit StrongGeneration(std::uint64_t v) noexcept : value_(v) {}

    constexpr std::uint64_t value() const noexcept { return value_; }
    constexpr bool is_valid() const noexcept { return value_ != 0; }
    constexpr explicit operator bool() const noexcept { return is_valid(); }

    constexpr StrongGeneration next() const noexcept { return StrongGeneration(value_ + 1); }

    constexpr bool operator==(const StrongGeneration& other) const noexcept { return value_ == other.value_; }
    constexpr bool operator!=(const StrongGeneration& other) const noexcept { return value_ != other.value_; }
    constexpr bool operator<(const StrongGeneration& other) const noexcept { return value_ < other.value_; }
    constexpr bool operator>(const StrongGeneration& other) const noexcept { return value_ > other.value_; }
    constexpr bool operator<=(const StrongGeneration& other) const noexcept { return value_ <= other.value_; }
    constexpr bool operator>=(const StrongGeneration& other) const noexcept { return value_ >= other.value_; }
};

} // namespace detail

#define RDMABUFFER_DECLARE_GENERATION(NAME)                           \
    using NAME = ::rdmabuffer::detail::StrongGeneration<struct NAME##Tag>;

RDMABUFFER_DECLARE_GENERATION(CoordinatorEpoch)
RDMABUFFER_DECLARE_GENERATION(BufferGeneration)
RDMABUFFER_DECLARE_GENERATION(RegistrationGeneration)
RDMABUFFER_DECLARE_GENERATION(LeaseGeneration)
RDMABUFFER_DECLARE_GENERATION(OwnerGeneration)
RDMABUFFER_DECLARE_GENERATION(WorkerGeneration)
RDMABUFFER_DECLARE_GENERATION(MemoryGeneration)
RDMABUFFER_DECLARE_GENERATION(DeviceGeneration)
RDMABUFFER_DECLARE_GENERATION(NicGeneration)
RDMABUFFER_DECLARE_GENERATION(TransportGeneration)
RDMABUFFER_DECLARE_GENERATION(BackendGeneration)
RDMABUFFER_DECLARE_GENERATION(RemoteKeyGeneration)
RDMABUFFER_DECLARE_GENERATION(AttemptGeneration)
RDMABUFFER_DECLARE_GENERATION(DispatchGeneration)
RDMABUFFER_DECLARE_GENERATION(ObservationGeneration)
RDMABUFFER_DECLARE_GENERATION(PolicyGeneration)
RDMABUFFER_DECLARE_GENERATION(ProtectionDomainGeneration)

#undef RDMABUFFER_DECLARE_GENERATION

// Explicit natural-number comparison; use only after authority has been
// established as incarnation-scoped.
template <typename G>
constexpr bool generation_newer(const G& lhs, const G& rhs) noexcept {
    return lhs.value() > rhs.value();
}

template <typename G>
constexpr bool generation_same(const G& lhs, const G& rhs) noexcept {
    return lhs.value() == rhs.value();
}

template <typename G>
constexpr bool generation_older_or_equal(const G& lhs, const G& rhs) noexcept {
    return lhs.value() <= rhs.value();
}

} // namespace rdmabuffer

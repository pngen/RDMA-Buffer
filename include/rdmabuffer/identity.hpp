// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Strong, non-interchangeable identity types. Two identities of different kinds
// are never implicitly comparable or assignable.

#pragma once

#include <cstdint>
#include <functional>
#include <string_view>

namespace rdmabuffer {
namespace detail {

template <typename Tag, typename Rep = std::uint64_t>
struct StrongId {
    Rep value_{};

    constexpr StrongId() noexcept = default;
    constexpr explicit StrongId(Rep v) noexcept : value_(v) {}

    constexpr Rep value() const noexcept { return value_; }
    constexpr bool is_valid() const noexcept { return value_ != Rep{}; }
    constexpr explicit operator bool() const noexcept { return is_valid(); }

    constexpr bool operator==(const StrongId& other) const noexcept { return value_ == other.value_; }
    constexpr bool operator!=(const StrongId& other) const noexcept { return value_ != other.value_; }
    constexpr bool operator<(const StrongId& other) const noexcept { return value_ < other.value_; }
    constexpr bool operator>(const StrongId& other) const noexcept { return value_ > other.value_; }
    constexpr bool operator<=(const StrongId& other) const noexcept { return value_ <= other.value_; }
    constexpr bool operator>=(const StrongId& other) const noexcept { return value_ >= other.value_; }

    // Explicit textual rendering; useful for explain() and diagnostics.
    [[nodiscard]] constexpr Rep raw() const noexcept { return value_; }
};

} // namespace detail

// MACRO-generated identity types.
#define RDMABUFFER_DECLARE_ID(NAME)                                              \
    using NAME = ::rdmabuffer::detail::StrongId<struct NAME##Tag>;

RDMABUFFER_DECLARE_ID(BufferId)
RDMABUFFER_DECLARE_ID(RegistrationId)
RDMABUFFER_DECLARE_ID(RegistrationLeaseId)
RDMABUFFER_DECLARE_ID(MemoryRegionId)
RDMABUFFER_DECLARE_ID(OwnerId)
RDMABUFFER_DECLARE_ID(ProcessId)
RDMABUFFER_DECLARE_ID(WorkerId)
RDMABUFFER_DECLARE_ID(WorkerBootId)
RDMABUFFER_DECLARE_ID(NodeId)
RDMABUFFER_DECLARE_ID(DeviceId)
RDMABUFFER_DECLARE_ID(NicId)
RDMABUFFER_DECLARE_ID(ProtectionDomainId)
RDMABUFFER_DECLARE_ID(TransportId)
RDMABUFFER_DECLARE_ID(BackendId)
RDMABUFFER_DECLARE_ID(TransferId)
RDMABUFFER_DECLARE_ID(AttemptId)
RDMABUFFER_DECLARE_ID(DispatchId)
RDMABUFFER_DECLARE_ID(RemoteKeyId)
RDMABUFFER_DECLARE_ID(LocalKeyId)
RDMABUFFER_DECLARE_ID(ObservationId)
RDMABUFFER_DECLARE_ID(ReservationId)

#undef RDMABUFFER_DECLARE_ID

} // namespace rdmabuffer

namespace std {
template <typename Tag, typename Rep>
struct hash<::rdmabuffer::detail::StrongId<Tag, Rep>> {
    size_t operator()(const ::rdmabuffer::detail::StrongId<Tag, Rep>& v) const noexcept {
        return std::hash<Rep>{}(v.value());
    }
};
} // namespace std

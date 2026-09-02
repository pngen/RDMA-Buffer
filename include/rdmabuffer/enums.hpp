// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Value and state enums for the RDMA Buffer runtime. Every enum value keeps an
// explicit, stable name so output can always be attributed (provenance,
// capability, outcome) without silent coercion.

#pragma once

#include <cstdint>
#include <string_view>

namespace rdmabuffer {

enum class MemoryDomain : std::uint8_t {
    HOST_PAGEABLE = 0,
    HOST_PINNED = 1,
    CUDA_DEVICE = 2,
    CUDA_MANAGED = 3,
    SHARED_MEMORY = 4,
    FILE_BACKED = 5,
    SYNTHETIC_REMOTE_CAPABLE = 6,
    UNKNOWN = 7,
};

enum class AccessRight : std::uint8_t {
    LOCAL_READ = 0x01,
    LOCAL_WRITE = 0x02,
    REMOTE_READ = 0x04,
    REMOTE_WRITE = 0x08,
    REMOTE_ATOMIC = 0x10,
};

// Access mask stored as an unsigned byte of the bit flags above.
using AccessMask = std::uint8_t;

enum class RegistrationLifecycle : std::uint8_t {
    UNREGISTERED = 0,
    REGISTERING = 1,
    REGISTERED = 2,
    ACTIVE = 3,
    REVOKING = 4,
    REVOKED = 5,
    DEREGISTERING = 6,
    DEREGISTERED = 7,
    FAILED = 8,
    STALE = 9,
    REVALIDATION_REQUIRED = 10,
};

enum class AccessOutcome : std::uint8_t {
    ALLOW = 0,
    REJECT_STALE_EPOCH = 1,
    REJECT_STALE_BOOT = 2,
    REJECT_STALE_BUFFER = 3,
    REJECT_STALE_REGISTRATION = 4,
    REJECT_STALE_KEY = 5,
    REJECT_RANGE = 6,
    REJECT_PERMISSION = 7,
    REJECT_DOMAIN = 8,
    REJECT_BACKEND = 9,
    REJECT_TRANSPORT = 10,
    REJECT_REVOKED = 11,
    REJECT_DEREGISTERED = 12,
    REJECT_UNKNOWN_CAPABILITY = 13,
    REJECT_NOT_REGISTERED = 14,
    REJECT_LEASE = 15,
};

enum class TransportClass : std::uint8_t {
    INFINIBAND_CLASS = 0,
    ROCE_CLASS = 1,
    IWARP_CLASS = 2,
    WINDOWS_ND_CLASS = 3,
    LIBFABRIC_CLASS = 4,
    VERBS_CLASS = 5,
    TCP_REFERENCE = 6,
    SYNTHETIC = 7,
    UNKNOWN = 8,
};

enum class Provenance : std::uint8_t {
    REAL = 0,      // exercised against real OS / hardware / runtime semantics.
    SYNTHETIC = 1, // deterministic simulation; explicitly not hardware.
    UNKNOWN = 2,   // not established.
};

enum class RevocationMode : std::uint8_t {
    SOFT_REVOKE = 0,
    HARD_REVOKE = 1,
};

enum class RegistrationMode : std::uint8_t {
    PIN_ONLY = 0,  // prepare/pin memory, no remote key material.
    REMOTE_ACCESS = 1, // full registration including remote keys.
    ANY = 2,
};

enum class LifetimePolicy : std::uint8_t {
    TRANSACTIONAL = 0, // tied to a lease or explicit scope.
    PERSISTENT = 1,    // survives until explicitly revoked/deregistered.
    EPHEMERAL = 2,     // reclaimed when last reference drops.
};

enum class NicState : std::uint8_t {
    KNOWN = 0,
    UNKNOWN = 1,
    SYNTHETIC = 2,
};

enum class DomainState : std::uint8_t {
    CREATED = 0,
    ACTIVE = 1,
    DESTROYING = 2,
    DESTROYED = 3,
};

enum class LeaseState : std::uint8_t {
    PENDING = 0,
    ACTIVE = 1,
    RELEASED = 2,
    REVOKED = 3,
};

enum class TransferDirection : std::uint8_t {
    NONE = 0,
    SEND = 1,
    RECEIVE = 2,
    BIDIRECTIONAL = 3,
};

enum class OperationKind : std::uint8_t {
    READ = 0,
    WRITE = 1,
    ATOMIC_COMPARE_SWAP = 2,
};

// Boolean capability tri-state. `UNKNOWN` must never become implicit
// permission.
enum class CapabilityState : std::uint8_t {
    SUPPORTED = 0,
    NOT_SUPPORTED = 1,
    UNKNOWN = 2,
};

enum class RegistrationResult : std::uint8_t {
    REGISTERED = 0,
    REUSED = 1,
    REJECTED = 2,
    PARTIAL_FAILURE = 3,
};

enum class ReuseDecision : std::uint8_t {
    REUSE_HIT = 0,
    REUSE_MISS = 1,
};

enum class BackendState : std::uint8_t {
    READY = 0,
    DISCOVERING = 1,
    FAILED = 2,
    DESTROYED = 3,
};

enum class PersistenceError : std::uint8_t {
    NONE = 0,
    BAD_MAGIC = 1,
    BAD_VERSION = 2,
    TRUNCATED = 3,
    CHECKSUM_MISMATCH = 4,
    DUPLICATE_IDENTITY = 5,
    INVALID_ENUM = 6,
    IMPOSSIBLE_COUNT = 7,
    GENERATION_REGRESSION = 8,
    TRAILING_GARBAGE = 9,
    IO_ERROR = 10,
    IO_ERROR_OPEN = 11,
    IO_ERROR_READ = 12,
    IO_ERROR_WRITE = 13,
};

enum class ProtocolError : std::uint8_t {
    NONE = 0,
    BAD_MAGIC = 1,
    BAD_VERSION = 2,
    OVERSIZED = 3,
    TRUNCATED = 4,
    CHECKSUM_MISMATCH = 5,
    INVALID_ENUM = 6,
    IMPOSSIBLE_GENERATION = 7,
    DUPLICATE_ID = 8,
    MALFORMED_RANGE = 9,
    TRAILING_GARBAGE = 10,
    IO_ERROR = 11,
};

enum class CapabilityTri : std::uint8_t {
    YES = 0,
    NO = 1,
    MAYBE = 2, // treated as UNKNOWN for authorization.
};

enum class Freshness : std::uint8_t {
    VALID = 0,              // proven current under live authority.
    REVALIDATION_REQUIRED = 1, // recovered/persisted; needs re-registration.
    STALE = 2,              // known to be superseded.
    UNKNOWN = 3,
};

enum class CapabilityStatus : std::uint8_t {
    DETECTED = 0,   // genuinely present and exercised.
    NOT_PRESENT = 1,
    UNKNOWN = 2,    // not established; never treated as permission.
};

// --- name mapping (stable, machine-readable) --------------------------------

namespace detail {
constexpr std::string_view name_of(MemoryDomain v) noexcept {
    switch (v) {
        case MemoryDomain::HOST_PAGEABLE: return "HOST_PAGEABLE";
        case MemoryDomain::HOST_PINNED: return "HOST_PINNED";
        case MemoryDomain::CUDA_DEVICE: return "CUDA_DEVICE";
        case MemoryDomain::CUDA_MANAGED: return "CUDA_MANAGED";
        case MemoryDomain::SHARED_MEMORY: return "SHARED_MEMORY";
        case MemoryDomain::FILE_BACKED: return "FILE_BACKED";
        case MemoryDomain::SYNTHETIC_REMOTE_CAPABLE: return "SYNTHETIC_REMOTE_CAPABLE";
        case MemoryDomain::UNKNOWN: return "UNKNOWN";
    }
    return "UNKNOWN";
}
} // namespace detail

inline constexpr std::string_view memory_domain_name(MemoryDomain v) noexcept {
    return detail::name_of(v);
}

constexpr bool is_strict_cuda_domain(MemoryDomain v) noexcept {
    return v == MemoryDomain::CUDA_DEVICE || v == MemoryDomain::CUDA_MANAGED;
}

// access-mask helpers --------------------------------------------------------

constexpr AccessMask access_mask(AccessRight r) noexcept {
    return static_cast<AccessMask>(r);
}

constexpr bool access_has(AccessMask mask, AccessRight r) noexcept {
    return (mask & access_mask(r)) != 0;
}

constexpr AccessMask access_add(AccessMask mask, AccessRight r) noexcept {
    return static_cast<AccessMask>(mask | access_mask(r));
}

// Right combination produces an access mask. Unknown capability never becomes
// permission; these operators only assemble a bit mask.
constexpr AccessMask operator|(AccessRight a, AccessRight b) noexcept {
    return static_cast<AccessMask>(access_mask(a) | access_mask(b));
}
constexpr AccessMask operator|(AccessMask m, AccessRight r) noexcept {
    return static_cast<AccessMask>(m | access_mask(r));
}
constexpr AccessMask operator|(AccessRight r, AccessMask m) noexcept {
    return static_cast<AccessMask>(access_mask(r) | m);
}


// lifecycle name mapping
inline constexpr std::string_view lifecycle_name(RegistrationLifecycle v) noexcept {
    switch (v) {
        case RegistrationLifecycle::UNREGISTERED: return "UNREGISTERED";
        case RegistrationLifecycle::REGISTERING: return "REGISTERING";
        case RegistrationLifecycle::REGISTERED: return "REGISTERED";
        case RegistrationLifecycle::ACTIVE: return "ACTIVE";
        case RegistrationLifecycle::REVOKING: return "REVOKING";
        case RegistrationLifecycle::REVOKED: return "REVOKED";
        case RegistrationLifecycle::DEREGISTERING: return "DEREGISTERING";
        case RegistrationLifecycle::DEREGISTERED: return "DEREGISTERED";
        case RegistrationLifecycle::FAILED: return "FAILED";
        case RegistrationLifecycle::STALE: return "STALE";
        case RegistrationLifecycle::REVALIDATION_REQUIRED: return "REVALIDATION_REQUIRED";
    }
    return "UNKNOWN";
}

inline constexpr std::string_view access_outcome_name(AccessOutcome v) noexcept {
    switch (v) {
        case AccessOutcome::ALLOW: return "ALLOW";
        case AccessOutcome::REJECT_STALE_EPOCH: return "REJECT_STALE_EPOCH";
        case AccessOutcome::REJECT_STALE_BOOT: return "REJECT_STALE_BOOT";
        case AccessOutcome::REJECT_STALE_BUFFER: return "REJECT_STALE_BUFFER";
        case AccessOutcome::REJECT_STALE_REGISTRATION: return "REJECT_STALE_REGISTRATION";
        case AccessOutcome::REJECT_STALE_KEY: return "REJECT_STALE_KEY";
        case AccessOutcome::REJECT_RANGE: return "REJECT_RANGE";
        case AccessOutcome::REJECT_PERMISSION: return "REJECT_PERMISSION";
        case AccessOutcome::REJECT_DOMAIN: return "REJECT_DOMAIN";
        case AccessOutcome::REJECT_BACKEND: return "REJECT_BACKEND";
        case AccessOutcome::REJECT_TRANSPORT: return "REJECT_TRANSPORT";
        case AccessOutcome::REJECT_REVOKED: return "REJECT_REVOKED";
        case AccessOutcome::REJECT_DEREGISTERED: return "REJECT_DEREGISTERED";
        case AccessOutcome::REJECT_UNKNOWN_CAPABILITY: return "REJECT_UNKNOWN_CAPABILITY";
        case AccessOutcome::REJECT_NOT_REGISTERED: return "REJECT_NOT_REGISTERED";
        case AccessOutcome::REJECT_LEASE: return "REJECT_LEASE";
    }
    return "UNKNOWN";
}

inline constexpr std::string_view provenance_name(Provenance v) noexcept {
    switch (v) {
        case Provenance::REAL: return "REAL";
        case Provenance::SYNTHETIC: return "SYNTHETIC";
        case Provenance::UNKNOWN: return "UNKNOWN";
    }
    return "UNKNOWN";
}

inline constexpr std::string_view transport_class_name(TransportClass v) noexcept {
    switch (v) {
        case TransportClass::INFINIBAND_CLASS: return "INFINIBAND_CLASS";
        case TransportClass::ROCE_CLASS: return "ROCE_CLASS";
        case TransportClass::IWARP_CLASS: return "IWARP_CLASS";
        case TransportClass::WINDOWS_ND_CLASS: return "WINDOWS_ND_CLASS";
        case TransportClass::LIBFABRIC_CLASS: return "LIBFABRIC_CLASS";
        case TransportClass::VERBS_CLASS: return "VERBS_CLASS";
        case TransportClass::TCP_REFERENCE: return "TCP_REFERENCE";
        case TransportClass::SYNTHETIC: return "SYNTHETIC";
        case TransportClass::UNKNOWN: return "UNKNOWN";
    }
    return "UNKNOWN";
}

inline constexpr std::string_view capability_state_name(CapabilityState v) noexcept {
    switch (v) {
        case CapabilityState::SUPPORTED: return "SUPPORTED";
        case CapabilityState::NOT_SUPPORTED: return "NOT_SUPPORTED";
        case CapabilityState::UNKNOWN: return "UNKNOWN";
    }
    return "UNKNOWN";
}

inline constexpr std::string_view revocation_mode_name(RevocationMode v) noexcept {
    switch (v) {
        case RevocationMode::SOFT_REVOKE: return "SOFT_REVOKE";
        case RevocationMode::HARD_REVOKE: return "HARD_REVOKE";
    }
    return "UNKNOWN";
}

inline constexpr std::string_view registration_mode_name(RegistrationMode v) noexcept {
    switch (v) {
        case RegistrationMode::PIN_ONLY: return "PIN_ONLY";
        case RegistrationMode::REMOTE_ACCESS: return "REMOTE_ACCESS";
        case RegistrationMode::ANY: return "ANY";
    }
    return "UNKNOWN";
}

inline constexpr std::string_view operation_kind_name(OperationKind v) noexcept {
    switch (v) {
        case OperationKind::READ: return "READ";
        case OperationKind::WRITE: return "WRITE";
        case OperationKind::ATOMIC_COMPARE_SWAP: return "ATOMIC_COMPARE_SWAP";
    }
    return "UNKNOWN";
}

inline constexpr std::string_view domain_state_name(DomainState v) noexcept {
    switch (v) {
        case DomainState::CREATED: return "CREATED";
        case DomainState::ACTIVE: return "ACTIVE";
        case DomainState::DESTROYING: return "DESTROYING";
        case DomainState::DESTROYED: return "DESTROYED";
    }
    return "UNKNOWN";
}

inline constexpr std::string_view lease_state_name(LeaseState v) noexcept {
    switch (v) {
        case LeaseState::PENDING: return "PENDING";
        case LeaseState::ACTIVE: return "ACTIVE";
        case LeaseState::RELEASED: return "RELEASED";
        case LeaseState::REVOKED: return "REVOKED";
    }
    return "UNKNOWN";
}

inline constexpr std::string_view freshness_name(Freshness v) noexcept {
    switch (v) {
        case Freshness::VALID: return "VALID";
        case Freshness::REVALIDATION_REQUIRED: return "REVALIDATION_REQUIRED";
        case Freshness::STALE: return "STALE";
        case Freshness::UNKNOWN: return "UNKNOWN";
    }
    return "UNKNOWN";
}

inline constexpr std::string_view capability_status_name(CapabilityStatus v) noexcept {
    switch (v) {
        case CapabilityStatus::DETECTED: return "DETECTED";
        case CapabilityStatus::NOT_PRESENT: return "NOT_PRESENT";
        case CapabilityStatus::UNKNOWN: return "UNKNOWN";
    }
    return "UNKNOWN";
}

} // namespace rdmabuffer

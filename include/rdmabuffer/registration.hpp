// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Registration record: a generation-bound object describing one registered
// buffer. All transitions are guarded.

#pragma once

#include "buffer_model.hpp"
#include "enums.hpp"
#include "generation.hpp"
#include "identity.hpp"
#include "remote_key.hpp"

#include <cstdint>
#include <string>

namespace rdmabuffer {

struct RegistrationRecord {
    RegistrationId id;
    BufferId buffer_id;
    BufferGeneration buffer_generation;
    RegistrationGeneration registration_generation;
    BufferDescriptor descriptor;
    BackendId backend;
    BackendGeneration backend_generation;
    TransportId transport;
    TransportClass transport_class{TransportClass::UNKNOWN};
    NicId nic;
    MemoryDomain domain{MemoryDomain::UNKNOWN};
    AccessMask granted_access{0};
    LocalKey local_key;
    RemoteKey remote_key;
    std::uint64_t start{0};
    std::uint64_t length{0};
    std::uint64_t page_alignment{1};
    // Live backend material (never persisted as authoritative).
    MemoryRegionId memory_region_id;
    std::string backend_handle;
    OwnerId owner;
    ProcessId process;
    WorkerId worker;
    WorkerBootId boot;
    CoordinatorEpoch epoch;
    DeviceId device;
    ProtectionDomainId domain_id;
    std::uint64_t registration_timestamp_ns{0};
    Provenance provenance{Provenance::UNKNOWN};
    Freshness freshness{Freshness::UNKNOWN};
    RegistrationLifecycle lifecycle{RegistrationLifecycle::UNREGISTERED};
    std::uint64_t lease_count{0};
    std::uint64_t ref_count{0};
    std::string invalidation_reason;
    PolicyGeneration policy_generation;

    constexpr bool has_valid_remote_key() const noexcept {
        return remote_key.id.is_valid() && !remote_key.revoked;
    }
};

// Guarded lifecycle transitions. Returns true when `from -> to` is allowed.
inline bool can_transition(RegistrationLifecycle from, RegistrationLifecycle to) noexcept {
    switch (from) {
        case RegistrationLifecycle::UNREGISTERED:
            return to == RegistrationLifecycle::REGISTERING;
        case RegistrationLifecycle::REGISTERING:
            return to == RegistrationLifecycle::REGISTERED ||
                   to == RegistrationLifecycle::ACTIVE ||
                   to == RegistrationLifecycle::FAILED ||
                   to == RegistrationLifecycle::UNREGISTERED;
        case RegistrationLifecycle::REGISTERED:
            return to == RegistrationLifecycle::ACTIVE ||
                   to == RegistrationLifecycle::DEREGISTERING ||
                   to == RegistrationLifecycle::REVOKING ||
                   to == RegistrationLifecycle::STALE ||
                   to == RegistrationLifecycle::REVALIDATION_REQUIRED;
        case RegistrationLifecycle::ACTIVE:
            return to == RegistrationLifecycle::REVOKING ||
                   to == RegistrationLifecycle::DEREGISTERING ||
                   to == RegistrationLifecycle::STALE ||
                   to == RegistrationLifecycle::REVALIDATION_REQUIRED;
        case RegistrationLifecycle::REVOKING:
            return to == RegistrationLifecycle::REVOKED ||
                   to == RegistrationLifecycle::DEREGISTERING ||
                   to == RegistrationLifecycle::DEREGISTERED ||
                   to == RegistrationLifecycle::FAILED;
        case RegistrationLifecycle::REVOKED:
            return to == RegistrationLifecycle::DEREGISTERING ||
                   to == RegistrationLifecycle::DEREGISTERED;
        case RegistrationLifecycle::DEREGISTERING:
            return to == RegistrationLifecycle::DEREGISTERED ||
                   to == RegistrationLifecycle::FAILED;
        case RegistrationLifecycle::DEREGISTERED:
            return false; // terminal unless STALE/REVALIDATION_REQUIRED via force.
        case RegistrationLifecycle::FAILED:
            return to == RegistrationLifecycle::UNREGISTERED ||
                   to == RegistrationLifecycle::DEREGISTERED;
        case RegistrationLifecycle::STALE:
            return to == RegistrationLifecycle::REVALIDATION_REQUIRED ||
                   to == RegistrationLifecycle::DEREGISTERING ||
                   to == RegistrationLifecycle::DEREGISTERED;
        case RegistrationLifecycle::REVALIDATION_REQUIRED:
            return to == RegistrationLifecycle::REGISTERING ||
                   to == RegistrationLifecycle::DEREGISTERED;
    }
    return false;
}

} // namespace rdmabuffer

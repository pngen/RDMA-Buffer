// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Backend capability model. Every capability tri-states into
// SUPPORTED / NOT_SUPPORTED / UNKNOWN. `UNKNOWN` must never be treated as
// implicit permission; the runtime rejects unknown capability.

#pragma once

#include "enums.hpp"
#include "generation.hpp"
#include "identity.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace rdmabuffer {

struct BackendCapabilities {
    std::vector<MemoryDomain> supported_domains;
    std::uint64_t max_registration_length{0}; // 0 => unknown/unbounded.
    std::uint64_t required_alignment{1};
    CapabilityState remote_read{CapabilityState::UNKNOWN};
    CapabilityState remote_write{CapabilityState::UNKNOWN};
    CapabilityState remote_atomic{CapabilityState::UNKNOWN};
    CapabilityState host_pinned{CapabilityState::UNKNOWN};
    CapabilityState pageable_registration{CapabilityState::UNKNOWN};
    CapabilityState cuda_device{CapabilityState::UNKNOWN};
    CapabilityState cuda_managed{CapabilityState::UNKNOWN};
    CapabilityState on_demand_paging{CapabilityState::UNKNOWN};
    CapabilityState one_sided{CapabilityState::UNKNOWN};
    CapabilityState multiprocess{CapabilityState::UNKNOWN};
    CapabilityState multinode{CapabilityState::UNKNOWN};
    CapabilityState key_rotation{CapabilityState::UNKNOWN};
    CapabilityState revocation{CapabilityState::UNKNOWN};
    Provenance provenance{Provenance::UNKNOWN};
};

// A summarized, named backend capability view for output. Used to report
// capability snapshots and keep them out of the authorization path.
struct BackendInfo {
    BackendId id;
    std::string name;
    std::string description;
    Provenance provenance{Provenance::UNKNOWN};
    BackendCapabilities capabilities;
    BackendState state{BackendState::READY};
    BackendGeneration generation;
    std::uint64_t prot_domain_count{0};
    std::uint64_t registration_count{0};
};

// A convenience capability query: is `domain` supported (explicitly) at all?
inline bool domain_supported(const BackendCapabilities& caps, MemoryDomain domain) noexcept {
    for (const auto d : caps.supported_domains) {
        if (d == domain) return true;
    }
    return false;
}

// Resolve one remote capability to a boolean permission basis. UNKNOWN => false
// (authorization must reject).
inline bool capability_allows(CapabilityState s) noexcept {
    return s == CapabilityState::SUPPORTED;
}

} // namespace rdmabuffer

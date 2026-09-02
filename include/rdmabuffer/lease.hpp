// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Leases and governed reuse. A registration may be shared for reuse only while
// all eligibility predicates hold; leases are reference-counted safely and
// duplicate release never decrements twice.

#pragma once

#include "enums.hpp"
#include "generation.hpp"
#include "identity.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace rdmabuffer {

struct Lease {
    RegistrationLeaseId id;
    RegistrationId registration;
    RegistrationGeneration registration_generation;
    LeaseGeneration lease_generation;
    BufferGeneration buffer_generation;
    WorkerBootId boot;
    OwnerId owner;
    ProtectionDomainId domain;
    AccessMask access{0};
    LeaseState state{LeaseState::PENDING};
    Provenance provenance{Provenance::UNKNOWN};
    std::uint64_t acquired_at_ns{0};
};

// Whether a registration recorded as `candidate` may be leased for the
// requested access. `reason` is non-empty when not eligible.
struct LeaseEligibility {
    bool eligible{false};
    std::string reason; // stable miss code
};

struct ReuseEligibility {
    bool reusable{false};
    std::string reason; // reuse miss code
};

} // namespace rdmabuffer

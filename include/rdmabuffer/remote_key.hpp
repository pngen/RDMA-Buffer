// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Remote and local key model. Remote keys are authority-bearing capabilities.
// A stale remote key must never regain validity after deregistration, buffer
// replacement, registration renewal, process restart, owner restart, epoch
// rollover, memory reallocation, backend reset, or NIC generation change.

#pragma once

#include "enums.hpp"
#include "generation.hpp"
#include "identity.hpp"

#include <cstdint>
#include <string_view>

namespace rdmabuffer {

struct RemoteKey {
    RemoteKeyId id;
    RegistrationId registration;
    RegistrationGeneration registration_generation;
    RemoteKeyGeneration key_generation;
    BufferGeneration buffer_generation;
    WorkerBootId boot;
    ProcessId process;
    BackendId backend;
    TransportClass transport{TransportClass::UNKNOWN};
    AccessMask access{0};
    std::uint64_t start{0};
    std::uint64_t length{0};
    std::uint64_t opaque_value{0};
    bool revoked{false};
    Provenance provenance{Provenance::UNKNOWN};

    constexpr bool is_valid() const noexcept { return id.is_valid(); }
};

struct LocalKey {
    LocalKeyId id;
    RegistrationId registration;
    RegistrationGeneration registration_generation;
    WorkerBootId boot;
    BackendId backend;
    TransportClass transport{TransportClass::UNKNOWN};
    AccessMask access{0};
    std::uint64_t opaque_value{0};
    Provenance provenance{Provenance::UNKNOWN};
};

} // namespace rdmabuffer

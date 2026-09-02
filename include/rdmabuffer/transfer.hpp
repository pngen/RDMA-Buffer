// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Transfer safety. RDMA Buffer does not own global transfer planning; it owns
// whether a specific registered memory region is safe to use for a requested
// remote operation.

#pragma once

#include "authority.hpp"
#include "buffer_model.hpp"
#include "enums.hpp"
#include "generation.hpp"
#include "identity.hpp"

#include <cstdint>

namespace rdmabuffer {

struct RemoteAccessRequest {
    TransferId transfer_id;
    RegistrationId source_registration;
    std::uint64_t offset{0};
    std::uint64_t length{0};
    OperationKind kind{OperationKind::WRITE};
    AccessMask required_rights{0};
    BufferGeneration expected_buffer_generation;
    RegistrationGeneration expected_registration_generation;
    RemoteKeyGeneration expected_remote_key_generation;
    AttemptId attempt;
    DispatchId dispatch;
    AuthorityEnvelope authority;
    ProtectionDomainId domain;
    BackendId backend;
    TransportId transport;
    NicId nic;
    ProcessId process;
    NodeId node;

    // Deterministic simulation seed; ignored for real backends.
    std::uint64_t sim_seed{0};
};

struct AccessValidationQuery {
    RegistrationId registration;
    RemoteKeyId key;
    BufferGeneration expected_buffer_generation;
    RegistrationGeneration expected_registration_generation;
    RemoteKeyGeneration expected_remote_key_generation;
    AuthorityEnvelope authority;
};

} // namespace rdmabuffer

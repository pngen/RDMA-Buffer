// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#pragma once

#include "rdmabuffer/rdmabuffer.hpp"

namespace exutil {

inline rdmabuffer::AuthoritySnapshot snapshot(std::uint64_t epoch = 1, std::uint64_t boot = 1) {
    rdmabuffer::AuthoritySnapshot s;
    s.coordinator_epoch = rdmabuffer::CoordinatorEpoch(epoch);
    s.worker_boot = rdmabuffer::WorkerBootId(boot);
    s.worker = rdmabuffer::WorkerId(1); s.owner = rdmabuffer::OwnerId(1);
    s.owner_generation = rdmabuffer::OwnerGeneration(1); s.worker_generation = rdmabuffer::WorkerGeneration(1);
    s.policy_generation = rdmabuffer::PolicyGeneration(1);
    s.backend_generation = rdmabuffer::BackendGeneration(1);
    s.transport_generation = rdmabuffer::TransportGeneration(1); s.nic_generation = rdmabuffer::NicGeneration(1);
    s.node = rdmabuffer::NodeId(1); s.process = rdmabuffer::ProcessId(1);
    s.provenance = rdmabuffer::Provenance::SYNTHETIC;
    return s;
}

inline rdmabuffer::AuthorityEnvelope envelope(std::uint64_t epoch = 1, std::uint64_t boot = 1) {
    rdmabuffer::AuthorityEnvelope e;
    e.coordinator_epoch = rdmabuffer::CoordinatorEpoch(epoch);
    e.worker_boot = rdmabuffer::WorkerBootId(boot);
    e.owner = rdmabuffer::OwnerId(1); e.owner_generation = rdmabuffer::OwnerGeneration(1);
    e.worker_generation = rdmabuffer::WorkerGeneration(1);
    e.node = rdmabuffer::NodeId(1); e.process = rdmabuffer::ProcessId(1);
    return e;
}

inline rdmabuffer::BufferDescriptor make_buffer(std::uint64_t id, std::uint64_t gen,
                                                rdmabuffer::MemoryDomain domain, std::uint64_t len,
                                                rdmabuffer::AccessMask access) {
    rdmabuffer::BufferDescriptor d;
    d.id = rdmabuffer::BufferId(id); d.generation = rdmabuffer::BufferGeneration(gen);
    d.domain = domain; d.base.address = 0x1000;
    d.base.kind = domain == rdmabuffer::MemoryDomain::SYNTHETIC_REMOTE_CAPABLE
                  ? rdmabuffer::PointerKind::SYNTHETIC : rdmabuffer::PointerKind::VIRTUAL;
    d.byte_length = len; d.alignment = 4096; d.page_size = 4096;
    d.owner = rdmabuffer::OwnerId(1); d.process = rdmabuffer::ProcessId(1);
    d.worker = rdmabuffer::WorkerId(1); d.node = rdmabuffer::NodeId(1);
    d.direction = rdmabuffer::TransferDirection::BIDIRECTIONAL;
    d.requested_access = access;
    d.registration_mode = rdmabuffer::RegistrationMode::REMOTE_ACCESS;
    d.lifetime = rdmabuffer::LifetimePolicy::TRANSACTIONAL;
    d.provenance = rdmabuffer::Provenance::SYNTHETIC; d.freshness = rdmabuffer::Freshness::VALID;
    d.policy_generation = rdmabuffer::PolicyGeneration(1);
    return d;
}

} // namespace exutil

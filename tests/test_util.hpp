// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Shared test helpers. Deterministic and fixed-seed.

#pragma once

#include "rdmabuffer/rdmabuffer.hpp"

namespace testutil {

inline rdmabuffer::AuthoritySnapshot make_snapshot(std::uint64_t epoch = 1, std::uint64_t boot = 1,
                                                   std::uint64_t worker = 1, std::uint64_t owner = 1,
                                                   std::uint64_t node = 1, std::uint64_t process = 1) {
    rdmabuffer::AuthoritySnapshot s;
    s.coordinator_epoch = rdmabuffer::CoordinatorEpoch(epoch);
    s.worker_boot = rdmabuffer::WorkerBootId(boot);
    s.worker = rdmabuffer::WorkerId(worker);
    s.owner = rdmabuffer::OwnerId(owner);
    s.owner_generation = rdmabuffer::OwnerGeneration(1);
    s.worker_generation = rdmabuffer::WorkerGeneration(1);
    s.policy_generation = rdmabuffer::PolicyGeneration(1);
    s.backend_generation = rdmabuffer::BackendGeneration(1);
    s.transport_generation = rdmabuffer::TransportGeneration(1);
    s.nic_generation = rdmabuffer::NicGeneration(1);
    s.node = rdmabuffer::NodeId(node);
    s.process = rdmabuffer::ProcessId(process);
    s.provenance = rdmabuffer::Provenance::SYNTHETIC;
    return s;
}

inline rdmabuffer::AuthorityEnvelope make_envelope(std::uint64_t epoch = 1, std::uint64_t boot = 1,
                                                   std::uint64_t owner = 1, std::uint64_t node = 1,
                                                   std::uint64_t process = 1) {
    rdmabuffer::AuthorityEnvelope e;
    e.coordinator_epoch = rdmabuffer::CoordinatorEpoch(epoch);
    e.worker_boot = rdmabuffer::WorkerBootId(boot);
    e.owner = rdmabuffer::OwnerId(owner);
    e.owner_generation = rdmabuffer::OwnerGeneration(1);
    e.worker_generation = rdmabuffer::WorkerGeneration(1);
    e.node = rdmabuffer::NodeId(node);
    e.process = rdmabuffer::ProcessId(process);
    return e;
}

inline rdmabuffer::BufferDescriptor make_buffer(std::uint64_t id, std::uint64_t gen,
                                                rdmabuffer::MemoryDomain domain,
                                                std::uint64_t length, std::uint64_t alignment,
                                                rdmabuffer::AccessMask access,
                                                std::uint64_t addr = 0x1000) {
    rdmabuffer::BufferDescriptor d;
    d.id = rdmabuffer::BufferId(id);
    d.generation = rdmabuffer::BufferGeneration(gen);
    d.domain = domain;
    d.base.address = addr;
    d.base.kind = domain == rdmabuffer::MemoryDomain::SYNTHETIC_REMOTE_CAPABLE
                      ? rdmabuffer::PointerKind::SYNTHETIC
                      : rdmabuffer::PointerKind::VIRTUAL;
    d.byte_length = length;
    d.alignment = alignment;
    d.page_size = 4096;
    d.owner = rdmabuffer::OwnerId(1);
    d.process = rdmabuffer::ProcessId(1);
    d.worker = rdmabuffer::WorkerId(1);
    d.node = rdmabuffer::NodeId(1);
    d.direction = rdmabuffer::TransferDirection::BIDIRECTIONAL;
    d.requested_access = access;
    d.registration_mode = rdmabuffer::RegistrationMode::REMOTE_ACCESS;
    d.lifetime = rdmabuffer::LifetimePolicy::TRANSACTIONAL;
    d.provenance = rdmabuffer::Provenance::SYNTHETIC;
    d.freshness = rdmabuffer::Freshness::VALID;
    d.policy_generation = rdmabuffer::PolicyGeneration(1);
    return d;
}

inline rdmabuffer::BufferDescriptor make_buffer(std::uint64_t id, std::uint64_t gen,
                                                rdmabuffer::MemoryDomain domain,
                                                std::uint64_t length, std::uint64_t alignment,
                                                rdmabuffer::AccessRight access,
                                                std::uint64_t addr = 0x1000) {
    return make_buffer(id, gen, domain, length, alignment, rdmabuffer::access_mask(access), addr);
}

} // namespace testutil

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#pragma once

#include "rdmabuffer/rdmabuffer.hpp"
#include "test_util.hpp"

namespace testutil {

// A runtime preconfigured with one synthetic backend, one protection domain and
// one active SYNTHETIC_REMOTE_CAPABLE registration.
struct RegFixture {
    std::shared_ptr<rdmabuffer::SyntheticBackend> backend;
    rdmabuffer::Rdmabuffer rt;
    rdmabuffer::ProtectionDomainId domain;
    rdmabuffer::RegistrationId reg;
    rdmabuffer::RemoteKeyGeneration key_gen;
    rdmabuffer::BufferDescriptor buffer;

    void init(std::uint64_t seed = 42, rdmabuffer::AccessMask access =
                 rdmabuffer::AccessRight::REMOTE_READ | rdmabuffer::AccessRight::REMOTE_WRITE) {
        backend = std::make_shared<rdmabuffer::SyntheticBackend>(seed);
        rt.add_backend(backend);
        rt.set_authority(make_snapshot());
        domain = rt.create_protection_domain(rdmabuffer::NodeId(1), rdmabuffer::ProcessId(1));
        buffer = make_buffer(1, 1, rdmabuffer::MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096, access);
        rt.create_buffer(buffer);
        rdmabuffer::RegisterResult r = rt.register_buffer(buffer, backend->id(), domain, make_envelope());
        reg = r.registration;
        rdmabuffer::RegistrationRecord rec;
        rt.get_registration(reg, rec);
        key_gen = rec.remote_key.key_generation;
    }
};

} // namespace testutil

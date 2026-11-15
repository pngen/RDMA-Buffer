// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#pragma once

#include "rdmabuffer/rdmabuffer.hpp"
#include "test_util.hpp"

#include <functional>
#include <string>
#include <string_view>
#include <utility>

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

// A backend that forwards to a SyntheticBackend and can run a callback at the
// point where the runtime has released its own lock for backend work. A test
// uses it to place a second runtime call exactly where a concurrent caller
// would run, without depending on thread timing.
class HookBackend final : public rdmabuffer::IBackend {
public:
    explicit HookBackend(std::uint64_t seed) : inner_(seed) {}

    std::function<void()> on_register;   // runs once, inside register_buffer.
    std::function<void()> on_deregister; // runs once, inside deregister_buffer.

    std::size_t live_registrations() const noexcept { return inner_.live_registrations(); }

    rdmabuffer::BackendId id() const noexcept override { return inner_.id(); }
    std::string_view name() const noexcept override { return inner_.name(); }
    rdmabuffer::Provenance provenance() const noexcept override { return inner_.provenance(); }
    rdmabuffer::BackendGeneration generation() const noexcept override { return inner_.generation(); }
    rdmabuffer::BackendState state() const noexcept override { return inner_.state(); }
    rdmabuffer::BackendCapabilities discover_capabilities() override { return inner_.discover_capabilities(); }
    rdmabuffer::BackendCapabilities capabilities() const noexcept override { return inner_.capabilities(); }
    std::string can_register(const rdmabuffer::BufferDescriptor& buffer) const override {
        return inner_.can_register(buffer);
    }
    rdmabuffer::RegisterOutcome register_buffer(const rdmabuffer::BufferDescriptor& buffer,
                                                const rdmabuffer::RegistrationContext& ctx,
                                                rdmabuffer::BackendRegistration& out) override {
        run_once(on_register);
        return inner_.register_buffer(buffer, ctx, out);
    }
    rdmabuffer::RegisterOutcome deregister_buffer(const rdmabuffer::RegisterHandle& handle) override {
        run_once(on_deregister);
        return inner_.deregister_buffer(handle);
    }
    rdmabuffer::RegisterOutcome query_registration(const rdmabuffer::RegisterHandle& handle,
                                                   rdmabuffer::BackendRegistration& out) override {
        return inner_.query_registration(handle, out);
    }
    rdmabuffer::AccessOutcome query_remote_access(const rdmabuffer::RegisterHandle& handle,
                                                  const rdmabuffer::BackendKey& key,
                                                  rdmabuffer::OperationKind kind,
                                                  std::uint64_t offset,
                                                  std::uint64_t length,
                                                  std::string& explanation) override {
        return inner_.query_remote_access(handle, key, kind, offset, length, explanation);
    }
    rdmabuffer::AccessOutcome revalidate(const rdmabuffer::RegisterHandle& handle,
                                         std::string& explanation) override {
        return inner_.revalidate(handle, explanation);
    }
    bool abort_registration(const rdmabuffer::RegisterHandle& handle, std::string& explanation) override {
        return inner_.abort_registration(handle, explanation);
    }
    bool rotate_key(const rdmabuffer::RegisterHandle& handle, rdmabuffer::RemoteKeyGeneration new_gen,
                    std::string& explanation) override {
        return inner_.rotate_key(handle, new_gen, explanation);
    }
    void advance_backend_generation() noexcept override { inner_.advance_backend_generation(); }

private:
    static void run_once(std::function<void()>& hook) {
        if (!hook) return;
        std::function<void()> f = std::move(hook);
        hook = nullptr;
        f();
    }

    rdmabuffer::SyntheticBackend inner_;
};

} // namespace testutil

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Reference host memory / TCP authority backend (provenance REAL for the OS
// primitives it actually exercises). It models registration, local/remote
// access rights, range validation, and the TCP_REFERENCE transport authority
// path. It does NOT model RNIC registration or hardware remote access; and it
// makes no claims about RDMA-capable memory. Real host-memory preparation and
// pinning is reported through probe_host_pinning().

#pragma once

#include "backend.hpp"
#include "enums.hpp"
#include "generation.hpp"
#include "identity.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>

namespace rdmabuffer {

struct PinProbeResult {
    bool ok{false};
    std::uint64_t bytes{0};
    std::string detail;
    bool allocation_committed{false};
    bool locked{false};
    Provenance provenance{Provenance::UNKNOWN};
};

class ReferenceBackend final : public IBackend {
public:
    explicit ReferenceBackend(BackendId id = BackendId(0x524546ull)); // "REF"

    BackendId id() const noexcept override;
    std::string_view name() const noexcept override;
    Provenance provenance() const noexcept override;
    BackendGeneration generation() const noexcept override;
    BackendState state() const noexcept override;

    BackendCapabilities discover_capabilities() override;
    BackendCapabilities capabilities() const noexcept override;

    std::string can_register(const BufferDescriptor& buffer) const override;

    RegisterOutcome register_buffer(const BufferDescriptor& buffer,
                                    const RegistrationContext& ctx,
                                    BackendRegistration& out) override;

    RegisterOutcome deregister_buffer(const RegisterHandle& handle) override;
    RegisterOutcome query_registration(const RegisterHandle& handle,
                                       BackendRegistration& out) override;

    AccessOutcome query_remote_access(const RegisterHandle& handle,
                                      const BackendKey& key,
                                      OperationKind kind,
                                      std::uint64_t offset,
                                      std::uint64_t length,
                                      std::string& explanation) override;

    AccessOutcome revalidate(const RegisterHandle& handle, std::string& explanation) override;
    bool abort_registration(const RegisterHandle& handle, std::string& explanation) override;

    bool rotate_key(const RegisterHandle& handle,
                    RemoteKeyGeneration new_gen,
                    std::string& explanation) override;

    void advance_backend_generation() noexcept override;

    // Real host-memory preparation probe (Windows: VirtualAlloc + VirtualLock).
    // Reports actual OS results and provenance. Never claims RDMA.
    PinProbeResult probe_host_pinning(std::uintptr_t address, std::uint64_t length) const;

private:
    struct Entry {
        RegistrationContext ctx;
        BackendRegistration reg;
        bool revoked{false};
    };

    BackendId id_;
    BackendGeneration backend_gen_{BackendGeneration(1)};
    BackendState state_{BackendState::READY};
    std::uint64_t next_seq_{1};
    mutable std::unordered_map<std::string, Entry> entries_;
};

} // namespace rdmabuffer

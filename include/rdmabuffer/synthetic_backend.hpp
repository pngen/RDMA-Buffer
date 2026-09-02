// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Deterministic SYNTHETIC RDMA-capability backend.
//
// This backend models realistic capability semantics WITHOUT pretending to be
// hardware. It simulates protection domains, registration handles, opaque
// lkey/rkey-like capabilities, access flags, key generations, range checking,
// owner/process authority, registration reuse, deregistration, revocation,
// stale-key rejection, backend restart, NIC generation rollover, transport
// generation rollover, and bounded remote access simulation.
//
// Every observation it produces carries provenance == SYNTHETIC. It is never
// described as a hardware "verbs" or "RDMA NIC" backend.

#pragma once

#include "backend.hpp"
#include "enums.hpp"
#include "generation.hpp"
#include "identity.hpp"

#include <cstdint>
#include <string>
#include <unordered_map>

namespace rdmabuffer {

class SyntheticBackend final : public IBackend {
public:
    // seed makes all simulated remote access deterministic.
    explicit SyntheticBackend(std::uint64_t seed = 0x52444D41ull);

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

    // -- Configuration (SYNTHETIC capability profile) ----------------------
    void configure_device_memory_support(bool supported) noexcept;
    void configure_atomic_support(bool supported) noexcept;
    void configure_remote_write(bool supported) noexcept;
    void configure_remote_read(bool supported) noexcept;
    void configure_required_alignment(std::uint64_t alignment) noexcept;
    void configure_synthetic_domain_support(bool supported) noexcept;

    // -- Scenario control (SYNTHETIC only) ----------------------------------
    void rollover_backend_generation() noexcept;
    void rollover_transport_generation() noexcept;
    void rollover_nic_generation() noexcept;
    void simulate_backend_restart();
    TransportGeneration transport_generation() const noexcept { return transport_gen_; }
    NicGeneration nic_generation() const noexcept { return nic_gen_; }

    // Backend-layer remote access simulation. The runtime performs the
    // authoritative generation/incarnation validation; this confirms the
    // backend's own key/topology currency.
    AccessOutcome simulate_remote(OperationKind kind,
                                  std::uint64_t offset,
                                  std::uint64_t length,
                                  std::uint64_t expected_key_generation,
                                  std::string& explanation,
                                  std::uint64_t& result_delta);

    std::size_t live_registrations() const noexcept { return entries_.size(); }

private:
    struct Entry {
        RegistrationContext ctx;
        BackendRegistration reg;
        RemoteKeyGeneration key_generation;
        bool revoked{false};
        bool revalidate_required{false};
    };

    std::string make_handle(MemoryRegionId id) const;

    BackendId id_;
    BackendGeneration backend_gen_;
    TransportGeneration transport_gen_;
    NicGeneration nic_gen_;
    NicId nic_;
    BackendState state_{BackendState::READY};
    std::uint64_t seed_;
    std::uint64_t next_seq_{1};

    // capability profile
    bool host_pinned_supported_{true};
    bool pageable_supported_{true};
    bool shared_supported_{true};
    bool file_backed_supported_{true};
    bool cuda_device_supported_{false};
    bool cuda_managed_supported_{false};
    bool synthetic_domain_supported_{true};
    bool remote_read_supported_{true};
    bool remote_write_supported_{true};
    bool atomic_supported_{false};
    bool one_sided_supported_{true};
    std::uint64_t required_alignment_{4096};

    std::unordered_map<std::string, Entry> entries_;
    std::unordered_map<MemoryRegionId, std::string> region_handle_;
};

} // namespace rdmabuffer

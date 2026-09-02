// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Vendor-neutral registration backend contract. A backend models how a
// particular execution environment registers and exposes memory for remote
// access. The runtime never assumes capability: every claim must come through
// the capability model, and unknown capability is rejected.

#pragma once

#include "buffer_model.hpp"
#include "capabilities.hpp"
#include "enums.hpp"
#include "generation.hpp"
#include "identity.hpp"

#include <cstdint>
#include <string>
#include <string_view>

namespace rdmabuffer {

// Context a backend needs to perform a registration. Generations and incarnations
// are assigned by the runtime and are authoritative.
struct RegistrationContext {
    ProtectionDomainId domain;
    NodeId node;
    ProcessId process;
    WorkerId worker;
    WorkerBootId worker_boot;
    CoordinatorEpoch epoch;
    OwnerId owner;
    OwnerGeneration owner_generation;
    RegistrationGeneration registration_generation;
    BackendGeneration backend_generation;
    AccessMask requested_access{0};
    RegistrationMode mode{RegistrationMode::ANY};
};

// Opaque local/remote key material produced by a backend.
struct BackendKey {
    RemoteKeyId remote_key_id;
    LocalKeyId local_key_id;
    RemoteKeyGeneration remote_key_generation;
    std::uint64_t opaque_value{0}; // lkey/rkey-like opaque capability.
    AccessMask granted_access{0};  // rights the backend actually granted.
    Provenance provenance{Provenance::UNKNOWN};
};

// The material returned by a backend after a successful registration.
struct BackendRegistration {
    MemoryRegionId memory_region_id;
    std::string handle;             // opaque, backend-scoped registration handle.
    std::uint64_t registered_base{0};
    std::uint64_t registered_length{0};
    AccessMask granted_access{0};
    BackendKey keys;
    TransportId transport;
    NicId nic;
    DeviceId device;
    Provenance provenance{Provenance::UNKNOWN};
    Freshness freshness{Freshness::VALID};
};

// A result bundle for registering. `ok` governs the path; `code` is stable.
struct RegisterOutcome {
    bool ok{false};
    std::string code;
    std::string message;
};

// A handle used to address a live registration within a backend.
struct RegisterHandle {
    MemoryRegionId memory_region_id;
    std::string handle;
};

class IBackend {
public:
    virtual ~IBackend() = default;

    virtual BackendId id() const noexcept = 0;
    virtual std::string_view name() const noexcept = 0;
    virtual Provenance provenance() const noexcept = 0;
    virtual BackendGeneration generation() const noexcept = 0;
    virtual BackendState state() const noexcept = 0;

    // discover_capabilities() re-probes the environment (e.g. re-detects a NIC).
    virtual BackendCapabilities discover_capabilities() = 0;
    virtual BackendCapabilities capabilities() const noexcept = 0;

    // can_register returns "" if registration is permissible, else a reason.
    virtual std::string can_register(const BufferDescriptor& buffer) const = 0;

    virtual RegisterOutcome register_buffer(const BufferDescriptor& buffer,
                                            const RegistrationContext& ctx,
                                            BackendRegistration& out) = 0;

    virtual RegisterOutcome deregister_buffer(const RegisterHandle& handle) = 0;

    // query_registration revalidates a live registration and refreshes `out`.
    virtual RegisterOutcome query_registration(const RegisterHandle& handle,
                                               BackendRegistration& out) = 0;

    // query_remote_access resolves whether a remote operation on this backend
    // would currently be permitted. The runtime performs the authoritative
    // validation; the backend confirms that its own key/topology state is
    // current.
    virtual AccessOutcome query_remote_access(const RegisterHandle& handle,
                                              const BackendKey& key,
                                              OperationKind kind,
                                              std::uint64_t offset,
                                              std::uint64_t length,
                                              std::string& explanation) = 0;

    virtual AccessOutcome revalidate(const RegisterHandle& handle, std::string& explanation) = 0;

    virtual bool abort_registration(const RegisterHandle& handle, std::string& explanation) = 0;

    // Advance this registration's key generation at the backend layer, so the
    // backend's own authority token matches the runtime's.
    virtual bool rotate_key(const RegisterHandle& handle,
                            RemoteKeyGeneration new_gen,
                            std::string& explanation) = 0;

    // Backend-scoped generation rollover (used by synthetic/NIC topologies).
    virtual void advance_backend_generation() noexcept = 0;
};

} // namespace rdmabuffer

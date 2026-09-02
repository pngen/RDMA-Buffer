// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// The RDMA Buffer runtime: the single boundary object that owns registration,
// leases, remote keys, revocation, reuse, accounting, and authority for a set
// of registered transfer buffers. It never performs global transfer planning;
// it answers whether a specific registered region is safe to expose to remote
// transfer machinery.

#pragma once

#include "accounting.hpp"
#include "authority.hpp"
#include "backend.hpp"
#include "buffer_model.hpp"
#include "capabilities.hpp"
#include "enums.hpp"
#include "generation.hpp"
#include "identity.hpp"
#include "lease.hpp"
#include "registration.hpp"
#include "transfer.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace rdmabuffer {

struct RegisterResult {
    bool ok{false};
    RegistrationResult result{RegistrationResult::REJECTED};
    RegistrationId registration;
    ReuseDecision reuse{ReuseDecision::REUSE_MISS};
    std::string explanation;
    std::string miss_reason;
};

struct LeaseAcquireResult {
    bool ok{false};
    Lease lease;
    std::string explanation;
};

struct RevokeResult {
    bool ok{false};
    RegistrationLifecycle lifecycle{RegistrationLifecycle::UNREGISTERED};
    bool keys_invalidated{false};
    std::string explanation;
};

struct RecoveryReport {
    std::uint64_t recovered_buffers{0};
    std::uint64_t recovered_registrations{0};
    std::uint64_t recovered_domains{0};
    std::uint64_t auto_deregistered{0};
    bool persistence_ok{false};
    std::string persistence_error;
    std::string semantic_digest;
};

class Rdmabuffer {
public:
    Rdmabuffer();
    ~Rdmabuffer();
    Rdmabuffer(const Rdmabuffer&) = delete;
    Rdmabuffer& operator=(const Rdmabuffer&) = delete;

    // -- authority ------------------------------------------------
    void set_authority(const AuthoritySnapshot& snap);
    AuthoritySnapshot authority() const;
    CoordinatorEpoch current_epoch() const;
    void advance_epoch();
    void note_participant_restart();

    // -- backends --------------------------------------------------
    bool add_backend(std::shared_ptr<IBackend> backend);
    bool has_backend(BackendId id) const;
    BackendCapabilities backend_capabilities(BackendId id) const;
    std::vector<BackendInfo> backend_summaries() const;

    // -- protection domains -----------------------------------------
    ProtectionDomainId create_protection_domain(NodeId node, ProcessId process);
    bool destroy_protection_domain(ProtectionDomainId domain);

    // -- buffers ----------------------------------------------------
    BufferId create_buffer(const BufferDescriptor& descriptor);
    bool has_buffer(BufferId id) const;

    // -- registration ------------------------------------------------
    RegisterResult register_buffer(const BufferDescriptor& descriptor,
                                   BackendId backend,
                                   ProtectionDomainId domain,
                                   const AuthorityEnvelope& authority);

    RegisterResult register_buffer_reuse(const BufferDescriptor& descriptor,
                                         BackendId backend,
                                         ProtectionDomainId domain,
                                         const AuthorityEnvelope& authority);

    // -- leases -----------------------------------------------------
    LeaseAcquireResult acquire_lease(RegistrationId registration,
                                     const AuthorityEnvelope& authority,
                                     AccessMask needed);
    bool release_lease(RegistrationLeaseId lease);

    // -- access -----------------------------------------------------
    AccessDecision validate_remote_access(const RemoteAccessRequest& request);

    // -- revocation -------------------------------------------------
    RevokeResult revoke(RegistrationId registration, RevocationMode mode);

    // -- key rotation ------------------------------------------------
    bool rotate_key(RegistrationId registration, std::string& explanation);

    // -- deregistration ---------------------------------------------
    bool deregister(RegistrationId registration, std::string& explanation);

    // -- query -------------------------------------------------------
    bool get_registration(RegistrationId id, RegistrationRecord& out) const;
    bool get_buffer(BufferId id, BufferDescriptor& out) const;
    std::vector<RegistrationId> registrations() const;

    // -- accounting --------------------------------------------------
    const Accounting& accounting() const;
    bool accounting_clean() const; // true when all counters are zero.

    // -- persistence -------------------------------------------------
    bool save(const std::string& path, std::string& err) const;
    bool recover(const std::string& path, std::string& err, RecoveryReport& report);

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace rdmabuffer

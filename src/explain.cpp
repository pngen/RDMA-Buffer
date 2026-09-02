// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "rdmabuffer/explain.hpp"

#include "rdmabuffer/accounting.hpp"

#include <sstream>

namespace rdmabuffer {

std::string Accounting::summary() const {
    std::ostringstream o;
    o << "logical_buffers=" << logical_buffers.get()
      << " live_bytes=" << live_buffer_bytes.get()
      << " pinned_bytes=" << pinned_bytes.get()
      << " registered_bytes=" << registered_bytes.get()
      << " active_registrations=" << active_registrations.get()
      << " active_leases=" << active_leases.get()
      << " protection_domains=" << protection_domains.get()
      << " local_keys=" << local_keys.get()
      << " remote_keys=" << remote_keys.get()
      << " remote_read_bytes=" << remote_read_bytes.get()
      << " remote_write_bytes=" << remote_write_bytes.get()
      << " atomic_ops=" << atomic_operations.get()
      << " failed_access=" << failed_access_attempts.get()
      << " stale_rejections=" << stale_access_rejections.get()
      << " revocations=" << revocations.get()
      << " deregistrations=" << deregistrations.get()
      << " reuse_hits=" << registration_reuse_hits.get()
      << " reuse_misses=" << registration_misses.get()
      << " participant_restarts=" << participant_restarts.get();
    return o.str();
}

std::string explain_registration(const RegistrationRecord& reg) {
    std::ostringstream o;
    o << "registration id=" << reg.id.value()
      << " buffer=" << reg.buffer_id.value()
      << " buffer_generation=" << reg.buffer_generation.value()
      << " registration_generation=" << reg.registration_generation.value()
      << " backend=" << reg.backend.value()
      << " domain=" << memory_domain_name(reg.domain)
      << " lifecycle=" << lifecycle_name(reg.lifecycle)
      << " freshness=" << freshness_name(reg.freshness)
      << " provenance=" << provenance_name(reg.provenance)
      << " rights=0x" << std::hex << static_cast<unsigned>(reg.granted_access) << std::dec
      << " remote_key_gen=" << reg.remote_key.key_generation.value();
    return o.str();
}

std::string explain_reuse(const BufferDescriptor& requested,
                          const RegistrationRecord& candidate,
                          bool reusable,
                          std::string_view miss_reason) {
    std::ostringstream o;
    o << "reuse of buffer " << requested.id.value()
      << " generation " << requested.generation.value()
      << " against registration " << candidate.id.value() << ": ";
    if (reusable) {
        o << "REUSE_HIT";
    } else {
        o << "REUSE_MISS: " << miss_reason;
    }
    return o.str();
}

std::string explain_remote_access(const RemoteAccessRequest& request,
                                  const AccessDecision& decision) {
    std::ostringstream o;
    o << "remote " << operation_kind_name(request.kind)
      << " registration=" << request.source_registration.value()
      << " offset=" << request.offset << " length=" << request.length
      << " result=" << decision.code << ": " << decision.explanation;
    return o.str();
}

std::string explain_revocation(const RegistrationRecord& reg,
                               RevocationMode mode,
                               bool keys_invalidated) {
    std::ostringstream o;
    o << "registration " << reg.id.value() << " " << revocation_mode_name(mode)
      << " revoke; lifecycle=" << lifecycle_name(reg.lifecycle)
      << " keys_invalidated=" << (keys_invalidated ? "true" : "false")
      << " reason=" << reg.invalidation_reason;
    return o.str();
}

std::string explain_recovery(const RegistrationRecord& recovered,
                             const AuthoritySnapshot& now) {
    std::ostringstream o;
    o << "recovered registration " << recovered.id.value()
      << " marked " << lifecycle_name(recovered.lifecycle)
      << " because physical registration handles are process/backend scoped; "
      << "current boot=" << now.worker_boot.value()
      << " epoch=" << now.coordinator_epoch.value();
    return o.str();
}

std::string explain_backend_capability(const BackendCapabilities& caps,
                                       MemoryDomain domain,
                                       AccessMask requested_rights) {
    std::ostringstream o;
    o << "backend domain=" << memory_domain_name(domain)
      << " dom_supported=" << (domain_supported(caps, domain) ? "true" : "false")
      << " remote_read=" << capability_state_name(caps.remote_read)
      << " remote_write=" << capability_state_name(caps.remote_write)
      << " remote_atomic=" << capability_state_name(caps.remote_atomic)
      << " provenance=" << provenance_name(caps.provenance)
      << " requested_rights=0x" << std::hex << static_cast<unsigned>(requested_rights) << std::dec;
    return o.str();
}

std::string explain_protection_domain(ProtectionDomainId id,
                                      MemoryDomain domain,
                                      bool reusable_under_same_domain) {
    std::ostringstream o;
    o << "protection domain " << id.value() << " domain=" << memory_domain_name(domain)
      << " same_domain_reuse=" << (reusable_under_same_domain ? "true" : "false");
    return o.str();
}

} // namespace rdmabuffer

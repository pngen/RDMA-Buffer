// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "rdmabuffer/registry.hpp"

#include "rdmabuffer/explain.hpp"
#include "rdmabuffer/persistence.hpp"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <mutex>
#include <unordered_map>
#include <vector>

namespace rdmabuffer {

namespace {

bool access_superset(AccessMask granted, AccessMask requested) noexcept {
    return (granted & requested) == requested;
}

std::string int_to_str(std::uint64_t v) { return std::to_string(v); }

} // namespace

class Rdmabuffer::Impl {
public:
    mutable std::mutex mutex_;

    AuthoritySnapshot authority_;
    std::unordered_map<BackendId, std::shared_ptr<IBackend>> backends_;

    struct DomainEntry {
        MemoryDomain domain{MemoryDomain::UNKNOWN};
        DomainState state{DomainState::CREATED};
        ProtectionDomainGeneration generation;
        NodeId node;
        ProcessId process;
    };

    struct BufferEntry {
        BufferDescriptor descriptor;
        bool registered{false};
    };

    std::unordered_map<ProtectionDomainId, DomainEntry> domains_;
    std::unordered_map<BufferId, BufferEntry> buffers_;
    std::unordered_map<RegistrationId, RegistrationRecord> registrations_;
    std::unordered_map<BufferId, RegistrationId> active_registration_for_buffer_;
    std::unordered_map<RegistrationLeaseId, Lease> leases_;
    Accounting acct_;

    std::uint64_t next_buffer_{1};
    std::uint64_t next_registration_{1};
    std::uint64_t next_domain_{1};
    std::uint64_t next_lease_{1};

    // -- authority -------------------------------------------------
    AuthoritySnapshot snapshot() const {
        std::lock_guard<std::mutex> g(mutex_);
        return authority_;
    }

    void set_authority(const AuthoritySnapshot& s) {
        std::lock_guard<std::mutex> g(mutex_);
        authority_ = s;
    }

    // -- backends -------------------------------------------------
    bool add_backend(std::shared_ptr<IBackend> b) {
        std::lock_guard<std::mutex> g(mutex_);
        if (!b) return false;
        const BackendId id = b->id();
        if (backends_.count(id) != 0) return false;
        backends_[id] = std::move(b);
        return true;
    }

    bool has_backend(BackendId id) {
        std::lock_guard<std::mutex> g(mutex_);
        return backends_.count(id) != 0;
    }

    BackendCapabilities backend_capabilities(BackendId id) {
        std::lock_guard<std::mutex> g(mutex_);
        auto it = backends_.find(id);
        if (it == backends_.end()) return {};
        return it->second->capabilities();
    }

    std::vector<BackendInfo> backend_summaries() {
        std::lock_guard<std::mutex> g(mutex_);
        std::vector<BackendInfo> out;
        for (auto& [id, b] : backends_) {
            BackendInfo info;
            info.id = id;
            info.name = std::string(b->name());
            info.provenance = b->provenance();
            info.capabilities = b->capabilities();
            info.state = b->state();
            info.generation = b->generation();
            info.prot_domain_count = domains_.size();
            info.registration_count = registrations_.size();
            out.push_back(std::move(info));
        }
        return out;
    }

    std::shared_ptr<IBackend> backend_locked(BackendId id) {
        auto it = backends_.find(id);
        if (it == backends_.end()) return nullptr;
        return it->second;
    }

    // -- domains ---------------------------------------------------
    ProtectionDomainId create_protection_domain(NodeId node, ProcessId process) {
        std::lock_guard<std::mutex> g(mutex_);
        ProtectionDomainId id(next_domain_++);
        DomainEntry de;
        de.domain = MemoryDomain::UNKNOWN;
        de.state = DomainState::ACTIVE;
        de.generation = ProtectionDomainGeneration(1);
        de.node = node;
        de.process = process;
        domains_[id] = std::move(de);
        acct_.protection_domains.increment();
        return id;
    }

    bool destroy_protection_domain(ProtectionDomainId d) {
        std::lock_guard<std::mutex> g(mutex_);
        auto it = domains_.find(d);
        if (it == domains_.end()) return false;
        // Revoke any registrations that belong to the destroyed domain.
        for (auto& [rid, rec] : registrations_) {
            if (rec.domain_id == d &&
                (rec.lifecycle == RegistrationLifecycle::ACTIVE ||
                 rec.lifecycle == RegistrationLifecycle::REGISTERED)) {
                rec.lifecycle = RegistrationLifecycle::REVOKED;
                rec.freshness = Freshness::STALE;
                rec.invalidation_reason = "protection domain destroyed";
                account_registration_invalidate(rec);
            }
        }
        it->second.state = DomainState::DESTROYED;
        it->second.generation = it->second.generation.next();
        acct_.protection_domains.decrement();
        return true;
    }

    // -- buffers ---------------------------------------------------
    BufferId create_buffer(const BufferDescriptor& descriptor) {
        std::lock_guard<std::mutex> g(mutex_);
        BufferId id = descriptor.id.is_valid() ? descriptor.id : BufferId(next_buffer_++);
        auto it = buffers_.find(id);
        if (it != buffers_.end()) {
            const std::uint64_t cur = it->second.descriptor.generation.value();
            const std::uint64_t want = descriptor.generation.value();
            if (want == cur) return {};                        // duplicate buffer id.
            if (want < cur) return {};                         // generation regression.
            // Reallocation under a new generation: invalidate older registrations.
            for (auto& [rid, rec] : registrations_) {
                if (rec.buffer_id == id &&
                    (rec.lifecycle == RegistrationLifecycle::ACTIVE ||
                     rec.lifecycle == RegistrationLifecycle::REGISTERED ||
                     rec.lifecycle == RegistrationLifecycle::REGISTERING)) {
                    rec.lifecycle = RegistrationLifecycle::STALE;
                    rec.freshness = Freshness::STALE;
                    rec.invalidation_reason = "memory reallocated under new generation";
                    account_registration_invalidate(rec);
                }
            }
            // Adjust live bytes delta.
            if (descriptor.byte_length >= it->second.descriptor.byte_length) {
                acct_.live_buffer_bytes.increment(descriptor.byte_length - it->second.descriptor.byte_length);
            } else {
                acct_.live_buffer_bytes.decrement(it->second.descriptor.byte_length - descriptor.byte_length);
            }
            it->second.descriptor = descriptor;
            it->second.registered = false;
            return id;
        }
        BufferEntry be;
        be.descriptor = descriptor;
        be.registered = false;
        buffers_[id] = std::move(be);
        acct_.logical_buffers.increment();
        acct_.live_buffer_bytes.increment(descriptor.byte_length);
        return id;
    }

    bool has_buffer(BufferId id) {
        std::lock_guard<std::mutex> g(mutex_);
        return buffers_.count(id) != 0;
    }

    bool get_buffer(BufferId id, BufferDescriptor& out) {
        std::lock_guard<std::mutex> g(mutex_);
        auto it = buffers_.find(id);
        if (it == buffers_.end()) return false;
        out = it->second.descriptor;
        return true;
    }

    // -- registration ------------------------------------------------
    RegisterResult register_buffer(const BufferDescriptor& descriptor,
                                   BackendId backend,
                                   ProtectionDomainId domain,
                                   const AuthorityEnvelope& env) {
        RegisterResult rr;
        RegistrationRecord rec;
        RegistrationContext ctx;
        {
            std::lock_guard<std::mutex> g(mutex_);
            AccessDecision ad = validate_authority(authority_, env);
            if (ad.outcome != AccessOutcome::ALLOW) {
                rr.ok = false;
                rr.result = RegistrationResult::REJECTED;
                rr.explanation = ad.explanation;
                rr.miss_reason = ad.code;
                return rr;
            }
            auto b = backend_locked(backend);
            if (!b) {
                rr.ok = false;
                rr.explanation = "unknown backend";
                rr.miss_reason = "UNKNOWN_BACKEND";
                return rr;
            }
            auto dit = domains_.find(domain);
            if (dit == domains_.end() || dit->second.state != DomainState::ACTIVE) {
                rr.ok = false;
                rr.explanation = "protection domain missing or not active";
                rr.miss_reason = "DOMAIN_INVALID";
                return rr;
            }
            const auto vr = validate_range(descriptor);
            if (!vr.ok) {
                rr.ok = false;
                rr.explanation = "invalid buffer range: " + vr.code;
                rr.miss_reason = vr.code;
                return rr;
            }
            auto bit = buffers_.find(descriptor.id);
            if (bit == buffers_.end()) {
                rr.ok = false;
                rr.explanation = "buffer not created; call create_buffer first";
                rr.miss_reason = "BUFFER_NOT_FOUND";
                return rr;
            }
            if (bit->second.descriptor.generation != descriptor.generation) {
                rr.ok = false;
                rr.explanation = "buffer generation mismatch";
                rr.miss_reason = "GENERATION_MISMATCH";
                return rr;
            }
            auto ait = active_registration_for_buffer_.find(descriptor.id);
            if (ait != active_registration_for_buffer_.end()) {
                rr.ok = false;
                rr.explanation = "buffer already has an active registration";
                rr.miss_reason = "REGISTRATION_IN_FLIGHT";
                return rr;
            }
            std::string can = b->can_register(descriptor);
            if (!can.empty()) {
                rr.ok = false;
                rr.explanation = "backend rejects registration: " + can;
                rr.miss_reason = can;
                return rr;
            }

            rec.id = RegistrationId(next_registration_++);
            rec.buffer_id = descriptor.id;
            rec.buffer_generation = descriptor.generation;
            rec.registration_generation = RegistrationGeneration(1);
            rec.descriptor = descriptor;
            rec.backend = backend;
            rec.domain_id = domain;
            rec.domain = descriptor.domain;
            rec.start = descriptor.base.address;
            rec.length = descriptor.byte_length;
            rec.page_alignment = descriptor.alignment;
            rec.owner = env.owner;
            rec.process = authority_.process;
            rec.worker = authority_.worker;
            rec.boot = env.worker_boot;
            rec.epoch = authority_.coordinator_epoch;
            rec.device = descriptor.device;
            rec.provenance = b->provenance();
            rec.granted_access = 0;
            rec.lifecycle = RegistrationLifecycle::REGISTERING;
            rec.freshness = Freshness::UNKNOWN;
            rec.backend_generation = b->generation();
            rec.policy_generation = authority_.policy_generation;

            ctx.domain = domain;
            ctx.node = authority_.node;
            ctx.process = authority_.process;
            ctx.worker = authority_.worker;
            ctx.worker_boot = env.worker_boot;
            ctx.epoch = authority_.coordinator_epoch;
            ctx.owner = env.owner;
            ctx.owner_generation = env.owner_generation;
            ctx.registration_generation = rec.registration_generation;
            ctx.backend_generation = b->generation();
            ctx.requested_access = descriptor.requested_access;
            ctx.mode = descriptor.registration_mode;
        } // unlock

        // Backend registration work happens outside the global lock.
        BackendRegistration bout;
        if (auto b = backend_locked(backend); b) {
            RegisterOutcome bo = b->register_buffer(descriptor, ctx, bout);
            if (!bo.ok) {
                std::lock_guard<std::mutex> g(mutex_);
                rr.ok = false;
                rr.result = RegistrationResult::PARTIAL_FAILURE;
                rr.explanation = "backend registration failed: " + bo.message;
                rr.miss_reason = bo.code;
                return rr;
            }
        } else {
            std::lock_guard<std::mutex> g(mutex_);
            rr.ok = false;
            rr.explanation = "backend vanished during registration";
            rr.miss_reason = "UNKNOWN_BACKEND";
            return rr;
        }
        {
            std::lock_guard<std::mutex> g(mutex_);
            rec.memory_region_id = bout.memory_region_id;
            rec.backend_handle = bout.handle;
            rec.start = bout.registered_base;
            rec.length = bout.registered_length;
            rec.granted_access = bout.granted_access;
            rec.local_key = LocalKey{bout.keys.local_key_id, rec.id, rec.registration_generation,
                                     authority_.worker_boot, backend, TransportClass::TCP_REFERENCE,
                                     bout.granted_access, bout.keys.opaque_value, Provenance::SYNTHETIC};
            rec.remote_key = RemoteKey{bout.keys.remote_key_id, rec.id, rec.registration_generation,
                                       bout.keys.remote_key_generation, rec.buffer_generation,
                                       authority_.worker_boot, authority_.process, backend,
                                       TransportClass::TCP_REFERENCE, bout.granted_access,
                                       rec.start, rec.length, bout.keys.opaque_value, false,
                                       Provenance::SYNTHETIC};
            rec.provenance = bout.provenance;
            rec.freshness = Freshness::VALID;
            rec.lifecycle = RegistrationLifecycle::ACTIVE;
            account_registration_commit(rec);
            registrations_[rec.id] = rec;
            active_registration_for_buffer_[rec.buffer_id] = rec.id;
            rr.ok = true;
            rr.result = RegistrationResult::REGISTERED;
            rr.registration = rec.id;
            rr.reuse = ReuseDecision::REUSE_MISS;
            rr.explanation = explain_registration(rec);
            rr.miss_reason.clear();
        }
        return rr;
    }

    RegisterResult register_buffer_reuse(const BufferDescriptor& descriptor,
                                         BackendId backend,
                                         ProtectionDomainId domain,
                                         const AuthorityEnvelope& env) {
        RegisterResult rr;
        std::lock_guard<std::mutex> g(mutex_);
        AccessDecision ad = validate_authority(authority_, env);
        if (ad.outcome != AccessOutcome::ALLOW) {
            rr.ok = false;
            rr.explanation = ad.explanation;
            rr.miss_reason = ad.code;
            return rr;
        }
        auto ait = active_registration_for_buffer_.find(descriptor.id);
        if (ait == active_registration_for_buffer_.end()) {
            rr.ok = false;
            rr.explanation = "no registration available for reuse";
            rr.miss_reason = "NO_CANDIDATE";
            return rr;
        }
        auto rit = registrations_.find(ait->second);
        if (rit == registrations_.end()) {
            rr.ok = false;
            rr.explanation = "candidate registration missing";
            rr.miss_reason = "NO_CANDIDATE";
            return rr;
        }
        const RegistrationRecord& cand = rit->second;
        std::string miss = reuse_miss_reason(descriptor, cand, backend, domain, env);
        if (!miss.empty()) {
            rr.ok = false;
            rr.result = RegistrationResult::REJECTED;
            rr.reuse = ReuseDecision::REUSE_MISS;
            rr.explanation = explain_reuse(descriptor, cand, false, miss);
            rr.miss_reason = miss;
            acct_.registration_misses.increment();
            return rr;
        }
        rr.ok = true;
        rr.result = RegistrationResult::REUSED;
        rr.reuse = ReuseDecision::REUSE_HIT;
        rr.registration = cand.id;
        rr.explanation = explain_reuse(descriptor, cand, true, "");
        acct_.registration_reuse_hits.increment();
        return rr;
    }

    std::string reuse_miss_reason(const BufferDescriptor& descriptor,
                                  const RegistrationRecord& cand,
                                  BackendId backend,
                                  ProtectionDomainId domain,
                                  const AuthorityEnvelope& env) const {
        if (cand.buffer_id != descriptor.id) return "BufferId mismatch";
        if (cand.buffer_generation != descriptor.generation)
            return "BufferGeneration changed from " + int_to_str(cand.buffer_generation.value()) +
                   " to " + int_to_str(descriptor.generation.value()) + " after memory reallocation";
        if (cand.domain != descriptor.domain) return "MemoryDomain mismatch";
        if (cand.backend != backend) return "Backend mismatch";
        if (cand.domain_id != domain) return "ProtectionDomain mismatch";
        if (!access_superset(cand.granted_access, descriptor.requested_access))
            return "Requested access rights not a subset of granted access";
        if (cand.lifecycle != RegistrationLifecycle::ACTIVE &&
            cand.lifecycle != RegistrationLifecycle::REGISTERED)
            return "Candidate registration not active";
        if (cand.boot != env.worker_boot) return "WorkerBootId mismatch";
        if (cand.freshness != Freshness::VALID) return "Candidate freshness not valid";
        if (!cand.remote_key.revoked && !cand.remote_key.id.is_valid())
            return "Candidate remote key absent";
        return "";
    }

    // -- leases -----------------------------------------------------
    LeaseAcquireResult acquire_lease(RegistrationId registration,
                                     const AuthorityEnvelope& env,
                                     AccessMask needed) {
        LeaseAcquireResult lr;
        std::lock_guard<std::mutex> g(mutex_);
        AccessDecision ad = validate_authority(authority_, env);
        if (ad.outcome != AccessOutcome::ALLOW) {
            lr.ok = false;
            lr.explanation = ad.explanation;
            return lr;
        }
        auto rit = registrations_.find(registration);
        if (rit == registrations_.end()) {
            lr.ok = false;
            lr.explanation = "registration not found";
            return lr;
        }
        RegistrationRecord& rec = rit->second;
        if (rec.lifecycle != RegistrationLifecycle::ACTIVE &&
            rec.lifecycle != RegistrationLifecycle::REGISTERED) {
            lr.ok = false;
            lr.explanation = "registration lifecycle does not permit leasing: " +
                             std::string(lifecycle_name(rec.lifecycle));
            return lr;
        }
        if (!access_superset(rec.granted_access, needed)) {
            lr.ok = false;
            lr.explanation = "registration does not grant requested access rights";
            return lr;
        }
        if (rec.freshness != Freshness::VALID) {
            lr.ok = false;
            lr.explanation = "registration freshness is not VALID";
            return lr;
        }
        Lease ls;
        ls.id = RegistrationLeaseId(next_lease_++);
        ls.registration = registration;
        ls.registration_generation = rec.registration_generation;
        ls.lease_generation = LeaseGeneration(rec.lease_count + 1);
        ls.buffer_generation = rec.buffer_generation;
        ls.boot = env.worker_boot;
        ls.owner = env.owner;
        ls.domain = rec.domain_id;
        ls.access = needed;
        ls.state = LeaseState::ACTIVE;
        ls.provenance = rec.provenance;
        leases_[ls.id] = ls;
        ++rec.lease_count;
        acct_.active_leases.increment();
        lr.ok = true;
        lr.lease = ls;
        lr.explanation = "lease acquired on registration " + int_to_str(registration.value());
        return lr;
    }

    bool release_lease(RegistrationLeaseId lease) {
        std::lock_guard<std::mutex> g(mutex_);
        auto it = leases_.find(lease);
        if (it == leases_.end()) return false;   // duplicate release or unknown.
        if (it->second.state == LeaseState::RELEASED) return false; // duplicate release.
        it->second.state = LeaseState::RELEASED;
        auto rit = registrations_.find(it->second.registration);
        if (rit != registrations_.end()) {
            if (rit->second.lease_count > 0) --rit->second.lease_count;
        }
        acct_.active_leases.decrement();
        return true;
    }

    // -- access -----------------------------------------------------
    AccessDecision validate_remote_access(const RemoteAccessRequest& request) {
        std::lock_guard<std::mutex> g(mutex_);

        auto decision = [this](AccessOutcome o, std::string e) {
            if (o != AccessOutcome::ALLOW) {
                acct_.failed_access_attempts.increment();
                if (o == AccessOutcome::REJECT_STALE_EPOCH ||
                    o == AccessOutcome::REJECT_STALE_BOOT ||
                    o == AccessOutcome::REJECT_STALE_BUFFER ||
                    o == AccessOutcome::REJECT_STALE_REGISTRATION ||
                    o == AccessOutcome::REJECT_STALE_KEY) {
                    acct_.stale_access_rejections.increment();
                }
            }
            AccessDecision d;
            d.outcome = o;
            d.code = std::string(access_outcome_name(o));
            d.explanation = std::move(e);
            return d;
        };

        auto rit = registrations_.find(request.source_registration);
        if (rit == registrations_.end()) {
            return decision(AccessOutcome::REJECT_NOT_REGISTERED,
                                 "registration not found");
        }
        const RegistrationRecord& rec = rit->second;

        // Lifecycle and freshness.
        if (rec.lifecycle == RegistrationLifecycle::REVOKED ||
            rec.lifecycle == RegistrationLifecycle::DEREGISTERED ||
            rec.lifecycle == RegistrationLifecycle::STALE) {
            return decision(AccessOutcome::REJECT_REVOKED,
                                 "registration lifecycle " + std::string(lifecycle_name(rec.lifecycle)) +
                                 " does not permit remote access");
        }
        if (rec.lifecycle == RegistrationLifecycle::REVOKING) {
            return decision(AccessOutcome::REJECT_REVOKED, "registration is being revoked");
        }
        if (rec.freshness != Freshness::VALID) {
            return decision(AccessOutcome::REJECT_STALE_REGISTRATION,
                                 "registration freshness is " + std::string(freshness_name(rec.freshness)));
        }

        // Authority.
        AccessDecision ad = validate_authority(authority_, request.authority);
        if (ad.outcome != AccessOutcome::ALLOW) return ad;

        // Generation currentness.
        if (request.expected_registration_generation.is_valid() &&
            request.expected_registration_generation != rec.registration_generation) {
            return decision(AccessOutcome::REJECT_STALE_REGISTRATION,
                                 "registration generation " + int_to_str(request.expected_registration_generation.value()) +
                                 " is stale; current " + int_to_str(rec.registration_generation.value()));
        }
        if (request.expected_buffer_generation.is_valid() &&
            request.expected_buffer_generation != rec.buffer_generation) {
            return decision(AccessOutcome::REJECT_STALE_BUFFER,
                                 "buffer generation " + int_to_str(request.expected_buffer_generation.value()) +
                                 " is stale; current " + int_to_str(rec.buffer_generation.value()));
        }
        if (request.expected_remote_key_generation.is_valid() &&
            request.expected_remote_key_generation != rec.remote_key.key_generation) {
            return decision(AccessOutcome::REJECT_STALE_KEY,
                                 "RemoteKeyGeneration " + int_to_str(request.expected_remote_key_generation.value()) +
                                 " is stale; current " + int_to_str(rec.remote_key.key_generation.value()));
        }
        if (rec.remote_key.revoked) {
            return decision(AccessOutcome::REJECT_STALE_KEY, "remote key has been revoked");
        }

        // Backend / transport / NIC currentness.
        if (request.backend.is_valid() && request.backend != rec.backend) {
            return decision(AccessOutcome::REJECT_BACKEND, "backend mismatch");
        }
        auto bit = backends_.find(rec.backend);
        if (bit == backends_.end() || bit->second->generation() != rec.backend_generation) {
            return decision(AccessOutcome::REJECT_BACKEND, "backend generation changed");
        }
        if (request.transport.is_valid() && request.transport != rec.transport) {
            return decision(AccessOutcome::REJECT_TRANSPORT, "transport mismatch");
        }

        // Protection domain.
        if (request.domain.is_valid() && request.domain != rec.domain_id) {
            return decision(AccessOutcome::REJECT_DOMAIN, "protection domain mismatch");
        }

        // Required rights granted.
        if (!access_superset(rec.granted_access, request.required_rights)) {
            return decision(AccessOutcome::REJECT_PERMISSION,
                                 "required rights 0x" + int_to_str(request.required_rights) +
                                 " not granted (granted 0x" + int_to_str(rec.granted_access) + ")");
        }
        // Intrinsic right for the operation must be granted.
        {
            AccessRight intrinsic = AccessRight::REMOTE_ATOMIC;
            if (request.kind == OperationKind::WRITE) intrinsic = AccessRight::REMOTE_WRITE;
            else if (request.kind == OperationKind::READ) intrinsic = AccessRight::REMOTE_READ;
            if (!access_has(rec.granted_access, intrinsic)) {
                return decision(AccessOutcome::REJECT_PERMISSION,
                                 std::string(operation_kind_name(request.kind)) + " requires " +
                                 (request.kind == OperationKind::WRITE ? std::string("REMOTE_WRITE")
                                  : (request.kind == OperationKind::READ ? std::string("REMOTE_READ")
                                                                         : std::string("REMOTE_ATOMIC"))) +
                                 " which is not granted");
            }
        }
        // Atomic capability must be explicitly supported.
        if (request.kind == OperationKind::ATOMIC_COMPARE_SWAP &&
            access_has(request.required_rights, AccessRight::REMOTE_ATOMIC)) {
            const BackendCapabilities caps = bit->second->capabilities();
            if (!capability_allows(caps.remote_atomic)) {
                return decision(AccessOutcome::REJECT_UNKNOWN_CAPABILITY,
                                     "backend does not explicitly support REMOTE_ATOMIC");
            }
        }

        // Range inside registered range.
        if (!range_inside(rec.descriptor, request.offset, request.length)) {
            return decision(AccessOutcome::REJECT_RANGE,
                                 "requested range [" + int_to_str(request.offset) + ", " +
                                 int_to_str(request.length) + "] outside registered range");
        }

        // Backend currency confirmation.
        RegisterHandle h{rec.memory_region_id, rec.backend_handle};
        std::string ex;
        AccessOutcome bo = bit->second->query_remote_access(h, back_dummy_remote_key(rec), request.kind,
                                                            request.offset, request.length, ex);
        if (bo != AccessOutcome::ALLOW) {
            return decision(bo, ex);
        }

        // Accounting observation (completed-work micro-accounting).
        if (request.kind == OperationKind::WRITE) acct_.remote_write_bytes.increment(request.length);
        else if (request.kind == OperationKind::READ) acct_.remote_read_bytes.increment(request.length);
        else if (request.kind == OperationKind::ATOMIC_COMPARE_SWAP) acct_.atomic_operations.increment();

        return decision(AccessOutcome::ALLOW,
                             "remote " + std::string(operation_kind_name(request.kind)) + " allowed");
    }

    // -- revocation --------------------------------------------------
    RevokeResult revoke(RegistrationId registration, RevocationMode mode) {
        RevokeResult vz;
        std::lock_guard<std::mutex> g(mutex_);
        auto rit = registrations_.find(registration);
        if (rit == registrations_.end()) {
            vz.ok = false;
            vz.explanation = "registration not found";
            return vz;
        }
        RegistrationRecord& rec = rit->second;
        if (rec.lifecycle != RegistrationLifecycle::ACTIVE &&
            rec.lifecycle != RegistrationLifecycle::REGISTERED) {
            vz.ok = false;
            vz.explanation = "registration not in revocable state";
            return vz;
        }
        rec.lifecycle = RegistrationLifecycle::REVOKING;
        rec.invalidation_reason = mode == RevocationMode::HARD_REVOKE ? "hard revoke" : "soft revoke";
        if (mode == RevocationMode::HARD_REVOKE) {
            rec.remote_key.key_generation = rec.remote_key.key_generation.next();
            rec.remote_key.revoked = true;
            rec.freshness = Freshness::STALE;
            rec.lifecycle = RegistrationLifecycle::REVOKED;
            vz.keys_invalidated = true;
            // Mark live leases revoked.
            for (auto& [lid, ls] : leases_) {
                if (ls.registration == registration && ls.state == LeaseState::ACTIVE) {
                    ls.state = LeaseState::REVOKED;
                    acct_.active_leases.decrement();
                }
            }
            // Free the buffer's single-flight registration slot so a fresh
            // registration can proceed under new authority.
            active_registration_for_buffer_.erase(rec.buffer_id);
            acct_.revocations.increment();
        } else {
            // SOFT: block new acquisitions/access; keep key material until
            // leases drain (modelled as REVOKING until lease_count reaches 0).
            rec.freshness = Freshness::STALE;
            vz.keys_invalidated = false;
            if (rec.lease_count == 0) {
                rec.lifecycle = RegistrationLifecycle::REVOKED;
                acct_.revocations.increment();
            }
        }
        vz.ok = true;
        vz.lifecycle = rec.lifecycle;
        vz.explanation = explain_revocation(rec, mode, vz.keys_invalidated);
        return vz;
    }

    bool rotate_key(RegistrationId registration, std::string& explanation) {
        std::lock_guard<std::mutex> g(mutex_);
        auto rit = registrations_.find(registration);
        if (rit == registrations_.end()) {
            explanation = "registration not found";
            return false;
        }
        RegistrationRecord& rec = rit->second;
        if (rec.lifecycle != RegistrationLifecycle::ACTIVE &&
            rec.lifecycle != RegistrationLifecycle::REGISTERED) {
            explanation = "registration not active";
            return false;
        }
        rec.remote_key.key_generation = rec.remote_key.key_generation.next();
        rec.remote_key.revoked = false;
        rec.remote_key.opaque_value = rec.remote_key.opaque_value ^ 0x0101010101010101ull;
        // Propagate to the backend so its authority token matches the runtime.
        if (auto b = backend_locked(rec.backend); b && !rec.backend_handle.empty()) {
            std::string bex;
            b->rotate_key(RegisterHandle{rec.memory_region_id, rec.backend_handle},
                          rec.remote_key.key_generation, bex);
        }
        explanation = "remote key rotated to generation " + int_to_str(rec.remote_key.key_generation.value());
        return true;
    }

    bool deregister(RegistrationId registration, std::string& explanation) {
        // Prepare outside-lock state.
        std::string handle;
        MemoryRegionId region;
        BackendId backend;
        {
            std::lock_guard<std::mutex> g(mutex_);
            auto rit = registrations_.find(registration);
            if (rit == registrations_.end()) {
                explanation = "registration not found";
                return false;
            }
            RegistrationRecord& rec = rit->second;
            if (rec.lease_count > 0) {
                explanation = "registration has active leases; revoke first or force-revoke";
                return false;
            }
            if (rec.lifecycle != RegistrationLifecycle::ACTIVE &&
                rec.lifecycle != RegistrationLifecycle::REGISTERED &&
                rec.lifecycle != RegistrationLifecycle::REVOKED &&
                rec.lifecycle != RegistrationLifecycle::STALE &&
                rec.lifecycle != RegistrationLifecycle::REVALIDATION_REQUIRED) {
                explanation = "registration not in deregisterable state";
                return false;
            }
            rec.lifecycle = RegistrationLifecycle::DEREGISTERING;
            handle = rec.backend_handle;
            region = rec.memory_region_id;
            backend = rec.backend;
        }
        // Backend deregister outside the lock.
        if (backend.is_valid()) {
            auto b = backend_locked(backend);
            if (b) {
                RegisterOutcome bo = b->deregister_buffer(RegisterHandle{region, handle});
                if (!bo.ok) {
                    std::lock_guard<std::mutex> g(mutex_);
                    auto rit = registrations_.find(registration);
                    if (rit != registrations_.end()) rit->second.lifecycle = RegistrationLifecycle::FAILED;
                    explanation = "backend deregister failed: " + bo.message;
                    return false;
                }
            }
        }
        std::lock_guard<std::mutex> g(mutex_);
        auto rit = registrations_.find(registration);
        if (rit == registrations_.end()) {
            explanation = "registration vanished during deregister";
            return false;
        }
        RegistrationRecord rec = rit->second;
        if (rec.lifecycle == RegistrationLifecycle::DEREGISTERING) {
            rec.lifecycle = RegistrationLifecycle::DEREGISTERED;
        }
        account_registration_invalidate(rec);
        registrations_.erase(rit);
        // Clear active registration pointer.
        for (auto it = active_registration_for_buffer_.begin(); it != active_registration_for_buffer_.end();) {
            if (it->second == registration) { it = active_registration_for_buffer_.erase(it); }
            else { ++it; }
        }
        for (auto it = leases_.begin(); it != leases_.end();) {
            if (it->second.registration == registration) { it = leases_.erase(it); }
            else { ++it; }
        }
        acct_.deregistrations.increment();
        explanation = "registration deregistered";
        return true;
    }

    bool get_registration(RegistrationId id, RegistrationRecord& out) const {
        std::lock_guard<std::mutex> g(mutex_);
        auto it = registrations_.find(id);
        if (it == registrations_.end()) return false;
        out = it->second;
        return true;
    }

    std::vector<RegistrationId> registrations() {
        std::lock_guard<std::mutex> g(mutex_);
        std::vector<RegistrationId> out;
        out.reserve(registrations_.size());
        for (auto& [id, rec] : registrations_) { (void)rec; out.push_back(id); }
        std::sort(out.begin(), out.end(), [](const RegistrationId& a, const RegistrationId& b) {
            return a.value() < b.value();
        });
        return out;
    }

    const Accounting& accounting() const { return acct_; }
    bool accounting_clean() const { return !static_cast<bool>(acct_); }

    // -- accounting helpers ------------------------------------------
    void account_registration_commit(RegistrationRecord& rec) {
        acct_.active_registrations.increment();
        acct_.registered_bytes.increment(rec.length);
        if (rec.domain == MemoryDomain::HOST_PINNED) acct_.pinned_bytes.increment(rec.length);
        acct_.local_keys.increment();
        acct_.remote_keys.increment();
    }

    void account_registration_invalidate(RegistrationRecord& rec) {
        acct_.active_registrations.decrement();
        acct_.registered_bytes.decrement(rec.length);
        if (rec.domain == MemoryDomain::HOST_PINNED) acct_.pinned_bytes.decrement(rec.length);
        acct_.local_keys.decrement();
        acct_.remote_keys.decrement();
    }

    BackendKey back_dummy_remote_key(const RegistrationRecord& rec) {
        BackendKey k;
        k.remote_key_id = rec.remote_key.id;
        k.local_key_id = rec.local_key.id;
        k.remote_key_generation = rec.remote_key.key_generation;
        k.opaque_value = rec.remote_key.opaque_value;
        k.granted_access = rec.remote_key.access;
        k.provenance = rec.provenance;
        return k;
    }

    // -- persistence ---------------------------------------------
    bool save(const std::string& path, std::string& err) {
        PersistableState state;
        {
            std::lock_guard<std::mutex> g(mutex_);
            for (auto& [id, be] : buffers_) { (void)id; state.buffers.push_back(be.descriptor); }
            for (auto& [id, rec] : registrations_) {
                (void)id;
                RegistrationRecord logical = rec;
                logical.backend_handle.clear();
                logical.memory_region_id = MemoryRegionId{};
                logical.local_key.opaque_value = 0;
                logical.remote_key.opaque_value = 0;
                logical.lifecycle = RegistrationLifecycle::REVALIDATION_REQUIRED;
                logical.freshness = Freshness::REVALIDATION_REQUIRED;
                state.registrations.push_back(logical);
            }
            for (auto& [id, de] : domains_) { (void)id; (void)de; state.domains.push_back(ProtectionDomainId(id.value())); }
            for (auto& [id, rec] : registrations_) { state.remote_key_history.push_back(rec.remote_key); }
            for (auto& [id, rec] : registrations_) { state.local_key_history.push_back(rec.local_key); }
            for (auto& [id, rec] : registrations_) {
                if (!rec.invalidation_reason.empty()) state.revocation_history.push_back(rec.invalidation_reason);
            }
            state.accounting_summary = acct_;
            state.backend_capability_snapshot = backend_summaries_unlocked();
            state.authority_snapshot = authority_;
            state.policy_generation = authority_.policy_generation;
        }
        const std::vector<std::uint8_t> blob = rdmabuffer::persistence::serialize(state);

        // temp -> flush -> close -> rename
        const std::string tmp = path + ".tmp";
        {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            if (!f) { err = "IO_ERROR_OPEN"; return false; }
            f.write(reinterpret_cast<const char*>(blob.data()), static_cast<std::streamsize>(blob.size()));
            f.flush();
            if (!f) { err = "IO_ERROR_WRITE"; return false; }
            f.close();
        }
        if (std::remove(path.c_str()) == 0) { /* fine */ }
        if (std::rename(tmp.c_str(), path.c_str()) != 0) {
            err = "IO_ERROR_WRITE";
            return false;
        }
        err.clear();
        return true;
    }

    std::vector<BackendInfo> backend_summaries_unlocked() {
        std::vector<BackendInfo> out;
        for (auto& [id, b] : backends_) {
            BackendInfo info;
            info.id = id;
            info.name = std::string(b->name());
            info.provenance = b->provenance();
            info.capabilities = b->capabilities();
            info.state = b->state();
            info.generation = b->generation();
            out.push_back(std::move(info));
        }
        return out;
    }

    bool recover(const std::string& path, std::string& err, RecoveryReport& report) {
        std::ifstream f(path, std::ios::binary);
        if (!f) { err = "IO_ERROR_OPEN"; return false; }
        std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        PersistableState state;
        if (!rdmabuffer::persistence::parse(bytes, state, err)) return false;

        std::lock_guard<std::mutex> g(mutex_);
        for (const BufferDescriptor& b : state.buffers) {
            BufferEntry be; be.descriptor = b; be.registered = false;
            if (buffers_.count(b.id) == 0) {
                buffers_[b.id] = std::move(be);
                acct_.logical_buffers.increment();
                acct_.live_buffer_bytes.increment(b.byte_length);
                ++report.recovered_buffers;
            }
        }
        for (const ProtectionDomainId& d : state.domains) {
            if (domains_.count(d) == 0) {
                DomainEntry de; de.state = DomainState::ACTIVE; de.generation = ProtectionDomainGeneration(1);
                domains_[d] = std::move(de);
                acct_.protection_domains.increment();
                ++report.recovered_domains;
            }
        }
        // Recovered registrations are NOT automatically live.
        for (const RegistrationRecord& rec : state.registrations) {
            if (registrations_.count(rec.id) != 0) { /* duplicate identity -> skip */ }
            if (rec.lease_count != 0) { /* logical */ }
            RegistrationRecord r = rec;
            r.lifecycle = RegistrationLifecycle::REVALIDATION_REQUIRED;
            r.freshness = Freshness::REVALIDATION_REQUIRED;
            r.remote_key.revoked = true;
            r.remote_key.opaque_value = 0;
            r.local_key.opaque_value = 0;
            r.backend_handle.clear();
            r.memory_region_id = MemoryRegionId{};
            registrations_[r.id] = std::move(r);
            ++report.recovered_registrations;
        }
        authority_ = state.authority_snapshot;
        report.persistence_ok = true;
        report.semantic_digest = rdmabuffer::persistence::semantic_digest(state);
        // Never auto-ACCOUNT recovered live registrations: nothing is live.
        err.clear();
        return true;
    }

};

// ---------------------------------------------------------------------------
// Rdmabuffer public API delegation
// ---------------------------------------------------------------------------
Rdmabuffer::Rdmabuffer() : impl_(std::make_unique<Impl>()) {}
Rdmabuffer::~Rdmabuffer() = default;

void Rdmabuffer::set_authority(const AuthoritySnapshot& s) { impl_->set_authority(s); }
AuthoritySnapshot Rdmabuffer::authority() const { return impl_->snapshot(); }
CoordinatorEpoch Rdmabuffer::current_epoch() const { return impl_->snapshot().coordinator_epoch; }

void Rdmabuffer::advance_epoch() {
    std::lock_guard<std::mutex> g(impl_->mutex_);
    impl_->authority_.coordinator_epoch = impl_->authority_.coordinator_epoch.next();
}

void Rdmabuffer::note_participant_restart() {
    std::lock_guard<std::mutex> g(impl_->mutex_);
    impl_->authority_.coordinator_epoch = impl_->authority_.coordinator_epoch.next();
    impl_->authority_.worker_boot = WorkerBootId(impl_->authority_.worker_boot.value() + 1);
    impl_->acct_.participant_restarts.increment();
}

bool Rdmabuffer::add_backend(std::shared_ptr<IBackend> b) { return impl_->add_backend(std::move(b)); }
bool Rdmabuffer::has_backend(BackendId id) const { return impl_->has_backend(id); }
BackendCapabilities Rdmabuffer::backend_capabilities(BackendId id) const { return impl_->backend_capabilities(id); }
std::vector<BackendInfo> Rdmabuffer::backend_summaries() const { return impl_->backend_summaries(); }

ProtectionDomainId Rdmabuffer::create_protection_domain(NodeId node, ProcessId process) {
    return impl_->create_protection_domain(node, process);
}
bool Rdmabuffer::destroy_protection_domain(ProtectionDomainId d) { return impl_->destroy_protection_domain(d); }

BufferId Rdmabuffer::create_buffer(const BufferDescriptor& d) { return impl_->create_buffer(d); }
bool Rdmabuffer::has_buffer(BufferId id) const { return impl_->has_buffer(id); }

RegisterResult Rdmabuffer::register_buffer(const BufferDescriptor& d, BackendId b, ProtectionDomainId dom,
                                            const AuthorityEnvelope& env) {
    return impl_->register_buffer(d, b, dom, env);
}
RegisterResult Rdmabuffer::register_buffer_reuse(const BufferDescriptor& d, BackendId b, ProtectionDomainId dom,
                                                  const AuthorityEnvelope& env) {
    return impl_->register_buffer_reuse(d, b, dom, env);
}

LeaseAcquireResult Rdmabuffer::acquire_lease(RegistrationId reg, const AuthorityEnvelope& env,
                                              AccessMask needed) {
    return impl_->acquire_lease(reg, env, needed);
}
bool Rdmabuffer::release_lease(RegistrationLeaseId lease) { return impl_->release_lease(lease); }

AccessDecision Rdmabuffer::validate_remote_access(const RemoteAccessRequest& req) {
    return impl_->validate_remote_access(req);
}

RevokeResult Rdmabuffer::revoke(RegistrationId reg, RevocationMode mode) { return impl_->revoke(reg, mode); }
bool Rdmabuffer::rotate_key(RegistrationId reg, std::string& ex) { return impl_->rotate_key(reg, ex); }
bool Rdmabuffer::deregister(RegistrationId reg, std::string& ex) { return impl_->deregister(reg, ex); }

bool Rdmabuffer::get_registration(RegistrationId id, RegistrationRecord& out) const {
    return impl_->get_registration(id, out);
}
bool Rdmabuffer::get_buffer(BufferId id, BufferDescriptor& out) const { return impl_->get_buffer(id, out); }
std::vector<RegistrationId> Rdmabuffer::registrations() const { return impl_->registrations(); }

const Accounting& Rdmabuffer::accounting() const { return impl_->accounting(); }
bool Rdmabuffer::accounting_clean() const { return impl_->accounting_clean(); }

bool Rdmabuffer::save(const std::string& path, std::string& err) const { return impl_->save(path, err); }
bool Rdmabuffer::recover(const std::string& path, std::string& err, RecoveryReport& report) {
    return impl_->recover(path, err, report);
}

} // namespace rdmabuffer

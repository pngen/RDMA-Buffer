// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "rdmabuffer/reference_backend.hpp"

#include "windows_os.hpp"

#include <memory>
#include <string>

namespace rdmabuffer {

ReferenceBackend::ReferenceBackend(BackendId id) : id_(id) {}

BackendId ReferenceBackend::id() const noexcept { return id_; }
std::string_view ReferenceBackend::name() const noexcept { return "reference-tcp"; }
Provenance ReferenceBackend::provenance() const noexcept { return Provenance::REAL; }
BackendGeneration ReferenceBackend::generation() const noexcept { return backend_gen_; }
BackendState ReferenceBackend::state() const noexcept { return state_; }

BackendCapabilities ReferenceBackend::capabilities() const noexcept {
    BackendCapabilities c;
    c.supported_domains.push_back(MemoryDomain::HOST_PAGEABLE);
    c.supported_domains.push_back(MemoryDomain::HOST_PINNED);
    c.supported_domains.push_back(MemoryDomain::SHARED_MEMORY);
    c.supported_domains.push_back(MemoryDomain::FILE_BACKED);
    c.max_registration_length = 0;
    c.required_alignment = windows_os::page_size();
    c.remote_read = CapabilityState::SUPPORTED;   // logical reference transport.
    c.remote_write = CapabilityState::SUPPORTED;  // logical reference transport.
    c.remote_atomic = CapabilityState::NOT_SUPPORTED;
    c.host_pinned = CapabilityState::SUPPORTED;
    c.pageable_registration = CapabilityState::SUPPORTED;
    c.cuda_device = CapabilityState::NOT_SUPPORTED;
    c.cuda_managed = CapabilityState::NOT_SUPPORTED;
    c.on_demand_paging = CapabilityState::UNKNOWN;
    c.one_sided = CapabilityState::NOT_SUPPORTED;
    c.multiprocess = CapabilityState::SUPPORTED;
    c.multinode = CapabilityState::SUPPORTED;
    c.key_rotation = CapabilityState::SUPPORTED;
    c.revocation = CapabilityState::SUPPORTED;
    c.provenance = Provenance::REAL;
    return c;
}

BackendCapabilities ReferenceBackend::discover_capabilities() { return capabilities(); }

std::string ReferenceBackend::can_register(const BufferDescriptor& buffer) const {
    const auto caps = capabilities();
    if (!domain_supported(caps, buffer.domain)) return "DOMAIN_UNSUPPORTED";
    if (buffer.byte_length == 0) return "ZERO_LENGTH";
    const auto vr = validate_range(buffer);
    if (!vr.ok) return vr.code;
    if (access_has(buffer.requested_access, AccessRight::REMOTE_ATOMIC)) {
        return "REMOTE_ATOMIC_UNSUPPORTED";
    }
    return "";
}

RegisterOutcome ReferenceBackend::register_buffer(const BufferDescriptor& buffer,
                                                  const RegistrationContext& ctx,
                                                  BackendRegistration& out) {
    std::string reason = can_register(buffer);
    if (!reason.empty()) {
        return RegisterOutcome{false, reason, "Reference backend rejects registration: " + reason};
    }
    MemoryRegionId region(0x100000000ull + next_seq_);
    ++next_seq_;
    const std::string handle = "ref-" + std::to_string(region.value());

    Entry e;
    e.ctx = ctx;
    e.revoked = false;
    BackendRegistration& r = e.reg;
    r.memory_region_id = region;
    r.handle = handle;
    r.registered_base = buffer.base.address;
    r.registered_length = buffer.byte_length;
    r.granted_access = buffer.requested_access;
    r.keys.remote_key_id = RemoteKeyId(region.value() * 3 + 1);
    r.keys.local_key_id = LocalKeyId(region.value() * 3 + 2);
    r.keys.remote_key_generation = RemoteKeyGeneration(1);
    r.keys.opaque_value = region.value() ^ 0x5A5A5A5A5A5A5A5Aull;
    r.keys.granted_access = buffer.requested_access;
    r.keys.provenance = Provenance::REAL;
    r.transport = TransportId(0x525046ull); // "RPF"
    r.nic = NicId{};
    r.provenance = Provenance::REAL;
    r.freshness = Freshness::VALID;

    entries_[handle] = e;
    out = r;
    return RegisterOutcome{true, "REGISTERED", "Reference registration committed (TCP_REFERENCE)."};
}

RegisterOutcome ReferenceBackend::deregister_buffer(const RegisterHandle& handle) {
    auto it = entries_.find(handle.handle);
    if (it == entries_.end()) {
        return RegisterOutcome{false, "NOT_FOUND", "No reference registration for handle."};
    }
    entries_.erase(it);
    return RegisterOutcome{true, "DEREGISTERED", "Reference registration released."};
}

RegisterOutcome ReferenceBackend::query_registration(const RegisterHandle& handle,
                                                     BackendRegistration& out) {
    auto it = entries_.find(handle.handle);
    if (it == entries_.end()) {
        return RegisterOutcome{false, "NOT_FOUND", "No reference registration for handle."};
    }
    out = it->second.reg;
    return RegisterOutcome{true, "QUERIED", "Reference registration revalidated."};
}

AccessOutcome ReferenceBackend::query_remote_access(const RegisterHandle& handle,
                                                    const BackendKey& key,
                                                    OperationKind kind,
                                                    std::uint64_t offset,
                                                    std::uint64_t length,
                                                    std::string& explanation) {
    auto it = entries_.find(handle.handle);
    if (it == entries_.end()) {
        explanation = "Reference backend has no live registration for this handle.";
        return AccessOutcome::REJECT_NOT_REGISTERED;
    }
    const Entry& e = it->second;
    if (e.revoked) {
        explanation = "Reference registration has been revoked.";
        return AccessOutcome::REJECT_REVOKED;
    }
    if (key.remote_key_generation != e.reg.keys.remote_key_generation) {
        explanation = "Reference remote key generation is stale.";
        return AccessOutcome::REJECT_STALE_KEY;
    }
    if (offset > e.reg.registered_length || length > (e.reg.registered_length - offset)) {
        explanation = "Reference access range exceeds registered length.";
        return AccessOutcome::REJECT_RANGE;
    }
    if (kind == OperationKind::WRITE && !access_has(e.reg.granted_access, AccessRight::REMOTE_WRITE)) {
        explanation = "Reference registration does not grant REMOTE_WRITE.";
        return AccessOutcome::REJECT_PERMISSION;
    }
    if (kind == OperationKind::READ && !access_has(e.reg.granted_access, AccessRight::REMOTE_READ)) {
        explanation = "Reference registration does not grant REMOTE_READ.";
        return AccessOutcome::REJECT_PERMISSION;
    }
    if (kind == OperationKind::ATOMIC_COMPARE_SWAP) {
        explanation = "Reference backend does not support REMOTE_ATOMIC.";
        return AccessOutcome::REJECT_UNKNOWN_CAPABILITY;
    }
    explanation = "Reference backend permits this reference transport operation.";
    return AccessOutcome::ALLOW;
}

AccessOutcome ReferenceBackend::revalidate(const RegisterHandle& handle, std::string& explanation) {
    if (entries_.find(handle.handle) == entries_.end()) {
        explanation = "Cannot revalidate: reference registration not found.";
        return AccessOutcome::REJECT_NOT_REGISTERED;
    }
    explanation = "Reference registration revalidated.";
    return AccessOutcome::ALLOW;
}

bool ReferenceBackend::abort_registration(const RegisterHandle& handle, std::string& explanation) {
    auto it = entries_.find(handle.handle);
    if (it == entries_.end()) {
        explanation = "Abort: reference registration not found.";
        return false;
    }
    entries_.erase(it);
    explanation = "Reference registration aborted.";
    return true;
}

bool ReferenceBackend::rotate_key(const RegisterHandle& handle, RemoteKeyGeneration new_gen,
                                             std::string& explanation) {
    auto it = entries_.find(handle.handle);
    if (it == entries_.end()) {
        explanation = "rotate_key: reference registration not found.";
        return false;
    }
    it->second.reg.keys.remote_key_generation = new_gen;
    explanation = "reference key rotated to generation " + std::to_string(new_gen.value());
    return true;
}

void ReferenceBackend::advance_backend_generation() noexcept {
    backend_gen_ = backend_gen_.next();
}

PinProbeResult ReferenceBackend::probe_host_pinning(std::uintptr_t address, std::uint64_t length) const {
    (void)address;
    PinProbeResult r;
    r.bytes = length;
    if (length == 0) {
        r.detail = "zero length probe";
        return r;
    }
#ifdef RDMABUFFER_WINDOWS
    std::string allocErr;
    void* p = windows_os::commit_pages(length, allocErr);
    if (p == nullptr) {
        r.detail = "allocation failed: " + allocErr;
        r.provenance = Provenance::REAL;
        return r;
    }
    r.allocation_committed = true;
    std::uint64_t touched = windows_os::touch_range(static_cast<volatile unsigned char*>(p), length);
    (void)touched;
    std::string lockErr;
    if (windows_os::virtual_lock(p, length, lockErr)) {
        r.ok = true;
        r.locked = true;
    } else {
        r.ok = false;
        r.locked = false;
    }
    r.detail = (r.locked ? "VirtualAlloc committed + touched + VirtualLock succeeded"
                         : "VirtualAlloc committed + touched; VirtualLock failed: " + lockErr);
    std::string unlockErr;
    windows_os::virtual_unlock(p, length, unlockErr);
    std::string freeErr;
    windows_os::release_pages(p, length, freeErr);
    r.provenance = Provenance::REAL;
    return r;
#else
    std::string allocErr;
    void* p = windows_os::commit_pages(length, allocErr);
    if (p == nullptr) {
        r.detail = "allocation failed: " + allocErr;
        return r;
    }
    r.allocation_committed = true;
    r.detail = "allocation committed + touched; VirtualLock unsupported on this platform";
    r.provenance = Provenance::UNKNOWN;
    std::string freeErr;
    windows_os::release_pages(p, length, freeErr);
    return r;
#endif
}

} // namespace rdmabuffer

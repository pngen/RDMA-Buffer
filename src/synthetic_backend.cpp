// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "rdmabuffer/synthetic_backend.hpp"

#include <charconv>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <vector>

namespace rdmabuffer {
namespace {

std::uint64_t xorshift64(std::uint64_t& s) noexcept {
    std::uint64_t x = s;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    s = x;
    return x;
}

std::string to_hex(std::uint64_t v) {
    char buf[32];
    auto [p, ec] = std::to_chars(buf, buf + sizeof(buf), v, 16);
    (void)ec;
    return std::string(buf, p);
}

bool str_contains_remote(AccessMask m) noexcept {
    return access_has(m, AccessRight::REMOTE_READ) || access_has(m, AccessRight::REMOTE_WRITE) ||
           access_has(m, AccessRight::REMOTE_ATOMIC);
}

} // namespace

SyntheticBackend::SyntheticBackend(std::uint64_t seed)
    : id_(BackendId(0x53594E54ull)),   // "SYNT"
      backend_gen_(BackendGeneration(1)),
      transport_gen_(TransportGeneration(1)),
      nic_gen_(NicGeneration(1)),
      nic_(NicId(0x53594E49ull)),      // "SYNI"
      seed_(seed) {}

BackendId SyntheticBackend::id() const noexcept { return id_; }
std::string_view SyntheticBackend::name() const noexcept { return "synthetic-rdma"; }
Provenance SyntheticBackend::provenance() const noexcept { return Provenance::SYNTHETIC; }
BackendGeneration SyntheticBackend::generation() const noexcept { return backend_gen_; }
BackendState SyntheticBackend::state() const noexcept { return state_; }

BackendCapabilities SyntheticBackend::capabilities() const noexcept {
    BackendCapabilities c;
    if (synthetic_domain_supported_) c.supported_domains.push_back(MemoryDomain::SYNTHETIC_REMOTE_CAPABLE);
    if (host_pinned_supported_) c.supported_domains.push_back(MemoryDomain::HOST_PINNED);
    if (pageable_supported_) c.supported_domains.push_back(MemoryDomain::HOST_PAGEABLE);
    if (shared_supported_) c.supported_domains.push_back(MemoryDomain::SHARED_MEMORY);
    if (file_backed_supported_) c.supported_domains.push_back(MemoryDomain::FILE_BACKED);
    if (cuda_device_supported_) c.supported_domains.push_back(MemoryDomain::CUDA_DEVICE);
    if (cuda_managed_supported_) c.supported_domains.push_back(MemoryDomain::CUDA_MANAGED);
    c.max_registration_length = 0;
    c.required_alignment = required_alignment_;
    c.remote_read = remote_read_supported_ ? CapabilityState::SUPPORTED : CapabilityState::NOT_SUPPORTED;
    c.remote_write = remote_write_supported_ ? CapabilityState::SUPPORTED : CapabilityState::NOT_SUPPORTED;
    c.remote_atomic = atomic_supported_ ? CapabilityState::SUPPORTED : CapabilityState::NOT_SUPPORTED;
    c.host_pinned = host_pinned_supported_ ? CapabilityState::SUPPORTED : CapabilityState::NOT_SUPPORTED;
    c.pageable_registration = pageable_supported_ ? CapabilityState::SUPPORTED : CapabilityState::NOT_SUPPORTED;
    c.cuda_device = cuda_device_supported_ ? CapabilityState::SUPPORTED : CapabilityState::NOT_SUPPORTED;
    c.cuda_managed = cuda_managed_supported_ ? CapabilityState::SUPPORTED : CapabilityState::NOT_SUPPORTED;
    c.on_demand_paging = CapabilityState::UNKNOWN;
    c.one_sided = one_sided_supported_ ? CapabilityState::SUPPORTED : CapabilityState::NOT_SUPPORTED;
    c.multiprocess = CapabilityState::SUPPORTED;
    c.multinode = CapabilityState::SUPPORTED;
    c.key_rotation = CapabilityState::SUPPORTED;
    c.revocation = CapabilityState::SUPPORTED;
    c.provenance = Provenance::SYNTHETIC;
    return c;
}

BackendCapabilities SyntheticBackend::discover_capabilities() { return capabilities(); }

void SyntheticBackend::configure_device_memory_support(bool s) noexcept { cuda_device_supported_ = s; }
void SyntheticBackend::configure_atomic_support(bool s) noexcept { atomic_supported_ = s; }
void SyntheticBackend::configure_remote_write(bool s) noexcept { remote_write_supported_ = s; }
void SyntheticBackend::configure_remote_read(bool s) noexcept { remote_read_supported_ = s; }
void SyntheticBackend::configure_required_alignment(std::uint64_t a) noexcept { required_alignment_ = a; }
void SyntheticBackend::configure_synthetic_domain_support(bool s) noexcept { synthetic_domain_supported_ = s; }

std::string SyntheticBackend::can_register(const BufferDescriptor& buffer) const {
    const auto caps = capabilities();
    if (!domain_supported(caps, buffer.domain)) {
        return "DOMAIN_UNSUPPORTED";
    }
    if (buffer.byte_length == 0) return "ZERO_LENGTH";
    const auto vr = validate_range(buffer);
    if (!vr.ok) return vr.code;
    if (required_alignment_ != 0 && buffer.alignment != 0 &&
        (buffer.alignment % required_alignment_ != 0 || required_alignment_ % buffer.alignment != 0)) {
        return "ALIGNMENT_INCOMPATIBLE";
    }
    // Remote capability gating: requested remote rights must be supported.
    const bool wants_read = access_has(buffer.requested_access, AccessRight::REMOTE_READ);
    const bool wants_write = access_has(buffer.requested_access, AccessRight::REMOTE_WRITE);
    const bool wants_atomic = access_has(buffer.requested_access, AccessRight::REMOTE_ATOMIC);
    if (wants_read && !remote_read_supported_) return "REMOTE_READ_UNSUPPORTED";
    if (wants_write && !remote_write_supported_) return "REMOTE_WRITE_UNSUPPORTED";
    if (wants_atomic && !atomic_supported_) return "REMOTE_ATOMIC_UNSUPPORTED";
    if ((wants_read || wants_write || wants_atomic) &&
        buffer.domain == MemoryDomain::CUDA_DEVICE && !cuda_device_supported_) {
        return "CUDA_DEVICE_UNSUPPORTED";
    }
    return "";
}

std::string SyntheticBackend::make_handle(MemoryRegionId id) const {
    return std::string("syn-") + to_hex(id.value());
}

RegisterOutcome SyntheticBackend::register_buffer(const BufferDescriptor& buffer,
                                                  const RegistrationContext& ctx,
                                                  BackendRegistration& out) {
    std::string reason = can_register(buffer);
    if (!reason.empty()) {
        return RegisterOutcome{false, reason, std::string("Synthetic backend rejects registration: ") + reason};
    }
    MemoryRegionId region(seed_ ^ (next_seq_ << 7) ^ 0x9E3779B97F4A7C15ull);
    ++next_seq_;
    std::string handle = make_handle(region);

    Entry e;
    e.ctx = ctx;
    e.key_generation = RemoteKeyGeneration(1);
    e.revoked = false;
    e.revalidate_required = false;

    BackendRegistration& r = e.reg;
    r.memory_region_id = region;
    r.handle = handle;
    r.registered_base = buffer.base.address;
    r.registered_length = buffer.byte_length;
    r.granted_access = buffer.requested_access;
    r.keys.remote_key_id = RemoteKeyId(region.value() * 3 + 1);
    r.keys.local_key_id = LocalKeyId(region.value() * 3 + 2);
    r.keys.remote_key_generation = e.key_generation;
    r.keys.opaque_value = region.value() ^ 0xA5A5A5A5A5A5A5A5ull;
    r.keys.granted_access = buffer.requested_access;
    r.keys.provenance = Provenance::SYNTHETIC;
    r.transport = TransportId(0x53594E54ull);
    r.nic = nic_;
    r.device = ctx.worker.is_valid() ? DeviceId(ctx.worker.value() + 1) : DeviceId{};
    r.provenance = Provenance::SYNTHETIC;
    r.freshness = Freshness::VALID;

    entries_[handle] = e;
    region_handle_[region] = handle;

    out = r;
    return RegisterOutcome{true, "REGISTERED", "Synthetic registration committed."};
}

RegisterOutcome SyntheticBackend::deregister_buffer(const RegisterHandle& handle) {
    auto it = entries_.find(handle.handle);
    if (it == entries_.end()) {
        return RegisterOutcome{false, "NOT_FOUND", "No synthetic registration for handle."};
    }
    region_handle_.erase(it->second.reg.memory_region_id);
    entries_.erase(it);
    return RegisterOutcome{true, "DEREGISTERED", "Synthetic registration released."};
}

RegisterOutcome SyntheticBackend::query_registration(const RegisterHandle& handle,
                                                     BackendRegistration& out) {
    auto it = entries_.find(handle.handle);
    if (it == entries_.end()) {
        return RegisterOutcome{false, "NOT_FOUND", "No synthetic registration for handle."};
    }
    out = it->second.reg;
    return RegisterOutcome{true, "QUERIED", "Synthetic registration revalidated."};
}

AccessOutcome SyntheticBackend::query_remote_access(const RegisterHandle& handle,
                                                    const BackendKey& key,
                                                    OperationKind kind,
                                                    std::uint64_t offset,
                                                    std::uint64_t length,
                                                    std::string& explanation) {
    auto it = entries_.find(handle.handle);
    if (it == entries_.end()) {
        explanation = "Synthetic backend has no live registration for this handle.";
        return AccessOutcome::REJECT_NOT_REGISTERED;
    }
    const Entry& e = it->second;
    if (e.revalidate_required) {
        explanation = "Synthetic registration requires revalidation; key is not authoritative.";
        return AccessOutcome::REJECT_STALE_REGISTRATION;
    }
    if (e.revoked) {
        explanation = "Synthetic registration has been revoked.";
        return AccessOutcome::REJECT_REVOKED;
    }
    if (key.remote_key_generation != e.key_generation) {
        explanation = "Synthetic remote key generation " + std::to_string(key.remote_key_generation.value()) +
                      " is stale; current is " + std::to_string(e.key_generation.value()) + ".";
        return AccessOutcome::REJECT_STALE_KEY;
    }
    if (offset > e.reg.registered_length || length > (e.reg.registered_length - offset)) {
        explanation = "Synthetic access range [" + std::to_string(offset) + ", " +
                      std::to_string(length) + "] exceeds registered length " +
                      std::to_string(e.reg.registered_length) + ".";
        return AccessOutcome::REJECT_RANGE;
    }
    if (kind == OperationKind::WRITE) {
        if (!remote_write_supported_) {
            explanation = "Synthetic backend does not support REMOTE_WRITE.";
            return AccessOutcome::REJECT_UNKNOWN_CAPABILITY;
        }
        if (!access_has(e.reg.granted_access, AccessRight::REMOTE_WRITE)) {
            explanation = "Synthetic registration does not grant REMOTE_WRITE.";
            return AccessOutcome::REJECT_PERMISSION;
        }
    } else if (kind == OperationKind::READ) {
        if (!remote_read_supported_) {
            explanation = "Synthetic backend does not support REMOTE_READ.";
            return AccessOutcome::REJECT_UNKNOWN_CAPABILITY;
        }
        if (!access_has(e.reg.granted_access, AccessRight::REMOTE_READ)) {
            explanation = "Synthetic registration does not grant REMOTE_READ.";
            return AccessOutcome::REJECT_PERMISSION;
        }
    } else if (kind == OperationKind::ATOMIC_COMPARE_SWAP) {
        if (!atomic_supported_) {
            explanation = "Synthetic backend does not support REMOTE_ATOMIC.";
            return AccessOutcome::REJECT_UNKNOWN_CAPABILITY;
        }
        if (!access_has(e.reg.granted_access, AccessRight::REMOTE_ATOMIC)) {
            explanation = "Synthetic registration does not grant REMOTE_ATOMIC.";
            return AccessOutcome::REJECT_PERMISSION;
        }
    }
    explanation = "Synthetic backend permits this remote operation.";
    return AccessOutcome::ALLOW;
}

AccessOutcome SyntheticBackend::revalidate(const RegisterHandle& handle, std::string& explanation) {
    auto it = entries_.find(handle.handle);
    if (it == entries_.end()) {
        explanation = "Cannot revalidate: synthetic registration not found.";
        return AccessOutcome::REJECT_NOT_REGISTERED;
    }
    it->second.revalidate_required = false;
    explanation = "Synthetic registration revalidated.";
    return AccessOutcome::ALLOW;
}

bool SyntheticBackend::abort_registration(const RegisterHandle& handle, std::string& explanation) {
    auto it = entries_.find(handle.handle);
    if (it == entries_.end()) {
        explanation = "Abort: synthetic registration not found.";
        return false;
    }
    region_handle_.erase(it->second.reg.memory_region_id);
    entries_.erase(it);
    explanation = "Synthetic registration aborted.";
    return true;
}

bool SyntheticBackend::rotate_key(const RegisterHandle& handle, RemoteKeyGeneration new_gen,
                                             std::string& explanation) {
    auto it = entries_.find(handle.handle);
    if (it == entries_.end()) {
        explanation = "rotate_key: synthetic registration not found.";
        return false;
    }
    it->second.key_generation = new_gen;
    it->second.reg.keys.remote_key_generation = new_gen;
    it->second.revalidate_required = false;
    explanation = "synthetic key rotated to generation " + std::to_string(new_gen.value());
    return true;
}

void SyntheticBackend::advance_backend_generation() noexcept { rollover_backend_generation(); }

void SyntheticBackend::rollover_backend_generation() noexcept {
    backend_gen_ = backend_gen_.next();
}

void SyntheticBackend::rollover_transport_generation() noexcept {
    transport_gen_ = transport_gen_.next();
    // Transport rollover invalidates live key material for safety.
    for (auto& [k, e] : entries_) {
        (void)k;
        e.revalidate_required = true;
        e.key_generation = e.key_generation.next();
    }
}

void SyntheticBackend::rollover_nic_generation() noexcept { nic_gen_ = nic_gen_.next(); }

void SyntheticBackend::simulate_backend_restart() {
    // A fresh backend incarnation starts with no live handles. All previously
    // issued key material becomes stale because the handle namespace is gone.
    entries_.clear();
    region_handle_.clear();
    backend_gen_ = backend_gen_.next();
    transport_gen_ = transport_gen_.next();
    nic_gen_ = nic_gen_.next();
    state_ = BackendState::READY;
}

AccessOutcome SyntheticBackend::simulate_remote(OperationKind kind,
                                                std::uint64_t offset,
                                                std::uint64_t length,
                                                std::uint64_t expected_key_generation,
                                                std::string& explanation,
                                                std::uint64_t& result_delta) {
    result_delta = 0;
    // Deterministic selection: scan all live entries whose key generation
    // matches and pick the lexicographically smallest handle. This keeps
    // scenario output reproducible regardless of hash-map ordering.
    std::string best_handle;
    for (auto& [handle_key, e] : entries_) {
        if (e.revoked || e.revalidate_required) continue;
        if (e.key_generation.value() != expected_key_generation) continue;
        if (best_handle.empty() || handle_key < best_handle) best_handle = handle_key;
    }
    if (best_handle.empty()) {
        explanation = "Synthetic backend could not locate a live registration with the supplied key generation.";
        return AccessOutcome::REJECT_STALE_KEY;
    }
    {
        const Entry& e = entries_.at(best_handle);
        RegisterHandle h{e.reg.memory_region_id, e.reg.handle};
        AccessOutcome o = query_remote_access(h, e.reg.keys, kind, offset, length, explanation);
        if (o == AccessOutcome::ALLOW) {
            std::uint64_t state = seed_ ^ e.reg.memory_region_id.value() ^ (offset << 3);
            result_delta = xorshift64(state) % length;
            explanation = "Synthetic remote " + std::string(access_outcome_name(AccessOutcome::ALLOW)) +
                          " simulated (provenance=SYNTHETIC).";
        }
        return o;
    }
}

} // namespace rdmabuffer

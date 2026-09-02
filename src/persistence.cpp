// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "rdmabuffer/persistence.hpp"

#include "rdmabuffer/bytes.hpp"
#include "rdmabuffer/crc32.hpp"

#include <charconv>
#include <cstring>
#include <sstream>

namespace rdmabuffer {
namespace persistence {

namespace {

constexpr std::size_t max_count = (1u << 20); // bounded element count.

void write_id(bytes::Writer& w, std::uint64_t v) { w.u64(v); }

// -- BufferDescriptor -----------------------------------------------
void encode_descriptor(bytes::Writer& w, const BufferDescriptor& b) {
    w.u64(b.id.value());
    w.u64(b.generation.value());
    w.u8(static_cast<std::uint8_t>(b.domain));
    w.u64(b.base.address);
    w.u8(static_cast<std::uint8_t>(b.base.kind));
    w.u64(b.byte_length);
    w.u64(b.alignment);
    w.u64(b.page_size);
    w.u64(b.owner.value());
    w.u64(b.process.value());
    w.u64(b.worker.value());
    w.u64(b.node.value());
    w.u64(b.device.value());
    w.u8(static_cast<std::uint8_t>(b.direction));
    w.u8(b.requested_access);
    w.u8(static_cast<std::uint8_t>(b.registration_mode));
    w.u8(static_cast<std::uint8_t>(b.lifetime));
    w.u8(static_cast<std::uint8_t>(b.provenance));
    w.u8(static_cast<std::uint8_t>(b.freshness));
    w.u64(b.policy_generation.value());
}

bool decode_descriptor(bytes::Reader& r, BufferDescriptor& b) {
    if (!r.u64(reinterpret_cast<std::uint64_t&>(b.id)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(b.generation))) return false;
    std::uint8_t d = 0; if (!r.u8(d)) return false;
    if (d > static_cast<std::uint8_t>(MemoryDomain::UNKNOWN)) return false;
    b.domain = static_cast<MemoryDomain>(d);
    if (!r.u64(b.base.address)) return false;
    std::uint8_t pk = 0; if (!r.u8(pk)) return false; if (pk > 5) return false;
    b.base.kind = static_cast<PointerKind>(pk);
    if (!r.u64(b.byte_length) || !r.u64(b.alignment) || !r.u64(b.page_size)) return false;
    if (!r.u64(reinterpret_cast<std::uint64_t&>(b.owner)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(b.process)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(b.worker)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(b.node)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(b.device))) return false;
    std::uint8_t dr = 0, am = 0, rm = 0, lt = 0, pv = 0, fr = 0;
    if (!r.u8(dr) || !r.u8(am) || !r.u8(rm) || !r.u8(lt) || !r.u8(pv) || !r.u8(fr)) return false;
    if (dr > static_cast<std::uint8_t>(TransferDirection::BIDIRECTIONAL)) return false;
    if (rm > static_cast<std::uint8_t>(RegistrationMode::ANY)) return false;
    if (lt > static_cast<std::uint8_t>(LifetimePolicy::EPHEMERAL)) return false;
    if (pv > static_cast<std::uint8_t>(Provenance::UNKNOWN)) return false;
    if (fr > static_cast<std::uint8_t>(Freshness::UNKNOWN)) return false;
    b.direction = static_cast<TransferDirection>(dr);
    b.requested_access = am;
    b.registration_mode = static_cast<RegistrationMode>(rm);
    b.lifetime = static_cast<LifetimePolicy>(lt);
    b.provenance = static_cast<Provenance>(pv);
    b.freshness = static_cast<Freshness>(fr);
    if (!r.u64(reinterpret_cast<std::uint64_t&>(b.policy_generation))) return false;
    return true;
}

// -- RemoteKey / LocalKey -------------------------------------------
void encode_remote_key(bytes::Writer& w, const RemoteKey& k) {
    w.u64(k.id.value()); w.u64(k.registration.value());
    w.u64(k.registration_generation.value()); w.u64(k.key_generation.value());
    w.u64(k.buffer_generation.value()); w.u64(k.boot.value()); w.u64(k.process.value());
    w.u64(k.backend.value()); w.u8(static_cast<std::uint8_t>(k.transport));
    w.u8(k.access); w.u64(k.start); w.u64(k.length);
    w.u64(k.opaque_value); w.u8(k.revoked ? 1 : 0);
    w.u8(static_cast<std::uint8_t>(k.provenance));
}

bool decode_remote_key(bytes::Reader& r, RemoteKey& k) {
    if (!r.u64(reinterpret_cast<std::uint64_t&>(k.id)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(k.registration)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(k.registration_generation)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(k.key_generation)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(k.buffer_generation)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(k.boot)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(k.process)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(k.backend))) return false;
    std::uint8_t t = 0; if (!r.u8(t)) return false; if (t > static_cast<std::uint8_t>(TransportClass::UNKNOWN)) return false;
    k.transport = static_cast<TransportClass>(t);
    if (!r.u8(k.access)) return false;
    if (!r.u64(k.start) || !r.u64(k.length) || !r.u64(k.opaque_value)) return false;
    std::uint8_t rv = 0, pv = 0; if (!r.u8(rv) || !r.u8(pv)) return false;
    k.revoked = rv != 0; if (pv > static_cast<std::uint8_t>(Provenance::UNKNOWN)) return false;
    k.provenance = static_cast<Provenance>(pv);
    return true;
}

void encode_local_key(bytes::Writer& w, const LocalKey& k) {
    w.u64(k.id.value()); w.u64(k.registration.value());
    w.u64(k.registration_generation.value()); w.u64(k.boot.value()); w.u64(k.backend.value());
    w.u8(static_cast<std::uint8_t>(k.transport)); w.u8(k.access);
    w.u64(k.opaque_value); w.u8(static_cast<std::uint8_t>(k.provenance));
}

bool decode_local_key(bytes::Reader& r, LocalKey& k) {
    if (!r.u64(reinterpret_cast<std::uint64_t&>(k.id)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(k.registration)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(k.registration_generation)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(k.boot)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(k.backend))) return false;
    std::uint8_t t = 0, pv = 0;
    if (!r.u8(t) || !r.u8(k.access)) return false;
    if (t > static_cast<std::uint8_t>(TransportClass::UNKNOWN)) return false;
    if (!r.u64(k.opaque_value) || !r.u8(pv)) return false;
    if (pv > static_cast<std::uint8_t>(Provenance::UNKNOWN)) return false;
    k.transport = static_cast<TransportClass>(t);
    k.provenance = static_cast<Provenance>(pv);
    return true;
}

// -- RegistrationRecord ---------------------------------------------
void encode_registration(bytes::Writer& w, const RegistrationRecord& rec) {
    w.u64(rec.id.value()); w.u64(rec.buffer_id.value());
    w.u64(rec.buffer_generation.value()); w.u64(rec.registration_generation.value());
    w.u64(rec.backend.value()); w.u64(rec.backend_generation.value());
    w.u64(rec.transport.value()); w.u64(rec.nic.value());
    w.u8(static_cast<std::uint8_t>(rec.domain));
    w.u8(static_cast<std::uint8_t>(rec.transport_class));
    w.u8(rec.granted_access);
    w.u64(rec.start); w.u64(rec.length); w.u64(rec.page_alignment);
    w.u64(rec.owner.value()); w.u64(rec.process.value()); w.u64(rec.worker.value());
    w.u64(rec.boot.value()); w.u64(rec.epoch.value()); w.u64(rec.device.value());
    w.u64(rec.domain_id.value()); w.u64(rec.registration_timestamp_ns);
    w.u8(static_cast<std::uint8_t>(rec.provenance));
    w.u8(static_cast<std::uint8_t>(rec.freshness));
    w.u8(static_cast<std::uint8_t>(rec.lifecycle));
    w.u64(rec.lease_count); w.u64(rec.ref_count);
    w.u64(rec.memory_region_id.value());
    w.str(rec.backend_handle);
    w.str(rec.invalidation_reason);
    encode_descriptor(w, rec.descriptor);
    encode_remote_key(w, rec.remote_key);
    encode_local_key(w, rec.local_key);
}

bool decode_registration(bytes::Reader& r, RegistrationRecord& rec) {
    if (!r.u64(reinterpret_cast<std::uint64_t&>(rec.id)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(rec.buffer_id)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(rec.buffer_generation)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(rec.registration_generation)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(rec.backend)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(rec.backend_generation)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(rec.transport)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(rec.nic))) return false;
    std::uint8_t dom = 0, tc = 0, acc = 0, pv = 0, fr = 0, lc = 0;
    if (!r.u8(dom) || !r.u8(tc) || !r.u8(acc)) return false;
    if (dom > static_cast<std::uint8_t>(MemoryDomain::UNKNOWN)) return false;
    if (tc > static_cast<std::uint8_t>(TransportClass::UNKNOWN)) return false;
    rec.domain = static_cast<MemoryDomain>(dom);
    rec.transport_class = static_cast<TransportClass>(tc);
    rec.granted_access = acc;
    if (!r.u64(rec.start) || !r.u64(rec.length) || !r.u64(rec.page_alignment)) return false;
    if (!r.u64(reinterpret_cast<std::uint64_t&>(rec.owner)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(rec.process)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(rec.worker)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(rec.boot)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(rec.epoch)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(rec.device)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(rec.domain_id)) ||
        !r.u64(rec.registration_timestamp_ns)) return false;
    if (!r.u8(pv) || !r.u8(fr) || !r.u8(lc)) return false;
    if (pv > static_cast<std::uint8_t>(Provenance::UNKNOWN)) return false;
    if (fr > static_cast<std::uint8_t>(Freshness::UNKNOWN)) return false;
    if (lc > static_cast<std::uint8_t>(RegistrationLifecycle::REVALIDATION_REQUIRED)) return false;
    rec.provenance = static_cast<Provenance>(pv);
    rec.freshness = static_cast<Freshness>(fr);
    rec.lifecycle = static_cast<RegistrationLifecycle>(lc);
    if (!r.u64(rec.lease_count) || !r.u64(rec.ref_count)) return false;
    if (!r.u64(reinterpret_cast<std::uint64_t&>(rec.memory_region_id))) return false;
    if (!r.str(rec.backend_handle, max_count) || !r.str(rec.invalidation_reason, max_count)) return false;
    if (!decode_descriptor(r, rec.descriptor)) return false;
    if (!decode_remote_key(r, rec.remote_key)) return false;
    if (!decode_local_key(r, rec.local_key)) return false;
    return true;
}

// -- BackendInfo capability snapshot ---------------------------------
void encode_backend_info(bytes::Writer& w, const BackendInfo& b) {
    w.u64(b.id.value());
    w.str(b.name);
    w.str(b.description);
    w.u8(static_cast<std::uint8_t>(b.provenance));
    w.u8(static_cast<std::uint8_t>(b.state));
    w.u64(b.generation.value());
    w.u64(b.prot_domain_count);
    w.u64(b.registration_count);
    // capabilities
    w.u64(static_cast<std::uint64_t>(b.capabilities.supported_domains.size()));
    for (auto d : b.capabilities.supported_domains) w.u8(static_cast<std::uint8_t>(d));
    w.u64(b.capabilities.max_registration_length);
    w.u64(b.capabilities.required_alignment);
    w.u8(static_cast<std::uint8_t>(b.capabilities.remote_read));
    w.u8(static_cast<std::uint8_t>(b.capabilities.remote_write));
    w.u8(static_cast<std::uint8_t>(b.capabilities.remote_atomic));
    w.u8(static_cast<std::uint8_t>(b.capabilities.host_pinned));
    w.u8(static_cast<std::uint8_t>(b.capabilities.pageable_registration));
    w.u8(static_cast<std::uint8_t>(b.capabilities.cuda_device));
    w.u8(static_cast<std::uint8_t>(b.capabilities.cuda_managed));
    w.u8(static_cast<std::uint8_t>(b.capabilities.on_demand_paging));
    w.u8(static_cast<std::uint8_t>(b.capabilities.one_sided));
    w.u8(static_cast<std::uint8_t>(b.capabilities.multiprocess));
    w.u8(static_cast<std::uint8_t>(b.capabilities.multinode));
    w.u8(static_cast<std::uint8_t>(b.capabilities.key_rotation));
    w.u8(static_cast<std::uint8_t>(b.capabilities.revocation));
    w.u8(static_cast<std::uint8_t>(b.capabilities.provenance));
}

bool decode_backend_info(bytes::Reader& r, BackendInfo& b) {
    if (!r.u64(reinterpret_cast<std::uint64_t&>(b.id))) return false;
    if (!r.str(b.name, 256) || !r.str(b.description, 1024)) return false;
    std::uint8_t pv = 0, st = 0;
    if (!r.u8(pv) || !r.u8(st)) return false;
    if (pv > static_cast<std::uint8_t>(Provenance::UNKNOWN)) return false;
    if (st > static_cast<std::uint8_t>(BackendState::DESTROYED)) return false;
    b.provenance = static_cast<Provenance>(pv);
    b.state = static_cast<BackendState>(st);
    if (!r.u64(reinterpret_cast<std::uint64_t&>(b.generation))) return false;
    if (!r.u64(b.prot_domain_count) || !r.u64(b.registration_count)) return false;
    std::uint64_t ndom = 0;
    if (!r.u64(ndom)) return false;
    if (ndom > max_count) return false;
    b.capabilities.supported_domains.clear();
    for (std::uint64_t i = 0; i < ndom; ++i) {
        std::uint8_t d = 0; if (!r.u8(d)) return false;
        if (d > static_cast<std::uint8_t>(MemoryDomain::UNKNOWN)) return false;
        b.capabilities.supported_domains.push_back(static_cast<MemoryDomain>(d));
    }
    if (!r.u64(b.capabilities.max_registration_length) || !r.u64(b.capabilities.required_alignment)) return false;
    std::uint8_t v[13];
    for (auto& x : v) { if (!r.u8(x)) return false; }
    auto cap8 = [](std::uint8_t x) { return x <= static_cast<std::uint8_t>(CapabilityState::UNKNOWN)
                                        ? static_cast<CapabilityState>(x) : CapabilityState::UNKNOWN; };
    b.capabilities.remote_read = cap8(v[0]);
    b.capabilities.remote_write = cap8(v[1]);
    b.capabilities.remote_atomic = cap8(v[2]);
    b.capabilities.host_pinned = cap8(v[3]);
    b.capabilities.pageable_registration = cap8(v[4]);
    b.capabilities.cuda_device = cap8(v[5]);
    b.capabilities.cuda_managed = cap8(v[6]);
    b.capabilities.on_demand_paging = cap8(v[7]);
    b.capabilities.one_sided = cap8(v[8]);
    b.capabilities.multiprocess = cap8(v[9]);
    b.capabilities.multinode = cap8(v[10]);
    b.capabilities.key_rotation = cap8(v[11]);
    b.capabilities.revocation = cap8(v[12]);
    std::uint8_t cp = 0; if (!r.u8(cp)) return false;
    b.capabilities.provenance = cp <= static_cast<std::uint8_t>(Provenance::UNKNOWN)
                                     ? static_cast<Provenance>(cp) : Provenance::UNKNOWN;
    return true;
}

// -- Accounting ------------------------------------------------------
void encode_accounting(bytes::Writer& w, const Accounting& a) {
    const Counter* cs[] = {
        &a.logical_buffers, &a.live_buffer_bytes, &a.pinned_bytes, &a.registered_bytes,
        &a.active_registrations, &a.active_leases, &a.protection_domains, &a.local_keys,
        &a.remote_keys, &a.remote_read_bytes, &a.remote_write_bytes, &a.atomic_operations,
        &a.failed_access_attempts, &a.stale_access_rejections, &a.revocations,
        &a.deregistrations, &a.registration_reuse_hits, &a.registration_misses,
        &a.participant_restarts,
    };
    for (const Counter* c : cs) w.u64(c->get());
}

bool decode_accounting(bytes::Reader& r, Accounting& a) {
    Counter* cs[] = {
        &a.logical_buffers, &a.live_buffer_bytes, &a.pinned_bytes, &a.registered_bytes,
        &a.active_registrations, &a.active_leases, &a.protection_domains, &a.local_keys,
        &a.remote_keys, &a.remote_read_bytes, &a.remote_write_bytes, &a.atomic_operations,
        &a.failed_access_attempts, &a.stale_access_rejections, &a.revocations,
        &a.deregistrations, &a.registration_reuse_hits, &a.registration_misses,
        &a.participant_restarts,
    };
    for (Counter* c : cs) { std::uint64_t v = 0; if (!r.u64(v)) return false; c->value = v; }
    return true;
}

// -- AuthoritySnapshot -----------------------------------------------
void encode_authority(bytes::Writer& w, const AuthoritySnapshot& s) {
    w.u64(s.coordinator_epoch.value()); w.u64(s.worker_boot.value()); w.u64(s.worker.value());
    w.u64(s.owner.value()); w.u64(s.owner_generation.value()); w.u64(s.worker_generation.value());
    w.u64(s.policy_generation.value()); w.u64(s.backend_generation.value());
    w.u64(s.transport_generation.value()); w.u64(s.nic_generation.value());
    w.u64(s.node.value()); w.u64(s.process.value());
    w.u8(static_cast<std::uint8_t>(s.provenance));
}

bool decode_authority(bytes::Reader& r, AuthoritySnapshot& s) {
    if (!r.u64(reinterpret_cast<std::uint64_t&>(s.coordinator_epoch)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(s.worker_boot)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(s.worker)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(s.owner)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(s.owner_generation)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(s.worker_generation)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(s.policy_generation)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(s.backend_generation)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(s.transport_generation)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(s.nic_generation)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(s.node)) ||
        !r.u64(reinterpret_cast<std::uint64_t&>(s.process))) return false;
    std::uint8_t pv = 0; if (!r.u8(pv)) return false;
    return true;
}

std::uint64_t fnv1a(const std::string& s) {
    std::uint64_t h = 0xCBF29CE484222325ull;
    for (char c : s) { h ^= static_cast<unsigned char>(c); h *= 0x100000001B3ull; }
    return h;
}

std::string hex(std::uint64_t v) {
    char buf[24];
    auto [p, ec] = std::to_chars(buf, buf + sizeof(buf), v, 16);
    (void)ec;
    return std::string(buf, p);
}

} // namespace

std::vector<std::uint8_t> serialize(const PersistableState& state) {
    bytes::Writer w;
    w.u32(format_magic);
    w.u32(format_version);
    w.u64(state.policy_generation.value());
    encode_authority(w, state.authority_snapshot);

    w.u64(static_cast<std::uint64_t>(state.buffers.size()));
    for (const auto& b : state.buffers) encode_descriptor(w, b);
    w.u64(static_cast<std::uint64_t>(state.registrations.size()));
    for (const auto& rec : state.registrations) encode_registration(w, rec);
    w.u64(static_cast<std::uint64_t>(state.domains.size()));
    for (const auto& d : state.domains) w.u64(d.value());
    w.u64(static_cast<std::uint64_t>(state.remote_key_history.size()));
    for (const auto& k : state.remote_key_history) encode_remote_key(w, k);
    w.u64(static_cast<std::uint64_t>(state.local_key_history.size()));
    for (const auto& k : state.local_key_history) encode_local_key(w, k);
    w.u64(static_cast<std::uint64_t>(state.revocation_history.size()));
    for (const auto& s : state.revocation_history) w.str(s);
    encode_accounting(w, state.accounting_summary);
    w.u64(static_cast<std::uint64_t>(state.backend_capability_snapshot.size()));
    for (const auto& b : state.backend_capability_snapshot) encode_backend_info(w, b);

    std::vector<std::uint8_t> body = w.take();
    const std::uint32_t c = crc32(body.data(), body.size());
    bytes::Writer tw;
    tw.raw(body);
    tw.u32(c);
    return tw.take();
}

bool parse(std::span<const std::uint8_t> bytes_in, PersistableState& state, std::string& err) {
    if (bytes_in.size() < 4 + 4 + 4) { err = "TRUNCATED"; return false; }

    const std::span<const std::uint8_t> body = bytes_in.subspan(0, bytes_in.size() - 4);
    bytes::Reader r(body);
    std::uint32_t magic = 0, ver = 0;
    if (!r.u32(magic) || !r.u32(ver)) { err = "TRUNCATED"; return false; }
    if (magic != format_magic) { err = "BAD_MAGIC"; return false; }
    if (ver != format_version) { err = "BAD_VERSION"; return false; }

    // Checksum over the body (everything except the trailer).
    const std::uint32_t expected = crc32(body.data(), body.size());
    std::uint32_t stored_crc = 0;
    {
        std::size_t p = bytes_in.size() - 4;
        for (int i = 0; i < 4; ++i) stored_crc |= static_cast<std::uint32_t>(bytes_in[p + i]) << (8 * i);
    }
    if (expected != stored_crc) { err = "CHECKSUM_MISMATCH"; return false; }

    if (!r.u64(reinterpret_cast<std::uint64_t&>(state.policy_generation))) { err = "TRUNCATED"; return false; }
    if (!decode_authority(r, state.authority_snapshot)) { err = "TRUNCATED"; return false; }

    std::uint64_t n = 0;
    if (!r.u64(n)) { err = "TRUNCATED"; return false; }
    if (n > max_count) { err = "IMPOSSIBLE_COUNT"; return false; }
    state.buffers.clear();
    for (std::uint64_t i = 0; i < n; ++i) { BufferDescriptor b; if (!decode_descriptor(r, b)) { err = "TRUNCATED"; return false; } state.buffers.push_back(std::move(b)); }
    if (!r.u64(n) || n > max_count) { err = "IMPOSSIBLE_COUNT"; return false; }
    state.registrations.clear();
    for (std::uint64_t i = 0; i < n; ++i) { RegistrationRecord rec; if (!decode_registration(r, rec)) { err = "TRUNCATED"; return false; } state.registrations.push_back(std::move(rec)); }
    if (!r.u64(n) || n > max_count) { err = "IMPOSSIBLE_COUNT"; return false; }
    state.domains.clear();
    for (std::uint64_t i = 0; i < n; ++i) { std::uint64_t v = 0; if (!r.u64(v)) { err = "TRUNCATED"; return false; } state.domains.push_back(ProtectionDomainId(v)); }
    if (!r.u64(n) || n > max_count) { err = "IMPOSSIBLE_COUNT"; return false; }
    state.remote_key_history.clear();
    for (std::uint64_t i = 0; i < n; ++i) { RemoteKey k; if (!decode_remote_key(r, k)) { err = "TRUNCATED"; return false; } state.remote_key_history.push_back(std::move(k)); }
    if (!r.u64(n) || n > max_count) { err = "IMPOSSIBLE_COUNT"; return false; }
    state.local_key_history.clear();
    for (std::uint64_t i = 0; i < n; ++i) { LocalKey k; if (!decode_local_key(r, k)) { err = "TRUNCATED"; return false; } state.local_key_history.push_back(std::move(k)); }
    if (!r.u64(n) || n > max_count) { err = "IMPOSSIBLE_COUNT"; return false; }
    state.revocation_history.clear();
    for (std::uint64_t i = 0; i < n; ++i) { std::string s; if (!r.str(s, max_count)) { err = "TRUNCATED"; return false; } state.revocation_history.push_back(std::move(s)); }
    if (!decode_accounting(r, state.accounting_summary)) { err = "TRUNCATED"; return false; }
    if (!r.u64(n) || n > max_count) { err = "IMPOSSIBLE_COUNT"; return false; }
    state.backend_capability_snapshot.clear();
    for (std::uint64_t i = 0; i < n; ++i) { BackendInfo b; if (!decode_backend_info(r, b)) { err = "TRUNCATED"; return false; } state.backend_capability_snapshot.push_back(std::move(b)); }
    if (r.remaining() != 0) { err = "TRAILING_GARBAGE"; return false; }

    // Logical integrity checks: duplicate identity and generation regression.
    {
        std::vector<std::uint64_t> seen;
        for (const auto& b : state.buffers) {
            if (b.generation.value() == 0) { err = "GENERATION_REGRESSION"; return false; }
            for (const auto v : seen) if (v == b.id.value()) { err = "DUPLICATE_IDENTITY"; return false; }
            seen.push_back(b.id.value());
        }
        seen.clear();
        for (const auto& rec : state.registrations) {
            if (rec.registration_generation.value() == 0) { err = "GENERATION_REGRESSION"; return false; }
            for (const auto v : seen) if (v == rec.id.value()) { err = "DUPLICATE_IDENTITY"; return false; }
            seen.push_back(rec.id.value());
        }
        seen.clear();
        for (const auto& d : state.domains) {
            for (const auto v : seen) if (v == d.value()) { err = "DUPLICATE_IDENTITY"; return false; }
            seen.push_back(d.value());
        }
    }
    err.clear();
    return true;
}

std::string semantic_digest(const PersistableState& state) {
    // Build a canonical text digest over logical content.
    std::ostringstream o;
    o << "v" << state.format_version << ":";
    o << "pc" << state.policy_generation.value() << ";";
    o << "a" << state.authority_snapshot.coordinator_epoch.value()
      << "," << state.authority_snapshot.worker_boot.value()
      << "," << state.authority_snapshot.backend_generation.value() << ";";
    for (const auto& b : state.buffers) {
        o << "buf" << b.id.value() << ":" << b.generation.value() << ":" << b.byte_length << ":"
          << static_cast<int>(b.domain) << ";";
    }
    for (const auto& rec : state.registrations) {
        o << "reg" << rec.id.value() << ":" << rec.buffer_id.value() << ":"
          << rec.buffer_generation.value() << ":" << rec.registration_generation.value() << ":"
          << rec.start << ":" << rec.length << ";" ;
    }
    for (const auto& d : state.domains) o << "dom" << d.value() << ";";
    for (const auto& k : state.remote_key_history) {
        o << "rk" << k.id.value() << ":" << k.registration.value() << ":"
          << k.key_generation.value() << ":" << k.revoked << ";";
    }
    for (const auto& s : state.revocation_history) o << "rv" << s << ";";
    const std::uint64_t h = fnv1a(o.str());
    return hex(h);
}

} // namespace persistence
} // namespace rdmabuffer

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Deterministic, bounded wire codec for the coordinator/worker protocol. Used
// to serialize BufferDescriptor and command payloads into the framed TCP
// protocol's payload region.

#pragma once

#include "buffer_model.hpp"
#include "bytes.hpp"
#include "enums.hpp"
#include "generation.hpp"
#include "identity.hpp"

#include <cstdint>
#include <string>

namespace rdmabuffer {
namespace wire {

// ---- BufferDescriptor -------------------------------------------------
inline void write_descriptor(bytes::Writer& w, const BufferDescriptor& d) {
    w.u64(d.id.value());
    w.u64(d.generation.value());
    w.u8(static_cast<std::uint8_t>(d.domain));
    w.u64(d.base.address);
    w.u8(static_cast<std::uint8_t>(d.base.kind));
    w.u64(d.byte_length);
    w.u64(d.alignment);
    w.u64(d.page_size);
    w.u64(d.owner.value());
    w.u64(d.process.value());
    w.u64(d.worker.value());
    w.u64(d.node.value());
    w.u64(d.device.value());
    w.u8(static_cast<std::uint8_t>(d.direction));
    w.u8(d.requested_access);
    w.u8(static_cast<std::uint8_t>(d.registration_mode));
    w.u8(static_cast<std::uint8_t>(d.lifetime));
    w.u8(static_cast<std::uint8_t>(d.provenance));
    w.u8(static_cast<std::uint8_t>(d.freshness));
    w.u64(d.policy_generation.value());
}

inline bool read_descriptor(bytes::Reader& r, BufferDescriptor& d) {
    std::uint64_t v = 0;
    if (!r.u64(v)) return false; d.id = BufferId(v);
    if (!r.u64(v)) return false; d.generation = BufferGeneration(v);
    std::uint8_t u = 0;
    if (!r.u8(u)) return false; if (u > static_cast<std::uint8_t>(MemoryDomain::UNKNOWN)) return false;
    d.domain = static_cast<MemoryDomain>(u);
    if (!r.u64(d.base.address)) return false;
    if (!r.u8(u)) return false; if (u > 5) return false; d.base.kind = static_cast<PointerKind>(u);
    if (!r.u64(d.byte_length) || !r.u64(d.alignment) || !r.u64(d.page_size)) return false;
    if (!r.u64(v)) return false; d.owner = OwnerId(v);
    if (!r.u64(v)) return false; d.process = ProcessId(v);
    if (!r.u64(v)) return false; d.worker = WorkerId(v);
    if (!r.u64(v)) return false; d.node = NodeId(v);
    if (!r.u64(v)) return false; d.device = DeviceId(v);
    std::uint8_t dr = 0, am = 0, rm = 0, lt = 0, pv = 0, fr = 0;
    if (!r.u8(dr) || !r.u8(am) || !r.u8(rm) || !r.u8(lt) || !r.u8(pv) || !r.u8(fr)) return false;
    if (dr > static_cast<std::uint8_t>(TransferDirection::BIDIRECTIONAL)) return false;
    if (rm > static_cast<std::uint8_t>(RegistrationMode::ANY)) return false;
    if (lt > static_cast<std::uint8_t>(LifetimePolicy::EPHEMERAL)) return false;
    if (pv > static_cast<std::uint8_t>(Provenance::UNKNOWN)) return false;
    if (fr > static_cast<std::uint8_t>(Freshness::UNKNOWN)) return false;
    d.direction = static_cast<TransferDirection>(dr);
    d.requested_access = am;
    d.registration_mode = static_cast<RegistrationMode>(rm);
    d.lifetime = static_cast<LifetimePolicy>(lt);
    d.provenance = static_cast<Provenance>(pv);
    d.freshness = static_cast<Freshness>(fr);
    if (!r.u64(v)) return false; d.policy_generation = PolicyGeneration(v);
    return true;
}

// ---- command payloads --------------------------------------------------
// HELLO payload: role string.
inline std::vector<std::uint8_t> encode_hello(const std::string& role) {
    bytes::Writer w; w.str(role); return w.take();
}
inline bool decode_hello(std::span<const std::uint8_t> p, std::string& role) {
    bytes::Reader r(p); return r.str(role, 64);
}

// HELLO_ACK payload: boot u64, epoch u64, node u64.
inline std::vector<std::uint8_t> encode_hello_ack(std::uint64_t boot, std::uint64_t epoch, std::uint64_t node) {
    bytes::Writer w; w.u64(boot); w.u64(epoch); w.u64(node); return w.take();
}
inline bool decode_hello_ack(std::span<const std::uint8_t> p, std::uint64_t& boot, std::uint64_t& epoch, std::uint64_t& node) {
    bytes::Reader r(p); return r.u64(boot) && r.u64(epoch) && r.u64(node);
}

// REGISTER payload: descriptor + domain u64.
inline std::vector<std::uint8_t> encode_register(const BufferDescriptor& d, std::uint64_t domain, std::uint64_t backend) {
    bytes::Writer w; w.u64(domain); w.u64(backend); write_descriptor(w, d); return w.take();
}
inline bool decode_register(std::span<const std::uint8_t> p, BufferDescriptor& d, std::uint64_t& domain, std::uint64_t& backend) {
    bytes::Reader r(p);
    if (!r.u64(domain) || !r.u64(backend)) return false;
    return read_descriptor(r, d);
}

// REGISTER_ACK payload: ok u8, reg_id u64, key_gen u64, msg string.
inline std::vector<std::uint8_t> encode_register_ack(bool ok, std::uint64_t reg, std::uint64_t keygen, const std::string& msg) {
    bytes::Writer w; w.u8(ok ? 1 : 0); w.u64(reg); w.u64(keygen); w.str(msg); return w.take();
}
inline bool decode_register_ack(std::span<const std::uint8_t> p, bool& ok, std::uint64_t& reg, std::uint64_t& keygen, std::string& msg) {
    bytes::Reader r(p); std::uint8_t o = 0;
    if (!r.u8(o) || !r.u64(reg) || !r.u64(keygen) || !r.str(msg, 4096)) return false;
    ok = o != 0;
    return true;
}

// ACCESS payload: reg_id, offset, length, kind u8, access u8, boot u64, expkeygen u64.
inline std::vector<std::uint8_t> encode_access(std::uint64_t reg, std::uint64_t off, std::uint64_t len,
                                               std::uint64_t kind, std::uint8_t access, std::uint64_t boot, std::uint64_t expkeygen) {
    bytes::Writer w; w.u64(reg); w.u64(off); w.u64(len); w.u64(kind); w.u8(access); w.u64(boot); w.u64(expkeygen); return w.take();
}
inline bool decode_access(std::span<const std::uint8_t> p, std::uint64_t& reg, std::uint64_t& off, std::uint64_t& len,
                          std::uint64_t& kind, std::uint8_t& access, std::uint64_t& boot, std::uint64_t& expkeygen) {
    bytes::Reader r(p); return r.u64(reg) && r.u64(off) && r.u64(len) && r.u64(kind) &&
        r.u8(access) && r.u64(boot) && r.u64(expkeygen);
}

// ACCESS_ACK payload: outcome u8, msg string.
inline std::vector<std::uint8_t> encode_access_ack(std::uint8_t outcome, const std::string& msg) {
    bytes::Writer w; w.u8(outcome); w.str(msg); return w.take();
}
inline bool decode_access_ack(std::span<const std::uint8_t> p, std::uint8_t& outcome, std::string& msg) {
    bytes::Reader r(p); return r.u8(outcome) && r.str(msg, 4096);
}

// RAW_RESULT payload: ok u8, msg string (used for revoke/deregister/persist).
inline std::vector<std::uint8_t> encode_result(bool ok, const std::string& msg) {
    bytes::Writer w; w.u8(ok ? 1 : 0); w.str(msg); return w.take();
}
inline bool decode_result(std::span<const std::uint8_t> p, bool& ok, std::string& msg) {
    bytes::Reader r(p); std::uint8_t o = 0;
    if (!r.u8(o) || !r.str(msg, 4096)) return false;
    ok = o != 0; return true;
}

} // namespace wire
} // namespace rdmabuffer


// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Completed-work benchmarks. All results are measured on the host; synthetic
// remote operations are labelled SYNTHETIC and are not RDMA bandwidth.

#include "rdmabuffer/rdmabuffer.hpp"

#include <chrono>
#include <cstdio>
#include <memory>
#include <string>
#include <vector>

using namespace rdmabuffer;

namespace {
using Clock = std::chrono::steady_clock;
double wall_ms(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}
struct Report { const char* name; double ops; double nsop; double bytes; };
std::vector<Report> g_reports;
void report(const char* name, std::uint64_t ops, double ms, std::uint64_t bytes = 0) {
    double nsop = ms == 0 ? 0.0 : (ms * 1e6) / static_cast<double>(ops);
    double opssec = ms == 0 ? 0.0 : (static_cast<double>(ops) / (ms / 1000.0));
    g_reports.push_back({name, opssec, nsop, static_cast<double>(bytes)});
    std::printf("%-32s %10.0f ops/s  %8.1f ns/op  %12.0f bytes/s  (wall %.3f ms)\n",
                name, opssec, nsop, static_cast<double>(bytes) / (ms / 1000.0), ms);
}

AuthoritySnapshot snap() {
    AuthoritySnapshot s; s.coordinator_epoch = CoordinatorEpoch(1); s.worker_boot = WorkerBootId(1);
    s.worker = WorkerId(1); s.owner = OwnerId(1);
    s.owner_generation = OwnerGeneration(1); s.worker_generation = WorkerGeneration(1);
    s.policy_generation = PolicyGeneration(1);
    s.backend_generation = BackendGeneration(1); s.transport_generation = TransportGeneration(1);
    s.nic_generation = NicGeneration(1); s.node = NodeId(1); s.process = ProcessId(1);
    s.provenance = Provenance::SYNTHETIC; return s;
}
AuthorityEnvelope env() {
    AuthorityEnvelope e; e.coordinator_epoch = CoordinatorEpoch(1); e.worker_boot = WorkerBootId(1);
    e.owner = OwnerId(1); e.owner_generation = OwnerGeneration(1); e.worker_generation = WorkerGeneration(1);
    e.node = NodeId(1); e.process = ProcessId(1); return e;
}
BufferDescriptor mk(std::uint64_t id) {
    BufferDescriptor d; d.id = BufferId(id); d.generation = BufferGeneration(1);
    d.domain = MemoryDomain::SYNTHETIC_REMOTE_CAPABLE; d.base.address = 0x1000;
    d.base.kind = PointerKind::SYNTHETIC; d.byte_length = 4096; d.alignment = 4096; d.page_size = 4096;
    d.owner = OwnerId(1); d.process = ProcessId(1); d.worker = WorkerId(1); d.node = NodeId(1);
    d.direction = TransferDirection::BIDIRECTIONAL;
    d.requested_access = access_mask(AccessRight::REMOTE_READ) | access_mask(AccessRight::REMOTE_WRITE);
    d.registration_mode = RegistrationMode::REMOTE_ACCESS; d.lifetime = LifetimePolicy::TRANSACTIONAL;
    d.provenance = Provenance::SYNTHETIC; d.freshness = Freshness::VALID; d.policy_generation = PolicyGeneration(1);
    return d;
}
} // namespace

int main() {
    const std::uint64_t N = 10000;
    auto syn = std::make_shared<SyntheticBackend>(3);
    Rdmabuffer rt; rt.add_backend(syn); rt.set_authority(snap());
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    auto d = mk(1); rt.create_buffer(d);
    RegisterResult r = rt.register_buffer(d, syn->id(), dom, env());
    auto q = [&]() {
        RemoteAccessRequest q; q.source_registration = r.registration; q.offset = 0; q.length = 8;
        q.kind = OperationKind::WRITE; q.required_rights = access_mask(AccessRight::REMOTE_WRITE);
        q.expected_buffer_generation = BufferGeneration(1); q.expected_registration_generation = RegistrationGeneration(1);
        q.expected_remote_key_generation = RemoteKeyGeneration(1);
        q.authority = env(); q.domain = dom; q.backend = syn->id(); q.node = NodeId(1); q.process = ProcessId(1);
        return q;
    };

    // descriptor validation
    { auto t0 = Clock::now(); for (std::uint64_t i = 0; i < N; ++i) { BufferDescriptor x = mk(1); validate_range(x); } auto t1 = Clock::now(); report("buffer descriptor validation", N, wall_ms(t0,t1)); }
    // registration lookup
    { RegistrationRecord rec; auto t0 = Clock::now(); for (std::uint64_t i = 0; i < N; ++i) rt.get_registration(r.registration, rec); auto t1 = Clock::now(); report("registration lookup", N, wall_ms(t0,t1)); }
    // registration create/destroy (reference)
    { ReferenceBackend refb; RegistrationContext ctx; ctx.epoch = CoordinatorEpoch(1); ctx.worker_boot = WorkerBootId(1);
      ctx.registration_generation = RegistrationGeneration(1); ctx.backend_generation = BackendGeneration(1);
      ctx.requested_access = access_mask(AccessRight::REMOTE_WRITE);
      auto t0 = Clock::now(); BackendRegistration o; for (std::uint64_t i = 0; i < N; ++i) { auto bd = mk(i%7+1); bd.domain = MemoryDomain::HOST_PINNED; refb.register_buffer(bd, ctx, o); refb.deregister_buffer(RegisterHandle{o.memory_region_id, o.handle}); } auto t1 = Clock::now(); report("registration create/destroy (ref)", N, wall_ms(t0,t1)); }
    // reuse eligibility
    { auto t0 = Clock::now(); for (std::uint64_t i = 0; i < N; ++i) rt.register_buffer_reuse(d, syn->id(), dom, env()); auto t1 = Clock::now(); report("reuse eligibility", N, wall_ms(t0,t1)); }
    // lease acquire/release
    { auto t0 = Clock::now(); for (std::uint64_t i = 0; i < N; ++i) { auto l = rt.acquire_lease(r.registration, env(), access_mask(AccessRight::REMOTE_WRITE)); if (l.ok) rt.release_lease(l.lease.id); } auto t1 = Clock::now(); report("lease acquire/release", N, wall_ms(t0,t1)); }
    // remote access validation
    { auto t0 = Clock::now(); for (std::uint64_t i = 0; i < N; ++i) { auto aa = q(); rt.validate_remote_access(aa); } auto t1 = Clock::now(); report("remote access validation", N, wall_ms(t0,t1), N*8); }
    // key rotation
    { std::string ex; auto t0 = Clock::now(); for (std::uint64_t i = 0; i < N/2; ++i) rt.rotate_key(r.registration, ex); auto t1 = Clock::now(); report("key rotation", N/2, wall_ms(t0,t1)); }
    // revocation
    { auto t0 = Clock::now(); for (std::uint64_t i = 0; i < N/4; ++i) { Rdmabuffer r2; r2.add_backend(syn); r2.set_authority(snap()); auto dd = mk(100+i); r2.create_buffer(dd); auto rr = r2.register_buffer(dd, syn->id(), r2.create_protection_domain(NodeId(1),ProcessId(1)), env()); r2.revoke(rr.registration, RevocationMode::HARD_REVOKE); } auto t1 = Clock::now(); report("revocation", N/4, wall_ms(t0,t1)); }
    // canonical serialization
    { PersistableState st; st.buffers.push_back(d); RegistrationRecord rec; rt.get_registration(r.registration, rec); st.registrations.push_back(rec); st.authority_snapshot = snap(); st.policy_generation = PolicyGeneration(1);
      auto t0 = Clock::now(); std::vector<std::uint8_t> blob; for (std::uint64_t i = 0; i < N/2; ++i) blob = persistence::serialize(st); auto t1 = Clock::now(); report("canonical serialization", N/2, wall_ms(t0,t1), blob.size()*(N/2)); }
    // protocol encode/decode
    { auto pay = protocol::payload_string("benchmark payload"); auto t0 = Clock::now(); std::size_t consumed; std::string err; protocol::Frame out; for (std::uint64_t i = 0; i < N; ++i) { auto fr = protocol::encode_frame(protocol::MessageKind::OK, i, pay); protocol::decode_frame(fr, out, consumed, err); } auto t1 = Clock::now(); report("protocol encode/decode", N, wall_ms(t0,t1), pay.size()*N); }
    // synthetic remote write
    { std::string ex; std::uint64_t delta = 0; auto t0 = Clock::now(); for (std::uint64_t i = 0; i < N; ++i) { syn->simulate_remote(OperationKind::WRITE, 0, 64, 1, ex, delta); } auto t1 = Clock::now(); report("synthetic remote write (SYNTH)", N, wall_ms(t0,t1)); }
    // synthetic remote read
    { std::string ex; std::uint64_t delta = 0; auto t0 = Clock::now(); for (std::uint64_t i = 0; i < N; ++i) { syn->simulate_remote(OperationKind::READ, 0, 64, 2, ex, delta); } auto t1 = Clock::now(); report("synthetic remote read (SYNTH)", N, wall_ms(t0,t1)); }

    std::printf("\nthreads=1 payload_bytes=8 seed=3 target=rdma-buffer\n");
    return 0;
}

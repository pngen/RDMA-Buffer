// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// rdma-buffer CLI. Exposes provenance and capability facts explicitly; never
// fabricates RDMA hardware.

#include "rdmabuffer/rdmabuffer.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

using namespace rdmabuffer;

namespace {
AuthoritySnapshot snap() {
    AuthoritySnapshot s;
    s.coordinator_epoch = CoordinatorEpoch(1); s.worker_boot = WorkerBootId(1);
    s.worker = WorkerId(1); s.owner = OwnerId(1);
    s.owner_generation = OwnerGeneration(1); s.worker_generation = WorkerGeneration(1);
    s.policy_generation = PolicyGeneration(1);
    s.backend_generation = BackendGeneration(1); s.transport_generation = TransportGeneration(1);
    s.nic_generation = NicGeneration(1); s.node = NodeId(1); s.process = ProcessId(1);
    s.provenance = Provenance::SYNTHETIC;
    return s;
}
AuthorityEnvelope env(const AuthoritySnapshot& s) {
    AuthorityEnvelope e;
    e.coordinator_epoch = s.coordinator_epoch; e.worker_boot = s.worker_boot;
    e.owner = OwnerId(1); e.owner_generation = OwnerGeneration(1); e.worker_generation = WorkerGeneration(1);
    e.node = NodeId(1); e.process = ProcessId(1);
    return e;
}
BufferDescriptor make_desc(std::uint64_t id = 1, std::uint64_t gen = 1, MemoryDomain domain = MemoryDomain::SYNTHETIC_REMOTE_CAPABLE,
                           std::uint64_t len = 4096, AccessMask rights = access_mask(AccessRight::REMOTE_READ) | access_mask(AccessRight::REMOTE_WRITE)) {
    BufferDescriptor d;
    d.id = BufferId(id); d.generation = BufferGeneration(gen); d.domain = domain;
    d.base.address = 0x1000; d.base.kind = domain == MemoryDomain::SYNTHETIC_REMOTE_CAPABLE ? PointerKind::SYNTHETIC : PointerKind::VIRTUAL;
    d.byte_length = len; d.alignment = 4096; d.page_size = 4096;
    d.owner = OwnerId(1); d.process = ProcessId(1); d.worker = WorkerId(1); d.node = NodeId(1);
    d.direction = TransferDirection::BIDIRECTIONAL; d.requested_access = rights;
    d.registration_mode = RegistrationMode::REMOTE_ACCESS; d.lifetime = LifetimePolicy::TRANSACTIONAL;
    d.provenance = Provenance::SYNTHETIC; d.freshness = Freshness::VALID; d.policy_generation = PolicyGeneration(1);
    return d;
}
int usage() {
    std::printf("rdma-buffer <cmd>\n"
                "  discover | buffer-create | buffer-show | register | deregister\n"
                "  lease-acquire | lease-release | access-check | revoke | rotate-key\n"
                "  explain | simulate | save | recover | benchmark\n");
    return 1;
}
} // namespace

int main(int argc, char** argv) {
    if (argc < 2) return usage();
    const std::string cmd = argv[1];
    auto syn = std::make_shared<SyntheticBackend>(7);
    auto ref = std::make_shared<ReferenceBackend>();
    Rdmabuffer rt;
    rt.add_backend(syn);
    rt.add_backend(ref);
    const AuthoritySnapshot s = snap();
    rt.set_authority(s);
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    const AuthorityEnvelope e = env(s);

    if (cmd == "discover") {
        for (const auto& bi : rt.backend_summaries()) {
            std::printf("backend=%s provenance=%s domain=HOST_PINNED dom_supported=%d remote_read=%s remote_write=%s remote_atomic=%s\n",
                        bi.name.c_str(), provenance_name(bi.provenance).data(),
                        domain_supported(bi.capabilities, MemoryDomain::HOST_PINNED) ? 1 : 0,
                        capability_state_name(bi.capabilities.remote_read).data(),
                        capability_state_name(bi.capabilities.remote_write).data(),
                        capability_state_name(bi.capabilities.remote_atomic).data());
        }
        return 0;
    }
    if (cmd == "buffer-create") {
        const std::uint64_t id = argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 1;
        const auto d = make_desc(id);
        const BufferId bid = rt.create_buffer(d);
        std::printf("buffer id=%llu generation=1 memory_domain=SYNTHETIC_REMOTE_CAPABLE created=%d provenance=SYNTHETIC\n",
                    static_cast<unsigned long long>(bid.value()), bid.is_valid() ? 1 : 0);
        return bid.is_valid() ? 0 : 1;
    }
    if (cmd == "register") {
        const auto d = make_desc();
        rt.create_buffer(d);
        RegisterResult r = rt.register_buffer(d, syn->id(), dom, e);
        std::printf("registration_capability=%s backend=SYNTHETIC result=%s msg=%s\n",
                    r.ok ? "REGISTERED" : "REJECTED", r.ok ? "ok" : "rejected", r.explanation.c_str());
        return r.ok ? 0 : 1;
    }
    if (cmd == "access-check") {
        rt.create_buffer(make_desc());
        RegisterResult r = rt.register_buffer(make_desc(), syn->id(), dom, e);
        if (!r.ok) { std::printf("access-check: registration failed\n"); return 1; }
        RemoteAccessRequest q; q.source_registration = r.registration; q.offset = 0; q.length = 4;
        q.kind = OperationKind::WRITE; q.required_rights = access_mask(AccessRight::REMOTE_WRITE);
        q.expected_buffer_generation = BufferGeneration(1); q.expected_registration_generation = RegistrationGeneration(1);
        q.expected_remote_key_generation = RemoteKeyGeneration(1);
        q.authority = e; q.domain = dom; q.backend = syn->id(); q.node = NodeId(1); q.process = ProcessId(1);
        AccessDecision d = rt.validate_remote_access(q);
        std::printf("remote_write=%s backend=SYNTHETIC freshness=VALID explanation=%s\n", d.code.c_str(), d.explanation.c_str());
        return d.outcome == AccessOutcome::ALLOW ? 0 : 1;
    }
    if (cmd == "revoke") {
        rt.create_buffer(make_desc());
        RegisterResult r = rt.register_buffer(make_desc(), syn->id(), dom, e);
        if (!r.ok) { std::printf("revoke: registration failed\n"); return 1; }
        RevokeResult rz = rt.revoke(r.registration, RevocationMode::HARD_REVOKE);
        std::printf("revoked=%d keys_invalidated=%d backend=SYNTHETIC lifecycle=%s\n",
                    rz.ok ? 1 : 0, rz.keys_invalidated ? 1 : 0, lifecycle_name(rz.lifecycle).data());
        return rz.ok ? 0 : 1;
    }
    if (cmd == "simulate") {
        rt.create_buffer(make_desc());
        RegisterResult r = rt.register_buffer(make_desc(), syn->id(), dom, e);
        if (!r.ok) { std::printf("simulate: registration failed\n"); return 1; }
        std::string ex; std::uint64_t delta = 0;
        AccessOutcome o = syn->simulate_remote(OperationKind::WRITE, 0, 64, 1, ex, delta);
        std::printf("simulate_remote_write=%s provenance=SYNTHETIC delta=%llu\n", access_outcome_name(o).data(),
                    static_cast<unsigned long long>(delta));
        return o == AccessOutcome::ALLOW ? 0 : 1;
    }
    if (cmd == "save") {
        const std::string path = argc > 2 ? argv[2] : "rdma-buffer-state.bin";
        std::string err;
        rt.create_buffer(make_desc());
        rt.register_buffer(make_desc(), syn->id(), dom, e);
        bool ok = rt.save(path, err);
        std::printf("save=%s path=%s err=%s\n", ok ? "ok" : "failed", path.c_str(), err.c_str());
        return ok ? 0 : 1;
    }
    if (cmd == "explain") {
        std::printf("explain_registration: registration requires identity, generation, incarnation, backend capability, and provenance to be current.\n");
        std::printf("explain_backend_capability: %s\n", explain_backend_capability(syn->capabilities(), MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, access_mask(AccessRight::REMOTE_WRITE)).c_str());
        return 0;
    }
    return usage();
}

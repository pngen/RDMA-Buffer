
#include "test_framework.hpp"
#include "rdmabuffer/rdmabuffer.hpp"
#include "test_util.hpp"
#include <memory>
#include <string>

using namespace rdmabuffer;

TEST_CASE(synthetic_backend_is_labelled_synthetic) {
    SyntheticBackend b(1);
    CHECK(b.provenance() == Provenance::SYNTHETIC);
    CHECK(std::string(b.name()) == "synthetic-rdma");
    BackendCapabilities c = b.capabilities();
    CHECK(c.provenance == Provenance::SYNTHETIC);
    CHECK(domain_supported(c, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE));
    CHECK(domain_supported(c, MemoryDomain::HOST_PINNED));
    CHECK(!domain_supported(c, MemoryDomain::CUDA_DEVICE)); // default: not supported
}

TEST_CASE(synthetic_rejects_device_memory_by_default) {
    SyntheticBackend b(1);
    auto d = testutil::make_buffer(1, 1, MemoryDomain::CUDA_DEVICE, 4096, 4096, AccessRight::REMOTE_WRITE);
    CHECK(b.can_register(d) == "DOMAIN_UNSUPPORTED");
    // Enable device memory support.
    b.configure_device_memory_support(true);
    // Now still requires explicit remote capability, which is granted for write by default.
    CHECK(b.can_register(d).empty());
}

TEST_CASE(synthetic_atomic_gating) {
    SyntheticBackend b(1);
    auto d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096, AccessRight::REMOTE_ATOMIC);
    CHECK(b.can_register(d) == "REMOTE_ATOMIC_UNSUPPORTED");
    b.configure_atomic_support(true);
    CHECK(b.can_register(d).empty());
    BackendCapabilities c = b.capabilities();
    CHECK(c.remote_atomic == CapabilityState::SUPPORTED);
}

TEST_CASE(synthetic_register_deregister_and_stale_key) {
    SyntheticBackend b(9);
    RegistrationContext ctx;
    ctx.worker_boot = WorkerBootId(1);
    ctx.epoch = CoordinatorEpoch(1);
    ctx.registration_generation = RegistrationGeneration(1);
    ctx.backend_generation = BackendGeneration(1);
    auto d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                    AccessRight::REMOTE_WRITE);
    BackendRegistration out;
    RegisterOutcome ro = b.register_buffer(d, ctx, out);
    CHECK(ro.ok);
    CHECK(out.provenance == Provenance::SYNTHETIC);
    std::string ex;
    AccessOutcome o = b.query_remote_access(RegisterHandle{out.memory_region_id, out.handle}, out.keys,
                                            OperationKind::WRITE, 0, 1024, ex);
    CHECK(o == AccessOutcome::ALLOW);
    // Stale key rejected.
    BackendKey stale = out.keys;
    stale.remote_key_generation = RemoteKeyGeneration(999);
    AccessOutcome o2 = b.query_remote_access(RegisterHandle{out.memory_region_id, out.handle}, stale,
                                             OperationKind::WRITE, 0, 1024, ex);
    CHECK(o2 == AccessOutcome::REJECT_STALE_KEY);
    // Range overrun rejected.
    AccessOutcome o3 = b.query_remote_access(RegisterHandle{out.memory_region_id, out.handle}, out.keys,
                                             OperationKind::WRITE, 3000, 4096, ex);
    CHECK(o3 == AccessOutcome::REJECT_RANGE);
    // Deregister.
    CHECK(b.deregister_buffer(RegisterHandle{out.memory_region_id, out.handle}).ok);
    // Access after deregister -> not registered.
    AccessOutcome o4 = b.query_remote_access(RegisterHandle{out.memory_region_id, out.handle}, out.keys,
                                             OperationKind::WRITE, 0, 1024, ex);
    CHECK(o4 == AccessOutcome::REJECT_NOT_REGISTERED);
}

TEST_CASE(synthetic_backend_restart_invalidates_handles) {
    SyntheticBackend b(7);
    RegistrationContext ctx;
    ctx.worker_boot = WorkerBootId(1); ctx.epoch = CoordinatorEpoch(1);
    ctx.registration_generation = RegistrationGeneration(1); ctx.backend_generation = BackendGeneration(1);
    auto d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096, AccessRight::REMOTE_WRITE);
    BackendRegistration out;
    CHECK(b.register_buffer(d, ctx, out).ok);
    std::string ex;
    CHECK(b.query_remote_access(RegisterHandle{out.memory_region_id, out.handle}, out.keys,
                                OperationKind::WRITE, 0, 8, ex) == AccessOutcome::ALLOW);
    b.simulate_backend_restart();
    CHECK(b.live_registrations() == 0);
    AccessOutcome o = b.query_remote_access(RegisterHandle{out.memory_region_id, out.handle}, out.keys,
                                            OperationKind::WRITE, 0, 8, ex);
    CHECK(o == AccessOutcome::REJECT_NOT_REGISTERED);
}

TEST_CASE(synthetic_generation_rollover_invalidates_keys) {
    SyntheticBackend b(3);
    RegistrationContext ctx;
    ctx.worker_boot = WorkerBootId(1); ctx.epoch = CoordinatorEpoch(1);
    ctx.registration_generation = RegistrationGeneration(1); ctx.backend_generation = BackendGeneration(1);
    auto d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096, AccessRight::REMOTE_WRITE);
    BackendRegistration out;
    CHECK(b.register_buffer(d, ctx, out).ok);
    b.rollover_transport_generation();
    std::string ex;
    AccessOutcome o = b.query_remote_access(RegisterHandle{out.memory_region_id, out.handle}, out.keys,
                                            OperationKind::WRITE, 0, 8, ex);
    CHECK(o == AccessOutcome::REJECT_STALE_REGISTRATION || o == AccessOutcome::REJECT_STALE_KEY);
}

TEST_CASE(synthetic_permission_denied_when_right_not_granted) {
    SyntheticBackend b(2);
    RegistrationContext ctx;
    ctx.worker_boot = WorkerBootId(1); ctx.epoch = CoordinatorEpoch(1);
    ctx.registration_generation = RegistrationGeneration(1); ctx.backend_generation = BackendGeneration(1);
    auto d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096, AccessRight::REMOTE_READ);
    BackendRegistration out;
    CHECK(b.register_buffer(d, ctx, out).ok);
    std::string ex;
    AccessOutcome o = b.query_remote_access(RegisterHandle{out.memory_region_id, out.handle}, out.keys,
                                            OperationKind::WRITE, 0, 8, ex);
    CHECK(o == AccessOutcome::REJECT_PERMISSION);
}

TEST_CASE(synthetic_simulate_remote_is_deterministic) {
    SyntheticBackend b(11);
    RegistrationContext ctx;
    ctx.worker_boot = WorkerBootId(1); ctx.epoch = CoordinatorEpoch(1);
    ctx.registration_generation = RegistrationGeneration(1); ctx.backend_generation = BackendGeneration(1);
    auto d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096, AccessRight::REMOTE_WRITE);
    BackendRegistration out;
    CHECK(b.register_buffer(d, ctx, out).ok);
    std::string ex;
    std::uint64_t delta1 = 0, delta2 = 0;
    AccessOutcome oa = b.simulate_remote(OperationKind::WRITE, 0, 64, out.keys.remote_key_generation.value(), ex, delta1);
    AccessOutcome ob = b.simulate_remote(OperationKind::WRITE, 0, 64, out.keys.remote_key_generation.value(), ex, delta2);
    CHECK(oa == AccessOutcome::ALLOW);
    CHECK(ob == AccessOutcome::ALLOW);
    CHECK(delta1 == delta2);
}

TEST_CASE(reference_backend_is_real_and_rejects_cuda) {
    ReferenceBackend b;
    CHECK(b.provenance() == Provenance::REAL);
    BackendCapabilities c = b.capabilities();
    CHECK(c.cuda_device == CapabilityState::NOT_SUPPORTED);
    CHECK(domain_supported(c, MemoryDomain::HOST_PINNED));
    auto dcuda = testutil::make_buffer(1, 1, MemoryDomain::CUDA_DEVICE, 4096, 4096, AccessRight::REMOTE_WRITE);
    CHECK(!b.can_register(dcuda).empty());
}

TEST_CASE(reference_backend_register_access_deregister) {
    ReferenceBackend b;
    RegistrationContext ctx;
    ctx.worker_boot = WorkerBootId(1); ctx.epoch = CoordinatorEpoch(1);
    ctx.registration_generation = RegistrationGeneration(1); ctx.backend_generation = BackendGeneration(1);
    auto d = testutil::make_buffer(1, 1, MemoryDomain::HOST_PINNED, 4096, 4096, AccessRight::REMOTE_WRITE);
    BackendRegistration out;
    CHECK(b.register_buffer(d, ctx, out).ok);
    CHECK(out.provenance == Provenance::REAL);
    std::string ex;
    CHECK(b.query_remote_access(RegisterHandle{out.memory_region_id, out.handle}, out.keys,
                                OperationKind::WRITE, 0, 8, ex) == AccessOutcome::ALLOW);
    CHECK(b.query_remote_access(RegisterHandle{out.memory_region_id, out.handle}, out.keys,
                                OperationKind::ATOMIC_COMPARE_SWAP, 0, 8, ex) == AccessOutcome::REJECT_UNKNOWN_CAPABILITY);
    CHECK(b.deregister_buffer(RegisterHandle{out.memory_region_id, out.handle}).ok);
}

TEST_CASE(reference_host_pinning_probe_reports_real_result) {
    ReferenceBackend b;
    // Probe allocations are bounded; report actual OS result, never claim RDMA.
    PinProbeResult p = b.probe_host_pinning(0, 1u << 20); // 1 MiB
    CHECK(p.bytes == (1u << 20));
#ifdef _WIN32
    // If VirtualLock is permitted by the current session, at least allocation
    // and touch must have committed; lock may or may not succeed depending on
    // privileges. Provenance must be REAL either way.
    CHECK(p.provenance == Provenance::REAL);
    CHECK(p.allocation_committed == true);
#else
    CHECK(p.provenance == Provenance::UNKNOWN);
#endif
    CHECK(!p.ok || p.provenance == Provenance::REAL);
    (void)p;
}

int main() { return testfw::run_all(); }

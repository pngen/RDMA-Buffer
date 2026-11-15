
#include "test_framework.hpp"
#include "rdmabuffer/rdmabuffer.hpp"
#include "test_util.hpp"
#include <memory>

using namespace rdmabuffer;

struct RegFixture {
    std::shared_ptr<SyntheticBackend> backend;
    Rdmabuffer rt;
    ProtectionDomainId domain;
    RegistrationId reg;
    RemoteKeyGeneration key_gen;

    void init(std::uint64_t seed = 42) {
        backend = std::make_shared<SyntheticBackend>(seed);
        rt.add_backend(backend);
        rt.set_authority(testutil::make_snapshot());
        domain = rt.create_protection_domain(NodeId(1), ProcessId(1));
        auto d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                        AccessRight::REMOTE_READ | AccessRight::REMOTE_WRITE);
        rt.create_buffer(d);
        RegisterResult r = rt.register_buffer(d, backend->id(), domain, testutil::make_envelope());
        reg = r.registration;
        RegistrationRecord rec;
        rt.get_registration(reg, rec);
        key_gen = rec.remote_key.key_generation;
    }

    RemoteAccessRequest request(OperationKind kind, std::uint64_t offset, std::uint64_t length,
                                AccessRight right, std::uint64_t boot = 1) {
        RemoteAccessRequest q;
        q.transfer_id = TransferId(1);
        q.source_registration = reg;
        q.offset = offset;
        q.length = length;
        q.kind = kind;
        q.required_rights = access_mask(right);
        q.expected_buffer_generation = BufferGeneration(1);
        q.expected_registration_generation = RegistrationGeneration(1);
        q.expected_remote_key_generation = key_gen;
        q.attempt = AttemptId(1);
        q.dispatch = DispatchId(1);
        q.authority = testutil::make_envelope(1, boot, 1, 1, 1);
        q.domain = domain;
        q.backend = backend->id();
        q.node = NodeId(1);
        q.process = ProcessId(1);
        return q;
    }
};

TEST_CASE(valid_remote_write_allowed) {
    RegFixture f; f.init();
    auto q = f.request(OperationKind::WRITE, 0, 1024, AccessRight::REMOTE_WRITE);
    AccessDecision d = f.rt.validate_remote_access(q);
    CHECK(d.outcome == AccessOutcome::ALLOW);
    CHECK(d.code == "ALLOW");
    // write bytes accounted
    CHECK(f.rt.accounting().remote_write_bytes.get() == 1024);
}

TEST_CASE(valid_remote_read_allowed) {
    RegFixture f; f.init();
    auto q = f.request(OperationKind::READ, 0, 512, AccessRight::REMOTE_READ);
    AccessDecision d = f.rt.validate_remote_access(q);
    CHECK(d.outcome == AccessOutcome::ALLOW);
}

TEST_CASE(out_of_range_rejected) {
    RegFixture f; f.init();
    auto q = f.request(OperationKind::WRITE, 3000, 4096, AccessRight::REMOTE_WRITE);
    AccessDecision d = f.rt.validate_remote_access(q);
    CHECK(d.outcome == AccessOutcome::REJECT_RANGE);
}

TEST_CASE(unauthorized_write_rejected) {
    RegFixture f; f.init();
    // Register a buffer granting only READ; WRITE must be rejected.
    auto rb = std::make_shared<SyntheticBackend>(2);
    Rdmabuffer rt; rt.add_backend(rb);
    rt.set_authority(testutil::make_snapshot());
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    auto d = testutil::make_buffer(100, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                   AccessRight::REMOTE_READ | AccessRight::LOCAL_READ);
    rt.create_buffer(d);
    RegisterResult r = rt.register_buffer(d, rb->id(), dom, testutil::make_envelope());
    REQUIRE(r.ok);
    RemoteAccessRequest q;
    q.source_registration = r.registration; q.offset = 0; q.length = 4;
    q.kind = OperationKind::WRITE; q.required_rights = access_mask(AccessRight::REMOTE_WRITE);
    q.expected_buffer_generation = BufferGeneration(1); q.expected_registration_generation = RegistrationGeneration(1);
    q.expected_remote_key_generation = RemoteKeyGeneration(1);
    q.authority = testutil::make_envelope(1, 1, 1, 1, 1); q.domain = dom; q.backend = rb->id();
    q.node = NodeId(1); q.process = ProcessId(1);
    AccessDecision dd = rt.validate_remote_access(q);
    CHECK(dd.outcome == AccessOutcome::REJECT_PERMISSION);
}

TEST_CASE(stale_key_rejected) {
    RegFixture f; f.init();
    auto q = f.request(OperationKind::WRITE, 0, 1024, AccessRight::REMOTE_WRITE);
    q.expected_remote_key_generation = RemoteKeyGeneration(f.key_gen.value() + 100); // stale
    AccessDecision d = f.rt.validate_remote_access(q);
    CHECK(d.outcome == AccessOutcome::REJECT_STALE_KEY);
}

TEST_CASE(stale_buffer_rejected) {
    RegFixture f; f.init();
    auto q = f.request(OperationKind::WRITE, 0, 1024, AccessRight::REMOTE_WRITE);
    q.expected_buffer_generation = BufferGeneration(999);
    AccessDecision d = f.rt.validate_remote_access(q);
    CHECK(d.outcome == AccessOutcome::REJECT_STALE_BUFFER);
}

TEST_CASE(stale_boot_rejected) {
    RegFixture f; f.init();
    auto q = f.request(OperationKind::WRITE, 0, 1024, AccessRight::REMOTE_WRITE);
    q.authority = testutil::make_envelope(1, 555, 1, 1, 1);
    AccessDecision d = f.rt.validate_remote_access(q);
    CHECK(d.outcome == AccessOutcome::REJECT_STALE_BOOT);
}

TEST_CASE(unknown_atomic_capability_rejected) {
    RegFixture f; f.init(); // atomic disabled by default
    auto q = f.request(OperationKind::ATOMIC_COMPARE_SWAP, 0, 8, AccessRight::REMOTE_ATOMIC);
    AccessDecision d = f.rt.validate_remote_access(q);
    CHECK(d.outcome != AccessOutcome::ALLOW);
}

// ---- regression: a registration is bound to the incarnation that issued it ----

TEST_CASE(registration_from_superseded_incarnation_rejected) {
    // Participant restart: the epoch and the boot id both move on. The fresh
    // incarnation's own envelope must not revive the old registration.
    {
        RegFixture f; f.init();
        f.rt.note_participant_restart();
        const AuthorityEnvelope fresh = testutil::make_envelope(2, 2, 1, 1, 1);
        auto q = f.request(OperationKind::WRITE, 0, 1024, AccessRight::REMOTE_WRITE);
        q.authority = fresh;
        CHECK(f.rt.validate_remote_access(q).outcome == AccessOutcome::REJECT_STALE_EPOCH);
        CHECK(!f.rt.acquire_lease(f.reg, fresh, access_mask(AccessRight::REMOTE_WRITE)).ok);
        CHECK(f.rt.accounting().active_leases.get() == 0);
    }
    // Epoch rollover alone.
    {
        RegFixture f; f.init();
        f.rt.advance_epoch();
        const AuthorityEnvelope fresh = testutil::make_envelope(2, 1, 1, 1, 1);
        auto q = f.request(OperationKind::WRITE, 0, 1024, AccessRight::REMOTE_WRITE);
        q.authority = fresh;
        CHECK(f.rt.validate_remote_access(q).outcome == AccessOutcome::REJECT_STALE_EPOCH);
        auto d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                        AccessRight::REMOTE_READ | AccessRight::REMOTE_WRITE);
        RegisterResult ru = f.rt.register_buffer_reuse(d, f.backend->id(), f.domain, fresh);
        CHECK(!ru.ok);
        CHECK(ru.reuse == ReuseDecision::REUSE_MISS);
    }
    // A new WorkerBootId under the same epoch.
    {
        RegFixture f; f.init();
        f.rt.set_authority(testutil::make_snapshot(1, 7));
        const AuthorityEnvelope fresh = testutil::make_envelope(1, 7, 1, 1, 1);
        auto q = f.request(OperationKind::WRITE, 0, 1024, AccessRight::REMOTE_WRITE);
        q.authority = fresh;
        CHECK(f.rt.validate_remote_access(q).outcome == AccessOutcome::REJECT_STALE_BOOT);
        CHECK(!f.rt.acquire_lease(f.reg, fresh, access_mask(AccessRight::REMOTE_WRITE)).ok);
    }
}

// ---- regression: stale-authority rejections are counted like every other rejection ----

TEST_CASE(stale_authority_rejections_are_counted) {
    RegFixture f; f.init();
    auto q = f.request(OperationKind::WRITE, 0, 1024, AccessRight::REMOTE_WRITE);
    q.authority = testutil::make_envelope(1, 555, 1, 1, 1); // stale boot
    CHECK(f.rt.validate_remote_access(q).outcome == AccessOutcome::REJECT_STALE_BOOT);
    CHECK(f.rt.accounting().failed_access_attempts.get() == 1);
    CHECK(f.rt.accounting().stale_access_rejections.get() == 1);
    q.authority = testutil::make_envelope(99, 1, 1, 1, 1);  // stale epoch
    CHECK(f.rt.validate_remote_access(q).outcome == AccessOutcome::REJECT_STALE_EPOCH);
    CHECK(f.rt.accounting().failed_access_attempts.get() == 2);
    CHECK(f.rt.accounting().stale_access_rejections.get() == 2);
}

int main() { return testfw::run_all(); }

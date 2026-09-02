
#include "test_framework.hpp"
#include "fixture.hpp"
#include <memory>
#include <string>

using namespace rdmabuffer;

static RemoteAccessRequest req(const testutil::RegFixture& f, OperationKind kind, std::uint64_t off,
                               std::uint64_t len, AccessRight right, RemoteKeyGeneration kgen,
                               std::uint64_t boot = 1, BufferGeneration bgen = BufferGeneration(1)) {
    RemoteAccessRequest q;
    q.source_registration = f.reg; q.offset = off; q.length = len; q.kind = kind;
    q.required_rights = access_mask(right);
    q.expected_buffer_generation = bgen;
    q.expected_registration_generation = RegistrationGeneration(1);
    q.expected_remote_key_generation = kgen;
    q.authority = testutil::make_envelope(1, boot, 1, 1, 1);
    q.domain = f.domain; q.backend = f.backend->id(); q.node = NodeId(1); q.process = ProcessId(1);
    return q;
}

TEST_CASE(adversarial_zero_length_registration_rejected) {
    auto b = std::make_shared<SyntheticBackend>(1);
    Rdmabuffer rt; rt.add_backend(b);
    rt.set_authority(testutil::make_snapshot());
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    auto d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 0, 4096, AccessRight::REMOTE_WRITE);
    rt.create_buffer(d);
    RegisterResult r = rt.register_buffer(d, b->id(), dom, testutil::make_envelope());
    CHECK(!r.ok);
    CHECK(r.miss_reason == "ZERO_LENGTH");
}

TEST_CASE(adversarial_overflow_registration_rejected) {
    auto b = std::make_shared<SyntheticBackend>(1);
    Rdmabuffer rt; rt.add_backend(b); rt.set_authority(testutil::make_snapshot());
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    auto d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 1 << 20, 4096,
                                    AccessRight::REMOTE_WRITE, UINT64_MAX - 8);
    rt.create_buffer(d);
    CHECK(!rt.register_buffer(d, b->id(), dom, testutil::make_envelope()).ok);
}

TEST_CASE(adversarial_null_pointer_rejected_for_host_domain) {
    BufferDescriptor d = testutil::make_buffer(1, 1, MemoryDomain::HOST_PINNED, 4096, 4096, AccessRight::REMOTE_WRITE, 0);
    CHECK(validate_range(d).code == "NULL_OR_INVALID_POINTER");
}

TEST_CASE(adversarial_duplicate_buffer_id_rejected) {
    auto b = std::make_shared<SyntheticBackend>(1);
    Rdmabuffer rt; rt.add_backend(b); rt.set_authority(testutil::make_snapshot());
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    auto d = testutil::make_buffer(5, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096, AccessRight::REMOTE_WRITE);
    CHECK(rt.create_buffer(d).is_valid());
    CHECK(!rt.create_buffer(d).is_valid()); // same id+gen -> duplicate
    // Generation regression rejected.
    auto d0 = testutil::make_buffer(5, 0, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096, AccessRight::REMOTE_WRITE);
    CHECK(!rt.create_buffer(d0).is_valid());
}

TEST_CASE(adversarial_wrong_protection_domain_rejected) {
    testutil::RegFixture f; f.init();
    auto q = req(f, OperationKind::WRITE, 0, 4, AccessRight::REMOTE_WRITE, f.key_gen);
    q.domain = ProtectionDomainId(999); // wrong domain
    CHECK(f.rt.validate_remote_access(q).outcome == AccessOutcome::REJECT_DOMAIN);
}

TEST_CASE(adversarial_unauthorized_read_and_write_rejected) {
    testutil::RegFixture f; f.init(); // registered for REMOTE_READ | REMOTE_WRITE
    auto q1 = req(f, OperationKind::WRITE, 0, 4, AccessRight::REMOTE_READ, f.key_gen);
    // A registration granting only READ must reject WRITE.
    auto b = std::make_shared<SyntheticBackend>(1);
    Rdmabuffer rt; rt.add_backend(b); rt.set_authority(testutil::make_snapshot());
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    auto dd = testutil::make_buffer(2, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096, AccessRight::REMOTE_READ | AccessRight::LOCAL_READ);
    rt.create_buffer(dd);
    RegisterResult r = rt.register_buffer(dd, b->id(), dom, testutil::make_envelope());
    REQUIRE(r.ok);
    RemoteAccessRequest q2;
    q2.source_registration = r.registration; q2.offset = 0; q2.length = 4;
    q2.kind = OperationKind::WRITE; q2.required_rights = access_mask(AccessRight::REMOTE_WRITE);
    q2.expected_buffer_generation = BufferGeneration(1); q2.expected_registration_generation = RegistrationGeneration(1);
    q2.expected_remote_key_generation = RemoteKeyGeneration(1);
    q2.authority = testutil::make_envelope(1, 1, 1, 1, 1); q2.domain = dom; q2.backend = b->id();
    q2.node = NodeId(1); q2.process = ProcessId(1);
    CHECK(rt.validate_remote_access(q2).outcome == AccessOutcome::REJECT_PERMISSION);
}

TEST_CASE(adversarial_range_overrun_rejected) {
    testutil::RegFixture f; f.init();
    CHECK(f.rt.validate_remote_access(req(f, OperationKind::WRITE, 0, 4096 + 1, AccessRight::REMOTE_WRITE, f.key_gen)).outcome == AccessOutcome::REJECT_RANGE);
}

TEST_CASE(adversarial_atomic_unsupported_rejected) {
    testutil::RegFixture f; f.init(); // atomic not enabled
    AccessOutcome o = f.rt.validate_remote_access(req(f, OperationKind::ATOMIC_COMPARE_SWAP, 0, 8, AccessRight::REMOTE_ATOMIC, f.key_gen)).outcome;
    // Capability is not granted and not supported: never ALLOW.
    CHECK(o != AccessOutcome::ALLOW);
    CHECK(o == AccessOutcome::REJECT_PERMISSION || o == AccessOutcome::REJECT_UNKNOWN_CAPABILITY);
}

TEST_CASE(adversarial_access_after_deregister_rejected) {
    testutil::RegFixture f; f.init();
    std::string ex;
    REQUIRE(f.rt.deregister(f.reg, ex));
    AccessDecision d = f.rt.validate_remote_access(req(f, OperationKind::WRITE, 0, 4, AccessRight::REMOTE_WRITE, f.key_gen));
    CHECK(d.outcome == AccessOutcome::REJECT_NOT_REGISTERED);
}

TEST_CASE(adversarial_invalid_lifecycle_transition_guarded) {
    CHECK(!can_transition(RegistrationLifecycle::DEREGISTERED, RegistrationLifecycle::ACTIVE));
    CHECK(!can_transition(RegistrationLifecycle::UNREGISTERED, RegistrationLifecycle::ACTIVE));
    CHECK(can_transition(RegistrationLifecycle::UNREGISTERED, RegistrationLifecycle::REGISTERING));
    CHECK(can_transition(RegistrationLifecycle::ACTIVE, RegistrationLifecycle::REVOKING));
}

int main() { return testfw::run_all(); }

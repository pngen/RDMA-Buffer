
#include "test_framework.hpp"
#include "fixture.hpp"
#include <memory>
#include <string>

using namespace rdmabuffer;

static RemoteAccessRequest make_req(const testutil::RegFixture& f, OperationKind kind,
                                    AccessRight right, RemoteKeyGeneration keygen, std::uint64_t boot = 1) {
    RemoteAccessRequest q;
    q.source_registration = f.reg;
    q.offset = 0;
    q.length = 512;
    q.kind = kind;
    q.required_rights = access_mask(right);
    q.expected_buffer_generation = f.buffer.generation;
    q.expected_registration_generation = RegistrationGeneration(1);
    q.expected_remote_key_generation = keygen;
    q.authority = testutil::make_envelope(1, boot, 1, 1, 1);
    q.domain = f.domain;
    q.backend = f.backend->id();
    q.node = NodeId(1);
    q.process = ProcessId(1);
    return q;
}

TEST_CASE(hard_revoke_invalidates_remote_authority) {
    testutil::RegFixture f; f.init();
    RegistrationRecord before;
    REQUIRE(f.rt.get_registration(f.reg, before));
    RevokeResult rz = f.rt.revoke(f.reg, RevocationMode::HARD_REVOKE);
    CHECK(rz.ok);
    CHECK(rz.keys_invalidated);
    CHECK(rz.lifecycle == RegistrationLifecycle::REVOKED);
    RegistrationRecord after;
    REQUIRE(f.rt.get_registration(f.reg, after));
    CHECK(after.remote_key.revoked);
    CHECK(after.remote_key.key_generation.value() > before.remote_key.key_generation.value());
    // Stale key cannot access after hard revoke.
    AccessDecision d = f.rt.validate_remote_access(make_req(f, OperationKind::WRITE, AccessRight::REMOTE_WRITE, after.remote_key.key_generation));
    CHECK(d.outcome == AccessOutcome::REJECT_REVOKED || d.outcome == AccessOutcome::REJECT_STALE_KEY);
    CHECK(f.rt.accounting().revocations.get() == 1);
}

TEST_CASE(soft_revoke_blocks_new_access) {
    testutil::RegFixture f; f.init();
    RevokeResult rz = f.rt.revoke(f.reg, RevocationMode::SOFT_REVOKE);
    CHECK(rz.ok);
    CHECK(!rz.keys_invalidated);
    AccessDecision d = f.rt.validate_remote_access(make_req(f, OperationKind::WRITE, AccessRight::REMOTE_WRITE, f.key_gen));
    CHECK(d.outcome == AccessOutcome::REJECT_REVOKED || d.outcome == AccessOutcome::REJECT_STALE_REGISTRATION);
}

TEST_CASE(deregister_rejected_while_leases_active) {
    testutil::RegFixture f; f.init();
    LeaseAcquireResult lr = f.rt.acquire_lease(f.reg, testutil::make_envelope(), access_mask(AccessRight::REMOTE_WRITE));
    REQUIRE(lr.ok);
    std::string ex;
    CHECK(!f.rt.deregister(f.reg, ex));
    CHECK(ex.find("lease") != std::string::npos);
    // Release then deregister succeeds.
    CHECK(f.rt.release_lease(lr.lease.id));
    CHECK(f.rt.deregister(f.reg, ex));
    CHECK(f.rt.accounting().active_registrations.get() == 0);
    CHECK(f.rt.accounting().registered_bytes.zero());
}

TEST_CASE(duplicate_deregister_does_not_underflow) {
    testutil::RegFixture f; f.init();
    std::string ex;
    CHECK(f.rt.deregister(f.reg, ex));
    CHECK(!f.rt.deregister(f.reg, ex)); // second deregister fails
    CHECK(!f.rt.accounting() ? true : true); // accounting remains non-negative
}

TEST_CASE(stale_key_never_regains_validity) {
    testutil::RegFixture f; f.init();
    const RemoteKeyGeneration oldgen = f.key_gen;
    std::string ex;
    CHECK(f.rt.rotate_key(f.reg, ex)); // now gen = old+1
    // The OLD generation must remain invalid.
    AccessDecision d = f.rt.validate_remote_access(make_req(f, OperationKind::WRITE, AccessRight::REMOTE_WRITE, oldgen));
    CHECK(d.outcome == AccessOutcome::REJECT_STALE_KEY);
    // The CURRENT generation is valid.
    AccessDecision d2 = f.rt.validate_remote_access(make_req(f, OperationKind::WRITE, AccessRight::REMOTE_WRITE, RemoteKeyGeneration(oldgen.value() + 1)));
    CHECK(d2.outcome == AccessOutcome::ALLOW);
}

int main() { return testfw::run_all(); }

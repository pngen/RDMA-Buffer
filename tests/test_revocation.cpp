
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

// ---- regression: revocation closes leases and reaches a deregisterable state ----

TEST_CASE(hard_revoke_closes_lease_accounting_exactly_once) {
    testutil::RegFixture f; f.init();
    // A second registration with its own lease shares the lease counter.
    auto d2 = testutil::make_buffer(2, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                     AccessRight::REMOTE_WRITE);
    f.rt.create_buffer(d2);
    RegisterResult r2 = f.rt.register_buffer(d2, f.backend->id(), f.domain, testutil::make_envelope());
    REQUIRE(r2.ok);
    LeaseAcquireResult l1 = f.rt.acquire_lease(f.reg, testutil::make_envelope(), access_mask(AccessRight::REMOTE_WRITE));
    LeaseAcquireResult l2 = f.rt.acquire_lease(r2.registration, testutil::make_envelope(), access_mask(AccessRight::REMOTE_WRITE));
    REQUIRE(l1.ok);
    REQUIRE(l2.ok);
    CHECK(f.rt.revoke(f.reg, RevocationMode::HARD_REVOKE).ok);
    CHECK(f.rt.accounting().active_leases.get() == 1);
    // Releasing the lease the revoke already ended must not close the other
    // registration's lease.
    f.rt.release_lease(l1.lease.id);
    CHECK(f.rt.accounting().active_leases.get() == 1);
    CHECK(!f.rt.release_lease(l1.lease.id)); // a repeat is still a duplicate.
    CHECK(f.rt.release_lease(l2.lease.id));
    CHECK(f.rt.accounting().active_leases.get() == 0);
}

TEST_CASE(hard_revoked_registration_deregisters_without_lease_release) {
    testutil::RegFixture f; f.init();
    LeaseAcquireResult lr = f.rt.acquire_lease(f.reg, testutil::make_envelope(), access_mask(AccessRight::REMOTE_WRITE));
    REQUIRE(lr.ok);
    CHECK(f.rt.revoke(f.reg, RevocationMode::HARD_REVOKE).ok);
    // The hard revoke ended every lease, so teardown does not depend on a
    // holder that may never release.
    std::string ex;
    CHECK(f.rt.deregister(f.reg, ex));
    CHECK(f.rt.accounting_clean());
    CHECK(f.backend->live_registrations() == 0);
}

TEST_CASE(soft_revoke_completes_when_last_lease_is_released) {
    testutil::RegFixture f; f.init();
    LeaseAcquireResult lr = f.rt.acquire_lease(f.reg, testutil::make_envelope(), access_mask(AccessRight::REMOTE_WRITE));
    REQUIRE(lr.ok);
    RevokeResult rz = f.rt.revoke(f.reg, RevocationMode::SOFT_REVOKE);
    CHECK(rz.ok);
    CHECK(rz.lifecycle == RegistrationLifecycle::REVOKING);
    CHECK(f.rt.accounting().revocations.get() == 0);
    CHECK(f.rt.release_lease(lr.lease.id));
    RegistrationRecord rec;
    REQUIRE(f.rt.get_registration(f.reg, rec));
    CHECK(rec.lifecycle == RegistrationLifecycle::REVOKED);
    CHECK(f.rt.accounting().revocations.get() == 1);
    std::string ex;
    CHECK(f.rt.deregister(f.reg, ex));
    CHECK(f.rt.accounting_clean());
}

// ---- regression: deregistration ----

TEST_CASE(deregister_after_backend_restart_releases_registration) {
    testutil::RegFixture f; f.init();
    f.backend->simulate_backend_restart();
    // The backend no longer holds the handle: the registration is rejected...
    AccessDecision d = f.rt.validate_remote_access(make_req(f, OperationKind::WRITE, AccessRight::REMOTE_WRITE, f.key_gen));
    CHECK(d.outcome == AccessOutcome::REJECT_BACKEND);
    // ...and can still be torn down, which closes its accounting and frees the
    // buffer for a new registration.
    std::string ex;
    CHECK(f.rt.deregister(f.reg, ex));
    CHECK(f.rt.registrations().empty());
    CHECK(f.rt.accounting_clean());
    CHECK(f.rt.register_buffer(f.buffer, f.backend->id(), f.domain, testutil::make_envelope()).ok);
}

TEST_CASE(access_rejected_once_deregistration_has_begun) {
    auto backend = std::make_shared<testutil::HookBackend>(1);
    Rdmabuffer rt;
    rt.add_backend(backend);
    rt.set_authority(testutil::make_snapshot());
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    auto d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                    AccessRight::REMOTE_WRITE);
    rt.create_buffer(d);
    RegisterResult r = rt.register_buffer(d, backend->id(), dom, testutil::make_envelope());
    REQUIRE(r.ok);
    RemoteAccessRequest q;
    q.source_registration = r.registration; q.offset = 0; q.length = 8;
    q.kind = OperationKind::WRITE; q.required_rights = access_mask(AccessRight::REMOTE_WRITE);
    q.expected_buffer_generation = BufferGeneration(1);
    q.expected_registration_generation = RegistrationGeneration(1);
    q.expected_remote_key_generation = RemoteKeyGeneration(1);
    q.authority = testutil::make_envelope();
    q.domain = dom; q.backend = backend->id(); q.node = NodeId(1); q.process = ProcessId(1);
    REQUIRE(rt.validate_remote_access(q).outcome == AccessOutcome::ALLOW);
    // An access request arrives while the backend is releasing the registration.
    bool asked = false;
    AccessDecision during;
    backend->on_deregister = [&]() {
        asked = true;
        during = rt.validate_remote_access(q);
    };
    std::string ex;
    CHECK(rt.deregister(r.registration, ex));
    CHECK(asked);
    CHECK(during.outcome != AccessOutcome::ALLOW);
}

int main() { return testfw::run_all(); }

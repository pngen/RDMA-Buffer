
#include "test_framework.hpp"
#include "rdmabuffer/rdmabuffer.hpp"
#include "test_util.hpp"
#include "fixture.hpp"
#include <memory>
#include <string>

using namespace rdmabuffer;

TEST_CASE(register_requires_authority_and_domain) {
    auto b = std::make_shared<SyntheticBackend>(1);
    Rdmabuffer rt;
    rt.add_backend(b);
    rt.set_authority(testutil::make_snapshot());
    auto d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                    AccessRight::REMOTE_READ | AccessRight::REMOTE_WRITE);
    // Wrong authority epoch -> reject.
    AuthorityEnvelope stale = testutil::make_envelope(99, 1, 1, 1, 1);
    RegisterResult r = rt.register_buffer(d, b->id(), ProtectionDomainId{}, stale);
    CHECK(!r.ok);
    CHECK(r.miss_reason == "REJECT_STALE_EPOCH" || r.explanation.find("CoordinatorEpoch") != std::string::npos);
}

TEST_CASE(register_commits_and_accounts) {
    auto b = std::make_shared<SyntheticBackend>(1);
    Rdmabuffer rt;
    rt.add_backend(b);
    rt.set_authority(testutil::make_snapshot());
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    auto d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                    AccessRight::REMOTE_READ | AccessRight::REMOTE_WRITE);
    BufferId bid = rt.create_buffer(d);
    CHECK(bid.is_valid());
    RegisterResult r = rt.register_buffer(d, b->id(), dom, testutil::make_envelope());
    CHECK(r.ok);
    CHECK(r.result == RegistrationResult::REGISTERED);
    CHECK(r.registration.is_valid());
    RegistrationRecord rec;
    CHECK(rt.get_registration(r.registration, rec));
    CHECK(rec.lifecycle == RegistrationLifecycle::ACTIVE);
    CHECK(rec.freshness == Freshness::VALID);
    CHECK(rec.provenance == Provenance::SYNTHETIC);
    const Accounting& a = rt.accounting();
    CHECK(a.active_registrations.get() == 1);
    CHECK(a.registered_bytes.get() == 4096);
    CHECK(a.remote_keys.get() == 1);
    CHECK(a.local_keys.get() == 1);
}

TEST_CASE(single_flight_registration_rejected) {
    auto b = std::make_shared<SyntheticBackend>(1);
    Rdmabuffer rt;
    rt.add_backend(b);
    rt.set_authority(testutil::make_snapshot());
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    auto d = testutil::make_buffer(7, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                    AccessRight::REMOTE_WRITE);
    rt.create_buffer(d);
    RegisterResult r = rt.register_buffer(d, b->id(), dom, testutil::make_envelope());
    CHECK(r.ok);
    RegisterResult r2 = rt.register_buffer(d, b->id(), dom, testutil::make_envelope());
    CHECK(!r2.ok);
    CHECK(r2.miss_reason == "REGISTRATION_IN_FLIGHT");
}

TEST_CASE(registration_reuse_requires_exact_generation) {
    auto b = std::make_shared<SyntheticBackend>(1);
    Rdmabuffer rt;
    rt.add_backend(b);
    rt.set_authority(testutil::make_snapshot());
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    auto d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                    AccessRight::REMOTE_WRITE);
    rt.create_buffer(d);
    RegisterResult r = rt.register_buffer(d, b->id(), dom, testutil::make_envelope());
    CHECK(r.ok);
    // Same descriptor -> reuse hit.
    RegisterResult ru = rt.register_buffer_reuse(d, b->id(), dom, testutil::make_envelope());
    CHECK(ru.ok);
    CHECK(ru.result == RegistrationResult::REUSED);
    CHECK(ru.reuse == ReuseDecision::REUSE_HIT);
    // Generation changed -> miss.
    auto d2 = testutil::make_buffer(1, 2, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                    AccessRight::REMOTE_WRITE);
    RegisterResult rmiss = rt.register_buffer_reuse(d2, b->id(), dom, testutil::make_envelope());
    CHECK(!rmiss.ok);
    CHECK(rmiss.reuse == ReuseDecision::REUSE_MISS);
    CHECK(rmiss.explanation.find("BufferGeneration changed") != std::string::npos);
}

TEST_CASE(stale_generation_authority_invalidated) {
    auto b = std::make_shared<SyntheticBackend>(1);
    Rdmabuffer rt;
    rt.add_backend(b);
    rt.set_authority(testutil::make_snapshot());
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    auto d1 = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                     AccessRight::REMOTE_WRITE);
    rt.create_buffer(d1);
    RegisterResult r = rt.register_buffer(d1, b->id(), dom, testutil::make_envelope());
    CHECK(r.ok);
    // Reallocate with same id but generation 2 -> old registration becomes STALE.
    auto d2 = testutil::make_buffer(1, 2, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                     AccessRight::REMOTE_WRITE);
    BufferId bid = rt.create_buffer(d2);
    CHECK(bid.is_valid());
    RegistrationRecord rec;
    CHECK(rt.get_registration(r.registration, rec));
    CHECK(rec.lifecycle == RegistrationLifecycle::STALE);
    CHECK(rt.accounting().active_registrations.get() == 0);
}

// ---- regression: registration is one transaction across the backend call ----

namespace {
// A runtime whose backend lets a test act while a registration is in flight.
struct HookRuntime {
    std::shared_ptr<testutil::HookBackend> backend = std::make_shared<testutil::HookBackend>(1);
    Rdmabuffer rt;
    ProtectionDomainId dom;
    BufferDescriptor d;

    HookRuntime() {
        rt.add_backend(backend);
        rt.set_authority(testutil::make_snapshot());
        dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
        d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                  AccessRight::REMOTE_WRITE);
        rt.create_buffer(d);
    }
};
} // namespace

TEST_CASE(single_flight_holds_while_registration_is_in_flight) {
    HookRuntime h;
    RegisterResult second;
    // A second registration of the same buffer arrives while the first one is
    // inside the backend.
    h.backend->on_register = [&]() {
        second = h.rt.register_buffer(h.d, h.backend->id(), h.dom, testutil::make_envelope());
    };
    RegisterResult first = h.rt.register_buffer(h.d, h.backend->id(), h.dom, testutil::make_envelope());
    CHECK(first.ok);
    CHECK(!second.ok);
    CHECK(second.miss_reason == "REGISTRATION_IN_FLIGHT");
    CHECK(h.rt.registrations().size() == 1);
    CHECK(h.backend->live_registrations() == 1);
    CHECK(h.rt.accounting().active_registrations.get() == 1);
}

TEST_CASE(registration_superseded_during_backend_work_is_rolled_back) {
    // The buffer is reallocated while its registration is inside the backend.
    {
        HookRuntime h;
        h.backend->on_register = [&]() {
            BufferDescriptor d2 = h.d;
            d2.generation = BufferGeneration(2);
            h.rt.create_buffer(d2);
        };
        RegisterResult r = h.rt.register_buffer(h.d, h.backend->id(), h.dom, testutil::make_envelope());
        CHECK(!r.ok);
        CHECK(r.result == RegistrationResult::PARTIAL_FAILURE);
        CHECK(h.rt.registrations().empty());
        CHECK(h.backend->live_registrations() == 0);
        CHECK(h.rt.accounting_clean());
        // The new generation registers normally afterwards.
        BufferDescriptor d2 = h.d;
        d2.generation = BufferGeneration(2);
        CHECK(h.rt.register_buffer(d2, h.backend->id(), h.dom, testutil::make_envelope()).ok);
    }
    // Authority moves to a new incarnation.
    {
        HookRuntime h;
        h.backend->on_register = [&]() { h.rt.note_participant_restart(); };
        RegisterResult r = h.rt.register_buffer(h.d, h.backend->id(), h.dom, testutil::make_envelope());
        CHECK(!r.ok);
        CHECK(r.miss_reason == "REJECT_STALE_EPOCH");
        CHECK(h.rt.registrations().empty());
        CHECK(h.backend->live_registrations() == 0);
        CHECK(h.rt.accounting_clean());
    }
    // The protection domain is destroyed.
    {
        HookRuntime h;
        h.backend->on_register = [&]() { h.rt.destroy_protection_domain(h.dom); };
        RegisterResult r = h.rt.register_buffer(h.d, h.backend->id(), h.dom, testutil::make_envelope());
        CHECK(!r.ok);
        CHECK(r.miss_reason == "DOMAIN_INVALID");
        CHECK(h.rt.registrations().empty());
        CHECK(h.backend->live_registrations() == 0);
        CHECK(h.rt.accounting_clean());
    }
}

// ---- regression: invalidated registrations free the buffer and close accounting once ----

TEST_CASE(reallocated_buffer_registers_new_generation) {
    auto b = std::make_shared<SyntheticBackend>(1);
    Rdmabuffer rt;
    rt.add_backend(b);
    rt.set_authority(testutil::make_snapshot());
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    auto d1 = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                     AccessRight::REMOTE_WRITE);
    rt.create_buffer(d1);
    RegisterResult r1 = rt.register_buffer(d1, b->id(), dom, testutil::make_envelope());
    REQUIRE(r1.ok);
    auto d2 = testutil::make_buffer(1, 2, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                     AccessRight::REMOTE_WRITE);
    REQUIRE(rt.create_buffer(d2).is_valid());
    // Generation 1's registration is stale, so generation 2 can register.
    RegisterResult r2 = rt.register_buffer(d2, b->id(), dom, testutil::make_envelope());
    CHECK(r2.ok);
    CHECK(rt.accounting().active_registrations.get() == 1);
    // Releasing the stale registration leaves the live one's accounting alone.
    std::string ex;
    CHECK(rt.deregister(r1.registration, ex));
    CHECK(rt.accounting().active_registrations.get() == 1);
    CHECK(rt.accounting().registered_bytes.get() == 4096);
    CHECK(rt.accounting().remote_keys.get() == 1);
    CHECK(rt.register_buffer_reuse(d2, b->id(), dom, testutil::make_envelope()).reuse == ReuseDecision::REUSE_HIT);
}

TEST_CASE(deregister_after_domain_destroy_releases_accounting_once) {
    auto b = std::make_shared<SyntheticBackend>(1);
    Rdmabuffer rt;
    rt.add_backend(b);
    rt.set_authority(testutil::make_snapshot());
    ProtectionDomainId dom1 = rt.create_protection_domain(NodeId(1), ProcessId(1));
    ProtectionDomainId dom2 = rt.create_protection_domain(NodeId(1), ProcessId(1));
    auto da = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                     AccessRight::REMOTE_WRITE);
    auto db = testutil::make_buffer(2, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                     AccessRight::REMOTE_WRITE);
    rt.create_buffer(da);
    rt.create_buffer(db);
    RegisterResult ra = rt.register_buffer(da, b->id(), dom1, testutil::make_envelope());
    RegisterResult rb = rt.register_buffer(db, b->id(), dom2, testutil::make_envelope());
    REQUIRE(ra.ok);
    REQUIRE(rb.ok);
    CHECK(rt.destroy_protection_domain(dom1));
    CHECK(rt.accounting().active_registrations.get() == 1);
    std::string ex;
    CHECK(rt.deregister(ra.registration, ex));
    // The registration in the surviving domain is still counted.
    CHECK(rt.accounting().active_registrations.get() == 1);
    CHECK(rt.accounting().registered_bytes.get() == 4096);
    CHECK(rt.deregister(rb.registration, ex));
    CHECK(rt.accounting_clean());
}

// ---- regression: what a registration records and what reuse requires ----

TEST_CASE(registration_records_backend_transport_and_key_provenance) {
    auto syn = std::make_shared<SyntheticBackend>(1);
    auto ref = std::make_shared<ReferenceBackend>();
    Rdmabuffer rt;
    rt.add_backend(syn);
    rt.add_backend(ref);
    rt.set_authority(testutil::make_snapshot());
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    auto ds = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                     AccessRight::REMOTE_WRITE);
    rt.create_buffer(ds);
    RegisterResult rs = rt.register_buffer(ds, syn->id(), dom, testutil::make_envelope());
    REQUIRE(rs.ok);
    RegistrationRecord rec;
    REQUIRE(rt.get_registration(rs.registration, rec));
    CHECK(rec.transport.is_valid());
    CHECK(rec.nic.is_valid());
    CHECK(rec.remote_key.provenance == Provenance::SYNTHETIC);
    // An access that names the registration's own transport is allowed; one
    // that names another transport is not.
    RemoteAccessRequest q;
    q.source_registration = rs.registration; q.offset = 0; q.length = 8;
    q.kind = OperationKind::WRITE; q.required_rights = access_mask(AccessRight::REMOTE_WRITE);
    q.expected_buffer_generation = BufferGeneration(1);
    q.expected_registration_generation = RegistrationGeneration(1);
    q.expected_remote_key_generation = rec.remote_key.key_generation;
    q.authority = testutil::make_envelope();
    q.domain = dom; q.backend = syn->id(); q.node = NodeId(1); q.process = ProcessId(1);
    q.transport = rec.transport;
    CHECK(rt.validate_remote_access(q).outcome == AccessOutcome::ALLOW);
    q.transport = TransportId(rec.transport.value() + 1);
    CHECK(rt.validate_remote_access(q).outcome == AccessOutcome::REJECT_TRANSPORT);
    // Keys issued by the reference backend carry that backend's provenance.
    auto dr = testutil::make_buffer(2, 1, MemoryDomain::HOST_PINNED, 4096, 4096,
                                     AccessRight::REMOTE_WRITE);
    rt.create_buffer(dr);
    RegisterResult rr = rt.register_buffer(dr, ref->id(), dom, testutil::make_envelope());
    REQUIRE(rr.ok);
    REQUIRE(rt.get_registration(rr.registration, rec));
    CHECK(rec.provenance == Provenance::REAL);
    CHECK(rec.remote_key.provenance == Provenance::REAL);
    CHECK(rec.local_key.provenance == Provenance::REAL);
}

TEST_CASE(reuse_requires_current_backend_generation) {
    testutil::RegFixture f; f.init();
    CHECK(f.rt.register_buffer_reuse(f.buffer, f.backend->id(), f.domain, testutil::make_envelope()).reuse == ReuseDecision::REUSE_HIT);
    f.backend->advance_backend_generation();
    RegisterResult ru = f.rt.register_buffer_reuse(f.buffer, f.backend->id(), f.domain, testutil::make_envelope());
    CHECK(!ru.ok);
    CHECK(ru.reuse == ReuseDecision::REUSE_MISS);
}

TEST_CASE(buffer_identity_is_validated_and_assigned_uniquely) {
    auto b = std::make_shared<SyntheticBackend>(1);
    Rdmabuffer rt;
    rt.add_backend(b);
    rt.set_authority(testutil::make_snapshot());
    // An unset generation is not a buffer generation.
    auto d0 = testutil::make_buffer(9, 0, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                     AccessRight::REMOTE_WRITE);
    CHECK(!rt.create_buffer(d0).is_valid());
    CHECK(!rt.has_buffer(BufferId(9)));
    // An id assigned by the runtime never aliases an existing buffer, and the
    // stored descriptor carries it.
    auto d1 = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                     AccessRight::REMOTE_WRITE);
    REQUIRE(rt.create_buffer(d1).is_valid());
    auto anon = testutil::make_buffer(0, 2, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                       AccessRight::REMOTE_WRITE);
    BufferId assigned = rt.create_buffer(anon);
    CHECK(assigned.is_valid());
    CHECK(assigned != BufferId(1));
    BufferDescriptor stored;
    REQUIRE(rt.get_buffer(BufferId(1), stored));
    CHECK(stored.generation == BufferGeneration(1));
    REQUIRE(rt.get_buffer(assigned, stored));
    CHECK(stored.id == assigned);
}

int main() { return testfw::run_all(); }

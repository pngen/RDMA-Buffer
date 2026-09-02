
#include "test_framework.hpp"
#include "rdmabuffer/rdmabuffer.hpp"
#include "test_util.hpp"

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

int main() { return testfw::run_all(); }

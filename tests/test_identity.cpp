
#include "test_framework.hpp"
#include "rdmabuffer/rdmabuffer.hpp"
#include <type_traits>
#include "test_util.hpp"

using namespace rdmabuffer;

TEST_CASE(strong_types_are_non_interchangeable) {
    BufferId b(5);
    RegistrationId r(5);
    CHECK(b == BufferId(5));
    // Distinct identity kinds are never implicitly comparable or assignable.
    CHECK((!std::is_same_v<BufferId, RegistrationId>));
    CHECK((!std::is_convertible_v<RegistrationId, BufferId>));
    CHECK(b.is_valid());
    CHECK(BufferId{}.is_valid() == false);
    (void)r;
}

TEST_CASE(generation_order_is_natural) {
    BufferGeneration g1(1), g2(2);
    CHECK(g2 > g1);
    CHECK(generation_newer(g2, g1));
    CHECK(generation_same(g1, BufferGeneration(1)));
    CHECK(!g1.is_valid() == false);
    CHECK(BufferGeneration{}.is_valid() == false);
}

TEST_CASE(id_hash_and_map) {
    std::unordered_map<BufferId, int> m;
    m[BufferId(1)] = 10;
    m[BufferId(2)] = 20;
    CHECK(m[BufferId(1)] == 10);
    CHECK(m.count(BufferId(3)) == 0); // no accidental zero-collision
}

TEST_CASE(generation_uniqueness_requires_incarnation) {
    // A numerically larger generation under a stale incarnation must never be
    // treated as current authority. Proven here at the model level.
    AuthoritySnapshot snap = testutil::make_snapshot(1, 5, 1, 1, 1, 1);
    AuthorityEnvelope stale = testutil::make_envelope(1, 4, 1, 1, 1); // boot 4 != current 5
    CHECK(boot_current(snap, WorkerBootId(5)));
    CHECK(!boot_current(snap, WorkerBootId(4)));
    AccessDecision d = validate_authority(snap, stale);
    CHECK(d.outcome == AccessOutcome::REJECT_STALE_BOOT);
    CHECK(d.code == "REJECT_STALE_BOOT");
}

int main() { return testfw::run_all(); }

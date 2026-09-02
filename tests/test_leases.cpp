
#include "test_framework.hpp"
#include "fixture.hpp"
#include <memory>
#include <string>

using namespace rdmabuffer;

TEST_CASE(acquire_and_release_lease) {
    testutil::RegFixture f; f.init();
    LeaseAcquireResult lr = f.rt.acquire_lease(f.reg, testutil::make_envelope(), access_mask(AccessRight::REMOTE_WRITE));
    CHECK(lr.ok);
    CHECK(lr.lease.state == LeaseState::ACTIVE);
    CHECK(f.rt.accounting().active_leases.get() == 1);
    CHECK(f.rt.release_lease(lr.lease.id));
    CHECK(f.rt.accounting().active_leases.get() == 0);
}

TEST_CASE(duplicate_release_is_rejected) {
    testutil::RegFixture f; f.init();
    LeaseAcquireResult lr = f.rt.acquire_lease(f.reg, testutil::make_envelope(), access_mask(AccessRight::REMOTE_WRITE));
    REQUIRE(lr.ok);
    CHECK(f.rt.release_lease(lr.lease.id));
    CHECK(!f.rt.release_lease(lr.lease.id)); // second release -> false
    CHECK(f.rt.accounting().active_leases.get() == 0);
    // Accounting never underflows.
    CHECK(f.rt.accounting().active_leases.zero());
}

TEST_CASE(lease_requires_valid_freshness) {
    testutil::RegFixture f; f.init();
    // Rotate key then check lease still fine, then revoke path below.
    std::string ex;
    CHECK(f.rt.rotate_key(f.reg, ex));
    LeaseAcquireResult lr = f.rt.acquire_lease(f.reg, testutil::make_envelope(), access_mask(AccessRight::REMOTE_WRITE));
    CHECK(lr.ok);
}

TEST_CASE(lease_rejected_for_stale_authority) {
    testutil::RegFixture f; f.init();
    LeaseAcquireResult lr = f.rt.acquire_lease(f.reg, testutil::make_envelope(99, 1, 1, 1, 1), access_mask(AccessRight::REMOTE_WRITE));
    CHECK(!lr.ok);
    CHECK(f.rt.accounting().active_leases.get() == 0);
}

TEST_CASE(leases_are_distinct_and_refcounted) {
    testutil::RegFixture f; f.init();
    LeaseAcquireResult a = f.rt.acquire_lease(f.reg, testutil::make_envelope(), access_mask(AccessRight::REMOTE_WRITE));
    LeaseAcquireResult b = f.rt.acquire_lease(f.reg, testutil::make_envelope(), access_mask(AccessRight::REMOTE_READ));
    REQUIRE(a.ok);
    REQUIRE(b.ok);
    CHECK(a.lease.id != b.lease.id);
    CHECK(f.rt.accounting().active_leases.get() == 2);
    CHECK(f.rt.release_lease(a.lease.id));
    CHECK(f.rt.accounting().active_leases.get() == 1);
}

int main() { return testfw::run_all(); }

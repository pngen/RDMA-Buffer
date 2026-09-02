
#include "test_framework.hpp"
#include "rdmabuffer/rdmabuffer.hpp"
#include "test_util.hpp"

using namespace rdmabuffer;

TEST_CASE(zero_length_rejected) {
    auto d = testutil::make_buffer(1, 1, MemoryDomain::HOST_PINNED, 0, 4096, AccessRight::REMOTE_WRITE);
    auto v = validate_range(d);
    CHECK(!v.ok);
    CHECK(v.code == "ZERO_LENGTH");
}

TEST_CASE(overflow_rejected) {
    std::uint64_t base = UINT64_MAX & ~0xFFFull; // aligned to 4096, near 2^64
    auto d = testutil::make_buffer(1, 1, MemoryDomain::HOST_PINNED, 0x2000, 4096, AccessRight::REMOTE_WRITE, base);
    auto v = validate_range(d);
    CHECK(!v.ok);
    CHECK(v.code == "OVERFLOW");
}

TEST_CASE(misalignment_rejected) {
    auto d = testutil::make_buffer(1, 1, MemoryDomain::HOST_PINNED, 1024, 4096, AccessRight::REMOTE_WRITE, 0x1001);
    auto v = validate_range(d);
    CHECK(!v.ok);
    CHECK(v.code == "MISALIGNED_BASE");
}

TEST_CASE(valid_range_accepted) {
    auto d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096, AccessRight::REMOTE_WRITE | AccessRight::REMOTE_READ);
    auto v = validate_range(d);
    CHECK(v.ok);
    CHECK(range_inside(d, 0, 2048));
    CHECK(!range_inside(d, 3000, 2048));
}

TEST_CASE(access_mask_semantics) {
    AccessMask m = access_mask(AccessRight::REMOTE_WRITE) | access_mask(AccessRight::REMOTE_READ);
    CHECK(access_has(m, AccessRight::REMOTE_WRITE));
    CHECK(access_has(m, AccessRight::REMOTE_READ));
    CHECK(!access_has(m, AccessRight::REMOTE_ATOMIC));
}

TEST_CASE(enums_have_stable_names) {
    CHECK(std::string_view(memory_domain_name(MemoryDomain::CUDA_DEVICE)) == "CUDA_DEVICE");
    CHECK(std::string_view(access_outcome_name(AccessOutcome::REJECT_STALE_KEY)) == "REJECT_STALE_KEY");
    CHECK(std::string_view(provenance_name(Provenance::SYNTHETIC)) == "SYNTHETIC");
    CHECK(std::string_view(transport_class_name(TransportClass::TCP_REFERENCE)) == "TCP_REFERENCE");
}

int main() { return testfw::run_all(); }

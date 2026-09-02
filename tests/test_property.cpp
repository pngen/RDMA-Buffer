
#include "test_framework.hpp"
#include "fixture.hpp"
#include <cstdint>
#include <memory>
#include <string>

using namespace rdmabuffer;

namespace {
std::uint64_t prng(std::uint64_t& s) {
    s ^= s << 13; s ^= s >> 7; s ^= s << 17; return s;
}
}

TEST_CASE(property_registration_range_never_exceeds_buffer_range) {
    std::uint64_t seed = 0x1234;
    testutil::RegFixture f; f.init(seed);
    for (int i = 0; i < 64; ++i) {
        std::uint64_t len = 1 + (prng(seed) % 8192);
        std::uint64_t off = prng(seed) % 8192;
        BufferDescriptor d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, len, 4096,
                                                   AccessRight::REMOTE_WRITE);
        auto vr = validate_range(d);
        if (vr.ok) {
            CHECK(range_inside(d, 0, len));
            CHECK(!range_inside(d, off, len) || (off + len) <= len);
        }
    }
}

TEST_CASE(property_zero_length_never_valid) {
    std::uint64_t seed = 0x99;
    for (int i = 0; i < 128; ++i) {
        BufferDescriptor d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 0, 4096,
                                                   AccessRight::REMOTE_WRITE, prng(seed));
        CHECK(!validate_range(d).ok);
    }
}

TEST_CASE(property_arithmetic_overflow_never_valid) {
    std::uint64_t seed = 0x77;
    for (int i = 0; i < 64; ++i) {
        std::uint64_t base = UINT64_MAX - (prng(seed) % 8192);
        BufferDescriptor d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 1 << 20, 4096,
                                                   AccessRight::REMOTE_WRITE, base);
        CHECK(!validate_range(d).ok);
    }
}

TEST_CASE(property_stale_boot_never_fences_fresh_incarnation) {
    // A fresh boot id must observe all its own generations as current, and a
    // stale boot must never be treated as current even with a higher number.
    testutil::RegFixture f; f.init();
    // Access under current boot -> ALLOW.
    RemoteAccessRequest q;
    q.source_registration = f.reg; q.offset = 0; q.length = 4;
    q.kind = OperationKind::WRITE; q.required_rights = access_mask(AccessRight::REMOTE_WRITE);
    q.expected_buffer_generation = f.buffer.generation;
    q.expected_registration_generation = RegistrationGeneration(1);
    q.expected_remote_key_generation = f.key_gen;
    q.authority = testutil::make_envelope(1, 1, 1, 1, 1);
    q.domain = f.domain; q.backend = f.backend->id(); q.node = NodeId(1); q.process = ProcessId(1);
    CHECK(f.rt.validate_remote_access(q).outcome == AccessOutcome::ALLOW);
    // A stale boot with a higher boot number must be rejected, not fenced to
    // current.
    q.authority = testutil::make_envelope(1, 9999, 1, 1, 1);
    CHECK(f.rt.validate_remote_access(q).outcome == AccessOutcome::REJECT_STALE_BOOT);
}

TEST_CASE(property_reuse_requires_exact_generation_compatibility) {
    std::uint64_t seed = 0xbeef;
    testutil::RegFixture f; f.init(seed);
    // Reuse with same generation -> hit.
    CHECK(f.rt.register_buffer_reuse(f.buffer, f.backend->id(), f.domain, testutil::make_envelope()).reuse == ReuseDecision::REUSE_HIT);
    // Reuse with bumped generation -> miss.
    BufferDescriptor d = f.buffer; d.generation = BufferGeneration(2);
    CHECK(f.rt.register_buffer_reuse(d, f.backend->id(), f.domain, testutil::make_envelope()).reuse == ReuseDecision::REUSE_MISS);
}

TEST_CASE(property_unknown_capability_never_allows) {
    // The reference backend reports REMOTE_ATOMIC NOT_SUPPORTED; accessing it
    // must never return ALLOW.
    ReferenceBackend b;
    RegistrationContext ctx;
    ctx.worker_boot = WorkerBootId(1); ctx.epoch = CoordinatorEpoch(1);
    ctx.registration_generation = RegistrationGeneration(1); ctx.backend_generation = BackendGeneration(1);
    auto d = testutil::make_buffer(1, 1, MemoryDomain::HOST_PINNED, 4096, 4096,
                                    AccessRight::REMOTE_WRITE | AccessRight::REMOTE_ATOMIC);
    BackendRegistration out;
    RegisterOutcome ro = b.register_buffer(d, ctx, out);
    // Reference backend rejects REMOTE_ATOMIC at can_register, so register fails
    // -> no path yields ALLOW for atomic.
    CHECK(!ro.ok);
}

int main() { return testfw::run_all(); }

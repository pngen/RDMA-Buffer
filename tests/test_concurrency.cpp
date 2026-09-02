
#include "test_framework.hpp"
#include "fixture.hpp"
#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <thread>
#include <vector>

using namespace rdmabuffer;

TEST_CASE(concurrent_lease_acquire_release) {
    testutil::RegFixture f; f.init();
    const int N = 8;
    const int ITERS = 200;
    std::atomic<bool> stop{false};
    std::vector<std::thread> threads;
    for (int t = 0; t < N; ++t) {
        threads.emplace_back([&]() {
            for (int i = 0; i < ITERS; ++i) {
                LeaseAcquireResult lr = f.rt.acquire_lease(f.reg, testutil::make_envelope(), access_mask(AccessRight::REMOTE_WRITE));
                if (lr.ok) f.rt.release_lease(lr.lease.id);
            }
        });
    }
    for (auto& th : threads) th.join();
    (void)stop;
    CHECK(f.rt.accounting().active_leases.zero());
    CHECK(f.rt.accounting().active_leases.get() == 0);
}

TEST_CASE(concurrent_remote_access_validation_all_allowed) {
    testutil::RegFixture f; f.init();
    const int N = 8;
    const int ITERS = 50;
    std::atomic<std::uint64_t> allowed{0};
    std::vector<std::thread> threads;
    std::atomic<bool> go{false};
    for (int t = 0; t < N; ++t) {
        threads.emplace_back([&]() {
            while (!go.load()) { /* spin */ }
            for (int i = 0; i < ITERS; ++i) {
                RemoteAccessRequest q;
                q.source_registration = f.reg;
                q.offset = 0; q.length = 128;
                q.kind = OperationKind::WRITE;
                q.required_rights = access_mask(AccessRight::REMOTE_WRITE);
                q.expected_buffer_generation = f.buffer.generation;
                q.expected_registration_generation = RegistrationGeneration(1);
                q.expected_remote_key_generation = f.key_gen;
                q.authority = testutil::make_envelope(1, 1, 1, 1, 1);
                q.domain = f.domain; q.backend = f.backend->id(); q.node = NodeId(1); q.process = ProcessId(1);
                AccessDecision d = f.rt.validate_remote_access(q);
                if (d.outcome == AccessOutcome::ALLOW) allowed.fetch_add(1);
            }
        });
    }
    go.store(true);
    for (auto& th : threads) th.join();
    CHECK(allowed.load() == static_cast<std::uint64_t>(N) * ITERS);
}

TEST_CASE(revoke_prevents_future_access_concurrently) {
    testutil::RegFixture f; f.init();
    std::atomic<bool> revoke_done{false};
    std::atomic<std::uint64_t> allowed_after_revoke{0};
    std::thread spawn([&]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
        f.rt.revoke(f.reg, RevocationMode::HARD_REVOKE);
        revoke_done.store(true);
    });
    // Concurrent access attempts.
    std::atomic<std::uint64_t> after{0};
    std::thread accessor([&]() {
        while (!revoke_done.load()) {
            RemoteAccessRequest q;
            q.source_registration = f.reg; q.offset = 0; q.length = 4;
            q.kind = OperationKind::WRITE; q.required_rights = access_mask(AccessRight::REMOTE_WRITE);
            q.expected_buffer_generation = f.buffer.generation;
            q.expected_registration_generation = RegistrationGeneration(1);
            q.expected_remote_key_generation = f.key_gen;
            q.authority = testutil::make_envelope(1, 1, 1, 1, 1);
            q.domain = f.domain; q.backend = f.backend->id(); q.node = NodeId(1); q.process = ProcessId(1);
            AccessDecision d = f.rt.validate_remote_access(q);
            if (d.outcome == AccessOutcome::ALLOW && revoke_done.load()) after.fetch_add(1);
        }
    });
    spawn.join();
    accessor.join();
    (void)allowed_after_revoke;
    CHECK(after.load() == 0); // no ALLOW observed post-revoke
}

int main() { return testfw::run_all(); }

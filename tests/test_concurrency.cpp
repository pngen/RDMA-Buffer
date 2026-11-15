
#include "test_framework.hpp"
#include "fixture.hpp"
#include <algorithm>
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
        for (;;) {
            // Sample completion before the attempt: only an attempt that starts
            // after the revoke finished is a post-revoke access. Sampling after
            // the attempt would count an access that was correctly allowed just
            // before the revoke.
            const bool revoked_before_attempt = revoke_done.load();
            RemoteAccessRequest q;
            q.source_registration = f.reg; q.offset = 0; q.length = 4;
            q.kind = OperationKind::WRITE; q.required_rights = access_mask(AccessRight::REMOTE_WRITE);
            q.expected_buffer_generation = f.buffer.generation;
            q.expected_registration_generation = RegistrationGeneration(1);
            q.expected_remote_key_generation = f.key_gen;
            q.authority = testutil::make_envelope(1, 1, 1, 1, 1);
            q.domain = f.domain; q.backend = f.backend->id(); q.node = NodeId(1); q.process = ProcessId(1);
            AccessDecision d = f.rt.validate_remote_access(q);
            if (d.outcome == AccessOutcome::ALLOW && revoked_before_attempt) after.fetch_add(1);
            if (revoked_before_attempt) break; // at least one post-revoke attempt was made.
        }
    });
    spawn.join();
    accessor.join();
    (void)allowed_after_revoke;
    CHECK(after.load() == 0); // no ALLOW observed post-revoke
}

// ---- regression: concurrent registrations each own one backend registration ----

TEST_CASE(concurrent_registrations_keep_backend_and_accounting_exact) {
    auto backend = std::make_shared<SyntheticBackend>(7);
    Rdmabuffer rt;
    rt.add_backend(backend);
    rt.set_authority(testutil::make_snapshot());
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    const int N = 8;
    const int PER = 200;
    std::vector<std::vector<RegistrationId>> regs(N);
    std::atomic<bool> go{false};
    std::atomic<int> failed{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < N; ++t) {
        threads.emplace_back([&, t]() {
            while (!go.load()) { /* spin */ }
            for (int i = 0; i < PER; ++i) {
                const std::uint64_t id = static_cast<std::uint64_t>(t) * static_cast<std::uint64_t>(PER) + static_cast<std::uint64_t>(i) + 1;
                auto d = testutil::make_buffer(id, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                               AccessRight::REMOTE_WRITE);
                rt.create_buffer(d);
                RegisterResult r = rt.register_buffer(d, backend->id(), dom, testutil::make_envelope());
                if (r.ok) regs[static_cast<std::size_t>(t)].push_back(r.registration);
                else failed.fetch_add(1);
            }
        });
    }
    go.store(true);
    for (auto& th : threads) th.join();
    const std::uint64_t total = static_cast<std::uint64_t>(N) * static_cast<std::uint64_t>(PER);
    CHECK(failed.load() == 0);
    CHECK(rt.registrations().size() == total);
    // Every registration owns its own backend registration.
    CHECK(backend->live_registrations() == total);
    std::vector<std::uint64_t> regions;
    for (const auto& v : regs) {
        for (RegistrationId id : v) {
            RegistrationRecord rec;
            if (rt.get_registration(id, rec)) regions.push_back(rec.memory_region_id.value());
        }
    }
    std::sort(regions.begin(), regions.end());
    CHECK(regions.size() == total);
    CHECK(std::adjacent_find(regions.begin(), regions.end()) == regions.end());
    CHECK(rt.accounting().active_registrations.get() == total);
    CHECK(rt.accounting().registered_bytes.get() == total * 4096);
    std::uint64_t deregistered = 0;
    std::string ex;
    for (const auto& v : regs) {
        for (RegistrationId id : v) {
            if (rt.deregister(id, ex)) ++deregistered;
        }
    }
    CHECK(deregistered == total);
    CHECK(backend->live_registrations() == 0);
    CHECK(rt.accounting_clean());
}

int main() { return testfw::run_all(); }

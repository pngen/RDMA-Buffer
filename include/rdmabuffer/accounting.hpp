// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Exact accounting. Duplicate release/deregister must never double decrement;
// counters must never go negative. Final teardown must close every live,
// pinned, registered, and leased counter to zero.

#pragma once

#include <cstdint>
#include <string>

namespace rdmabuffer {

// A monotonic counter that never underflows. `decrement` returns false when
// the counter is already zero (callers use that to reject duplicate release).
struct Counter {
    std::uint64_t value{0};

    constexpr void increment(std::uint64_t n = 1) noexcept { value += n; }
    constexpr bool decrement(std::uint64_t n = 1) noexcept {
        if (n > value) return false;
        value -= n;
        return true;
    }
    constexpr std::uint64_t get() const noexcept { return value; }
    constexpr bool zero() const noexcept { return value == 0; }
};

struct Accounting {
    Counter logical_buffers;
    Counter live_buffer_bytes;
    Counter pinned_bytes;
    Counter registered_bytes;
    Counter active_registrations;
    Counter active_leases;
    Counter protection_domains;
    Counter local_keys;
    Counter remote_keys;
    Counter remote_read_bytes;
    Counter remote_write_bytes;
    Counter atomic_operations;
    Counter failed_access_attempts;
    Counter stale_access_rejections;
    Counter revocations;
    Counter deregistrations;
    Counter registration_reuse_hits;
    Counter registration_misses;
    Counter participant_restarts;

    // Duplicate-release/deregister tolerance: counters are never decremented
    // below zero because `decrement` guards.
    bool deregister_active() noexcept { return active_registrations.decrement(); }
    bool release_lease() noexcept { return active_leases.decrement(); }
    bool release_pinned(std::uint64_t n) noexcept { return pinned_bytes.decrement(n); }
    bool release_registered(std::uint64_t n) noexcept { return registered_bytes.decrement(n); }

    operator bool() const noexcept {
        // "Not clean" means live/pinned/registered/leased resource counters are
        // still open. Structural counters (logical buffers, protection domains)
        // may legitimately persist after a registration is torn down.
        return !(pinned_bytes.zero() && registered_bytes.zero() &&
                 active_registrations.zero() && active_leases.zero() &&
                 local_keys.zero() && remote_keys.zero());
    }

    std::string summary() const;
};

} // namespace rdmabuffer

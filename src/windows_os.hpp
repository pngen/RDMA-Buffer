// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Platform helpers for real Windows host-memory preparation/pinning proofs.
// These prove host memory behavior, NOT RNIC registration.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace rdmabuffer {
namespace windows_os {

// Result of a real host-memory preparation probe.
struct MemProbe {
    bool ok{false};
    std::uint64_t bytes{0};
    std::string detail;
    bool allocation_committed{false};
    bool locked{false};
    bool numa_cleanup{false};
};

// System page size in bytes (0 if undetermined).
std::uint64_t page_size() noexcept;

// Commit (allocate) a PAGE_READWRITE region of `length` bytes via VirtualAlloc.
// Returns a non-null pointer on success.
void* commit_pages(std::uint64_t length, std::string& err);

// Release a region returned by commit_pages.
bool release_pages(void* p, std::uint64_t length, std::string& err);

// Attempt VirtualLock on the given range. Reports the actual OS result.
bool virtual_lock(void* p, std::uint64_t length, std::string& err);

// Attempt VirtualUnlock on the given range.
bool virtual_unlock(void* p, std::uint64_t length, std::string& err);

// Touch every page of the range so it is resident.
std::uint64_t touch_range(volatile unsigned char* p, std::uint64_t length);

} // namespace windows_os
} // namespace rdmabuffer

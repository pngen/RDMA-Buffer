// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "windows_os.hpp"

#ifdef _WIN32
#include <windows.h>
#pragma comment(lib, "kernel32.lib")
#endif

#include <cstring>
#include <new>
#include <string>

namespace rdmabuffer {
namespace windows_os {

#ifdef _WIN32

std::uint64_t page_size() noexcept {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    return static_cast<std::uint64_t>(si.dwPageSize);
}

void* commit_pages(std::uint64_t length, std::string& err) {
    if (length == 0) {
        err = "commit_pages: zero length";
        return nullptr;
    }
    void* p = VirtualAlloc(nullptr, static_cast<SIZE_T>(length), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (p == nullptr) {
        err = "commit_pages VirtualAlloc failed, error=" + std::to_string(GetLastError());
        return nullptr;
    }
    err.clear();
    return p;
}

bool release_pages(void* p, std::uint64_t length, std::string& err) {
    (void)length;
    if (p == nullptr) return true;
    if (!VirtualFree(p, 0, MEM_RELEASE)) {
        err = "release_pages VirtualFree failed, error=" + std::to_string(GetLastError());
        return false;
    }
    return true;
}

bool virtual_lock(void* p, std::uint64_t length, std::string& err) {
    if (p == nullptr || length == 0) {
        err = "virtual_lock: null pointer or zero length";
        return false;
    }
    if (VirtualLock(p, static_cast<SIZE_T>(length)) != 0) {
        err.clear();
        return true;
    }
    err = "VirtualLock failed, error=" + std::to_string(GetLastError());
    return false;
}

bool virtual_unlock(void* p, std::uint64_t length, std::string& err) {
    if (p == nullptr) return true;
    if (VirtualUnlock(p, static_cast<SIZE_T>(length)) != 0) {
        err.clear();
        return true;
    }
    // VirtualUnlock can fail if the range was never locked; treat as no-op.
    err.clear();
    return true;
}

std::uint64_t touch_range(volatile unsigned char* p, std::uint64_t length) {
    if (p == nullptr) return 0;
    const std::uint64_t ps = page_size();
    const std::uint64_t stride = ps ? ps : 4096;
    std::uint64_t touched = 0;
    for (std::uint64_t off = 0; off < length; off += stride) {
        p[off] = 0;
        ++touched;
    }
    return touched;
}

#else // !_WIN32

std::uint64_t page_size() noexcept { return 4096; }

void* commit_pages(std::uint64_t length, std::string& err) {
    void* p = ::operator new[](length, std::nothrow);
    if (p == nullptr) { err = "commit_pages: allocation failed"; return nullptr; }
    std::memset(p, 0, length);
    err.clear();
    return p;
}

bool release_pages(void* p, std::uint64_t /*length*/, std::string& /*err*/) {
    if (p == nullptr) return true;
    ::operator delete[](p);
    return true;
}

bool virtual_lock(void* p, std::uint64_t length, std::string& err) {
    (void)p; (void)length;
    err = "virtual_lock: not supported on this platform";
    return false;
}

bool virtual_unlock(void* p, std::uint64_t length, std::string& err) {
    (void)p; (void)length; err.clear();
    return true;
}

std::uint64_t touch_range(volatile unsigned char* p, std::uint64_t length) {
    if (p == nullptr) return 0;
    const std::uint64_t stride = 4096;
    std::uint64_t touched = 0;
    for (std::uint64_t off = 0; off < length; off += stride) {
        p[off] = 0;
        ++touched;
    }
    return touched;
}

#endif // _WIN32

} // namespace windows_os
} // namespace rdmabuffer

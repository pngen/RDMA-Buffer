// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Minimal, dependency-free test framework. Deterministic: no timers, no
// watchdogs, no process-execution limits as substitutes for correctness.

#pragma once

#include <cstdio>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace testfw {

inline std::vector<std::pair<std::string, std::function<void()>>>& tests() {
    static std::vector<std::pair<std::string, std::function<void()>>> t;
    return t;
}

inline int& failures() {
    static int f = 0;
    return f;
}

inline int& pass_count() {
    static int p = 0;
    return p;
}

inline int run_all() {
    int ran = 0;
    for (auto& [name, fn] : tests()) {
        std::printf("RUN  %s\n", name.c_str());
        const int before = failures();
        fn();
        ++ran;
        if (failures() == before) {
            ++pass_count();
            std::printf("PASS %s\n", name.c_str());
        } else {
            std::printf("FAIL %s (%zu failed check(s))\n", name.c_str(),
                        static_cast<std::size_t>(failures() - before));
        }
    }
    std::printf("\n%d test(s) run, %d failed, %d passed.\n", ran, failures(), pass_count());
    return failures() == 0 ? 0 : 1;
}

struct Registrar {
    Registrar(const char* name, std::function<void()> fn) {
        tests().emplace_back(std::string(name), std::move(fn));
    }
};

} // namespace testfw

#define TEST_CASE(NAME)                                                             \
    static void NAME();                                                              \
    namespace { ::testfw::Registrar reg_##NAME(#NAME, NAME); }                      \
    static void NAME()

#define CHECK(cond)                                                                 \
    do {                                                                            \
        if (!(cond)) {                                                              \
            ++::testfw::failures();                                                 \
            std::printf("    FAIL %s:%d  CHECK(%s)\n", __FILE__, __LINE__, #cond);  \
        }                                                                           \
    } while (0)

#define REQUIRE(cond)                                                               \
    do {                                                                            \
        if (!(cond)) {                                                              \
            ++::testfw::failures();                                                 \
            std::printf("    FAIL %s:%d  REQUIRE(%s)\n", __FILE__, __LINE__, #cond);\
            return;                                                                 \
        }                                                                           \
    } while (0)

#define REQUIRE_EQ(a, b)                                                            \
    do {                                                                            \
        if (!((a) == (b))) {                                                        \
            ++::testfw::failures();                                                 \
            std::printf("    FAIL %s:%d  REQUIRE_EQ(%s, %s)\n", __FILE__, __LINE__, #a, #b); \
            return;                                                                 \
        }                                                                           \
    } while (0)

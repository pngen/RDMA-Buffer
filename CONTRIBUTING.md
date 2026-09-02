# Contributing to RDMA Buffer

Thank you for contributing to RDMA Buffer. This project manages a systems
boundary: the lifecycle and correctness of memory that is intended for
remote-access (RDMA-capable) transfer. The implementation is a vendor-neutral
C++20 runtime.

## Getting started

1. Clone the repository.
2. Configure a build directory. The portable core does not require any
   external dependency.
3. Build with the toolchain of your choice (MSVC, Clang, or GCC). C++20 is
   required.

## Build and test

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Optional feature flags (see `CMakeLists.txt`):

- `RDMABUFFER_ENABLE_CUDA`
- `RDMABUFFER_ENABLE_SYNTHETIC_RDMA`
- `RDMABUFFER_ENABLE_WINDOWS_RDMA`
- `RDMABUFFER_ENABLE_VERBS`
- `RDMABUFFER_BUILD_TESTS`
- `RDMABUFFER_BUILD_EXAMPLES`
- `RDMABUFFER_BUILD_BENCHMARKS`

The default configuration enables the synthetic and reference backends and
builds tests. CUDA and physical RDMA backends are enabled only when the
corresponding toolchain components are genuinely available.

## Engineering conventions

- C++20. Prefer strong types over primitive aliases where the code expresses a
  distinct conceptual identity. See `include/rdmabuffer/identity.hpp`.
- Do not silently coerce a value. Conversions and capability claims must be
  explicit.
- Never fabricate RDMA hardware facts. Unknown capabilities remain `UNKNOWN`.
  Synthetic backends are always labelled `SYNTHETIC`.
- Guard every lifecycle transition explicitly.
- Accounting must never go negative. Duplicate release or deregister must not
  double decrement.
- Keep the portable core dependency-free. Optional backends must not
  contaminate ordinary consumers.

## Quality bar

- Zero warnings under `/W4 /WX` (MSVC) or the equivalent strict settings of
  other compilers.
- Deterministic behavior: tests and benchmarks use fixed seeds.
- Honest reporting: measured results are separated from synthetic results.
- No test timeouts, watchdogs, or process-execution limits as substitutes for
  correctness.

## License

By contributing, you agree that your contributions are licensed under the
Apache License 2.0. See `LICENSE`.

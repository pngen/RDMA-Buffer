// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Configuration and version metadata for the RDMA Buffer runtime.

#pragma once

#ifndef RDMABUFFER_VERSION_MAJOR
#  define RDMABUFFER_VERSION_MAJOR 1
#endif
#ifndef RDMABUFFER_VERSION_MINOR
#  define RDMABUFFER_VERSION_MINOR 0
#endif
#ifndef RDMABUFFER_VERSION_PATCH
#  define RDMABUFFER_VERSION_PATCH 0
#endif

#define RDMABUFFER_VERSION_STRING "1.0.0"
#define RDMABUFFER_NAMESPACE rdmabuffer

// Vendor-neutral, boundary-only runtime. It does not replace verbs libraries,
// UCX, libfabric, NCCL, MPI, GPUDirect RDMA stacks, NIC drivers, or vendor
// transport runtimes. It governs lifecycle and correctness around registered
// transfer buffers through clean backend contracts.

namespace rdmabuffer {

// Semantic version of the public API surface.
constexpr const char* version_string() noexcept { return RDMABUFFER_VERSION_STRING; }

} // namespace rdmabuffer

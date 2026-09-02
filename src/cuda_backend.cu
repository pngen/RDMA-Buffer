// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs

#include "rdmabuffer/cuda_backend.hpp"

#include <cuda_runtime.h>
#include <cstdio>

namespace rdmabuffer {

// A real CUDA device is present. However, without a physical RDMA backend this
// runtime never claims that CUDA memory is RDMA-registerable; GPUDirect RDMA
// and RNIC registration are explicitly not asserted. Remote registration
// capability for device memory is therefore NOT_SUPPORTED (never UNKNOWN ->
// permission, and never a fabricated SUPPORTED).
CudaCapabilityProbe probe_cuda_capabilities() {
    CudaCapabilityProbe p;
    p.provenance = Provenance::REAL;

    int device_count = 0;
    if (cudaGetDeviceCount(&device_count) != cudaSuccess || device_count <= 0) {
        p.detail = "no usable CUDA device";
        p.host_pinned_remote_register = CapabilityState::UNKNOWN;
        p.device_remote_register = CapabilityState::UNKNOWN;
        p.provenance = Provenance::UNKNOWN;
        return p;
    }

    cudaDeviceProp prop{};
    if (cudaGetDeviceProperties(&prop, 0) != cudaSuccess) {
        p.detail = "cudaGetDeviceProperties failed";
        p.host_pinned_remote_register = CapabilityState::UNKNOWN;
        p.device_remote_register = CapabilityState::UNKNOWN;
        return p;
    }
    p.compute_capability_major = prop.major;
    p.compute_capability_minor = prop.minor;
    p.detail = std::string("device=") + prop.name;

    // Host pinned memory is prepared for transfer on the GPU (this is proven in
    // the proof binary), but remote registration is a distinct RNIC concern.
    p.host_pinned_remote_register = CapabilityState::NOT_SUPPORTED;
    p.device_remote_register = CapabilityState::NOT_SUPPORTED;
    return p;
}

} // namespace rdmabuffer

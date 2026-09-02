// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Optional CUDA memory-domain capability probe. When the CUDA backend is
// enabled, this reports whether CUDA host/device memory can be considered for
// remote registration. It never fabricates GPUDirect RDMA or RNIC support.

#pragma once

#include "capabilities.hpp"

#include <string>

namespace rdmabuffer {

struct CudaCapabilityProbe {
    CapabilityState host_pinned_remote_register{CapabilityState::UNKNOWN};
    CapabilityState device_remote_register{CapabilityState::UNKNOWN};
    unsigned compute_capability_major{0};
    unsigned compute_capability_minor{0};
    Provenance provenance{Provenance::UNKNOWN};
    std::string detail;
};

// Detect the CUDA device and report capability evidence. Remote registration
// is reported NOT_SUPPORTED/UNKNOWN unless a physical RDMA backend genuinely
// registered this pointer type, which is never claimed here.
CudaCapabilityProbe probe_cuda_capabilities();

} // namespace rdmabuffer

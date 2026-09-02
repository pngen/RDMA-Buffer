// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// CUDA test: real host-pinned and device memory, a tiny kernel, parity, and
// capability reporting. Kept small; the full RTX 5090 proof is the
// rdma-buffer-cuda-proof executable.

#include "test_framework.hpp"
#include "rdmabuffer/cuda_backend.hpp"
#include "rdmabuffer/rdmabuffer.hpp"
#include <cuda_runtime.h>
#include <cstring>
#include <string>

using namespace rdmabuffer;

namespace {
__global__ void scalar_kernel(int* out, int v) { out[threadIdx.x] = v; }
}

TEST_CASE(cuda_host_pinned_and_device_parity) {
    int* h = nullptr;
    REQUIRE(cudaMallocHost(&h, sizeof(int) * 4) == cudaSuccess);
    int* d = nullptr;
    REQUIRE(cudaMalloc(&d, sizeof(int) * 4) == cudaSuccess);
    const int src[4] = {1, 2, 3, 4};
    REQUIRE(cudaMemcpy(h, src, sizeof(int) * 4, cudaMemcpyHostToHost) == cudaSuccess);
    REQUIRE(cudaMemcpy(d, h, sizeof(int) * 4, cudaMemcpyHostToDevice) == cudaSuccess);
    scalar_kernel<<<1, 4>>>(d, 7);
    REQUIRE(cudaGetLastError() == cudaSuccess);
    int out[4];
    REQUIRE(cudaMemcpy(out, d, sizeof(int) * 4, cudaMemcpyDeviceToHost) == cudaSuccess);
    for (int i = 0; i < 4; ++i) CHECK(out[i] == 7);
    // Real capability report.
    CudaCapabilityProbe p = probe_cuda_capabilities();
    CHECK(p.provenance == Provenance::REAL);
    CHECK(p.device_remote_register == CapabilityState::NOT_SUPPORTED);
    REQUIRE(cudaFree(d) == cudaSuccess);
    REQUIRE(cudaFreeHost(h) == cudaSuccess);
}

int main() { return testfw::run_all(); }

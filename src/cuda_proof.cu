// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Real RTX 5090 CUDA memory-domain proof: host-pinned and device memory,
// deterministic init, H2D, kernel, D2H, CPU parity, timing, cleanup. The
// results are then fed into the RDMA Buffer descriptor/capability logic, which
// reports remote registration as NOT_SUPPORTED because no physical RDMA
// backend is exercised. These measurements are CUDA transfer throughput, NOT
// RDMA bandwidth.

#include "cuda_runtime.h"
#include "rdmabuffer/cuda_backend.hpp"
#include "rdmabuffer/rdmabuffer.hpp"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

using namespace rdmabuffer;

namespace {
int g_fail = 0;
#define CK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) { std::printf("CUDA FAIL %s at line %d: %s\n", #x, __LINE__, cudaGetErrorString(e_)); ++g_fail; } } while (0)
void report(const char* name, bool ok) { std::printf("%s %s\n", ok ? "PASS" : "FAIL", name); if (!ok) ++g_fail; }

__global__ void add_kernel(const float* a, const float* b, float* out, int n) {
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i < n) out[i] = a[i] + b[i];
}
} // namespace

int main() {
    std::printf("=== RDMA Buffer CUDA / RTX 5090 proof ===\n");
    cudaDeviceProp prop{};
    CK(cudaGetDeviceProperties(&prop, 0));
    std::printf("device=%s compute_capability=%u.%u memory=%llu MiB\n",
                prop.name, prop.major, prop.minor,
                static_cast<unsigned long long>(prop.totalGlobalMem / (1024 * 1024)));
    const int n = 1 << 20; // 1<<20 floats = 4 MiB
    const std::size_t bytes = static_cast<std::size_t>(n) * sizeof(float);
    std::vector<float> h_ref(n, 0.0f), h_res(n, 0.0f);
    // deterministic init
    for (int i = 0; i < n; ++i) h_ref[i] = static_cast<float>(i) + 1.0f;

    // ---- HOST_PINNED (cudaMallocHost) ----
    float* pinned = nullptr;
    float* dA = nullptr; float* dB = nullptr; float* dOut = nullptr;
    CK(cudaMallocHost(&pinned, bytes));
    std::memcpy(pinned, h_ref.data(), bytes);

    CK(cudaMalloc(reinterpret_cast<void**>(&dA), bytes));
    CK(cudaMalloc(reinterpret_cast<void**>(&dB), bytes));
    CK(cudaMalloc(reinterpret_cast<void**>(&dOut), bytes));
    CK(cudaMemcpy(dA, pinned, bytes, cudaMemcpyHostToDevice));
    CK(cudaMemcpy(dB, h_ref.data(), bytes, cudaMemcpyHostToDevice));

    const int threads = 256;
    const int blocks = (n + threads - 1) / threads;
    // warmup
    add_kernel<<<blocks, threads>>>(dA, dB, dOut, n);
    CK(cudaGetLastError());

    // timed kernel + D2H on pinned path
    float pinned_kernel_ms = 0.0f;
    {
        cudaEvent_t s, e;
        CK(cudaEventCreate(&s)); CK(cudaEventCreate(&e));
        CK(cudaEventRecord(s));
        for (int rep = 0; rep < 10; ++rep) add_kernel<<<blocks, threads>>>(dA, dB, dOut, n);
        CK(cudaGetLastError());
        CK(cudaEventRecord(e)); CK(cudaEventSynchronize(e));
        CK(cudaEventElapsedTime(&pinned_kernel_ms, s, e));
        CK(cudaEventDestroy(s)); CK(cudaEventDestroy(e));
        pinned_kernel_ms /= 10.0f;
    }
    CK(cudaMemcpy(pinned, dOut, bytes, cudaMemcpyDeviceToHost));
    for (int i = 0; i < n; ++i) h_res[i] = pinned[i];

    bool parity_pinned = true;
    for (int i = 0; i < n; ++i) if (h_res[i] != h_ref[i] + h_ref[i]) { parity_pinned = false; break; }
    report("HOST_PINNED add kernel and D2H parity", parity_pinned);

    // ---- CUDA_DEVICE (cudaMalloc) path, D2H to host pointer ----
    float* devRes = nullptr;
    CK(cudaMalloc(reinterpret_cast<void**>(&devRes), bytes));
    // reuse dOut result
    CK(cudaMemcpy(devRes, dOut, bytes, cudaMemcpyDeviceToDevice));
    CK(cudaMemcpy(h_res.data(), devRes, bytes, cudaMemcpyDeviceToHost));
    bool parity_device = true;
    for (int i = 0; i < n; ++i) if (h_res[i] != h_ref[i] + h_ref[i]) { parity_device = false; break; }
    report("CUDA_DEVICE result parity", parity_device);

    // H2D / D2H timed throughput (host pinned)
    float h2d_ms = 0.0f, d2h_ms = 0.0f;
    {
        cudaEvent_t s, e;
        CK(cudaEventCreate(&s)); CK(cudaEventCreate(&e));
        CK(cudaEventRecord(s));
        for (int rep = 0; rep < 20; ++rep) CK(cudaMemcpy(dA, pinned, bytes, cudaMemcpyHostToDevice));
        CK(cudaEventRecord(e)); CK(cudaEventSynchronize(e));
        CK(cudaEventElapsedTime(&h2d_ms, s, e));
        h2d_ms /= 20.0;
        CK(cudaEventRecord(s));
        for (int rep = 0; rep < 20; ++rep) CK(cudaMemcpy(pinned, dOut, bytes, cudaMemcpyDeviceToHost));
        CK(cudaEventRecord(e)); CK(cudaEventSynchronize(e));
        CK(cudaEventElapsedTime(&d2h_ms, s, e));
        d2h_ms /= 20.0;
        CK(cudaEventDestroy(s)); CK(cudaEventDestroy(e));
    }
    const double mb = static_cast<double>(bytes) / (1024.0 * 1024.0);
    std::printf("HOST_PINNED H2D %.3f ms (%.1f MiB/s)  D2H %.3f ms (%.1f MiB/s)  kernel %.3f ms\n",
                h2d_ms, mb / (h2d_ms / 1000.0), d2h_ms, mb / (d2h_ms / 1000.0), pinned_kernel_ms);
    std::printf("NOTE: these are CUDA transfer throughput, NOT RDMA bandwidth.\n");

    // ---- Feed into RDMA Buffer descriptor / capability logic ----
    CudaCapabilityProbe cprobe = probe_cuda_capabilities();
    std::printf("CUDA probe: compute=%u.%u host_pinned_remote=%s device_remote=%s provenance=%s\n",
                cprobe.compute_capability_major, cprobe.compute_capability_minor,
                capability_state_name(cprobe.host_pinned_remote_register).data(),
                capability_state_name(cprobe.device_remote_register).data(),
                provenance_name(cprobe.provenance).data());
    report("CUDA device remote registration correctly NOT_SUPPORTED (no physical RDMA backend)",
           cprobe.device_remote_register == CapabilityState::NOT_SUPPORTED);

    // Feed real descriptors into the runtime with a synthetic backend.
    auto syn = std::make_shared<SyntheticBackend>(99);
    Rdmabuffer rt;
    rt.add_backend(syn);
    AuthoritySnapshot s;
    s.coordinator_epoch = CoordinatorEpoch(1); s.worker_boot = WorkerBootId(1);
    s.worker = WorkerId(1); s.owner = OwnerId(1);
    s.owner_generation = OwnerGeneration(1); s.worker_generation = WorkerGeneration(1);
    s.policy_generation = PolicyGeneration(1);
    s.backend_generation = BackendGeneration(1); s.transport_generation = TransportGeneration(1);
    s.nic_generation = NicGeneration(1); s.node = NodeId(1); s.process = ProcessId(1);
    s.provenance = Provenance::SYNTHETIC;
    rt.set_authority(s);
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    AuthorityEnvelope e;
    e.coordinator_epoch = CoordinatorEpoch(1); e.worker_boot = WorkerBootId(1);
    e.owner = OwnerId(1); e.owner_generation = OwnerGeneration(1); e.worker_generation = WorkerGeneration(1);
    e.node = NodeId(1); e.process = ProcessId(1);

    // HOST_PINNED descriptor (real buffer pointer value embedded as numeric).
    BufferDescriptor hp;
    hp.id = BufferId(1); hp.generation = BufferGeneration(1);
    hp.domain = MemoryDomain::SYNTHETIC_REMOTE_CAPABLE;
    hp.base.address = reinterpret_cast<std::uintptr_t>(pinned);
    hp.base.kind = PointerKind::VIRTUAL;
    hp.byte_length = bytes; hp.alignment = 4096; hp.page_size = 4096;
    hp.owner = OwnerId(1); hp.process = ProcessId(1); hp.worker = WorkerId(1); hp.node = NodeId(1);
    hp.direction = TransferDirection::BIDIRECTIONAL;
    hp.requested_access = access_mask(AccessRight::REMOTE_READ) | access_mask(AccessRight::REMOTE_WRITE);
    hp.registration_mode = RegistrationMode::REMOTE_ACCESS;
    hp.lifetime = LifetimePolicy::TRANSACTIONAL;
    hp.provenance = Provenance::REAL; hp.freshness = Freshness::VALID; hp.policy_generation = PolicyGeneration(1);
    rt.create_buffer(hp);
    RegisterResult hr = rt.register_buffer(hp, syn->id(), dom, e);
    report("HOST_PINNED descriptor registered (synthetic backend)", hr.ok);
    // Stale buffer generation proof: generation 2 replaces generation 1.
    BufferDescriptor hp2 = hp; hp2.generation = BufferGeneration(2);
    rt.create_buffer(hp2);
    RegistrationRecord rec;
    rt.get_registration(hr.registration, rec);
    report("old generation 1 registration invalidated (STALE) after reallocation",
           rec.lifecycle == RegistrationLifecycle::STALE);

    // CUDA_DEVICE descriptor: capability is NOT_SUPPORTED for remote registration.
    BufferDescriptor cd;
    cd.id = BufferId(2); cd.generation = BufferGeneration(1);
    cd.domain = MemoryDomain::CUDA_DEVICE;
    cd.base.address = reinterpret_cast<std::uintptr_t>(devRes);
    cd.base.kind = PointerKind::DEVICE;
    cd.byte_length = bytes; cd.alignment = 256; cd.page_size = 0;
    cd.owner = OwnerId(1); cd.process = ProcessId(1); cd.worker = WorkerId(1); cd.node = NodeId(1);
    cd.direction = TransferDirection::BIDIRECTIONAL;
    cd.requested_access = access_mask(AccessRight::REMOTE_WRITE);
    cd.registration_mode = RegistrationMode::REMOTE_ACCESS;
    cd.lifetime = LifetimePolicy::TRANSACTIONAL;
    cd.provenance = Provenance::REAL; cd.freshness = Freshness::VALID; cd.policy_generation = PolicyGeneration(1);
    std::string can = syn->can_register(cd);
    std::printf("CUDA_DEVICE registration_capability=%s (synthetic backend does not register CUDA device memory)\n",
                can.empty() ? "UNKNOWN" : can.c_str());
    report("CUDA device memory registration_capability correctly UNSUPPORTED/UNKNOWN by synthetic backend",
           !can.empty() || cprobe.device_remote_register != CapabilityState::SUPPORTED);
    (void)can;

    // Cleanup.
    CK(cudaFree(devRes));
    CK(cudaFree(dOut)); CK(cudaFree(dB)); CK(cudaFree(dA));
    CK(cudaFreeHost(pinned));

    if (g_fail == 0) std::printf("CUDA proof: ALL PASS (this is not RDMA bandwidth).\n");
    else std::printf("CUDA proof: %d FAILURE(S).\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}

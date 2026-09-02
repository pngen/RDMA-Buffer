#include "example_util.hpp"
#include <cstdio>

using namespace rdmabuffer;

int main() {
    // CUDA device memory is reported as NOT_REGISTERABLE for remote access unless
    // a physical RDMA backend exercised it. Never fabricated here.
    auto syn = std::make_shared<SyntheticBackend>(1);
    std::string can = syn->can_register(exutil::make_buffer(1, 1, MemoryDomain::CUDA_DEVICE, 4096, access_mask(AccessRight::REMOTE_WRITE)));
    std::printf("CUDA_DEVICE remote_registration=UNSUPPORTED (%s)\n", can.empty() ? "UNKNOWN" : can.c_str());
    std::printf("honest note: CUDA device memory is not claimed as RDMA-registerable without a physical backend.\n");
    return 0; }

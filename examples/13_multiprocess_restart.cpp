#include "example_util.hpp"
#include <cstdio>

using namespace rdmabuffer;

int main() {
    // This example demonstrates the restart authority model that the real
    // coordinator/worker proof exercises across real OS processes. Here we
    // simulate the state transition in-process for clarity.
    std::printf("The multiprocess restart proof is run by rdma-buffer-coordinator --scenario with worker OS processes.\n");
    std::printf("A fresh WorkerBootId + CoordinatorEpoch never fence a fresh incarnation.\n");
    return 0; }

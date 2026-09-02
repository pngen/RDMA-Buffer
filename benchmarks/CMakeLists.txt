# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs

add_executable(rdma-buffer-benchmark benchmark_main.cpp)
target_link_libraries(rdma-buffer-benchmark PRIVATE rdmabuffer)
rdmabuffer_set_warnings(rdma-buffer-benchmark)

# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs

set(RDMABUFFER_TEST_BINARIES
  test_identity
  test_buffer_model
  test_registration
  test_access
  test_leases
  test_revocation
  test_backend
  test_persistence
  test_protocol
  test_property
  test_concurrency
  test_adversarial
  test_multiprocess
)

foreach(test_bin ${RDMABUFFER_TEST_BINARIES})
  add_executable(${test_bin} ${test_bin}.cpp)
  target_link_libraries(${test_bin} PRIVATE rdmabuffer)
  rdmabuffer_set_warnings(${test_bin})
  add_test(NAME ${test_bin} COMMAND ${test_bin})
endforeach()

if(RDMABUFFER_ENABLE_CUDA)
  add_executable(test_cuda test_cuda.cu)
  target_link_libraries(test_cuda PRIVATE rdmabuffer rdmabuffer_cuda)
  add_test(NAME test_cuda COMMAND test_cuda)
  set_tests_properties(test_cuda PROPERTIES LABELS "cuda")
endif()

# The multiprocess proof coordinates the coordinator and worker executables.
if(RDMABUFFER_BUILD_CLI)
  add_test(NAME test_multiprocess_run
           COMMAND ${CMAKE_COMMAND} -E env
             RDMABUFFER_COORD=$<TARGET_FILE:rdma-buffer-coordinator>
             RDMABUFFER_WORKER=$<TARGET_FILE:rdma-buffer-worker>
             test_multiprocess)
  set_tests_properties(test_multiprocess_run PROPERTIES DEPENDS test_multiprocess)
endif()

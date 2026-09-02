# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Summon Software Labs

set(RDMABUFFER_EXAMPLES
  01_buffer_identity
  02_host_pinned_memory
  03_registration_lifecycle
  04_registration_reuse
  05_access_rights
  06_remote_key_rotation
  07_protection_domain
  08_lease_lifecycle
  09_revocation
  10_stale_authority
  11_persistence_recovery
  12_synthetic_remote_write
  13_multiprocess_restart
  14_cuda_buffer_domains
  15_explain_access
)

foreach(ex ${RDMABUFFER_EXAMPLES})
  add_executable(${ex} ${ex}.cpp)
  target_link_libraries(${ex} PRIVATE rdmabuffer)
  rdmabuffer_set_warnings(${ex})
endforeach()

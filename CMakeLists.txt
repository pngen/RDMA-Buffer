cmake_minimum_required(VERSION 3.24)

project(RDMABuffer
  VERSION 1.0.0
  DESCRIPTION "Vendor-neutral C++20 runtime governing the lifecycle of RDMA-capable registered memory"
  LANGUAGES CXX
)

option(RDMABUFFER_ENABLE_CUDA          "Build the CUDA memory-domain backend and proof" OFF)
option(RDMABUFFER_ENABLE_SYNTHETIC_RDMA "Enable the deterministic synthetic RDMA backend" ON)
option(RDMABUFFER_ENABLE_WINDOWS_RDMA  "Enable the Windows Network Direct (ND) backend if genuinely available" OFF)
option(RDMABUFFER_ENABLE_VERBS         "Enable the verbs backend if genuinely available" OFF)
option(RDMABUFFER_BUILD_TESTS          "Build the test suite" ON)
option(RDMABUFFER_BUILD_EXAMPLES       "Build the example programs" ON)
option(RDMABUFFER_BUILD_BENCHMARKS     "Build the benchmarks" ON)
option(RDMABUFFER_BUILD_CLI            "Build the rdma-buffer CLI and coordinator/worker tools" ON)
option(RDMABUFFER_WARNINGS_AS_ERRORS   "Treat compiler warnings as errors" ON)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ---------------------------------------------------------------------------
# Warning settings
# ---------------------------------------------------------------------------
function(rdmabuffer_set_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
      target_compile_options(${target} PRIVATE /Zi)
    endif()
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
endfunction()

# ---------------------------------------------------------------------------
# Core library
# ---------------------------------------------------------------------------
set(RDMABUFFER_CORE_SOURCES
  src/registry.cpp
  src/synthetic_backend.cpp
  src/reference_backend.cpp
  src/persistence.cpp
  src/protocol.cpp
  src/crc32.cpp
  src/explain.cpp
  src/windows_os.cpp
)

add_library(rdmabuffer ${RDMABUFFER_CORE_SOURCES})
add_library(RDMABuffer::rdmabuffer ALIAS rdmabuffer)
target_include_directories(rdmabuffer
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)
target_compile_definitions(rdmabuffer PRIVATE RDMABUFFER_BUILDING_LIBRARY)
target_compile_definitions(rdmabuffer PUBLIC RDMABUFFER_VERSION_MAJOR=1 RDMABUFFER_VERSION_MINOR=0 RDMABUFFER_VERSION_PATCH=0)

if(NOT RDMABUFFER_ENABLE_SYNTHETIC_RDMA)
  target_compile_definitions(rdmabuffer PUBLIC RDMABUFFER_NO_SYNTHETIC_RDMA)
endif()

if(MSVC)
  target_compile_options(rdmabuffer PRIVATE /EHsc)
else()
  target_compile_options(rdmabuffer PRIVATE -fno-exceptions)
endif()

rdmabuffer_set_warnings(rdmabuffer)

set_target_properties(rdmabuffer PROPERTIES
  OUTPUT_NAME rdmabuffer
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
)

if(WIN32)
  target_compile_definitions(rdmabuffer PRIVATE RDMABUFFER_WINDOWS=1)
endif()

# ---------------------------------------------------------------------------
# CUDA backend (optional). Gated behind RDMABUFFER_ENABLE_CUDA.
# ---------------------------------------------------------------------------
if(RDMABUFFER_ENABLE_CUDA)
  enable_language(CUDA)
  set(CMAKE_CUDA_STANDARD 20)
  set(CMAKE_CUDA_STANDARD_REQUIRED ON)
  if(CMAKE_CUDA_COMPILER_VERSION VERSION_GREATER_EQUAL 12.8)
    set(CMAKE_CUDA_ARCHITECTURES 120)
  endif()

  find_package(CUDAToolkit REQUIRED)

  add_library(rdmabuffer_cuda src/cuda_backend.cu)
  add_library(RDMABuffer::cuda ALIAS rdmabuffer_cuda)
  target_include_directories(rdmabuffer_cuda PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  )
  target_link_libraries(rdmabuffer_cuda PUBLIC rdmabuffer CUDA::cudart)
  target_compile_definitions(rdmabuffer_cuda PUBLIC RDMABUFFER_HAS_CUDA)
  # CUDA compilation is handled by nvcc; the strict MSVC /W4 /WX sweep is applied
  # to the portable core, not to external CUDA runtime headers.

  add_executable(rdma-buffer-cuda-proof src/cuda_proof.cu)
  target_link_libraries(rdma-buffer-cuda-proof PRIVATE rdmabuffer rdmabuffer_cuda)
  target_compile_definitions(rdma-buffer-cuda-proof PRIVATE RDMABUFFER_HAS_CUDA)
endif()

# ---------------------------------------------------------------------------
# CLI / coordinator / worker tools
# ---------------------------------------------------------------------------
if(RDMABUFFER_BUILD_CLI)
  add_executable(rdma-buffer tools/rdma_buffer_cli.cpp)
  target_link_libraries(rdma-buffer PRIVATE rdmabuffer)
  rdmabuffer_set_warnings(rdma-buffer)

  add_executable(rdma-buffer-coordinator tools/coordinator.cpp)
  target_link_libraries(rdma-buffer-coordinator PRIVATE rdmabuffer)
  rdmabuffer_set_warnings(rdma-buffer-coordinator)

  add_executable(rdma-buffer-worker tools/worker.cpp)
  target_link_libraries(rdma-buffer-worker PRIVATE rdmabuffer)
  rdmabuffer_set_warnings(rdma-buffer-worker)
endif()

# ---------------------------------------------------------------------------
# Tests / examples / benchmarks
# ---------------------------------------------------------------------------
if(RDMABUFFER_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(RDMABUFFER_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(RDMABUFFER_BUILD_BENCHMARKS)
  add_subdirectory(benchmarks)
endif()

# ---------------------------------------------------------------------------
# Install / export
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

install(TARGETS rdmabuffer
  EXPORT RDMABufferTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY include/rdmabuffer
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
  FILES_MATCHING PATTERN "*.hpp"
)

install(EXPORT RDMABufferTargets
  FILE RDMABufferTargets.cmake
  NAMESPACE RDMABuffer::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/RDMABuffer
)

configure_package_config_file(
  cmake/RDMABufferConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/RDMABufferConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/RDMABuffer
)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/RDMABufferConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/RDMABufferConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/RDMABufferConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/RDMABuffer
)

set(CPACK_PACKAGE_NAME "RDMABuffer")
set(CPACK_PACKAGE_VENDOR "Summon Software Labs")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Vendor-neutral C++20 runtime for RDMA-capable registered memory")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_INSTALL_DIRECTORY "RDMABuffer")
if(WIN32)
  set(CPACK_GENERATOR "ZIP" "TGZ")
else()
  set(CPACK_GENERATOR "TGZ" "ZIP")
endif()
include(CPack)

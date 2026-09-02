// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// NIC and transport association. NIC identity and topology are modelled even
// when no physical NIC is present. Local NIC->GPU affinity is never invented;
// when unavailable it stays UNKNOWN.

#pragma once

#include "enums.hpp"
#include "generation.hpp"
#include "identity.hpp"

#include <cstdint>
#include <string_view>

namespace rdmabuffer {

struct NicDescriptor {
    NicId id;
    NodeId node;
    NicState state{NicState::UNKNOWN};
    std::uint64_t numa_node{0};  // 0 => unknown.
    std::uint64_t pcie_bus{0};
    std::uint64_t pcie_device{0};
    std::uint64_t pcie_function{0};
    Provenance provenance{Provenance::UNKNOWN};
    NicGeneration generation;
    CapabilityState rdma_capable{CapabilityState::UNKNOWN};
    CapabilityState gpu_affinity_known{CapabilityState::UNKNOWN}; // never invented.
    CapabilityState link_up{CapabilityState::UNKNOWN};
};

struct TransportDescriptor {
    TransportId id;
    TransportClass class_{TransportClass::UNKNOWN};
    BackendId backend;
    NicId nic;
    TransportGeneration generation;
    Provenance provenance{Provenance::UNKNOWN};
    CapabilityState one_sided{CapabilityState::UNKNOWN};
    CapabilityState reliable{CapabilityState::UNKNOWN};
};

struct NicCapabilityInfo {
    CapabilityState rdma{CapabilityState::UNKNOWN};
    CapabilityState gpu_affinity{CapabilityState::UNKNOWN};
    std::string description;
};

} // namespace rdmabuffer

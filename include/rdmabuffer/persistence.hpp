// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Versioned binary persistence. Persists logical metadata, never live OS
// pointers or live registration handles as authoritative. Recovery marks
// registrations REVALIDATION_REQUIRED; key material and handles are not
// restored as live.

#pragma once

#include "accounting.hpp"
#include "authority.hpp"
#include "buffer_model.hpp"
#include "capabilities.hpp"
#include "enums.hpp"
#include "generation.hpp"
#include "identity.hpp"
#include "registration.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace rdmabuffer {

// A logical snapshot of everything that is legal to persist.
struct PersistableState {
    std::uint32_t format_version{1};

    std::vector<BufferDescriptor> buffers;
    std::vector<RegistrationRecord> registrations;
    std::vector<ProtectionDomainId> domains;
    std::vector<RemoteKey> remote_key_history;
    std::vector<LocalKey> local_key_history;
    std::vector<std::string> revocation_history;
    Accounting accounting_summary;
    std::vector<BackendInfo> backend_capability_snapshot;
    AuthoritySnapshot authority_snapshot;
    PolicyGeneration policy_generation;
};

namespace persistence {

constexpr std::uint32_t format_magic = 0x52444D31u; // "RDM1"
constexpr std::uint32_t format_version = 1u;

// Deterministic serialization of the state into a bounded binary encoding with
// a CRC-32 trailer and a semantic digest string.
std::vector<std::uint8_t> serialize(const PersistableState& state);

// Parse with strict bounds/validation. On failure err is populated.
bool parse(std::span<const std::uint8_t> bytes, PersistableState& state, std::string& err);

// Stable semantic digest over the logical content; independent of binary
// layout, usable to prove deterministic round-trips.
std::string semantic_digest(const PersistableState& state);

} // namespace persistence

} // namespace rdmabuffer

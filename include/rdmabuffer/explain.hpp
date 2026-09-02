// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Explanation API. Every decision the runtime makes is explainable in terms of
// identity, generation, incarnation, capability, and provenance.

#pragma once

#include "accounting.hpp"
#include "buffer_model.hpp"
#include "capabilities.hpp"
#include "registration.hpp"
#include "transfer.hpp"

#include <string>
#include <string_view>

namespace rdmabuffer {

std::string explain_registration(const RegistrationRecord& reg);

std::string explain_reuse(const BufferDescriptor& requested,
                          const RegistrationRecord& candidate,
                          bool reusable,
                          std::string_view miss_reason);

std::string explain_remote_access(const RemoteAccessRequest& request,
                                  const AccessDecision& decision);

std::string explain_revocation(const RegistrationRecord& reg,
                               RevocationMode mode,
                               bool keys_invalidated);

std::string explain_recovery(const RegistrationRecord& recovered,
                             const AuthoritySnapshot& now);

std::string explain_backend_capability(const BackendCapabilities& caps,
                                       MemoryDomain domain,
                                       AccessMask requested_rights);

std::string explain_protection_domain(ProtectionDomainId id,
                                      MemoryDomain domain,
                                      bool reusable_under_same_domain);

} // namespace rdmabuffer

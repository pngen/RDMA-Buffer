// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// Authority model. Authority is incarnation-scoped: a generation is only
// authoritative when it is bound to the current CoordinatorEpoch and current
// WorkerBootId. This header defines the envelope, the current authority
// snapshot, and the verdict type returned by access validation.

#pragma once

#include "config.hpp"
#include "enums.hpp"
#include "generation.hpp"
#include "identity.hpp"

#include <string>
#include <string_view>

namespace rdmabuffer {

// The set of generation facts carried by the runtime that describe "now".
struct AuthoritySnapshot {
    CoordinatorEpoch coordinator_epoch;
    WorkerBootId worker_boot;
    WorkerId worker;
    OwnerId owner;
    OwnerGeneration owner_generation;
    WorkerGeneration worker_generation;
    PolicyGeneration policy_generation;
    BackendGeneration backend_generation;
    TransportGeneration transport_generation;
    NicGeneration nic_generation;
    NodeId node;
    ProcessId process;
    Provenance provenance{Provenance::UNKNOWN};
};

// The authority facts supplied by a caller and checked against the snapshot.
struct AuthorityEnvelope {
    CoordinatorEpoch coordinator_epoch;
    WorkerBootId worker_boot;
    OwnerId owner;
    OwnerGeneration owner_generation;
    WorkerGeneration worker_generation;
    NodeId node;
    ProcessId process;
};

// A verdict for any authorization query.
struct AccessDecision {
    AccessOutcome outcome{AccessOutcome::REJECT_UNKNOWN_CAPABILITY};
    std::string code;
    std::string explanation;
};

inline AccessDecision make_decision(AccessOutcome outcome, std::string explanation) {
    AccessDecision d;
    d.outcome = outcome;
    d.code = std::string(access_outcome_name(outcome));
    d.explanation = std::move(explanation);
    return d;
}

namespace detail {

// A generation + its incarnation are current only when the incarnation matches
// AND the stored generation equals the current generation. A numerically larger
// generation under a stale incarnation is rejected, never trusted.
inline bool incarnation_matches(const AuthoritySnapshot& snap, WorkerBootId boot) noexcept {
    return boot.is_valid() && snap.worker_boot == boot;
}

} // namespace detail

// ---------------------------------------------------------------------------
// Explicit, incarnation-scoped currentness checks.
// ---------------------------------------------------------------------------
inline bool authority_current(const AuthoritySnapshot& snap, const AuthorityEnvelope& env) noexcept {
    if (!detail::incarnation_matches(snap, env.worker_boot)) return false;
    if (!snap.coordinator_epoch.is_valid() || snap.coordinator_epoch != env.coordinator_epoch) return false;
    return true;
}

inline bool boot_current(const AuthoritySnapshot& snap, WorkerBootId boot) noexcept {
    return detail::incarnation_matches(snap, boot);
}

inline bool owner_current(const AuthoritySnapshot& snap, const AuthorityEnvelope& env) noexcept {
    return snap.owner.is_valid() && snap.owner == env.owner &&
           snap.owner_generation.is_valid() && snap.owner_generation == env.owner_generation;
}

// The complete currentness predicate with typed rejection. Returns ALLOW only
// when every authority fact is current; otherwise the precise stale class.
inline AccessDecision validate_authority(const AuthoritySnapshot& snap, const AuthorityEnvelope& env) {
    if (!env.coordinator_epoch.is_valid() || !snap.coordinator_epoch.is_valid() ||
        env.coordinator_epoch != snap.coordinator_epoch) {
        return make_decision(AccessOutcome::REJECT_STALE_EPOCH,
            "CoordinatorEpoch mismatch: request " + std::to_string(env.coordinator_epoch.value()) +
            " is not current " + std::to_string(snap.coordinator_epoch.value()) + ".");
    }
    if (!env.worker_boot.is_valid() || !snap.worker_boot.is_valid() || env.worker_boot != snap.worker_boot) {
        return make_decision(AccessOutcome::REJECT_STALE_BOOT,
            "WorkerBootId is stale or absent; authority is incarnation-scoped.");
    }
    if (!env.owner.is_valid() || !snap.owner.is_valid() || env.owner != snap.owner) {
        return make_decision(AccessOutcome::REJECT_PERMISSION,
            "Owner is not current for this authority snapshot.");
    }
    if (env.owner_generation.is_valid() && snap.owner_generation.is_valid() &&
        env.owner_generation != snap.owner_generation) {
        return make_decision(AccessOutcome::REJECT_PERMISSION,
            "OwnerGeneration mismatch; owner authority has been reissued.");
    }
    if (env.worker_generation.is_valid() && snap.worker_generation.is_valid() &&
        env.worker_generation != snap.worker_generation) {
        return make_decision(AccessOutcome::REJECT_PERMISSION,
            "WorkerGeneration mismatch; worker incarnation has been reissued.");
    }
    if (!env.node.is_valid() || !snap.node.is_valid() || env.node != snap.node) {
        return make_decision(AccessOutcome::REJECT_PERMISSION,
            "Node identity mismatch.");
    }
    return make_decision(AccessOutcome::ALLOW, "Authority is current.");
}

} // namespace rdmabuffer

#include "example_util.hpp"
#include <cstdio>

using namespace rdmabuffer;

int main() {
    auto syn = std::make_shared<SyntheticBackend>(1);
    Rdmabuffer rt; rt.add_backend(syn); rt.set_authority(exutil::snapshot(1, 1));
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    auto d = exutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096,
                                 access_mask(AccessRight::REMOTE_WRITE));
    rt.create_buffer(d);
    RegisterResult r = rt.register_buffer(d, syn->id(), dom, exutil::envelope(1, 1));
    RemoteAccessRequest q; q.source_registration = r.registration; q.offset = 0; q.length = 4;
    q.kind = OperationKind::WRITE; q.required_rights = access_mask(AccessRight::REMOTE_WRITE);
    q.expected_buffer_generation = BufferGeneration(1); q.expected_registration_generation = RegistrationGeneration(1);
    q.expected_remote_key_generation = RemoteKeyGeneration(1);
    q.authority = exutil::envelope(99, 1); q.domain = dom; q.backend = syn->id(); q.node = NodeId(1); q.process = ProcessId(1);
    AccessDecision ad = rt.validate_remote_access(q);
    std::printf("stale authority access=%s explanation=%s\n", ad.code.c_str(), ad.explanation.c_str());
    return 0; }

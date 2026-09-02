#include "example_util.hpp"
#include <cstdio>

using namespace rdmabuffer;

int main() {
    auto syn = std::make_shared<SyntheticBackend>(7);
    Rdmabuffer rt; rt.add_backend(syn); rt.set_authority(exutil::snapshot());
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    auto d = exutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096,
                                 access_mask(AccessRight::REMOTE_WRITE));
    rt.create_buffer(d);
    RegisterResult r = rt.register_buffer(d, syn->id(), dom, exutil::envelope());
    std::string ex; std::uint64_t delta = 0;
    AccessOutcome o = syn->simulate_remote(OperationKind::WRITE, 0, 64, 1, ex, delta);
    std::printf("synthetic remote write=%s delta=%llu provenance=SYNTHETIC (%s)\n",
                access_outcome_name(o).data(), (unsigned long long)delta, ex.c_str());
    return 0; }

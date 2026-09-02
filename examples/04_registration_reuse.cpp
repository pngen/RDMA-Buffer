#include "example_util.hpp"
#include <cstdio>

using namespace rdmabuffer;

int main() {
    auto syn = std::make_shared<SyntheticBackend>(1);
    Rdmabuffer rt; rt.add_backend(syn); rt.set_authority(exutil::snapshot());
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    auto d = exutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096,
                                 access_mask(AccessRight::REMOTE_WRITE));
    rt.create_buffer(d);
    rt.register_buffer(d, syn->id(), dom, exutil::envelope());
    RegisterResult reuse = rt.register_buffer_reuse(d, syn->id(), dom, exutil::envelope());
    std::printf("reuse=%s explanation=%s\n", reuse.ok ? "REUSE_HIT" : "REUSE_MISS", reuse.explanation.c_str());
    // Bumped generation must be a miss.
    auto d2 = d; d2.generation = BufferGeneration(2);
    RegisterResult miss = rt.register_buffer_reuse(d2, syn->id(), dom, exutil::envelope());
    std::printf("bumped generation reuse=%s explanation=%s\n", miss.ok ? "REUSE_HIT" : "REUSE_MISS", miss.explanation.c_str());
    return 0; }

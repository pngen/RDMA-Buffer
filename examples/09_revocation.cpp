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
    RegisterResult r = rt.register_buffer(d, syn->id(), dom, exutil::envelope());
    RevokeResult rz = rt.revoke(r.registration, RevocationMode::HARD_REVOKE);
    std::printf("hard revoke ok=%d keys=%d lifecycle=%s explanation=%s\n", (int)rz.ok, (int)rz.keys_invalidated,
                lifecycle_name(rz.lifecycle).data(), rz.explanation.c_str());
    return 0; }

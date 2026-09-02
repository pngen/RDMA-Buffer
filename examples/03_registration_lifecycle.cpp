#include "example_util.hpp"
#include <cstdio>

using namespace rdmabuffer;

int main() {
    auto syn = std::make_shared<SyntheticBackend>(1);
    Rdmabuffer rt; rt.add_backend(syn); rt.set_authority(exutil::snapshot());
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    auto d = exutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096,
                                 access_mask(AccessRight::REMOTE_READ) | access_mask(AccessRight::REMOTE_WRITE));
    rt.create_buffer(d);
    RegisterResult r = rt.register_buffer(d, syn->id(), dom, exutil::envelope());
    RegistrationRecord rec;
    rt.get_registration(r.registration, rec);
    std::printf("lifecycle: %s freshness=%s provenance=%s\n", lifecycle_name(rec.lifecycle).data(),
                freshness_name(rec.freshness).data(), provenance_name(rec.provenance).data());
    return r.ok ? 0 : 1; }

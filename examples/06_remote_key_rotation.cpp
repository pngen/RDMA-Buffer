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
    RegistrationRecord before; rt.get_registration(r.registration, before);
    std::string ex; rt.rotate_key(r.registration, ex);
    RegistrationRecord after; rt.get_registration(r.registration, after);
    std::printf("key generation %llu -> %llu (old key now stale)\n",
                (unsigned long long)before.remote_key.key_generation.value(),
                (unsigned long long)after.remote_key.key_generation.value());
    std::printf("%s\n", ex.c_str());
    return 0; }

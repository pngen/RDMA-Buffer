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
    LeaseAcquireResult lr = rt.acquire_lease(r.registration, exutil::envelope(), access_mask(AccessRight::REMOTE_WRITE));
    std::printf("lease acquired=%d count=%llu\n", (int)lr.ok, (unsigned long long)rt.accounting().active_leases.get());
    rt.release_lease(lr.lease.id);
    std::printf("lease released count=%llu duplicate=%d\n", (unsigned long long)rt.accounting().active_leases.get(),
                (int)rt.release_lease(lr.lease.id));
    return 0; }

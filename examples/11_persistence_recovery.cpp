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
    std::string err; rt.save("rdma-buffer-example.bin", err);
    // Recover into a fresh runtime.
    Rdmabuffer rt2; rt2.add_backend(syn); rt2.set_authority(exutil::snapshot());
    RecoveryReport rep; std::string rerr;
    rt2.recover("rdma-buffer-example.bin", rerr, rep);
    bool any = false;
    for (auto rid : rt2.registrations()) {
        RegistrationRecord rec; if (rt2.get_registration(rid, rec)) { any = true;
            std::printf("recovered registration lifecycle=%s freshness=%s (not live)\n",
                        lifecycle_name(rec.lifecycle).data(), freshness_name(rec.freshness).data()); }
    }
    std::printf("recovered registrations=%llu any=%d\n", (unsigned long long)rep.recovered_registrations, (int)any);
    return 0; }

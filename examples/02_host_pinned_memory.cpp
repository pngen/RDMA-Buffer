#include "example_util.hpp"
#include <cstdio>

using namespace rdmabuffer;

int main() {
    // Reference backend probes real host-pinned memory preparation (no RNIC).
    ReferenceBackend ref;
    PinProbeResult p = ref.probe_host_pinning(0, 1u << 20);
    std::printf("host-pin probe: ok=%d committed=%d locked=%d bytes=%llu provenance=%s detail=%s\n",
                (int)p.ok, (int)p.allocation_committed, (int)p.locked,
                (unsigned long long)p.bytes, provenance_name(p.provenance).data(), p.detail.c_str());
    std::printf("honest note: host pinning proves memory preparation, not RNIC registration.\n");
    return 0; }

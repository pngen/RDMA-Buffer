#include "example_util.hpp"
#include <cstdio>

using namespace rdmabuffer;

int main() {
    // Strong, non-interchangeable identities and incarnations.
    BufferId b(7); RegistrationId r(7);
    std::printf("BufferId=7 RegistrationId(7) equal types=%d interchangeable=%d\n",
                (int)std::is_same_v<BufferId, RegistrationId>, (int)std::is_convertible_v<RegistrationId, BufferId>);
    std::printf("buffer generation 7 < 8: %d\n", (int)generation_newer(BufferGeneration(8), BufferGeneration(7)));
    std::printf("authority is incarnation-scoped: fresh boot must never be fenced by a stale boot's higher generation.\n");
    return 0; }

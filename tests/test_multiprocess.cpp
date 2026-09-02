
#define _CRT_SECURE_NO_WARNINGS
#include "test_framework.hpp"
#include "rdmabuffer/protocol.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

using namespace rdmabuffer;

TEST_CASE(protocol_framing_smoke) {
    auto p = protocol::payload_string("probe");
    auto f = protocol::encode_frame(protocol::MessageKind::HELLO, 1, p);
    CHECK(!f.empty());
    protocol::Frame out; std::size_t consumed; std::string err;
    CHECK(protocol::decode_frame(f, out, consumed, err));
    CHECK(out.kind == protocol::MessageKind::HELLO);
}

#ifdef _WIN32
#include <windows.h>
#include <process.h>

static std::string normalize_slash(std::string s) { for (auto& c : s) if (c == '/') c = '\\'; return s; }

static bool run_coordinator_scenario(const std::string& coordExe, const std::string& workerExe) {
    // Use a proof file: the coordinator writes its proof log there. The
    // coordinator also spawns worker processes, so reading stdout through a
    // pipe would block on a held child; the file avoids that entirely.
    char tmp[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, tmp);
    std::string proof = std::string(tmp) + "rdma_buffer_mp_proof.txt";
    std::remove(proof.c_str());

    const std::string cmd = "\"" + normalize_slash(coordExe) + "\" --port 39123 --scenario --worker \"" + normalize_slash(workerExe) + "\" --proof \"" + normalize_slash(proof) + "\"";
    STARTUPINFOA si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::vector<char> cl(cmd.begin(), cmd.end()); cl.push_back('\0');
    if (!CreateProcessA(nullptr, cl.data(), nullptr, nullptr, TRUE, 0, nullptr, nullptr, &si, &pi)) {
        std::printf("multiprocess: CreateProcess failed (%lu)\n", (unsigned long)GetLastError());
        return false;
    }
    WaitForSingleObject(pi.hProcess, 15000);
    DWORD rc = 0;
    GetExitCodeProcess(pi.hProcess, &rc);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // Read the proof file.
    std::string out;
    if (FILE* f = std::fopen(proof.c_str(), "rb")) {
        char buf[4096];
        std::size_t n = 0;
        while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) out.append(buf, n);
        std::fclose(f);
    }
    std::printf("%s", out.c_str());
    std::printf("multiprocess coordinator exit=%lu\n", (unsigned long)rc);
    if (rc != 0) return false;
    if (out.find("PROOF-FAIL") != std::string::npos) return false;
    if (out.find("PROOF-PASS") == std::string::npos) return false;
    return true;
}

TEST_CASE(multiprocess_authority_proof) {
    const char* coord = std::getenv("RDMABUFFER_COORD");
    const char* worker = std::getenv("RDMABUFFER_WORKER");
    if (!coord || !worker) {
        std::printf("RDMABUFFER_COORD / WORKER not set; skipping real multiprocess proof.\n");
        return;
    }
    CHECK(run_coordinator_scenario(coord, worker));
}
#endif

int main() { return testfw::run_all(); }

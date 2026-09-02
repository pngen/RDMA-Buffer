// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Summon Software Labs
//
// rdma-buffer-worker: a real OS process that connects to the coordinator over
// framed TCP, receives a fresh WorkerBootId, and performs a bounded command
// (register or access) on the coordinator's authoritative runtime.

#include "rdmabuffer/codec.hpp"
#include "rdmabuffer/protocol.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define RDB_SOCKET SOCKET
#define RDB_INVALID INVALID_SOCKET
#define RDB_CLOSESOCK closesocket
#else
// Portable fallback is intentionally limited; the proof runs on Windows.
#define RDB_SOCKET int
#define RDB_INVALID (-1)
#define RDB_CLOSESOCK(c) ::close(c)
#endif

using namespace rdmabuffer;

namespace {

bool recv_all(RDB_SOCKET s, std::uint8_t* p, int n) {
    int got = 0;
    while (got < n) {
        int r = ::recv(s, reinterpret_cast<char*>(p + got), n - got, 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

bool send_all(RDB_SOCKET s, const std::uint8_t* p, int n) {
    int sent = 0;
    while (sent < n) {
        int r = ::send(s, reinterpret_cast<const char*>(p + sent), n - sent, 0);
        if (r <= 0) return false;
        sent += r;
    }
    return true;
}

bool send_frame(RDB_SOCKET s, protocol::MessageKind k, std::uint64_t seq,
                std::span<const std::uint8_t> payload) {
    auto f = protocol::encode_frame(k, seq, payload);
    if (f.empty()) return false;
    return send_all(s, f.data(), static_cast<int>(f.size()));
}

bool recv_frame(RDB_SOCKET s, std::uint64_t& seq, protocol::MessageKind& kind,
                std::vector<std::uint8_t>& payload, std::string& err) {
    // Read header then exact frame.
    std::vector<std::uint8_t> hdr(protocol::header_size);
    if (!recv_all(s, hdr.data(), static_cast<int>(protocol::header_size))) { err = "eof"; return false; }
    std::uint32_t magic = 0, ver = 0, kindu = 0;
    std::uint64_t len = 0;
    std::size_t p = 0;
    auto get32 = [&](std::uint32_t& x) { x = 0; for (int i = 0; i < 4; ++i) x |= static_cast<std::uint32_t>(hdr[p++]) << (8 * i); };
    auto get64 = [&](std::uint64_t& x) { x = 0; for (int i = 0; i < 8; ++i) x |= static_cast<std::uint64_t>(hdr[p++]) << (8 * i); };
    get32(magic); get32(ver); get32(kindu); get64(seq); get64(len);
    if (magic != protocol::frame_magic || ver != protocol::frame_version || len > protocol::max_payload) { err = "badheader"; return false; }
    std::vector<std::uint8_t> body(len);
    if (!recv_all(s, body.data(), static_cast<int>(len))) { err = "eof"; return false; }
    std::vector<std::uint8_t> trailer(4);
    if (!recv_all(s, trailer.data(), 4)) { err = "eof"; return false; }
    // Reassemble and decode through the parser for full validation.
    std::vector<std::uint8_t> frame = hdr;
    frame.insert(frame.end(), body.begin(), body.end());
    frame.insert(frame.end(), trailer.begin(), trailer.end());
    protocol::Frame out;
    std::size_t consumed = 0;
    if (!protocol::decode_frame(frame, out, consumed, err)) return false;
    kind = out.kind;
    seq = out.seq;
    payload = out.payload;
    return true;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 4) {
        std::printf("worker <host> <port> <role> [reg boot keygen opkind]\n");
        return 2;
    }
#ifdef _WIN32
    WSADATA wsa; WSAStartup(MAKEWORD(2, 2), &wsa);
#endif
    const std::string host = argv[1];
    const int port = std::atoi(argv[2]);
    const std::string role = argv[3];

    RDB_SOCKET s = ::socket(AF_INET, SOCK_STREAM, 0);
    if (s == RDB_INVALID) { std::printf("worker: socket failed\n"); return 1; }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<u_short>(port));
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    if (::connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        std::printf("worker: connect failed\n");
        RDB_CLOSESOCK(s);
        return 1;
    }

    std::string err;
    std::vector<std::uint8_t> payload;
    std::uint64_t seq = 0;
    protocol::MessageKind kind = protocol::MessageKind::UNKNOWN;

    // HELLO
    if (!send_frame(s, protocol::MessageKind::HELLO, 1, wire::encode_hello(role))) { std::printf("worker: hello send failed\n"); return 1; }
    if (!recv_frame(s, seq, kind, payload, err) || kind != protocol::MessageKind::HELLO_ACK) {
        std::printf("worker: hello ack failed (%s)\n", err.c_str());
        return 3;
    }
    std::uint64_t boot = 0, epoch = 0, node = 0;
    wire::decode_hello_ack(payload, boot, epoch, node);
    std::printf("WORKER %s BOOT %llu EPOCH %llu NODE %llu\n", role.c_str(),
                static_cast<unsigned long long>(boot), static_cast<unsigned long long>(epoch),
                static_cast<unsigned long long>(node));

    if (role == "register" || role == "register-hold" || role == "register-fresh") {
        BufferDescriptor d;
        d.id = BufferId(1);
        d.generation = BufferGeneration(1);
        d.domain = MemoryDomain::SYNTHETIC_REMOTE_CAPABLE;
        d.base.address = 0x1000;
        d.base.kind = PointerKind::SYNTHETIC;
        d.byte_length = 4096;
        d.alignment = 4096;
        d.page_size = 4096;
        d.owner = OwnerId(1);
        d.process = ProcessId(1);
        d.worker = WorkerId(1);
        d.node = NodeId(1);
        d.direction = TransferDirection::BIDIRECTIONAL;
        d.requested_access = access_mask(AccessRight::REMOTE_READ) | access_mask(AccessRight::REMOTE_WRITE);
        d.registration_mode = RegistrationMode::REMOTE_ACCESS;
        d.lifetime = LifetimePolicy::TRANSACTIONAL;
        d.provenance = Provenance::SYNTHETIC;
        d.freshness = Freshness::VALID;
        d.policy_generation = PolicyGeneration(1);
        if (!send_frame(s, protocol::MessageKind::REGISTER_BUFFER, 2, wire::encode_register(d, 1, 0))) {
            std::printf("worker: register send failed\n"); return 1;
        }
        // read ack
        std::vector<std::uint8_t> ackp;
        if (!recv_frame(s, seq, kind, ackp, err) || kind != protocol::MessageKind::REGISTER_BUFFER_ACK) {
            std::printf("worker: register ack failed (%s)\n", err.c_str()); return 4;
        }
        bool ok = false; std::uint64_t reg = 0, keygen = 0; std::string msg;
        wire::decode_register_ack(ackp, ok, reg, keygen, msg);
        std::printf("WORKER %s REGISTERED reg=%llu keygen=%llu ok=%d msg=%s\n", role.c_str(),
                    static_cast<unsigned long long>(reg), static_cast<unsigned long long>(keygen), ok ? 1 : 0, msg.c_str());
        // For register-hold: stay alive (silently) until the coordinator kills
        // this OS process.
        if (role == "register-hold") {
            for (;;) { std::this_thread::sleep_for(std::chrono::seconds(1)); }
        }
        return ok ? 0 : 5;
    }

    if (role == "access") {
        // args: reg, boot, keygen, op_kind
        const std::uint64_t reg = argc > 4 ? std::strtoull(argv[4], nullptr, 10) : 1;
        const std::uint64_t bootarg = argc > 5 ? std::strtoull(argv[5], nullptr, 10) : boot;
        const std::uint64_t keygen = argc > 6 ? std::strtoull(argv[6], nullptr, 10) : 1;
        const std::uint64_t opkind = argc > 7 ? std::strtoull(argv[7], nullptr, 10) : 1; // WRITE
        auto p = wire::encode_access(reg, 0, 4, opkind, access_mask(AccessRight::REMOTE_WRITE), bootarg, keygen);
        if (!send_frame(s, protocol::MessageKind::REQUEST_ACCESS, 3, p)) { std::printf("worker: access send failed\n"); return 1; }
        protocol::MessageKind ackkind = protocol::MessageKind::UNKNOWN;
        std::vector<std::uint8_t> ap;
        if (!recv_frame(s, seq, ackkind, ap, err) || ackkind != protocol::MessageKind::REQUEST_ACCESS_ACK) {
            std::printf("worker: access ack failed (%s)\n", err.c_str()); return 6;
        }
        std::uint8_t outcome = 0; std::string msg;
        wire::decode_access_ack(ap, outcome, msg);
        std::printf("WORKER %s ACCESS outcome=%u msg=%s\n", role.c_str(), static_cast<unsigned>(outcome), msg.c_str());
        return 0;
    }

    RDB_CLOSESOCK(s);
    return 0;
}

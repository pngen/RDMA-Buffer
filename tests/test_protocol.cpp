
#include "test_framework.hpp"
#include "rdmabuffer/rdmabuffer.hpp"
#include <vector>
#include <string>

using namespace rdmabuffer;
namespace proto = rdmabuffer::protocol;

static void put32(std::vector<std::uint8_t>& v, std::uint32_t x) {
    for (int i = 0; i < 4; ++i) v.push_back(static_cast<std::uint8_t>((x >> (8 * i)) & 0xFF));
}
static void put64(std::vector<std::uint8_t>& v, std::uint64_t x) {
    for (int i = 0; i < 8; ++i) v.push_back(static_cast<std::uint8_t>((x >> (8 * i)) & 0xFF));
}

TEST_CASE(frame_round_trip) {
    auto payload = proto::payload_string("hello rdma-buffer");
    auto frame = proto::encode_frame(proto::MessageKind::HELLO, 7, payload);
    CHECK(!frame.empty());
    proto::Frame out;
    std::size_t consumed = 0;
    std::string err;
    CHECK(proto::decode_frame(frame, out, consumed, err));
    CHECK(err.empty());
    CHECK(consumed == frame.size());
    CHECK(out.kind == proto::MessageKind::HELLO);
    CHECK(out.seq == 7);
    std::string s;
    CHECK(proto::parse_payload_string(out.payload, s));
    CHECK(s == "hello rdma-buffer");
}

TEST_CASE(bad_magic_rejected) {
    auto frame = proto::encode_frame(proto::MessageKind::OK, 1, {});
    frame[0] = 0x00; frame[1] = 0x00; frame[2] = 0x00; frame[3] = 0x00;
    proto::Frame out; std::size_t consumed; std::string err;
    CHECK(!proto::decode_frame(frame, out, consumed, err));
    CHECK(err == "BAD_MAGIC");
}

TEST_CASE(bad_version_rejected) {
    auto frame = proto::encode_frame(proto::MessageKind::OK, 1, {});
    frame[4] = 0x00; frame[5] = 0x00; frame[6] = 0x00; frame[7] = 0x00;
    proto::Frame out; std::size_t consumed; std::string err;
    CHECK(!proto::decode_frame(frame, out, consumed, err));
    CHECK(err == "BAD_VERSION");
}

TEST_CASE(invalid_enum_rejected) {
    auto frame = proto::encode_frame(proto::MessageKind::OK, 1, {});
    // kind at bytes 8..11
    frame[8] = 0xFF; frame[9] = 0xFF; frame[10] = 0xFF; frame[11] = 0xFF;
    proto::Frame out; std::size_t consumed; std::string err;
    CHECK(!proto::decode_frame(frame, out, consumed, err));
    CHECK(err == "INVALID_ENUM");
}

TEST_CASE(truncation_rejected) {
    auto frame = proto::encode_frame(proto::MessageKind::HELLO, 1, proto::payload_string("data"));
    frame.resize(frame.size() - 2);
    proto::Frame out; std::size_t consumed; std::string err;
    CHECK(!proto::decode_frame(frame, out, consumed, err));
    CHECK(err == "TRUNCATED" || err == "CHECKSUM_MISMATCH");
}

TEST_CASE(checksum_mismatch_rejected) {
    auto frame = proto::encode_frame(proto::MessageKind::HELLO, 1, proto::payload_string("data"));
    frame[frame.size() / 2] ^= 0x11;
    proto::Frame out; std::size_t consumed; std::string err;
    CHECK(!proto::decode_frame(frame, out, consumed, err));
    CHECK(err == "CHECKSUM_MISMATCH");
}

TEST_CASE(oversized_rejected) {
    std::vector<std::uint8_t> frame;
    put32(frame, proto::frame_magic);
    put32(frame, proto::frame_version);
    put32(frame, static_cast<std::uint32_t>(proto::MessageKind::OK));
    put64(frame, 1);
    put64(frame, proto::max_payload + 1); // oversized length
    proto::Frame out; std::size_t consumed; std::string err;
    CHECK(!proto::decode_frame(frame, out, consumed, err));
    CHECK(err == "OVERSIZED");
}

TEST_CASE(trailing_garbage_detected_by_consumer) {
    auto frame = proto::encode_frame(proto::MessageKind::OK, 1, {});
    std::vector<std::uint8_t> stream = frame;
    stream.push_back(0xDE); stream.push_back(0xAD);
    proto::Frame out; std::size_t consumed; std::string err;
    CHECK(proto::decode_frame(stream, out, consumed, err));
    CHECK(consumed == frame.size());
    CHECK(consumed < stream.size()); // consumer rejects trailing garbage
    // Decoding the remaining bytes fails.
    std::span<const std::uint8_t> rest(stream.data() + consumed, stream.size() - consumed);
    proto::Frame out2; std::size_t consumed2; std::string err2;
    CHECK(!proto::decode_frame(rest, out2, consumed2, err2));
}

int main() { return testfw::run_all(); }

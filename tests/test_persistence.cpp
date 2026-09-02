
#include "test_framework.hpp"
#include "rdmabuffer/rdmabuffer.hpp"
#include "test_util.hpp"
#include <cstring>
#include <memory>
#include <string>
#include <vector>

using namespace rdmabuffer;

static PersistableState make_state() {
    PersistableState s;
    s.policy_generation = PolicyGeneration(2);
    s.authority_snapshot = testutil::make_snapshot(1, 3, 1, 1, 1, 1);
    auto d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                    AccessRight::REMOTE_WRITE);
    s.buffers.push_back(d);
    RegistrationRecord rec;
    rec.id = RegistrationId(9);
    rec.buffer_id = d.id;
    rec.buffer_generation = d.generation;
    rec.registration_generation = RegistrationGeneration(1);
    rec.descriptor = d;
    rec.backend = BackendId(0x53594E54);
    rec.domain = MemoryDomain::SYNTHETIC_REMOTE_CAPABLE;
    rec.start = d.base.address; rec.length = d.byte_length;
    rec.granted_access = d.requested_access;
    rec.remote_key.id = RemoteKeyId(100);
    rec.remote_key.key_generation = RemoteKeyGeneration(1);
    rec.provenance = Provenance::SYNTHETIC;
    rec.freshness = Freshness::VALID;
    rec.lifecycle = RegistrationLifecycle::ACTIVE;
    s.registrations.push_back(rec);
    s.domains.push_back(ProtectionDomainId(5));
    s.remote_key_history.push_back(rec.remote_key);
    s.local_key_history.push_back(rec.local_key);
    s.accounting_summary.active_registrations.increment();
    s.accounting_summary.registered_bytes.increment(4096);
    BackendInfo bi;
    bi.id = BackendId(0x53594E54); bi.name = "synthetic-rdma";
    bi.provenance = Provenance::SYNTHETIC;
    bi.capabilities.provenance = Provenance::SYNTHETIC;
    bi.capabilities.remote_write = CapabilityState::SUPPORTED;
    s.backend_capability_snapshot.push_back(bi);
    return s;
}

TEST_CASE(persistence_round_trip_preserves_semantic_digest) {
    PersistableState s = make_state();
    auto blob = persistence::serialize(s);
    CHECK(blob.size() > 4);
    PersistableState out;
    std::string err;
    CHECK(persistence::parse(blob, out, err));
    CHECK(err.empty());
    CHECK(out.buffers.size() == 1);
    CHECK(out.registrations.size() == 1);
    CHECK(out.registrations[0].remote_key.key_generation == RemoteKeyGeneration(1));
    CHECK(persistence::semantic_digest(s) == persistence::semantic_digest(out));
}

TEST_CASE(serialization_is_deterministic) {
    PersistableState s = make_state();
    auto a = persistence::serialize(s);
    auto b = persistence::serialize(s);
    CHECK(a == b);
}

TEST_CASE(truncation_rejected) {
    PersistableState s = make_state();
    auto blob = persistence::serialize(s);
    blob.resize(blob.size() / 2);
    PersistableState out;
    std::string err;
    CHECK(!persistence::parse(blob, out, err));
    CHECK(err == "TRUNCATED" || err == "CHECKSUM_MISMATCH");
}

TEST_CASE(checksum_corruption_rejected) {
    PersistableState s = make_state();
    auto blob = persistence::serialize(s);
    blob[blob.size() / 2] ^= 0x55;
    PersistableState out;
    std::string err;
    CHECK(!persistence::parse(blob, out, err));
    CHECK(err == "CHECKSUM_MISMATCH");
}

TEST_CASE(bad_magic_rejected) {
    PersistableState s = make_state();
    auto blob = persistence::serialize(s);
    blob[0] = 0x00; blob[1] = 0x00; blob[2] = 0x00; blob[3] = 0x00;
    PersistableState out;
    std::string err;
    CHECK(!persistence::parse(blob, out, err));
    CHECK(err == "BAD_MAGIC");
}

TEST_CASE(bad_version_rejected) {
    PersistableState s = make_state();
    auto blob = persistence::serialize(s);
    // version is at bytes 4..7; write a different version.
    blob[4] = 0xFF; blob[5] = 0xFF; blob[6] = 0xFF; blob[7] = 0xFF;
    PersistableState out;
    std::string err;
    CHECK(!persistence::parse(blob, out, err));
    CHECK(err == "BAD_VERSION");
}

TEST_CASE(trailing_garbage_rejected) {
    PersistableState s = make_state();
    auto blob = persistence::serialize(s);
    // [fields | extra 2 bytes | crc over fields+extra]
    std::vector<std::uint8_t> nb(blob.begin(), blob.end() - 4);
    nb.push_back(0xAB); nb.push_back(0xCD);
    std::uint32_t c = crc32(nb.data(), nb.size());
    for (int i = 0; i < 4; ++i) nb.push_back(static_cast<std::uint8_t>((c >> (8 * i)) & 0xFF));
    PersistableState out;
    std::string err;
    CHECK(!persistence::parse(nb, out, err));
    CHECK(err == "TRAILING_GARBAGE");
}

TEST_CASE(impossible_count_rejected_when_count_huge) {
    PersistableState s = make_state();
    auto blob = persistence::serialize(s);
    // The buffer count field is the first u64 after magic+version+policy+authority.
    std::size_t pos = 4 + 4; // magic + version
    pos += 8; // policy gen
    pos += 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 8 + 1; // authority (12 u64 + 1 u8)
    // overflow guard: set count to a huge value
    blob[pos] = 0xFF; blob[pos+1] = 0xFF; blob[pos+2] = 0xFF; blob[pos+3] = 0xFF;
    PersistableState out;
    std::string err;
    CHECK(!persistence::parse(blob, out, err));
}

TEST_CASE(duplicate_identity_rejected) {
    PersistableState s = make_state();
    s.buffers.push_back(s.buffers[0]); // duplicate buffer id
    auto blob = persistence::serialize(s);
    PersistableState out;
    std::string err;
    CHECK(!persistence::parse(blob, out, err));
    CHECK(err == "DUPLICATE_IDENTITY");
}

TEST_CASE(runtime_save_recover_marks_revalidation_required) {
    auto b = std::make_shared<SyntheticBackend>(1);
    Rdmabuffer rt;
    rt.add_backend(b);
    rt.set_authority(testutil::make_snapshot());
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    auto d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                    AccessRight::REMOTE_WRITE);
    rt.create_buffer(d);
    RegisterResult r = rt.register_buffer(d, b->id(), dom, testutil::make_envelope());
    REQUIRE(r.ok);
    std::string perr;
    CHECK(rt.save("state.bin", perr));
    // Mutate runtime state (e.g. deregister) then recover from disk.
    std::string derr;
    CHECK(rt.deregister(r.registration, derr));
    RecoveryReport rep;
    CHECK(rt.recover("state.bin", perr, rep));
    REQUIRE(rep.persistence_ok);
    CHECK(rep.recovered_registrations == 1);
    // Recovered registration must NOT be live/ACTIVE.
    bool found = false;
    for (auto rid : rt.registrations()) {
        RegistrationRecord rec;
        if (rt.get_registration(rid, rec)) {
            found = true;
            CHECK(rec.lifecycle == RegistrationLifecycle::REVALIDATION_REQUIRED);
            CHECK(rec.freshness == Freshness::REVALIDATION_REQUIRED);
            CHECK(rec.remote_key.revoked); // key material not live.
        }
    }
    CHECK(found);
}

int main() { return testfw::run_all(); }

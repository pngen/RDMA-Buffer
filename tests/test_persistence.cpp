
#include "test_framework.hpp"
#include "rdmabuffer/rdmabuffer.hpp"
#include "test_util.hpp"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
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

// ---- regression: the authority snapshot's provenance is decoded and validated ----

TEST_CASE(authority_provenance_round_trips_and_is_validated) {
    PersistableState s = make_state(); // authority provenance is SYNTHETIC.
    auto blob = persistence::serialize(s);
    PersistableState out;
    std::string err;
    REQUIRE(persistence::parse(blob, out, err));
    CHECK(out.authority_snapshot.provenance == Provenance::SYNTHETIC);
    CHECK(persistence::serialize(out) == blob);
    // An out-of-range provenance byte is rejected.
    std::vector<std::uint8_t> bad(blob.begin(), blob.end() - 4);
    const std::size_t pos = 4 + 4 + 8 + 12 * 8; // magic, version, policy generation, 12 authority u64.
    bad[pos] = 0x7F;
    const std::uint32_t c = crc32(bad.data(), bad.size());
    for (int i = 0; i < 4; ++i) bad.push_back(static_cast<std::uint8_t>((c >> (8 * i)) & 0xFF));
    CHECK(!persistence::parse(bad, out, err));
}

// ---- regression: runtime save and recover ----

namespace {
// A runtime with one synthetic backend, one domain and one registered buffer.
struct LiveRuntime {
    std::shared_ptr<SyntheticBackend> backend = std::make_shared<SyntheticBackend>(1);
    Rdmabuffer rt;
    ProtectionDomainId dom;
    BufferDescriptor d;
    RegistrationId reg;

    LiveRuntime() {
        rt.add_backend(backend);
        rt.set_authority(testutil::make_snapshot());
        dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
        d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                  AccessRight::REMOTE_WRITE);
        rt.create_buffer(d);
        reg = rt.register_buffer(d, backend->id(), dom, testutil::make_envelope()).registration;
    }
};

std::vector<char> read_file(const char* path) {
    std::ifstream f(path, std::ios::binary);
    return std::vector<char>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
}
} // namespace

TEST_CASE(recover_keeps_live_registration_with_same_identity) {
    LiveRuntime live;
    std::string err;
    REQUIRE(live.rt.save("state_live.bin", err));
    RecoveryReport rep;
    REQUIRE(live.rt.recover("state_live.bin", err, rep));
    // The persisted copy of a registration that is still live is skipped.
    CHECK(rep.recovered_registrations == 0);
    RegistrationRecord rec;
    REQUIRE(live.rt.get_registration(live.reg, rec));
    CHECK(rec.lifecycle == RegistrationLifecycle::ACTIVE);
    CHECK(!rec.backend_handle.empty());
    std::remove("state_live.bin");
}

TEST_CASE(recovered_identities_are_not_reissued) {
    LiveRuntime old;
    std::string err;
    REQUIRE(old.rt.save("state_ids.bin", err));
    auto b = std::make_shared<SyntheticBackend>(2);
    Rdmabuffer rt;
    rt.add_backend(b);
    rt.set_authority(testutil::make_snapshot());
    RecoveryReport rep;
    REQUIRE(rt.recover("state_ids.bin", err, rep));
    REQUIRE(rep.recovered_registrations == 1);
    // New identities never collide with recovered ones.
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    CHECK(dom != old.dom);
    auto d = testutil::make_buffer(50, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                    AccessRight::REMOTE_WRITE);
    rt.create_buffer(d);
    RegisterResult r = rt.register_buffer(d, b->id(), dom, testutil::make_envelope());
    REQUIRE(r.ok);
    CHECK(r.registration != old.reg);
    CHECK(rt.registrations().size() == 2);
    RegistrationRecord rec;
    REQUIRE(rt.get_registration(old.reg, rec));
    CHECK(rec.lifecycle == RegistrationLifecycle::REVALIDATION_REQUIRED);
    // The recovered registration holds nothing live: it deregisters, and the
    // live registration's accounting is untouched.
    CHECK(rt.deregister(old.reg, err));
    CHECK(rt.registrations().size() == 1);
    CHECK(rt.accounting().active_registrations.get() == 1);
    CHECK(rt.accounting().registered_bytes.get() == 4096);
    std::remove("state_ids.bin");
}

TEST_CASE(recovered_registration_carries_no_leases) {
    LiveRuntime old;
    LeaseAcquireResult lr = old.rt.acquire_lease(old.reg, testutil::make_envelope(), access_mask(AccessRight::REMOTE_WRITE));
    REQUIRE(lr.ok);
    std::string err;
    REQUIRE(old.rt.save("state_lease.bin", err));
    auto b = std::make_shared<SyntheticBackend>(2);
    Rdmabuffer rt;
    rt.add_backend(b);
    rt.set_authority(testutil::make_snapshot());
    RecoveryReport rep;
    REQUIRE(rt.recover("state_lease.bin", err, rep));
    // Leases are not recovered, so none can block the registration's teardown.
    RegistrationRecord rec;
    REQUIRE(rt.get_registration(old.reg, rec));
    CHECK(rec.lease_count == 0);
    CHECK(rt.deregister(old.reg, err));
    CHECK(rt.registrations().empty());
    std::remove("state_lease.bin");
}

TEST_CASE(recover_does_not_regress_live_authority) {
    LiveRuntime old; // saved under epoch 1, boot 1.
    std::string err;
    REQUIRE(old.rt.save("state_auth.bin", err));
    auto b = std::make_shared<SyntheticBackend>(2);
    Rdmabuffer rt;
    rt.add_backend(b);
    rt.set_authority(testutil::make_snapshot(2, 2)); // the fresh incarnation.
    RecoveryReport rep;
    REQUIRE(rt.recover("state_auth.bin", err, rep));
    CHECK(rt.authority().coordinator_epoch == CoordinatorEpoch(2));
    CHECK(rt.authority().worker_boot == WorkerBootId(2));
    // The persisted incarnation's envelope stays stale.
    ProtectionDomainId dom = rt.create_protection_domain(NodeId(1), ProcessId(1));
    auto d = testutil::make_buffer(60, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                    AccessRight::REMOTE_WRITE);
    rt.create_buffer(d);
    RegisterResult r = rt.register_buffer(d, b->id(), dom, testutil::make_envelope(1, 1, 1, 1, 1));
    CHECK(!r.ok);
    CHECK(r.miss_reason == "REJECT_STALE_EPOCH");
    std::remove("state_auth.bin");
}

TEST_CASE(destroyed_domain_is_not_recovered_as_live) {
    auto b1 = std::make_shared<SyntheticBackend>(1);
    Rdmabuffer rt1;
    rt1.add_backend(b1);
    rt1.set_authority(testutil::make_snapshot());
    ProtectionDomainId gone = rt1.create_protection_domain(NodeId(1), ProcessId(1));
    ProtectionDomainId kept = rt1.create_protection_domain(NodeId(1), ProcessId(1));
    REQUIRE(rt1.destroy_protection_domain(gone));
    std::string err;
    REQUIRE(rt1.save("state_dom.bin", err));
    auto b2 = std::make_shared<SyntheticBackend>(2);
    Rdmabuffer rt2;
    rt2.add_backend(b2);
    rt2.set_authority(testutil::make_snapshot());
    RecoveryReport rep;
    REQUIRE(rt2.recover("state_dom.bin", err, rep));
    CHECK(rep.recovered_domains == 1);
    auto d = testutil::make_buffer(1, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                    AccessRight::REMOTE_WRITE);
    rt2.create_buffer(d);
    RegisterResult in_gone = rt2.register_buffer(d, b2->id(), gone, testutil::make_envelope());
    CHECK(!in_gone.ok);
    CHECK(in_gone.miss_reason == "DOMAIN_INVALID");
    CHECK(rt2.register_buffer(d, b2->id(), kept, testutil::make_envelope()).ok);
    std::remove("state_dom.bin");
}

TEST_CASE(assigned_buffer_ids_survive_save_and_recover) {
    auto b1 = std::make_shared<SyntheticBackend>(1);
    Rdmabuffer rt1;
    rt1.add_backend(b1);
    rt1.set_authority(testutil::make_snapshot());
    // Id unset: the runtime assigns one.
    auto anon = testutil::make_buffer(0, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                       AccessRight::REMOTE_WRITE);
    BufferId first = rt1.create_buffer(anon);
    BufferId second = rt1.create_buffer(anon);
    REQUIRE(first.is_valid());
    REQUIRE(second.is_valid());
    CHECK(first != second);
    std::string err;
    REQUIRE(rt1.save("state_auto.bin", err));
    Rdmabuffer rt2;
    RecoveryReport rep;
    CHECK(rt2.recover("state_auto.bin", err, rep));
    CHECK(rep.recovered_buffers == 2);
    CHECK(rt2.has_buffer(first));
    CHECK(rt2.has_buffer(second));
    std::remove("state_auto.bin");
}

TEST_CASE(save_encoding_is_independent_of_creation_order) {
    // The same logical state, built in two different orders, encodes to the
    // same bytes.
    const auto build = [](bool reversed, const char* path) {
        auto b = std::make_shared<SyntheticBackend>(1);
        Rdmabuffer rt;
        rt.add_backend(b);
        rt.set_authority(testutil::make_snapshot());
        rt.create_protection_domain(NodeId(1), ProcessId(1));
        for (std::uint64_t i = 1; i <= 8; ++i) {
            const std::uint64_t id = reversed ? 9 - i : i;
            rt.create_buffer(testutil::make_buffer(id, 1, MemoryDomain::SYNTHETIC_REMOTE_CAPABLE, 4096, 4096,
                                                   AccessRight::REMOTE_WRITE));
        }
        std::string err;
        return rt.save(path, err);
    };
    REQUIRE(build(false, "state_order_a.bin"));
    REQUIRE(build(true, "state_order_b.bin"));
    const std::vector<char> a = read_file("state_order_a.bin");
    const std::vector<char> b = read_file("state_order_b.bin");
    CHECK(!a.empty());
    CHECK(a == b);
    std::remove("state_order_a.bin");
    std::remove("state_order_b.bin");
}

int main() { return testfw::run_all(); }

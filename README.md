# RDMA Buffer

RDMA Buffer is a vendor-neutral C++20 runtime that governs the lifecycle and
correctness boundary around memory that is intended for remote-access (RDMA
capable) transfer. It is a **runtime object library**, not a transport stack. It
does not replace verbs libraries, UCX, libfabric, NCCL, MPI, GPUDirect RDMA
stacks, NIC drivers, or vendor transport runtimes.

## The systems question

> How should memory intended for RDMA-capable transfer be identified,
> registered, pinned, owned, reused, invalidated, fenced, and recovered so the
> system always knows which buffer is valid, accessible, authoritative, and
> safe to expose to remote transfer machinery?

The architectural thesis is:

> RDMA safety begins before any transfer happens.

A remote-accessible buffer is not just an address and a length. It is governed
state with identity, memory domain, registration lifetime, access rights,
generation, ownership, transport capability, remote-key semantics, locality,
freshness, provenance, and authority. RDMA Buffer makes remote-access memory
registration a first-class runtime object behind clean backend contracts.

## Why a runtime boundary?

The system can prove which buffer exists, which generation is current, who owns
it, which registration and remote key are authoritative, what access rights are
permitted, what backend and transport capabilities are actually known, which
leases remain valid, what became stale after restart or revocation, and whether
a remote operation is still allowed to touch the memory.

## Public API / package

- Namespace: `rdmabuffer`
- Installed package: `find_package(RDMABuffer CONFIG REQUIRED)`
- Imported target: `RDMABuffer::rdmabuffer`
- Include layout: `include/rdmabuffer/`
- Portable core is dependency-free C++20.

> Optional backends (CUDA, physical RDMA) must not contaminate ordinary
> consumers. Enable them only when the corresponding toolchain components are
> genuinely available.

## Buffer identity

Strong, non-interchangeable identity types (`BufferId`, `RegistrationId`,
`RegistrationLeaseId`, `MemoryRegionId`, `OwnerId`, `ProcessId`, `WorkerId`,
`WorkerBootId`, `NodeId`, `DeviceId`, `NicId`, `ProtectionDomainId`,
`TransportId`, `BackendId`, `TransferId`, `AttemptId`, `DispatchId`,
`RemoteKeyId`, `LocalKeyId`, `ObservationId`, `ReservationId`) are distinct
from generation types (`CoordinatorEpoch`, `BufferGeneration`,
`RegistrationGeneration`, `LeaseGeneration`, `OwnerGeneration`,
`WorkerGeneration`, `MemoryGeneration`, `DeviceGeneration`, `NicGeneration`,
`TransportGeneration`, `BackendGeneration`, `RemoteKeyGeneration`,
`AttemptGeneration`, `DispatchGeneration`, `ObservationGeneration`,
`PolicyGeneration`, `ProtectionDomainGeneration`).

Generation comparisons are explicit and incarnation-scoped: a numerically
larger generation from an old `WorkerBootId` never fences a fresh incarnation.
Authority is incarnation-scoped.

## Memory domains

`HOST_PAGEABLE`, `HOST_PINNED`, `CUDA_DEVICE`, `CUDA_MANAGED`, `SHARED_MEMORY`,
`FILE_BACKED`, `SYNTHETIC_REMOTE_CAPABLE`, `UNKNOWN`. CUDA device memory is not
claimed to be RDMA-registerable merely because it is CUDA memory. That must
come from backend capability evidence.

## Registration lifecycle

`UNREGISTERED`, `REGISTERING`, `REGISTERED`, `ACTIVE`, `REVOKING`, `REVOKED`,
`DEREGISTERING`, `DEREGISTERED`, plus `FAILED`, `STALE`, and
`REVALIDATION_REQUIRED`. Every transition is guarded. Registration is
transactional: validate, reserve accounting, pin/prepare, backend-register,
verify capability, publish keys, commit; on any failure it rolls back partial
registration, releases the reservation, clears unpublished key material,
restores previous authoritative state, and never leaks pinned memory or
registration handles.

## Access rights

`LOCAL_READ`, `LOCAL_WRITE`, `REMOTE_READ`, `REMOTE_WRITE`, `REMOTE_ATOMIC`.
Remote capabilities are granted only if the selected backend reports them.
Unknown capability never becomes implicit permission.

## Protection domains

A registration belongs to exactly one `ProtectionDomainId` per authoritative
registration generation. Cross-domain reuse is rejected unless the backend
explicitly supports and authorizes it. A recreated domain gets a new generation
and cannot inherit stale keys.

## Remote keys

Remote keys are authority-bearing capabilities bound to registration id and
generation, remote-key generation, buffer generation, `WorkerBootId`/process
incarnation, backend, transport, access rights, byte range, and
expiration/revocation state. A stale remote key never regains validity after
deregistration, buffer replacement, registration renewal, process/owner restart,
epoch rollover, memory reallocation, backend reset, or NIC generation change.

## Leases and reuse

A registration may be shared for reuse only while buffer identity, buffer
generation, memory, access rights, backend/transport capability, owner
authority, registration generation, remote-key generation, and lease policy all
remain current. Leases are reference-counted; duplicate release never
decrements twice; accounting never underflows.

## Revocation

`SOFT_REVOKE` blocks new leases/access while existing authorized operations may
finish; `HARD_REVOKE` immediately invalidates remote authority, advances the
key generation, marks future accesses rejected, and moves the registration to
`REVOKING`/`REVOKED`. Stale remote keys cannot access after a hard revoke.

## Backend contract

A vendor-neutral `IBackend` interface exposes `discover_capabilities()`,
`can_register()`, `register_buffer()`, `deregister_buffer()`,
`query_registration()`, `query_remote_access()`, `revalidate()`,
`abort_registration()`, and `rotate_key()`.

Provided backends:

1. **Synthetic RDMA backend** — deterministic simulation of protection
   domains, registration handles, opaque lkey/rkey-like capabilities, access
   flags, key generations, range checking, owner/process authority,
   registration reuse, deregistration, revocation, stale-key rejection,
   backend restart, NIC and transport generation rollover, and bounded
   READ/WRITE/ATOMIC_COMPARE_SWAP simulation. Every observation carries
   `provenance=SYNTHETIC`. It is never described as hardware.
2. **Reference backend** — `TCP_REFERENCE` authority model with `REAL`
   provenance for the OS primitives it exercises. It validates ranges and
   grants logical local/remote rights; it does not claim RNIC registration. It
   exposes a real host-memory preparation/pinning probe.
3. **CUDA backend** (optional, `RDMABUFFER_ENABLE_CUDA`) — performs real
   `cudaHostAlloc`/`cudaMallocHost` and `cudaMalloc` memory-domain proofs and
   reports remote registration capability as `NOT_SUPPORTED` because no
   physical RDMA backend is exercised.
4. **Physical backend** (verbs/ND/libfabric) — enabled only when genuinely
   available; otherwise not claimed.

## Synthetic RDMA backend

Deterministic, labelled `SYNTHETIC`. It models realistic capability semantics
without pretending to be hardware. Scenario control is provided for one-host /
two-host topologies, GPU + RNIC NUMA placement, device-memory support or
rejection, transport/NIC generation rollover, protection-domain
destruction/recreation, remote-key rotation, hard revoke, stale worker restart,
remote read/write allow/deny, atomic unsupported, and deterministic
registration reuse.

## Windows host-pinning proof

On Windows the reference backend and proof use `VirtualAlloc`, `VirtualLock`
(where privileges permit), page touching, alignment inspection, and unlock/free
with exact accounting. This proves host-memory preparation/pinning behavior,
**not** RNIC registration. Bounded allocations are used and the actual OS result
is reported.

## CUDA memory-domain proof

The `rdma-buffer-cuda-proof` executable runs on the RTX 5090 (compute
capability 12.0 / `sm_120`, CUDA 13.1):

- `HOST_PINNED`: `cudaMallocHost`, deterministic init, H2D, kernel, D2H, CPU
  parity, `cudaFreeHost`.
- `CUDA_DEVICE`: `cudaMalloc`, H2D, kernel, D2H, CPU parity, `cudaFree`.
- Real transfer timing is reported with explicit units. These measurements are
  **CUDA transfer throughput, not RDMA bandwidth**.

The buffers are fed into the RDMA Buffer descriptor and capability logic. CUDA
device remote registration is reported as `NOT_SUPPORTED` unless a physical
backend proves otherwise. Stale buffer-generation invalidation is proven
(allocate gen 1, register, free, allocate gen 2, replay gen 1 rejected, gen 2
accepted).

## Multiprocess authority proof

`rdma-buffer-coordinator --scenario` spawns real worker OS processes over
framed TCP, assigns fresh `WorkerBootId`s, kills a worker as a real OS
process, advances the coordinator epoch, restarts a fresh worker incarnation,
and replays stale `CoordinatorEpoch`, `WorkerBootId`, `OwnerGeneration`,
`BufferGeneration`, `RegistrationGeneration`, `RemoteKeyGeneration`,
`ProtectionDomainId`, and `BackendGeneration` — every stale class is rejected
without mutating current authoritative state. The proof is emitted as explicit
`PROOF-PASS`/`PROOF-FAIL` lines.

## Persistence / recovery

Versioned binary persistence (magic, version, bounded counts, deterministic
encoding, checksum, semantic digest) persists logical metadata — never live OS
pointers or live registration handles as authoritative. On recovery, live
registrations are marked `REVALIDATION_REQUIRED` (not automatically `ACTIVE`),
key material becomes invalid, and physical pointer values/handles are not
restored as live. Proven: deterministic round-trip, stable semantic digest,
truncation rejection, corruption/checksum rejection, duplicate identity
rejection, invalid enum rejection, impossible count rejection, generation
regression rejection, and trailing garbage rejection.

## Accounting

Exact accounting never goes negative. Duplicate release/deregister never double
decrements. Final teardown closes all live/pinned/registered/leased counters to
zero. Counter categories include logical buffers, live/pinned/registered bytes,
active registrations, active leases, protection domains, local/remote keys,
remote read/write bytes, atomic operations, failed access attempts, stale
rejections, revocations, deregistrations, reuse hits/misses, and participant
restarts.

## CLI

`rdma-buffer` exposes: `discover`, `buffer-create`, `buffer-show`, `register`,
`deregister`, `lease-acquire`, `lease-release`, `access-check`, `revoke`,
`rotate-key`, `explain`, `simulate`, `save`, `recover`, `benchmark`. Outputs
expose provenance and capability facts (e.g. `backend=SYNTHETIC`,
`registration_capability=UNKNOWN`, `remote_write=REJECT_UNKNOWN_CAPABILITY`).

## Examples

Approximately 15 runnable examples call the library API directly:
`01_buffer_identity`, `02_host_pinned_memory`, `03_registration_lifecycle`,
`04_registration_reuse`, `05_access_rights`, `06_remote_key_rotation`,
`07_protection_domain`, `08_lease_lifecycle`, `09_revocation`,
`10_stale_authority`, `11_persistence_recovery`, `12_synthetic_remote_write`,
`13_multiprocess_restart`, `14_cuda_buffer_domains`, `15_explain_access`.

## Benchmarks

The `rdma-buffer-benchmark` executable reports completed-work results:
descriptor validation, registration lookup, registration create/destroy on the
reference backend, reuse eligibility, lease acquire/release, remote access
validation, key rotation, revocation, canonical serialization, protocol
encode/decode, and synthetic remote read/write. It reports ops/s, ns/op, and
bytes/s where actual payload bytes move, with thread count, payload size, and
wall time. Labels host-pinned H2D/D2H and CUDA transfer timing as CUDA
throughput, not RDMA bandwidth.

## Package consumption

```
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
cmake --install build --prefix <prefix>
```

An independent consumer outside the source tree can then use the installed
package with `find_package(RDMABuffer CONFIG REQUIRED)` and link
`RDMABuffer::rdmabuffer`.

Optional CMake options: `RDMABUFFER_ENABLE_CUDA`,
`RDMABUFFER_ENABLE_SYNTHETIC_RDMA`, `RDMABUFFER_ENABLE_WINDOWS_RDMA`,
`RDMABUFFER_ENABLE_VERBS`, `RDMABUFFER_BUILD_TESTS`,
`RDMABUFFER_BUILD_EXAMPLES`, `RDMABUFFER_BUILD_BENCHMARKS`.

## Honest limitations

- Physical RDMA hardware may not be available on the validation host.
- Synthetic RDMA paths are explicitly synthetic.
- CUDA device memory proof does not imply GPUDirect RDMA support.
- Host-pinned memory proof does not imply RNIC registration.
- Remote-key behavior is hardware-backed only if a physical backend was actually
  exercised.
- Unknown capabilities remain `UNKNOWN`; they are never treated as permission.

No telemetry is transmitted. All observations, logs, benchmarks, and persisted
state remain local to the deployment.

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
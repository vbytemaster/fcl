# FORGE Thread-Safety Model

This document records the runtime concurrency contract for current FORGE runtime
components. It is intentionally precise: FORGE does not claim that all objects
are thread-safe by default. Each owner type must be either immutable,
internally synchronized, strand-owned or owner-confined.

## Categories

| Category | Meaning | Caller contract |
| --- | --- | --- |
| Immutable value | After construction the object exposes only read-only state or copies. | May be copied/read concurrently if the normal C++ object lifetime rules are satisfied. |
| Internally synchronized | The object owns its synchronization for documented concurrent calls. | Concurrent access is allowed only for the documented public operations. |
| Strand-owned | Mutations are serialized through one Boost.Asio strand, a handler serializer tied to an executor. | Callers may schedule work from multiple runtime threads, but state changes happen on the strand. |
| Owner-confined | The object is not thread-safe by itself and is only accessed under an owning object lock or single owner executor. | Do not call it concurrently except through the documented owner. |

## Current Contracts

| Component | Contract | Notes | Proof |
| --- | --- | --- | --- |
| `forge::net::transport::chunk` | Immutable value | The payload view has shared backing storage and no mutable consumer API. | `test_forge_transport` chunk lifetime tests |
| `forge::net::transport::chunk_builder` | Owner-confined move-only handle | A builder is a temporary writer for one caller; `commit(size)` transfers ownership to a chunk. | `test_forge_transport` invalid commit and move tests |
| `forge::net::transport::buffer_pool` | Internally synchronized | The pool mutex protects cached buffer count/bytes. Returned oversized buffers are dropped and cannot poison the pool. | `test_forge_transport transport_buffer_pool_drops_oversized_returned_storage` |
| `forge::net::transport::stream` | Owner-confined handle over backend model | `valid()` is advisory. Operations require an installed backend model and then defer typed errors to that model. | `test_forge_transport`, `test_forge_yamux` reset boundary tests |
| `forge::net::yamux::session` | Internally synchronized session state with serialized writes | Session maps, buffers, waiters and stream lifecycle are mutex-protected; one write queue serializes frames to the underlying stream. | `test_forge_yamux` concurrent writes, reset, reclaim and close tests |
| `forge::api::transport::client` | Owner-confined | One client owns one API stream, pending calls and serialized writes. It is not a shared concurrent object. | `test_forge_api_transport` client concurrency tests through one coroutine owner |
| `forge::api::transport::serve_session` | Strand-owned admission state | Accepted API stream slots and drain wakeups are serialized on one strand, so `max_concurrent_streams` is stable with multi-worker runtimes. | `test_forge_api_transport transport_api_serve_session_serializes_admission_on_multi_worker_runtime` |
| `forge::net::p2p::node` | Internally synchronized host facade | Node state is protected by `node::impl` ownership and mutexes. Public async operations go through the node owner. | `test_forge_quic_p2p` multi-worker host tests |
| `forge::net::p2p::resource_manager` | Internally synchronized scoped ledger | Manager copies and move-only reservations share one synchronized ledger for explicitly reserved scoped memory, descriptors, connections and streams. Reservations may be created, bound and released by concurrent transport operations; one reservation object must not be mutated concurrently except for the documented atomic dial binding. It is not a general allocator or process/native-heap synchronization boundary. | `test_forge_quic_p2p` resource-manager scope and concurrent dial-binding regressions |
| `forge::net::p2p::connection_manager` | Owner-confined under `node::impl` | It records session metadata and pruning decisions while the node owns synchronization. | `test_forge_quic_p2p` connection policy regressions |
| `forge::net::p2p::connection_gater` | Caller-supplied concurrent policy | Direct transport operations may invoke its synchronous, `noexcept` hooks concurrently. Implementations must be nonblocking and internally thread-safe. | `test_forge_quic_p2p` gater phase regressions |

## Rules

- Do not add hidden locks to owner-confined helpers just to make them appear
  thread-safe. Prefer one clear owner and tests at the owner boundary.
- Do not use atomics as a substitute for ordered wakeup/drain protocols. If a
  state machine requires ordered reservation and release, use a strand or owner
  lock.
- `forge::net::p2p::resource_manager` copies may be used concurrently. Individual
  move-only reservation objects remain single-owner handles unless an operation
  explicitly documents concurrent arbitration.
- Resource-manager synchronization protects only explicitly acquired scope
  reservations. A caller that needs a scoped memory bound must acquire the child
  reservation before allocating or enqueueing the owned buffer; unreserved
  process and native transport allocations are outside that contract.
- `transport::stream::valid()` is a status check, not a promise that the next
  operation cannot fail. Operations must still handle typed exceptions.
- Blocking waits, polling loops and detached raw threads are not part of this
  model. Use Boost.Asio awaitables, timers, strands and explicit owners.

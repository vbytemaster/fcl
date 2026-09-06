# Forge P2P Host Protection v1 Donor Note

## Scope

This note traces Stage 6 host connection gating and resource ownership. It does
not add a product authorization policy, transport protocol, topology loop or
wire extension.

## Pinned Sources

| Area | Donor | Accepted pattern | Forge owner |
|---|---|---|---|
| Connection gating | Go libp2p `9cfe2cc0`, `core/connmgr/gater.go` and `p2p/test/transport/gating_test.go` | Invoke peer dial, address dial, accept, secured and upgraded gates at their distinct lifecycle boundaries. A denial terminates only the current attempt. | `connection_gater`, `connection_gate`, direct TCP/QUIC profiles |
| Resource scopes | Go libp2p `9cfe2cc0`, `core/network/rcmgr.go` and `p2p/host/resource-manager/scope.go` | Start connection/stream work in transient scope, then atomically attach peer, protocol and optional service scopes as identity and protocol become known. A failed edge admission rolls back all earlier edge reservations. | `resource_manager`, move-only reservations |
| Default limits | Go libp2p `9cfe2cc0`, `p2p/host/resource-manager/limit_defaults.go` | Use the donor base values for transient and peer scopes. Keep Forge system concurrency explicit until donor-style host-memory auto-scaling exists. | `resource_manager::limits` |
| Memory priority | Go libp2p `9cfe2cc0`, `p2p/host/resource-manager/scope.go` | Admit memory at `floor((priority + 1) * limit / 256)` using the donor low, medium, high and always priorities. | `memory_priority`, scoped memory reservations |
| Native descriptors | Go libp2p `9cfe2cc0`, resource-manager connection scopes | Charge one descriptor for each TCP listener/connection and one shared UDP descriptor for a QUIC listener. Do not double-charge accepted QUIC connections sharing that socket. | direct TCP/QUIC profiles and transport-owned lifetime guards |

Canonical source links:

- <https://github.com/libp2p/go-libp2p/blob/9cfe2cc00be5b20a0be737f002c99f81b92255c5/core/connmgr/gater.go>
- <https://github.com/libp2p/go-libp2p/blob/9cfe2cc00be5b20a0be737f002c99f81b92255c5/core/network/rcmgr.go>
- <https://github.com/libp2p/go-libp2p/blob/9cfe2cc00be5b20a0be737f002c99f81b92255c5/p2p/host/resource-manager/limit_defaults.go>
- <https://github.com/libp2p/go-libp2p/blob/9cfe2cc00be5b20a0be737f002c99f81b92255c5/p2p/test/transport/gating_test.go>

## Accepted Rules

- The public gater is synchronous, nonblocking and safe for concurrent calls.
  It never owns network work and never mutates peer-store backoff.
- Outbound peer and address gates run before provisional session/descriptor
  admission. TCP inbound order is native accept, accept gate, session/descriptor
  admission, then security upgrade; idle listeners hold lifecycle ownership only.
  A session starts in system, transient and connection scopes. Authentication
  atomically removes transient ownership and adds the authenticated peer scope;
  system and connection ownership remain charged.
- A stream starts in system, transient, peer and stream scopes with its
  direction. Multistream binding atomically replaces transient with protocol and
  protocol-peer scopes; optional service binding adds service and service-peer
  scopes. A failed migration closes only that stream and leaves no partial
  counters.
- Resource reservations are move-only RAII values. Explicit child memory and
  descriptor reservations keep their ledger alive after the parent facade is
  destroyed and release exactly once when their owning buffer or native lifetime
  is destroyed. Queued outbound chunks retain their explicit memory child through
  drain, acknowledgement or reset.
- `resource_manager::limits` and `snapshot` bound only dimensions explicitly
  reserved through `resource_manager`: scoped memory, file descriptors,
  connections, streams and the listed operational budgets. They do not claim a
  bound on process RSS, kernel socket buffers, or every native transport,
  encryption, decoder or handshake allocation. Full donor-style reservation of
  every such allocation remains future work.
- Gater rejection, policy exhaustion, invalid transition and runtime failure
  are independent diagnostics. Product policy is not reported as remote peer
  failure.
- Forge uses fixed system limits rather than claiming donor AutoScale parity.
  Transient and peer defaults match the donor base profile; deployments may
  replace every scope limit explicitly.

## Rejected Patterns

- One combined allow/deny hook after the connection has already allocated all
  resources.
- Manual acquire/release pairs split across success, cancellation and exception
  paths.
- Treating a gater denial as endpoint failure or poisoning dial backoff.
- Counting QUIC accepted connections as independent UDP file descriptors.
- Releasing queued write memory when a coroutine merely hands bytes to the
  transport rather than when the transport drains, acknowledges or resets it.
- Presenting scoped reservation totals as a process-wide or native-transport
  heap limit.

## Evidence Gate

The implementation is not considered complete until the focused exact-head
tests prove all five gater phases on TCP and QUIC, scope migration and rollback,
concurrent reservation arbitration, explicitly reserved memory/descriptor
exhaustion, cancellation, transport handoff and deterministic release. The
standard Go/Rust interop suite must remain wire-clean because this PR changes host
policy only.

# FORGE P2P Connection Manager v1 Donor Note

## Scope

This note records the donor patterns for production-shaped connection/session
policy inside `forge_net_p2p` host/node orchestration. The implementation owns admission,
protection, pruning, pending limits, endpoint-local dial backoff and malformed
peer accounting around `node::impl::session_state`.

It is not a transport layer, not `direct`, not a plugin loop and not a public
connection-event bus. QUIC/TCP direct profiles and relay/circuit paths execute
connections; the connection manager decides whether sessions may be admitted,
kept, pruned or rejected.

## Donor Sources

| Area | Donor source | Accepted pattern | Forge owner |
|---|---|---|---|
| Go connection manager | `donors/go-libp2p/p2p/net/connmgr/*` | Low/high watermark pruning, protected peers and grace/silence periods are host policy, not transport behavior. | `connection_manager`, `node::protect_peer`, `node::unprotect_peer`, `node::is_peer_protected` |
| Go resource manager | `donors/go-libp2p/p2p/host/resource-manager/*`, `donors/go-libp2p/p2p/net/swarm/*` | Transient connection/stream spans attach peer, protocol and optional service scopes as context becomes known; explicitly reserved memory propagates atomically to constraining scopes. | `resource_manager::{reserve_session,reserve_stream}`, move-only child reservations, node metrics |
| Go dial backoff | `donors/go-libp2p/p2p/net/swarm/dial_ranker.go`, swarm dial backoff tests | Dial failures back off the failing address/candidate, not the whole peer. | `endpoint_backoff_until`, peer-store endpoint records, path selector |
| Rust connection limits | `donors/rust-libp2p/swarm/src/connection.rs`, connection-limits behaviour | Admission limits and close events are swarm/host policy; transport implementations stay focused on connect/listen mechanics. | `node::impl::remember_session`, `forget_session`, `async_stop` |
| PubSub abuse accounting | Go/Rust GossipSub score/backoff tests | Malformed/control-spam from one peer penalizes or closes that peer without poisoning unrelated peers. | `increment_pubsub_invalid`, per-peer malformed resource scope |

## Accepted Rules

- `forge_net_p2p` owns connection policy because Peer ID, session direction, path kind,
  protection and abuse scores are P2P host semantics.
- Direct QUIC/TCP profiles remain direct-only: transport profile selection,
  listen/connect/accept and no pruning/path scoring/relay discovery ownership.
- `resource_manager` counts explicitly reserved scopes and denials;
  `connection_manager` decides which session records are admitted or pruned.
  Resource-manager totals are not a claim about all process or native transport
  heap.
- `resource_manager` is internally synchronized across manager copies and
  reservations. `connection_manager` remains owner-confined under `node::impl`.
  The shared FORGE thread-safety model is recorded in
  `docs/runtime/thread-safety.md`.
- Protected peers survive pruning, but protection is not a bypass for hard
  admission if no unprotected session can be freed.
- Backoff is endpoint-local. A failed TCP address must not poison QUIC or relay
  paths for the same peer.
- `async_stop()` must close managed sessions/listeners and release resource
  scopes deterministically.

## Current Proof

| Case | Status | Proof |
|---|---|---|
| Transient and established session scopes | Ported | `p2p_resource_manager_enforces_connection_session_scopes`, `p2p_connection_manager_rejects_pending_outbound_limit_without_killing_first_attempt` |
| Denied stream scopes do not create stale peer/protocol counters; dial and relay operational budgets are independent | Ported | `p2p_resource_manager_enforces_peer_protocol_dial_and_reservation_scopes` |
| Protected peer API is tag-based | Ported | `p2p_node_peer_protection_api_is_tagged_and_additive` |
| Low/high watermark pruning preserves protected peers | Ported | `p2p_connection_manager_prunes_unprotected_sessions_and_keeps_protected_peer` |
| All-protected hard-cap rejection | Ported | `p2p_connection_manager_rejects_when_all_sessions_are_protected` |
| Outbound session admission limit | Ported | `p2p_connection_manager_enforces_outbound_session_limit` |
| Bounded parallel sessions per peer | Ported | `p2p_connection_manager_allows_bounded_parallel_sessions_per_peer`, `p2p_connection_manager_enforces_sessions_per_peer_limit` |
| Endpoint-local direct backoff | Ported | `p2p_path_manager_tries_next_direct_endpoint_after_attempt_timeout` |
| Malformed peer closes only offender session | Ported | `p2p_abusive_peer_crossing_malformed_threshold_closes_only_offender_session` |
| Stop releases managed sessions | Ported | existing `async_stop()` component coverage plus F.3 resource cleanup |
| Live interop remains compatible | Required gate | `test_forge_libp2p_interop` |

## Unsupported Gaps

- FORGE does not yet expose a public connection event stream. This work keeps operator
  control additive and narrow: protect/unprotect/is-protected.
- Donor live fixtures do not expose all pruning/protection knobs. These are
  component-proven and must stay in the donor matrix as local policy proof, not
  wire-protocol support claims.
- This work does not add WebSocket, new transports, product/plugin policy loops or a
  separate public multi-transport library.

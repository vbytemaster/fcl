module;

#include <forge/exceptions/macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <exception>
#include <functional>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/cancellation_state.hpp>
#include <boost/asio/cancellation_type.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/experimental/concurrent_channel.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/system_error.hpp>

module forge.net.p2p.node;

import forge.exceptions;
import forge.asio.gate;
import forge.crypto.asymmetric;
import forge.net.p2p.dht;
import forge.net.p2p.discovery;
import forge.net.p2p.endpoint;
import forge.net.p2p.exceptions;
import forge.net.p2p.hole_punch;
import forge.net.p2p.identify;
import forge.net.p2p.identity;
import forge.net.p2p.lifecycle;
import forge.net.p2p.message;
import forge.net.p2p.negotiation;
import forge.net.p2p.peer_store;
import forge.net.p2p.protocol;
import forge.net.p2p.pubsub;
import forge.net.p2p.reachability;
import forge.net.p2p.relay;
import forge.net.p2p.rendezvous;
import forge.net.p2p.resource_manager;
import forge.net.p2p.scoring;
import forge.net.p2p.stream;
import forge.net.transport.session;
import forge.net.transport.stream;
import forge.net.yamux.session;

#include "details/direct_transport.hxx"
#include "details/cancellation_latch.hxx"
#include "details/node_impl.hxx"
#include "details/path_selector.hxx"
#include "details/peer_exchange_codec.hxx"
#include "details/peer_failure.hxx"
#include "details/resource_stream.hxx"
#include "details/session_lifecycle.hxx"

namespace forge::net::p2p {

namespace asio = boost::asio;

[[nodiscard]] bool listener_is_active(const direct::registry& registry, const forge::net::p2p::endpoint& endpoint) {
   const auto active = registry.local_endpoints();
   return std::ranges::any_of(active, [&](const auto& candidate) {
      return candidate.transport.host_type == endpoint.transport.host_type &&
             candidate.transport.protocol == endpoint.transport.protocol &&
             candidate.transport.host == endpoint.transport.host && candidate.transport.port == endpoint.transport.port;
   });
}

void node::impl::launch_pruned_session_teardown(const std::shared_ptr<session_state>& session) noexcept {
   auto ticket = teardown.track([session] { session->connection.cancel(); });
   if (!ticket.active()) {
      session->connection.cancel();
      session->native_lifetime.reset();
      session->resource.release();
      return;
   }
   try {
      boost::asio::co_spawn(
          runtime.context(),
          [session, ticket = std::move(ticket)]() mutable -> boost::asio::awaitable<void> {
             try {
                co_await session->connection.async_close();
             } catch (...) {
                session->connection.cancel();
             }
             session->native_lifetime.reset();
             session->resource.release();
             ticket.release();
          },
          boost::asio::detached);
   } catch (...) {
      session->connection.cancel();
      session->native_lifetime.reset();
      session->resource.release();
   }
}

boost::asio::awaitable<void> node::impl::remember_session(std::shared_ptr<node::impl::session_state> session,
                                                          connection_manager::direction direction) {
   enum class rejection {
      none,
      admission,
      stopped,
   };

   auto admission_ticket = forge::asio::gate::ticket{};
   try {
      admission_ticket = co_await session_admission_gate.acquire();
   } catch (const forge::asio::exceptions::canceled&) {
      detail::mark_rejected_session(session);
      detail::cancel_rejected_session(session);
      session->native_lifetime.reset();
      FORGE_THROW_EXCEPTION(exceptions::canceled, "P2P session admission was canceled");
   } catch (const forge::asio::exceptions::rejected&) {
      detail::mark_rejected_session(session);
      detail::cancel_rejected_session(session);
      session->native_lifetime.reset();
      FORGE_THROW_EXCEPTION(exceptions::closed, "P2P node is stopped");
   }

   const auto resource_direction = direction == connection_manager::direction::inbound
                                       ? resource_manager::session_direction::inbound
                                       : resource_manager::session_direction::outbound;
   if (!session->resource.established() && !session->resource.establish(resource_manager::session_scope{
                                               .peer = session->info.remote_peer,
                                               .direction = resource_direction,
                                           })) {
      detail::cancel_rejected_session(session);
      session->native_lifetime.reset();
      auto lock = std::scoped_lock{mutex};
      ++metrics_value.backpressure_rejections;
      ++metrics_value.connection_rejections;
      FORGE_THROW_EXCEPTION(exceptions::backpressure_rejected, "P2P established session limit reached");
   }

   auto rejected = rejection::none;
   auto rejection_reason = std::string{};
   auto pruned_ids = std::vector<std::uint64_t>{};
   auto pruned_sessions = std::vector<std::shared_ptr<session_state>>{};
   refresh_connection_scores();
   const auto network_score = [&] {
      if (const auto record = store.find(session->info.remote_peer)) {
         return record->score;
      }
      return 0.0;
   }();
   pruned_ids.reserve(options.limits.max_sessions);
   pruned_sessions.reserve(options.limits.max_sessions);
   try {
      {
         auto lock = std::scoped_lock{mutex};
         if (stopped) {
            detail::mark_rejected_session(session);
            rejected = rejection::stopped;
         } else {
            session->direction = direction;
            if (session->id == 0) {
               session->id = next_session_id++;
            }
            const auto now = std::chrono::steady_clock::now();
            auto admission = connections.remember(
                connection_manager::session_record{
                    .id = session->id,
                    .peer = session->info.remote_peer,
                    .direction = direction,
                    .opened_at = now,
                    .last_used_at = now,
                    .network_score = network_score,
                },
                now);
            for (const auto id : admission.pruned) {
               auto found = sessions.find(id);
               if (found == sessions.end()) {
                  continue;
               }
               const auto pruned = found->second;
               pruned->closed = true;
               const auto peer = pruned->info.remote_peer;
               const auto session_id = pruned->id;
               sessions.erase(found);
               pruned_ids.push_back(session_id);
               pruned_sessions.push_back(pruned);
               invalidate_pubsub_outbound_locked(peer, session_id);
            }

            if (!admission.accepted) {
               detail::mark_rejected_session(session);
               ++metrics_value.backpressure_rejections;
               ++metrics_value.connection_rejections;
               rejected = rejection::admission;
               rejection_reason = std::move(admission.reason);
            }
         }

         metrics_value.active_sessions = sessions.size();
         metrics_value.sessions_pruned += pruned_ids.size();
         metrics_value.sessions_closed += pruned_ids.size();
      }
   } catch (...) {
      for (const auto id : pruned_ids) {
         identify_service.forget(id);
      }
      throw;
   }

   if (rejected == rejection::stopped || rejected == rejection::admission) {
      detail::cancel_marked_session(session);
      session->native_lifetime.reset();
      session->resource.release();
   }

   // identify_service owns a separate mutex; never take it while holding the
   // node mutex used by session admission and teardown.
   for (const auto id : pruned_ids) {
      identify_service.forget(id);
   }

   if (!pruned_sessions.empty()) {
      co_await boost::asio::this_coro::reset_cancellation_state(boost::asio::disable_cancellation{});
      for (const auto& pruned : pruned_sessions) {
         pruned->connection.cancel();
      }
      for (const auto& pruned : pruned_sessions) {
         auto teardown_ticket = teardown.track([pruned] { pruned->connection.cancel(); });
         if (!teardown_ticket.active()) {
            pruned->native_lifetime.reset();
            pruned->resource.release();
            continue;
         }
         try {
            co_await pruned->connection.async_close();
         } catch (...) {
            pruned->connection.cancel();
         }
         pruned->native_lifetime.reset();
         pruned->resource.release();
         teardown_ticket.release();
      }
   }

   if (rejected == rejection::stopped) {
      FORGE_THROW_EXCEPTION(exceptions::closed, "P2P node is stopped");
   }
   if (rejected == rejection::admission) {
      FORGE_THROW_EXCEPTION(exceptions::backpressure_rejected,
                            rejection_reason.empty() ? "P2P session admission rejected" : rejection_reason);
   }

   {
      auto lock = std::scoped_lock{mutex};
      if (stopped) {
         connections.forget(session->id);
         detail::mark_rejected_session(session);
         rejected = rejection::stopped;
      } else {
         sessions[session->id] = session;
         ++metrics_value.sessions_opened;
         ++metrics_value.handshakes_completed;
      }
      metrics_value.active_sessions = sessions.size();
   }

   if (rejected == rejection::stopped) {
      detail::cancel_marked_session(session);
      session->native_lifetime.reset();
      session->resource.release();
      FORGE_THROW_EXCEPTION(exceptions::closed, "P2P node is stopped");
   }
   co_return;
}

void node::impl::forget_session(const peer_id& peer) {
   auto removed_sessions = std::vector<std::shared_ptr<session_state>>{};
   {
      auto lock = std::scoped_lock{mutex};
      auto removed = std::size_t{0};
      for (auto it = sessions.begin(); it != sessions.end();) {
         if (it->second->info.remote_peer != peer) {
            ++it;
            continue;
         }
         it->second->closed = true;
         removed_sessions.push_back(it->second);
         connections.forget(it->second->id);
         it = sessions.erase(it);
         ++removed;
      }
      if (removed != 0) {
         metrics_value.active_sessions = sessions.size();
         metrics_value.sessions_closed += removed;
      }
      erase_inbound_relay_reservation_locked(peer);
      invalidate_pubsub_outbound_locked(peer);
      forget_pubsub_peer_locked(peer);
   }
   for (const auto& session : removed_sessions) {
      launch_pruned_session_teardown(session);
      identify_service.forget(session->id);
   }
}

void node::impl::forget_session(const std::shared_ptr<node::impl::session_state>& session) {
   auto removed = false;
   {
      auto lock = std::scoped_lock{mutex};
      if (!detail::erase_current_session(sessions, session)) {
         return;
      }
      session->closed = true;
      removed = true;
      connections.forget(session->id);
      metrics_value.active_sessions = sessions.size();
      ++metrics_value.sessions_closed;
      const auto peer = session->info.remote_peer;
      const auto peer_still_connected = std::ranges::any_of(
          sessions, [&](const auto& item) { return item.second->info.remote_peer == peer && !item.second->closed; });
      if (!peer_still_connected) {
         erase_inbound_relay_reservation_locked(peer);
         forget_pubsub_peer_locked(peer);
      }
      invalidate_pubsub_outbound_locked(session->info.remote_peer, session->id);
   }
   if (removed) {
      launch_pruned_session_teardown(session);
      identify_service.forget(session->id);
   }
}

[[nodiscard]] std::shared_ptr<node::impl::session_state> node::impl::session_for(const peer_id& peer) const {
   auto lock = std::scoped_lock{mutex};
   return session_for_locked(peer);
}

[[nodiscard]] std::shared_ptr<node::impl::session_state> node::impl::session_for_locked(const peer_id& peer) const {
   auto selected = std::shared_ptr<session_state>{};
   for (const auto& [_, session] : sessions) {
      if (session->info.remote_peer == peer && !session->closed) {
         selected = session;
      }
   }
   if (selected) {
      connections.touch(selected->id, std::chrono::steady_clock::now());
   }
   return selected;
}

[[nodiscard]] std::shared_ptr<node::impl::session_state>
node::impl::session_for_path(const peer_id& peer, path::kind kind, std::optional<peer_id> relay_peer) const {
   auto lock = std::scoped_lock{mutex};
   return session_for_path_locked(peer, kind, relay_peer);
}

[[nodiscard]] std::shared_ptr<node::impl::session_state>
node::impl::session_for_path_locked(const peer_id& peer, path::kind kind,
                                    const std::optional<peer_id>& relay_peer) const {
   auto selected = std::shared_ptr<session_state>{};
   for (const auto& [_, session] : sessions) {
      if (session->info.remote_peer != peer || session->info.path != kind || session->closed) {
         continue;
      }
      if (relay_peer && session->info.relay_peer != relay_peer) {
         continue;
      }
      selected = session;
   }
   if (selected) {
      connections.touch(selected->id, std::chrono::steady_clock::now());
   }
   return selected;
}

node::session_info node::impl::session_info_for(const std::shared_ptr<session_state>& session) const {
   auto lock = std::scoped_lock{mutex};
   return session->info;
}

boost::asio::awaitable<std::shared_ptr<node::impl::session_state>>
node::impl::connect_direct(forge::net::p2p::endpoint endpoint, node::connect_options connect_options_value,
                           resource_manager::dial_reservation* logical_dial,
                           std::shared_ptr<cancellation_latch> cancellation) {
   validate_operation_timeout(connect_options_value.timeout, "P2P connect timeout");
   const auto deadline_at = std::chrono::steady_clock::now() + connect_options_value.timeout;
   auto endpoint_copy = endpoint;
   const auto expected_peer = connect_options_value.expected_peer ? connect_options_value.expected_peer : endpoint.peer;
   if (expected_peer && logical_dial == nullptr) {
      connection_gate->peer_dial(*expected_peer);
   }
   if (expected_peer) {
      connection_gate->address_dial(*expected_peer, endpoint_copy);
   }
   auto owned_dial = std::optional<resource_manager::dial_reservation>{};
   if (logical_dial == nullptr) {
      owned_dial = resources.reserve_dial();
      if (!owned_dial) {
         auto lock = std::scoped_lock{mutex};
         ++metrics_value.backpressure_rejections;
         ++metrics_value.connection_rejections;
         FORGE_THROW_EXCEPTION(exceptions::backpressure_rejected, "P2P logical dial limit reached");
      }
      logical_dial = &*owned_dial;
   }
   if (expected_peer && !logical_dial->bound() && !logical_dial->bind(*expected_peer)) {
      auto lock = std::scoped_lock{mutex};
      ++metrics_value.backpressure_rejections;
      ++metrics_value.connection_rejections;
      FORGE_THROW_EXCEPTION(exceptions::backpressure_rejected, "P2P per-peer dial limit reached");
   }
   auto reservation = resources.reserve_session(resource_manager::session_direction::outbound);
   if (!reservation) {
      auto lock = std::scoped_lock{mutex};
      ++metrics_value.backpressure_rejections;
      ++metrics_value.connection_rejections;
      FORGE_THROW_EXCEPTION(exceptions::backpressure_rejected, "P2P pending outbound session limit reached");
   }
   if (expected_peer && !reservation->establish(resource_manager::session_scope{
                            .peer = *expected_peer,
                            .direction = resource_manager::session_direction::outbound,
                        })) {
      auto lock = std::scoped_lock{mutex};
      ++metrics_value.backpressure_rejections;
      ++metrics_value.connection_rejections;
      FORGE_THROW_EXCEPTION(exceptions::backpressure_rejected, "P2P established outbound session limit reached");
   }
   auto descriptor = reservation->reserve_file_descriptors(1);
   if (!descriptor) {
      auto lock = std::scoped_lock{mutex};
      ++metrics_value.backpressure_rejections;
      ++metrics_value.connection_rejections;
      FORGE_THROW_EXCEPTION(exceptions::backpressure_rejected, "P2P outbound TCP/QUIC file descriptor limit reached");
   }
   auto native_lifetime = std::make_shared<resource_manager::file_descriptor_reservation>(std::move(*descriptor));
   try {
      auto started = std::chrono::steady_clock::now();
      auto result = co_await direct_registry.async_connect(std::move(endpoint), connect_options_value,
                                                           std::move(cancellation), native_lifetime);
      if (!logical_dial->bound() && !logical_dial->bind(result.peer)) {
         result.session.cancel();
         FORGE_THROW_EXCEPTION(exceptions::backpressure_rejected, "P2P authenticated peer dial limit reached");
      }
      auto session = std::make_shared<session_state>();
      session->info = node::session_info{
          .remote_peer = result.peer,
          .path = path::kind::direct,
      };
      session->authentication = result.authentication;
      session->connection = std::move(result.session);
      session->resource = std::move(*reservation);
      session->native_lifetime = std::move(native_lifetime);
      session->direct_endpoint = endpoint_copy;
      session->remote_endpoint = result.remote_endpoint;
      co_await remember_session(session, connection_manager::direction::outbound);
      store.mark_endpoint_success(
          result.peer, endpoint_copy, path::kind::direct,
          std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started));
      launch_session_accept_loop(session);
      launch_identify(session);
      co_await announce_pubsub_subscriptions(result.peer);
      co_return session;
   } catch (const forge::exceptions::base& error) {
      auto stopped_before_deadline = false;
      {
         auto lock = std::scoped_lock{mutex};
         stopped_before_deadline = stop_requested_at && *stop_requested_at < deadline_at;
      }
      if (p2p_code(error) == exceptions::code::timeout && stopped_before_deadline) {
         FORGE_THROW_EXCEPTION(exceptions::closed, "P2P direct connect stopped with its node");
      }
      FORGE_THROW_CODE(p2p_code(error), error.what());
   }
}

boost::asio::awaitable<std::shared_ptr<node::impl::session_state>>
node::impl::ensure_direct_session(const peer_id& peer, std::chrono::milliseconds timeout,
                                  std::size_t max_direct_endpoints, std::chrono::milliseconds direct_attempt_timeout,
                                  std::shared_ptr<cancellation_latch> cancellation) {
   if (cancellation && cancellation->stop_requested()) {
      FORGE_THROW_EXCEPTION(exceptions::canceled, "P2P direct session acquisition canceled");
   }
   if (auto existing = session_for_path(peer, path::kind::direct)) {
      co_return existing;
   }
   connection_gate->peer_dial(peer);
   const auto record = store.find(peer);
   if (!record || record->endpoints.empty()) {
      FORGE_THROW_EXCEPTION(exceptions::peer_not_found, "P2P peer has no known direct endpoint");
   }
   if (max_direct_endpoints == 0) {
      FORGE_THROW_EXCEPTION(exceptions::invalid_options, "P2P max direct endpoints must be positive");
   }
   const auto now = std::chrono::system_clock::now();
   auto preferred = path_selector::rank_direct(*record, now);

   const auto started = std::chrono::steady_clock::now();
   auto last_kind = std::optional<exceptions::code>{};
   auto last_message = std::string{};
   const auto attempts = std::min(max_direct_endpoints, preferred.size());
   auto dial = resources.reserve_dial(peer);
   if (!dial) {
      auto lock = std::scoped_lock{mutex};
      ++metrics_value.backpressure_rejections;
      ++metrics_value.connection_rejections;
      FORGE_THROW_EXCEPTION(exceptions::backpressure_rejected, "P2P per-peer dial limit reached");
   }
   for (std::size_t index = 0; index < attempts; ++index) {
      if (cancellation && cancellation->stop_requested()) {
         FORGE_THROW_EXCEPTION(exceptions::canceled, "P2P direct session acquisition canceled");
      }
      const auto remaining = remaining_timeout(started, timeout, "P2P direct path");
      const auto per_attempt = attempt_timeout(remaining, direct_attempt_timeout, "P2P direct path attempt");
      const auto endpoint = preferred[index].endpoint;
      record_path_attempt(path::kind::direct);
      try {
         co_return co_await connect_direct(
             endpoint, node::connect_options{.expected_peer = peer, .allow_relay = false, .timeout = per_attempt},
             &*dial, cancellation);
      } catch (const forge::exceptions::base& error) {
         const auto kind = p2p_code(error);
         last_kind = kind;
         last_message = error.what();
         auto node_stopped = false;
         {
            auto lock = std::scoped_lock{mutex};
            node_stopped = stopped;
         }
         if (!detail::remote_peer_attributable_failure(kind, node_stopped)) {
            FORGE_THROW_CODE(kind, error.what());
         }
         store.mark_endpoint_failure(peer, endpoint, path::kind::direct,
                                     endpoint_backoff_until(peer, endpoint, path::kind::direct));
         increment_direct_failure();
      }
   }
   if (last_kind) {
      FORGE_THROW_CODE(*last_kind, last_message);
   }
   FORGE_THROW_EXCEPTION(exceptions::peer_not_found, "P2P peer has no direct endpoint outside backoff");
}

void node::impl::launch_accept_loop(forge::net::p2p::endpoint local_endpoint) {
   auto self = shared_from_this();
   static_cast<void>(launch_tracked([self, local_endpoint = std::move(local_endpoint)]() -> asio::awaitable<void> {
      while (true) {
         {
            auto lock = std::scoped_lock{self->mutex};
            if (self->stopped || !listener_is_active(self->direct_registry, local_endpoint)) {
               co_return;
            }
         }
         try {
            auto connection = co_await self->direct_registry.async_accept(local_endpoint);
            if (!connection.admission || !connection.admission->active()) {
               connection.session.cancel();
               {
                  auto lock = std::scoped_lock{self->mutex};
                  ++self->metrics_value.connection_rejections;
               }
               continue;
            }
            auto stopped = false;
            {
               auto lock = std::scoped_lock{self->mutex};
               stopped = self->stopped;
            }
            if (stopped) {
               try {
                  connection.session.cancel();
               } catch (...) {
               }
               co_return;
            }
            auto accepted = std::make_shared<direct::connection>(std::move(connection));
            auto admission = std::make_shared<resource_manager::session_reservation>(std::move(*accepted->admission));
            if (!self->launch_tracked([self, accepted, admission]() mutable -> asio::awaitable<void> {
                   co_await self->handle_inbound_connection(std::move(*accepted), std::move(*admission));
                })) {
               accepted->session.cancel();
            }
         } catch (const forge::exceptions::base& error) {
            auto lock = std::scoped_lock{self->mutex};
            if (self->stopped || !listener_is_active(self->direct_registry, local_endpoint)) {
               co_return;
            }
            const auto kind = p2p_code(error);
            if (kind == exceptions::code::connection_rejected || kind == exceptions::code::backpressure_rejected) {
               continue;
            }
            ++self->metrics_value.handshakes_failed;
         } catch (const std::exception&) {
            auto lock = std::scoped_lock{self->mutex};
            if (self->stopped || !listener_is_active(self->direct_registry, local_endpoint)) {
               co_return;
            }
            ++self->metrics_value.handshakes_failed;
         } catch (...) {
            auto lock = std::scoped_lock{self->mutex};
            if (self->stopped || !listener_is_active(self->direct_registry, local_endpoint)) {
               co_return;
            }
            ++self->metrics_value.handshakes_failed;
         }
      }
   }));
}

boost::asio::awaitable<void> node::impl::handle_inbound_connection(direct::connection connection,
                                                                   resource_manager::session_reservation reservation) {
   try {
      auto node_stopped = false;
      {
         auto lock = std::scoped_lock{mutex};
         node_stopped = stopped;
      }
      if (node_stopped) {
         try {
            connection.session.cancel();
         } catch (...) {
         }
         co_return;
      }
      auto remote = connection.peer;
      auto session = std::make_shared<session_state>();
      session->info = node::session_info{
          .remote_peer = remote,
          .path = path::kind::direct,
      };
      session->authentication = connection.authentication;
      session->connection = std::move(connection.session);
      session->resource = std::move(reservation);
      session->native_lifetime = std::move(connection.native_lifetime);
      session->direct_endpoint = connection.local_endpoint;
      session->remote_endpoint = connection.remote_endpoint;
      co_await remember_session(session, connection_manager::direction::inbound);
      launch_session_accept_loop(session);
      launch_identify(session);
      co_await announce_pubsub_subscriptions(remote);
   } catch (const forge::exceptions::base& error) {
      const auto kind = p2p_code(error);
      auto lock = std::scoped_lock{mutex};
      if (!detail::suppress_inbound_handshake_failure(kind, stopped)) {
         ++metrics_value.handshakes_failed;
      }
   } catch (const std::exception&) {
      // The listener owns detached accepts; failed handshakes are reflected in metrics.
      auto lock = std::scoped_lock{mutex};
      ++metrics_value.handshakes_failed;
   } catch (...) {
      // The listener owns detached accepts; failed handshakes are reflected in metrics.
      auto lock = std::scoped_lock{mutex};
      ++metrics_value.handshakes_failed;
   }
   co_return;
}

void node::impl::launch_session_accept_loop(std::shared_ptr<node::impl::session_state> session) {
   auto self = shared_from_this();
   static_cast<void>(launch_tracked([self, session = std::move(session)]() mutable -> asio::awaitable<void> {
      while (true) {
         {
            auto lock = std::scoped_lock{self->mutex};
            if (self->stopped || session->closed) {
               co_return;
            }
         }
         try {
            auto stream = co_await session->connection.async_accept_stream();
            auto reservation =
                self->resources.reserve_stream(session->info.remote_peer, resource_manager::session_direction::inbound);
            if (!reservation) {
               stream.cancel();
               auto lock = std::scoped_lock{self->mutex};
               ++self->metrics_value.backpressure_rejections;
               ++self->metrics_value.protocol_rejections;
               continue;
            }
            auto accepted = std::make_shared<forge::net::transport::stream>(std::move(stream));
            auto admission = std::make_shared<resource_manager::stream_reservation>(std::move(*reservation));
            if (!self->launch_tracked([self, session, accepted, admission]() mutable -> asio::awaitable<void> {
                   if (session->info.path == path::kind::relay) {
                      co_await self->handle_relayed_yamux_stream(session, std::move(*accepted), std::move(*admission));
                   } else {
                      co_await self->handle_incoming_stream(session, std::move(*accepted), std::move(*admission));
                   }
                })) {
               accepted->cancel();
            }
         } catch (...) {
            self->forget_session(session);
            co_return;
         }
      }
   }));
}

boost::asio::awaitable<void> node::impl::handle_incoming_stream(std::shared_ptr<node::impl::session_state> session,
                                                                forge::net::transport::stream raw,
                                                                resource_manager::stream_reservation reservation) {
   try {
      auto admitted =
          co_await accept_resource_stream(session->info.remote_peer, std::move(raw), std::move(reservation));
      detail::stream_access::set_authentication(admitted.stream, session->authentication);
      if (admitted.protocol == builtins::ping) {
         co_await handle_ping(std::move(admitted.stream));
      } else if (admitted.protocol == builtins::identify) {
         co_await handle_identify(session, std::move(admitted.stream));
      } else if (admitted.protocol == builtins::identify_push) {
         co_await handle_identify_push(session, std::move(admitted.stream), std::move(admitted.resource));
      } else if (admitted.protocol == builtins::peer_exchange) {
         auto request = co_await peer_exchange_codec::async_read(admitted.stream, codec_for(options));
         if (request.kind != peer_exchange_message::type::peer_exchange_request) {
            FORGE_THROW_EXCEPTION(exceptions::protocol_error, "P2P peer exchange expected request");
         }
         co_await handle_peer_exchange(std::move(admitted.stream), request.request_id, request.max_frame_size);
      } else if (admitted.protocol == builtins::autonat_v2_dial_request) {
         co_await handle_autonat_v2_dial_request(session, std::move(admitted.stream));
      } else if (admitted.protocol == builtins::autonat_v2_dial_back) {
         co_await handle_autonat_v2_dial_back(session, std::move(admitted.stream));
      } else if (admitted.protocol == builtins::autonat_v1) {
         co_await handle_autonat_v1(std::move(admitted.stream));
      } else if (admitted.protocol == builtins::relay_hop) {
         co_await handle_relay_hop(session, std::move(admitted.stream));
      } else if (admitted.protocol == builtins::relay_stop) {
         co_await handle_relay_stop(session, std::move(admitted.stream));
      } else if (admitted.protocol == builtins::dcutr) {
         co_await handle_dcutr(session, std::move(admitted.stream));
      } else if (dht_profiles.contains(admitted.protocol)) {
         co_await handle_dht(session, admitted.protocol, std::move(admitted.stream));
      } else if (admitted.protocol == builtins::rendezvous) {
         co_await handle_rendezvous(session, std::move(admitted.stream));
      } else if (admitted.protocol == builtins::meshsub_v11 || admitted.protocol == builtins::meshsub_v10) {
         co_await handle_pubsub(session, std::move(admitted.stream));
      } else {
         auto handler = handler_for(admitted.protocol);
         if (!handler) {
            increment_protocol_rejected();
            FORGE_THROW_EXCEPTION(exceptions::unsupported_protocol, "unsupported negotiated P2P protocol");
         }
         increment_protocol_accepted();
         co_await (*handler)(node::incoming_protocol_stream{
             .session = session_info_for(session),
             .protocol = admitted.protocol,
             .stream = std::move(admitted.stream),
         });
      }
      co_await detail::async_close_unescaped(admitted.resource);
   } catch (const std::exception&) {
      increment_protocol_rejected();
   } catch (...) {
      increment_protocol_rejected();
   }
}

} // namespace forge::net::p2p

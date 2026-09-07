module;

#include <forge/exceptions/macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/compat/move_only_function.hpp>

module forge.net.p2p.node;

import forge.asio.runtime;
import forge.net.p2p.endpoint;
import forge.net.p2p.exceptions;
import forge.net.p2p.identity;
import forge.net.p2p.resource_manager;
import forge.multiformats.exceptions;
import forge.multiformats.types;
import forge.multiformats.varint;
import forge.multiformats.multicodec;
import forge.multiformats.multihash;
import forge.multiformats.multibase;
import forge.multiformats.multiaddr;
import forge.net.quic.connection;
import forge.net.quic.connector;
import forge.net.quic.endpoint;
import forge.net.quic.exceptions;
import forge.net.quic.listener;
import forge.net.quic.options;
import forge.net.quic.security;
import forge.net.quic.transport;
import forge.net.transport.limits;
import forge.net.transport.session;

#include "details/direct_transport.hxx"
#include "details/direct_transport_quic.hxx"
#include "details/cancellation_latch.hxx"
#include "details/connection_gate.hxx"
#include "details/owner_cancellation.hxx"
#include "details/quic_client_token_cache.hxx"
#include "details/quic_client_options.hxx"

namespace forge::net::p2p::direct {

void detail::pending_quic_connection::install(forge::net::quic::connection value) noexcept {
   const auto lock = std::scoped_lock{mutex_};
   value_.emplace(std::move(value));
}

forge::net::quic::connection* detail::pending_quic_connection::get() noexcept {
   const auto lock = std::scoped_lock{mutex_};
   return value_ ? &*value_ : nullptr;
}

forge::net::quic::connection detail::pending_quic_connection::take() noexcept {
   const auto lock = std::scoped_lock{mutex_};
   if (!value_) {
      return {};
   }
   auto result = std::move(*value_);
   value_.reset();
   return result;
}

void detail::pending_quic_connection::request_cancel() noexcept {
   const auto lock = std::scoped_lock{mutex_};
   if (value_) {
      value_->request_cancel();
   }
}

namespace {

[[nodiscard]] forge::net::quic::transport_limits quic_limits(const forge::net::transport::limits& value) noexcept {
   return forge::net::quic::transport_limits{
       .max_connections = value.max_connections,
       .max_streams_per_connection = value.max_streams_per_connection,
       .max_queued_bytes = value.max_queued_bytes,
       .max_inbound_queued_bytes = value.max_inbound_queued_bytes,
       .max_inbound_queued_packets = value.max_inbound_queued_packets,
       .max_frame_size = value.max_frame_size,
   };
}

[[nodiscard]] forge::net::quic::endpoint quic_endpoint_for(const forge::net::p2p::endpoint& value) {
   if (!value.is_direct_quic()) {
      FORGE_THROW_EXCEPTION(exceptions::unsupported_protocol, "P2P endpoint is not a direct QUIC endpoint");
   }
   return forge::net::quic::from_transport_endpoint(value.transport);
}

[[nodiscard]] forge::net::p2p::endpoint p2p_endpoint_for(const forge::net::quic::endpoint& value) {
   return forge::net::p2p::endpoint{.transport = forge::net::quic::to_transport_endpoint(value)};
}

[[nodiscard]] std::string listener_key(forge::net::p2p::endpoint value) {
   value.peer.reset();
   return value.to_string();
}

[[nodiscard]] exceptions::code map_quic_error(forge::net::quic::exceptions::code kind) noexcept {
   using quic_kind = forge::net::quic::exceptions::code;
   switch (kind) {
   case quic_kind::invalid_endpoint:
   case quic_kind::invalid_options:
      return exceptions::code::invalid_options;
   case quic_kind::connect_timeout:
   case quic_kind::handshake_timeout:
   case quic_kind::idle_timeout:
      return exceptions::code::timeout;
   case quic_kind::peer_verification_failed:
   case quic_kind::alpn_mismatch:
   case quic_kind::tls_failed:
      return exceptions::code::peer_verification_failed;
   case quic_kind::frame_too_large:
   case quic_kind::malformed_frame:
      return exceptions::code::codec_error;
   case quic_kind::backpressure_rejected:
      return exceptions::code::backpressure_rejected;
   case quic_kind::connection_rejected:
      return exceptions::code::connection_rejected;
   case quic_kind::connection_closed:
   case quic_kind::stream_closed:
   case quic_kind::stream_reset:
      return exceptions::code::closed;
   case quic_kind::canceled:
      return exceptions::code::canceled;
   case quic_kind::dependency_unavailable:
   case quic_kind::internal:
   case quic_kind::unsupported:
      return exceptions::code::internal;
   }
   return exceptions::code::internal;
}

[[noreturn]] void rethrow_quic_as_p2p(const forge::exceptions::base& error) {
   const auto code = forge::net::quic::exceptions::code_of(error);
   if (code) {
      FORGE_THROW_CODE(map_quic_error(*code), error.what());
   }
   throw;
}

[[nodiscard]] peer_id insecure_legacy_peer_id(std::span<const std::uint8_t> der) {
   return peer_id::from_bytes(forge::multiformats::multihash::sha2_256(der).encode());
}

[[nodiscard]] peer_id strict_peer_id_from_certificate_der(std::span<const std::uint8_t> der) {
   try {
      return make_peer_id_from_certificate_der(der);
   } catch (const forge::exceptions::base&) {
      FORGE_THROW_EXCEPTION(exceptions::peer_verification_failed,
                            "P2P peer certificate is missing a valid signed libp2p identity extension");
   }
}

[[nodiscard]] peer_id verified_peer_id_for(const forge::net::quic::connection& connection,
                                           const std::optional<peer_id>& expected, bool insecure_test_mode) {
   if (insecure_test_mode) {
      if (expected) {
         return *expected;
      }
      if (const auto certificate = connection.peer_certificate()) {
         try {
            return make_peer_id_from_certificate_der(certificate->der);
         } catch (const forge::exceptions::base&) {
            // Insecure test mode still accepts legacy certificates without the libp2p extension.
         }
         return insecure_legacy_peer_id(certificate->der);
      }
      FORGE_THROW_EXCEPTION(exceptions::peer_verification_failed,
                            "P2P insecure QUIC test session has no peer certificate");
   }

   const auto certificate = connection.peer_certificate();
   if (!certificate) {
      FORGE_THROW_EXCEPTION(exceptions::peer_verification_failed, "P2P session has no verified peer certificate");
   }
   const auto remote = strict_peer_id_from_certificate_der(certificate->der);
   if (expected && remote != *expected) {
      FORGE_THROW_EXCEPTION(exceptions::peer_verification_failed, "P2P peer id does not match expected peer");
   }
   return remote;
}

[[nodiscard]] std::optional<peer_id> expected_peer_for(const forge::net::p2p::endpoint& endpoint,
                                                       const node::connect_options& options) {
   if (options.expected_peer) {
      return options.expected_peer;
   }
   return endpoint.peer;
}

class quic_profile final {
   struct listener_entry {
      std::shared_ptr<forge::net::quic::listener> value;
      std::shared_ptr<void> native_lifetime;
      forge::net::p2p::endpoint local;
      bool active = true;
   };

 public:
   quic_profile(forge::asio::runtime& runtime_value, const node::options& options_value,
                resource_manager resources_value, std::shared_ptr<forge::net::p2p::detail::connection_gate> gate)
       : runtime_(runtime_value), options_(options_value), resources_(std::move(resources_value)),
         gate_(std::move(gate)),
         client_tokens_(std::make_shared<detail::quic_client_token_cache>(options_value.peer_state.max_peers)) {}

   [[nodiscard]] bool supports(const forge::net::p2p::endpoint& endpoint) const noexcept {
      return endpoint.is_direct_quic();
   }

   [[nodiscard]] bool listening() const noexcept {
      auto lock = std::scoped_lock{listeners_mutex_};
      return std::ranges::any_of(listeners_, [](const auto& item) { return item.second.active; });
   }

   [[nodiscard]] std::vector<forge::net::p2p::endpoint> local_endpoints() const {
      auto out = std::vector<forge::net::p2p::endpoint>{};
      auto lock = std::scoped_lock{listeners_mutex_};
      out.reserve(listeners_.size());
      for (const auto& [_, listener] : listeners_) {
         if (listener.active) {
            out.push_back(listener.local);
         }
      }
      return out;
   }

   forge::net::p2p::endpoint listen(forge::net::p2p::endpoint endpoint) {
      if (!endpoint.is_direct_quic()) {
         FORGE_THROW_EXCEPTION(exceptions::unsupported_protocol, "P2P endpoint is not a direct QUIC endpoint");
      }
      const auto requested_key = listener_key(endpoint);
      {
         auto lock = std::scoped_lock{listeners_mutex_};
         if (listeners_stopped_) {
            FORGE_THROW_EXCEPTION(exceptions::closed, "P2P QUIC direct listener is stopped");
         }
         if (endpoint.transport.port != 0) {
            auto found = listeners_.find(requested_key);
            if (found != listeners_.end() && found->second.active) {
               FORGE_THROW_EXCEPTION(exceptions::invalid_options,
                                     "P2P QUIC direct listener endpoint is already active");
            }
         }
      }
      try {
         auto lifecycle = resources_.reserve_lifecycle();
         if (!lifecycle) {
            FORGE_THROW_EXCEPTION(exceptions::backpressure_rejected, "P2P QUIC listener lifecycle limit reached");
         }
         auto descriptor = lifecycle->reserve_file_descriptors(1);
         if (!descriptor) {
            FORGE_THROW_EXCEPTION(exceptions::backpressure_rejected, "P2P QUIC listener file descriptor limit reached");
         }
         auto native_lifetime = std::make_shared<resource_manager::file_descriptor_reservation>(std::move(*descriptor));
         auto listener =
             std::make_shared<forge::net::quic::listener>(runtime_, quic_endpoint_for(endpoint), server_options());
         auto local = p2p_endpoint_for(listener->local_endpoint());
         const auto key = listener_key(local);
         auto stopped = false;
         auto duplicate = false;
         {
            auto lock = std::scoped_lock{listeners_mutex_};
            stopped = listeners_stopped_;
            const auto found = listeners_.find(key);
            duplicate = found != listeners_.end() && found->second.active;
            if (!stopped && !duplicate) {
               listeners_.emplace(
                   key, listener_entry{
                            .value = listener, .native_lifetime = native_lifetime, .local = local, .active = true});
            }
         }
         if (stopped || duplicate) {
            try {
               listener->stop();
            } catch (...) {
            }
         }
         if (stopped) {
            FORGE_THROW_EXCEPTION(exceptions::closed, "P2P QUIC direct listener is stopped");
         }
         if (duplicate) {
            FORGE_THROW_EXCEPTION(exceptions::invalid_options, "P2P QUIC direct listener endpoint is already active");
         }
         return local;
      } catch (const forge::exceptions::base& error) {
         rethrow_quic_as_p2p(error);
      }
   }

   void stop() {
      client_tokens_->close();
      auto listeners = stop_listeners();
      for (const auto& listener : listeners) {
         try {
            listener->stop();
         } catch (...) {
         }
      }
      auto active = std::vector<std::shared_ptr<cancellation_latch>>{};
      {
         auto lock = std::scoped_lock{active_mutex_};
         stopped_ = true;
         for (auto iterator = active_.begin(); iterator != active_.end();) {
            if (auto operation = iterator->lock()) {
               active.push_back(std::move(operation));
               ++iterator;
            } else {
               iterator = active_.erase(iterator);
            }
         }
      }
      for (const auto& operation : active) {
         operation->request_stop();
      }
   }

   boost::asio::awaitable<void> async_stop() {
      stop();
      auto listeners = listener_snapshot();
      for (const auto& listener : listeners) {
         co_await listener->async_stop();
      }
      auto lock = std::scoped_lock{listeners_mutex_};
      listeners_.clear();
   }

   boost::asio::awaitable<connection> async_connect(forge::net::p2p::endpoint endpoint,
                                                    const node::connect_options& options,
                                                    std::shared_ptr<cancellation_latch> cancellation,
                                                    std::shared_ptr<void> native_lifetime,
                                                    authenticated_admission_handler authenticated) {
      auto cancel_current = std::make_shared<cancellation_latch>();
      auto parent_subscription =
          cancellation_latch::subscribe(cancellation, [cancel_current] noexcept { cancel_current->request_stop(); });
      track(cancel_current);
      auto connector = std::make_shared<forge::net::quic::connector>(runtime_);
      auto operation_stop = std::make_shared<forge::net::p2p::detail::worker_stop_bridge>();
      auto stop_requested = std::make_shared<std::atomic_bool>(false);
      auto pending = std::make_shared<detail::pending_quic_connection>();
      cancel_current->arm([operation_stop, stop_requested, pending] noexcept {
         stop_requested->store(true, std::memory_order_release);
         operation_stop->request_stop();
         pending->request_cancel();
      });
      try {
         const auto expected_peer = expected_peer_for(endpoint, options);
         co_await forge::net::p2p::detail::async_run_with_owner_cancellation(
             operation_stop,
             [this, connector, endpoint, options, expected_peer, stop_requested, native_lifetime,
              pending](boost::asio::cancellation_slot) mutable -> boost::asio::awaitable<void> {
                if (stop_requested->load(std::memory_order_acquire)) {
                   FORGE_THROW_EXCEPTION(exceptions::canceled, "P2P QUIC direct connect canceled before start");
                }
                auto client_options = detail::make_quic_client_options(
                    endpoint, expected_peer, options.timeout, quic_limits(options_.transport_limits),
                    options_.certificate_pem, options_.private_key_pem, options_.allow_insecure_test_mode,
                    client_tokens_);
                client_options.connection_lifetime = std::move(native_lifetime);
                pending->install(
                    co_await connector->async_connect(quic_endpoint_for(endpoint), std::move(client_options)));
             });
         auto quic = pending->get();
         if (!quic || stop_requested->load(std::memory_order_acquire)) {
            FORGE_THROW_EXCEPTION(exceptions::canceled, "P2P QUIC direct connect canceled");
         }
         const auto remote = verified_peer_id_for(*quic, expected_peer, options_.allow_insecure_test_mode);
         auto local_endpoint = p2p_endpoint_for(quic->local_endpoint());
         auto remote_endpoint = p2p_endpoint_for(quic->remote_endpoint());
         gate_->secured(connection_direction::outbound, remote, local_endpoint, remote_endpoint);
         if (authenticated) {
            authenticated(remote);
         }
         gate_->upgraded(connection_direction::outbound, remote, local_endpoint, remote_endpoint);
         if (!cancel_current->finish()) {
            pending->request_cancel();
            FORGE_THROW_EXCEPTION(exceptions::canceled, "P2P QUIC direct connect canceled");
         }
         auto promoted = pending->take();
         co_return connection{
             .peer = remote,
             .session = forge::net::quic::as_transport_session(std::move(promoted)),
             .local_endpoint = std::move(local_endpoint),
             .remote_endpoint = std::move(remote_endpoint),
             .authentication =
                 options_.allow_insecure_test_mode ? peer_authentication::unverified : peer_authentication::quic_tls,
         };
      } catch (const forge::exceptions::base& error) {
         pending->request_cancel();
         static_cast<void>(cancel_current->finish());
         rethrow_quic_as_p2p(error);
      } catch (...) {
         pending->request_cancel();
         static_cast<void>(cancel_current->finish());
         throw;
      }
   }

   boost::asio::awaitable<connection> async_accept(forge::net::p2p::endpoint endpoint) {
      try {
         const auto key = listener_key(std::move(endpoint));
         auto listener = std::shared_ptr<forge::net::quic::listener>{};
         {
            auto lock = std::scoped_lock{listeners_mutex_};
            const auto found = listeners_.find(key);
            if (found != listeners_.end() && found->second.active) {
               listener = found->second.value;
            }
         }
         if (!listener) {
            FORGE_THROW_EXCEPTION(exceptions::closed, "P2P QUIC direct listener is not active");
         }
         auto quic = co_await listener->async_accept();
         try {
            if (!listener_is_current(key, listener)) {
               FORGE_THROW_EXCEPTION(exceptions::closed, "P2P QUIC direct listener stopped during accept");
            }
            const auto local_endpoint = p2p_endpoint_for(quic.local_endpoint());
            const auto remote_endpoint = p2p_endpoint_for(quic.remote_endpoint());
            // Apply host policy after native acceptance. Rejecting an Initial
            // in the transport filter only causes QUIC packet retransmission.
            gate_->accept(local_endpoint, remote_endpoint);
            auto admission_token = forge::net::quic::detail::connection_access::take_inbound_admission(quic);
            auto admission =
                std::static_pointer_cast<resource_manager::session_reservation>(std::move(admission_token));
            if (!admission || !admission->active()) {
               FORGE_THROW_EXCEPTION(exceptions::internal, "P2P QUIC connection is missing inbound admission");
            }
            const auto remote = verified_peer_id_for(quic, std::nullopt, options_.allow_insecure_test_mode);
            const auto transition = admission->establish(resource_manager::session_scope{
                .peer = remote,
                .direction = resource_manager::session_direction::inbound,
            });
            if (transition != resource_manager::transition_result::accepted) {
               if (transition != resource_manager::transition_result::policy_rejected) {
                  FORGE_THROW_EXCEPTION(exceptions::internal, "P2P inbound QUIC session resource transition failed");
               }
               FORGE_THROW_EXCEPTION(exceptions::backpressure_rejected,
                                     "P2P established inbound session limit reached");
            }
            gate_->secured(connection_direction::inbound, remote, local_endpoint, remote_endpoint);
            gate_->upgraded(connection_direction::inbound, remote, local_endpoint, remote_endpoint);
            co_return connection{
                .peer = remote,
                .session = forge::net::quic::as_transport_session(std::move(quic)),
                .local_endpoint = std::move(local_endpoint),
                .remote_endpoint = std::move(remote_endpoint),
                .admission = std::move(*admission),
                .authentication =
                    options_.allow_insecure_test_mode ? peer_authentication::unverified : peer_authentication::quic_tls,
            };
         } catch (...) {
            quic.request_cancel();
            throw;
         }
      } catch (const forge::exceptions::base& error) {
         rethrow_quic_as_p2p(error);
      }
   }

 private:
   [[nodiscard]] bool listener_is_current(const std::string& key,
                                          const std::shared_ptr<forge::net::quic::listener>& listener) const {
      auto lock = std::scoped_lock{listeners_mutex_};
      const auto found = listeners_.find(key);
      return !listeners_stopped_ && found != listeners_.end() && found->second.active &&
             found->second.value == listener;
   }

   [[nodiscard]] std::vector<std::shared_ptr<forge::net::quic::listener>> stop_listeners() {
      auto listeners = std::vector<std::shared_ptr<forge::net::quic::listener>>{};
      auto lock = std::scoped_lock{listeners_mutex_};
      listeners_stopped_ = true;
      listeners.reserve(listeners_.size());
      for (auto& [_, listener] : listeners_) {
         listener.active = false;
         listeners.push_back(listener.value);
      }
      return listeners;
   }

   [[nodiscard]] std::vector<std::shared_ptr<forge::net::quic::listener>> listener_snapshot() const {
      auto listeners = std::vector<std::shared_ptr<forge::net::quic::listener>>{};
      auto lock = std::scoped_lock{listeners_mutex_};
      listeners.reserve(listeners_.size());
      for (const auto& [_, listener] : listeners_) {
         listeners.push_back(listener.value);
      }
      return listeners;
   }

   void track(const std::shared_ptr<cancellation_latch>& operation) {
      auto cancel_now = false;
      {
         auto lock = std::scoped_lock{active_mutex_};
         cancel_now = stopped_;
         if (!cancel_now) {
            active_.erase(std::remove_if(active_.begin(), active_.end(),
                                         [](const auto& operation) { return operation.expired(); }),
                          active_.end());
            active_.push_back(operation);
         }
      }
      if (cancel_now) {
         operation->request_stop();
      }
   }

   [[nodiscard]] forge::net::quic::server_options server_options() const {
      return forge::net::quic::server_options{
          .alpn = "libp2p",
          .limits = quic_limits(options_.transport_limits),
          .security = detail::make_quic_peer_verifier({}, options_.allow_insecure_test_mode),
          .certificate_pem = options_.certificate_pem,
          .private_key_pem = options_.private_key_pem,
          .inbound_admission = [resources = resources_]() mutable -> std::shared_ptr<void> {
             auto admission = resources.reserve_session(resource_manager::session_direction::inbound);
             if (!admission) {
                return {};
             }
             return std::make_shared<resource_manager::session_reservation>(std::move(*admission));
          },
      };
   }

   forge::asio::runtime& runtime_;
   const node::options& options_;
   resource_manager resources_;
   std::shared_ptr<forge::net::p2p::detail::connection_gate> gate_;
   mutable std::mutex listeners_mutex_;
   std::map<std::string, listener_entry> listeners_;
   bool listeners_stopped_ = false;
   std::mutex active_mutex_;
   std::vector<std::weak_ptr<cancellation_latch>> active_;
   bool stopped_ = false;
   std::shared_ptr<detail::quic_client_token_cache> client_tokens_;
};

} // namespace

void register_quic_profile(registry& value, forge::asio::runtime& runtime, const node::options& options,
                           resource_manager resources, std::shared_ptr<forge::net::p2p::detail::connection_gate> gate) {
   auto owned = std::make_shared<quic_profile>(runtime, options, std::move(resources), std::move(gate));
   value.add(profile{
       .supports = [owned](const forge::net::p2p::endpoint& endpoint) { return owned->supports(endpoint); },
       .listening = [owned] { return owned->listening(); },
       .local_endpoints = [owned] { return owned->local_endpoints(); },
       .listen = [owned](forge::net::p2p::endpoint endpoint) { return owned->listen(std::move(endpoint)); },
       .stop = [owned] { owned->stop(); },
       .async_stop = [owned] { return owned->async_stop(); },
       .async_connect =
           [owned](forge::net::p2p::endpoint endpoint, const node::connect_options& options,
                   std::shared_ptr<cancellation_latch> cancellation, std::shared_ptr<void> native_lifetime,
                   authenticated_admission_handler authenticated) {
              return owned->async_connect(std::move(endpoint), options, std::move(cancellation),
                                          std::move(native_lifetime), std::move(authenticated));
           },
       .async_accept = [owned](forge::net::p2p::endpoint endpoint) { return owned->async_accept(std::move(endpoint)); },
   });
}

} // namespace forge::net::p2p::direct

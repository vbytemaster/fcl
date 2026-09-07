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
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>

module forge.net.p2p.node;

import forge.asio.runtime;
import forge.crypto.asymmetric;
import forge.net.p2p.endpoint;
import forge.net.p2p.exceptions;
import forge.net.p2p.resource_manager;
import forge.net.p2p.stream;
import forge.net.tcp.connection;
import forge.net.tcp.connector;
import forge.net.tcp.exceptions;
import forge.net.tcp.listener;
import forge.net.stcp.options;
import forge.net.transport.connector;
import forge.net.transport.session;
import forge.net.transport.stream;
import forge.net.yamux.session;

#include "details/direct_transport.hxx"
#include "details/cancellation_latch.hxx"
#include "details/connection_gate.hxx"
#include "details/libp2p_tls.hxx"
#include "details/operation_deadline.hxx"
#include "details/stream_upgrade.hxx"

namespace forge::net::p2p::direct {
namespace {

[[nodiscard]] forge::net::p2p::endpoint p2p_endpoint_for(forge::net::transport::endpoint value) {
   return forge::net::p2p::endpoint{.transport = std::move(value)};
}

[[nodiscard]] std::string listener_key(forge::net::p2p::endpoint value) {
   value.peer.reset();
   return value.to_string();
}

[[nodiscard]] exceptions::code map_tcp_error(forge::net::tcp::exceptions::code kind) noexcept {
   using tcp_kind = forge::net::tcp::exceptions::code;
   switch (kind) {
   case tcp_kind::invalid_endpoint:
   case tcp_kind::invalid_options:
      return exceptions::code::invalid_options;
   case tcp_kind::canceled:
      return exceptions::code::canceled;
   case tcp_kind::closed:
      return exceptions::code::closed;
   case tcp_kind::connect_failed:
      return exceptions::code::peer_not_found;
   case tcp_kind::listen_failed:
   case tcp_kind::accept_failed:
   case tcp_kind::io_error:
      return exceptions::code::internal;
   }
   return exceptions::code::internal;
}

[[noreturn]] void rethrow_tcp_as_p2p(const forge::exceptions::base& error) {
   const auto code = forge::net::tcp::exceptions::code_of(error);
   if (code) {
      FORGE_THROW_CODE(map_tcp_error(*code), error.what());
   }
   throw;
}

[[nodiscard]] std::optional<peer_id> expected_peer_for(const forge::net::p2p::endpoint& endpoint,
                                                       const node::connect_options& options) {
   if (options.expected_peer) {
      return options.expected_peer;
   }
   return endpoint.peer;
}

struct cancel_current_scope {
   std::shared_ptr<cancellation_latch> value;

   ~cancel_current_scope() {
      if (value) {
         static_cast<void>(value->finish());
      }
   }
};

class tcp_profile final {
   struct listener_entry {
      std::shared_ptr<forge::net::tcp::listener> value;
      std::shared_ptr<void> native_lifetime;
      forge::net::p2p::endpoint local;
      bool active = true;
   };

 public:
   tcp_profile(forge::asio::runtime& runtime_value, const node::options& options_value,
               const libp2p_identity_material& identity_value, resource_manager resources_value,
               std::shared_ptr<forge::net::p2p::detail::connection_gate> gate)
       : runtime_(runtime_value), options_(options_value), identity_(identity_value),
         resources_(std::move(resources_value)), gate_(std::move(gate)) {}

   [[nodiscard]] bool supports(const forge::net::p2p::endpoint& endpoint) const noexcept {
      return endpoint.is_direct_tcp();
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
      if (!endpoint.is_direct_tcp()) {
         FORGE_THROW_EXCEPTION(exceptions::unsupported_protocol, "P2P endpoint is not a direct TCP endpoint");
      }
      const auto requested_key = listener_key(endpoint);
      {
         auto lock = std::scoped_lock{listeners_mutex_};
         if (listeners_stopped_) {
            FORGE_THROW_EXCEPTION(exceptions::closed, "P2P TCP direct listener is stopped");
         }
         if (endpoint.transport.port != 0) {
            auto found = listeners_.find(requested_key);
            if (found != listeners_.end() && found->second.active) {
               FORGE_THROW_EXCEPTION(exceptions::invalid_options, "P2P TCP direct listener endpoint is already active");
            }
         }
      }
      try {
         auto lifecycle = resources_.reserve_lifecycle();
         if (!lifecycle) {
            FORGE_THROW_EXCEPTION(exceptions::backpressure_rejected, "P2P TCP listener lifecycle limit reached");
         }
         auto descriptor = lifecycle->reserve_file_descriptors(1);
         if (!descriptor) {
            FORGE_THROW_EXCEPTION(exceptions::backpressure_rejected, "P2P TCP listener file descriptor limit reached");
         }
         auto native_lifetime = std::make_shared<resource_manager::file_descriptor_reservation>(std::move(*descriptor));
         auto listener =
             std::make_shared<forge::net::tcp::listener>(runtime_.context().get_executor(), endpoint.transport);
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
               listener->close();
            } catch (...) {
            }
         }
         if (stopped) {
            FORGE_THROW_EXCEPTION(exceptions::closed, "P2P TCP direct listener is stopped");
         }
         if (duplicate) {
            FORGE_THROW_EXCEPTION(exceptions::invalid_options, "P2P TCP direct listener endpoint is already active");
         }
         return local;
      } catch (const forge::exceptions::base& error) {
         rethrow_tcp_as_p2p(error);
      }
   }

   void stop() {
      auto listeners = stop_listeners();
      for (const auto& listener : listeners) {
         try {
            listener->close();
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
         co_await listener->async_close();
      }
      auto lock = std::scoped_lock{listeners_mutex_};
      listeners_.clear();
   }

   boost::asio::awaitable<connection> async_connect(forge::net::p2p::endpoint endpoint,
                                                    const node::connect_options& options,
                                                    std::shared_ptr<cancellation_latch> cancellation,
                                                    std::shared_ptr<void> native_lifetime,
                                                    authenticated_admission_handler authenticated) {
      if (!endpoint.is_direct_tcp()) {
         FORGE_THROW_EXCEPTION(exceptions::unsupported_protocol, "P2P endpoint is not a direct TCP endpoint");
      }
      auto expected_peer = expected_peer_for(endpoint, options);
      auto remote_transport = endpoint.transport;
      auto connector = forge::net::tcp::connector{runtime_.context().get_executor()};
      auto cancel_current = std::make_shared<cancellation_latch>();
      auto parent_subscription =
          cancellation_latch::subscribe(cancellation, [cancel_current] noexcept { cancel_current->request_stop(); });
      track(cancel_current);
      cancel_current->arm([&connector] noexcept { connector.request_cancel(); });
      auto deadline = operation_deadline{runtime_.context(), options.timeout};
      auto cancel_scope = cancel_current_scope{cancel_current};
      deadline.arm([cancel_current] noexcept { cancel_current->request_stop(); });
      try {
         auto tcp = std::make_shared<forge::net::tcp::connection>(
             co_await connector.async_connect_connection(std::move(remote_transport), {}, std::move(native_lifetime)));
         cancel_current->arm([tcp] noexcept { tcp->request_cancel(); });
         const auto local_endpoint = p2p_endpoint_for(tcp->local_endpoint());
         const auto remote_endpoint = p2p_endpoint_for(tcp->remote_endpoint());
         cancel_current->clear();
         auto upgraded = co_await upgrade_outbound_tcp(
             std::move(*tcp), options_, identity_, std::move(expected_peer),
             tcp_upgrade_deadline{
                 .context = &runtime_.context(), .timeout = options.timeout, .cancel_current = cancel_current},
             upgrade_callbacks{
                 .secured =
                     [gate = gate_, local_endpoint, remote_endpoint](const peer_id& peer) {
                        gate->secured(connection_direction::outbound, peer, local_endpoint, remote_endpoint);
                     },
                 .established = std::move(authenticated),
                 .upgraded =
                     [gate = gate_, local_endpoint, remote_endpoint](const peer_id& peer) {
                        gate->upgraded(connection_direction::outbound, peer, local_endpoint, remote_endpoint);
                     },
             });
         const auto deadline_completed = deadline.finish();
         const auto operation_completed = cancel_current->finish();
         if (!deadline_completed || !operation_completed) {
            upgraded.session->cancel();
         }
         if (!deadline_completed) {
            throw_operation_timeout("P2P TCP direct connect");
         }
         if (!operation_completed) {
            FORGE_THROW_EXCEPTION(exceptions::canceled, "P2P TCP direct connect canceled");
         }
         co_return connection{
             .peer = std::move(upgraded.peer),
             .session = std::move(*upgraded.session).as_transport(),
             .local_endpoint = std::move(local_endpoint),
             .remote_endpoint = std::move(remote_endpoint),
             .authentication = upgraded.authentication,
         };
      } catch (const forge::exceptions::base& error) {
         if (deadline.timed_out()) {
            throw_operation_timeout("P2P TCP direct connect");
         }
         if (cancel_current->stop_requested()) {
            if (!cancel_current->finish()) {
               FORGE_THROW_EXCEPTION(exceptions::canceled, "P2P TCP direct connect canceled");
            }
         } else {
            cancel_current->request_stop();
            static_cast<void>(cancel_current->finish());
         }
         rethrow_tcp_as_p2p(error);
      }
   }

   boost::asio::awaitable<connection> async_accept(forge::net::p2p::endpoint endpoint) {
      const auto key = listener_key(std::move(endpoint));
      auto listener = std::shared_ptr<forge::net::tcp::listener>{};
      {
         auto lock = std::scoped_lock{listeners_mutex_};
         const auto found = listeners_.find(key);
         if (found != listeners_.end() && found->second.active) {
            listener = found->second.value;
         }
      }
      if (!listener || !listener->valid()) {
         FORGE_THROW_EXCEPTION(exceptions::closed, "P2P TCP direct listener is not active");
      }
      try {
         // The terminal worker retains this holder across TCP/STCP handoff, but
         // it starts empty so an idle accept does not consume session or FD
         // budget before the kernel has produced a connection.
         auto native_lifetime =
             std::make_shared<std::optional<resource_manager::file_descriptor_reservation>>();
         auto tcp =
             std::make_shared<forge::net::tcp::connection>(co_await listener->async_accept_connection(native_lifetime));
         try {
            if (!listener_is_current(key, listener)) {
               FORGE_THROW_EXCEPTION(exceptions::closed, "P2P TCP direct listener stopped during accept");
            }
            const auto local_endpoint = p2p_endpoint_for(tcp->local_endpoint());
            const auto remote_endpoint = p2p_endpoint_for(tcp->remote_endpoint());
            gate_->accept(local_endpoint, remote_endpoint);
            auto admission = resources_.reserve_session(resource_manager::session_direction::inbound);
            if (!admission) {
               FORGE_THROW_EXCEPTION(exceptions::backpressure_rejected, "P2P inbound session limit reached");
            }
            auto descriptor = admission->reserve_file_descriptors(1);
            if (!descriptor) {
               FORGE_THROW_EXCEPTION(exceptions::backpressure_rejected, "P2P inbound TCP file descriptor limit reached");
            }
            native_lifetime->emplace(std::move(*descriptor));
            auto cancel_current = std::make_shared<cancellation_latch>();
            track(cancel_current);
            cancel_current->arm([tcp] noexcept { tcp->request_cancel(); });
            auto deadline = operation_deadline{runtime_.context(), node::connect_options{}.timeout};
            auto cancel_scope = cancel_current_scope{cancel_current};
            deadline.arm([cancel_current] noexcept { cancel_current->request_stop(); });
            auto upgraded = upgraded_session{};
            try {
               cancel_current->clear();
               upgraded = co_await upgrade_inbound_tcp(
                   std::move(*tcp), options_, identity_, std::nullopt,
                   tcp_upgrade_deadline{.context = &runtime_.context(),
                                        .timeout = node::connect_options{}.timeout,
                                        .cancel_current = cancel_current},
                   upgrade_callbacks{
                       .secured =
                           [gate = gate_, local_endpoint, remote_endpoint](const peer_id& peer) {
                              gate->secured(connection_direction::inbound, peer, local_endpoint, remote_endpoint);
                           },
                       .established =
                           [&admission](const peer_id& peer) {
                              const auto transition = admission->establish(resource_manager::session_scope{
                                  .peer = peer,
                                  .direction = resource_manager::session_direction::inbound,
                              });
                              if (transition != resource_manager::transition_result::accepted) {
                                 if (transition != resource_manager::transition_result::policy_rejected) {
                                    FORGE_THROW_EXCEPTION(exceptions::internal,
                                                          "P2P inbound TCP session resource transition failed");
                                 }
                                 FORGE_THROW_EXCEPTION(exceptions::backpressure_rejected,
                                                       "P2P established inbound session limit reached");
                              }
                           },
                       .upgraded =
                           [gate = gate_, local_endpoint, remote_endpoint](const peer_id& peer) {
                              gate->upgraded(connection_direction::inbound, peer, local_endpoint, remote_endpoint);
                           },
                   });
               const auto deadline_completed = deadline.finish();
               const auto operation_completed = cancel_current->finish();
               if (!deadline_completed || !operation_completed) {
                  upgraded.session->cancel();
               }
               if (!deadline_completed) {
                  throw_operation_timeout("P2P TCP direct accept");
               }
               if (!operation_completed) {
                  FORGE_THROW_EXCEPTION(exceptions::canceled, "P2P TCP direct accept canceled");
               }
            } catch (const forge::exceptions::base&) {
               if (deadline.timed_out()) {
                  throw_operation_timeout("P2P TCP direct accept");
               }
               if (!cancel_current->finish()) {
                  FORGE_THROW_EXCEPTION(exceptions::canceled, "P2P TCP direct accept canceled");
               }
               throw;
            }
            co_return connection{
                .peer = std::move(upgraded.peer),
                .session = std::move(*upgraded.session).as_transport(),
                .local_endpoint = std::move(local_endpoint),
                .remote_endpoint = std::move(remote_endpoint),
                .admission = std::move(admission),
                .native_lifetime = std::move(native_lifetime),
                .authentication = upgraded.authentication,
            };
         } catch (...) {
            tcp->request_cancel();
            throw;
         }
      } catch (const forge::exceptions::base& error) {
         rethrow_tcp_as_p2p(error);
      }
   }

 private:
   [[nodiscard]] bool listener_is_current(const std::string& key,
                                          const std::shared_ptr<forge::net::tcp::listener>& listener) const {
      auto lock = std::scoped_lock{listeners_mutex_};
      const auto found = listeners_.find(key);
      return !listeners_stopped_ && found != listeners_.end() && found->second.active &&
             found->second.value == listener;
   }

   [[nodiscard]] std::vector<std::shared_ptr<forge::net::tcp::listener>> stop_listeners() {
      auto listeners = std::vector<std::shared_ptr<forge::net::tcp::listener>>{};
      auto lock = std::scoped_lock{listeners_mutex_};
      listeners_stopped_ = true;
      listeners.reserve(listeners_.size());
      for (auto& [_, listener] : listeners_) {
         listener.active = false;
         listeners.push_back(listener.value);
      }
      return listeners;
   }

   [[nodiscard]] std::vector<std::shared_ptr<forge::net::tcp::listener>> listener_snapshot() const {
      auto listeners = std::vector<std::shared_ptr<forge::net::tcp::listener>>{};
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

   forge::asio::runtime& runtime_;
   const node::options& options_;
   const libp2p_identity_material& identity_;
   resource_manager resources_;
   std::shared_ptr<forge::net::p2p::detail::connection_gate> gate_;
   mutable std::mutex listeners_mutex_;
   std::map<std::string, listener_entry> listeners_;
   bool listeners_stopped_ = false;
   std::mutex active_mutex_;
   std::vector<std::weak_ptr<cancellation_latch>> active_;
   bool stopped_ = false;
};

} // namespace

void register_tcp_profile(registry& value, forge::asio::runtime& runtime, const node::options& options,
                          const libp2p_identity_material& identity, resource_manager resources,
                          std::shared_ptr<forge::net::p2p::detail::connection_gate> gate) {
   auto owned = std::make_shared<tcp_profile>(runtime, options, identity, std::move(resources), std::move(gate));
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

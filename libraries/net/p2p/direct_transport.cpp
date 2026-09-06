module;

#include <forge/exceptions/macros.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <memory>
#include <ranges>
#include <utility>
#include <vector>

#include <boost/asio/awaitable.hpp>

module forge.net.p2p.node;

import forge.asio.runtime;
import forge.net.p2p.endpoint;
import forge.net.p2p.exceptions;
import forge.net.p2p.resource_manager;
import forge.net.transport.session;

#include "details/direct_transport.hxx"
#include "details/connection_gate.hxx"

namespace forge::net::p2p::direct {
namespace {

[[nodiscard]] profile& profile_for(std::vector<profile>& profiles, const forge::net::p2p::endpoint& endpoint) {
   for (auto& candidate : profiles) {
      if (candidate.supports(endpoint)) {
         return candidate;
      }
   }
   FORGE_THROW_EXCEPTION(exceptions::unsupported_protocol, "unsupported P2P direct transport");
}

} // namespace

struct registry::state {
   std::vector<profile> profiles;
};

registry::registry(forge::asio::runtime& runtime, const node::options& options,
                   const libp2p_identity_material& identity, resource_manager resources,
                   std::shared_ptr<forge::net::p2p::detail::connection_gate> gate)
    : state_(std::make_unique<state>()) {
   if (!gate) {
      gate = std::make_shared<forge::net::p2p::detail::connection_gate>(nullptr);
   }
   register_quic_profile(*this, runtime, options, resources, gate);
   register_tcp_profile(*this, runtime, options, identity, std::move(resources), std::move(gate));
}

registry::~registry() = default;

bool registry::listening() const noexcept {
   return state_ && std::ranges::any_of(state_->profiles, [](const profile& value) { return value.listening(); });
}

std::optional<forge::net::p2p::endpoint> registry::local_endpoint() const {
   auto endpoints = local_endpoints();
   if (endpoints.empty()) {
      return std::nullopt;
   }
   return endpoints.front();
}

std::vector<forge::net::p2p::endpoint> registry::local_endpoints() const {
   auto out = std::vector<forge::net::p2p::endpoint>{};
   if (!state_) {
      return out;
   }
   for (const auto& value : state_->profiles) {
      auto endpoints = value.local_endpoints();
      out.insert(out.end(), std::make_move_iterator(endpoints.begin()), std::make_move_iterator(endpoints.end()));
   }
   return out;
}

void registry::add(profile value) {
   if (!value.supports || !value.listening || !value.local_endpoints || !value.listen || !value.stop ||
       !value.async_stop || !value.async_connect || !value.async_accept) {
      FORGE_THROW_EXCEPTION(exceptions::invalid_options, "P2P direct transport profile is empty");
   }
   state_->profiles.push_back(std::move(value));
}

forge::net::p2p::endpoint registry::listen(forge::net::p2p::endpoint endpoint) {
   const auto requested = endpoint.to_string();
   const auto existing = local_endpoints();
   if (std::ranges::any_of(existing, [&](const auto& value) { return value.to_string() == requested; })) {
      FORGE_THROW_EXCEPTION(exceptions::invalid_options, "P2P direct listener endpoint is already active");
   }
   auto& selected = profile_for(state_->profiles, endpoint);
   return selected.listen(std::move(endpoint));
}

void registry::stop() noexcept {
   if (!state_) {
      return;
   }
   for (auto& value : state_->profiles) {
      try {
         value.stop();
      } catch (...) {
         // Teardown cancellation is best effort and must reach every transport.
      }
   }
}

detail::session_teardown::operation registry::teardown_operation() const {
   auto close_profiles = state_ ? state_->profiles : std::vector<profile>{};
   auto cancel_profiles = close_profiles;
   return detail::session_teardown::operation{
       .close = [profiles = std::move(close_profiles)]() mutable -> boost::asio::awaitable<void> {
          for (auto& value : profiles) {
             try {
                co_await value.async_stop();
             } catch (...) {
                // A failed backend must not bypass the remaining teardown operations.
             }
          }
       },
       .cancel =
           [profiles = std::move(cancel_profiles)]() mutable noexcept {
              for (auto& value : profiles) {
                 try {
                    value.stop();
                 } catch (...) {
                 }
              }
           },
   };
}

boost::asio::awaitable<connection> registry::async_connect(forge::net::p2p::endpoint endpoint,
                                                           const node::connect_options& options,
                                                           std::shared_ptr<cancellation_latch> cancellation,
                                                           std::shared_ptr<void> native_lifetime) {
   auto& selected = profile_for(state_->profiles, endpoint);
   co_return co_await selected.async_connect(std::move(endpoint), options, std::move(cancellation),
                                             std::move(native_lifetime));
}

boost::asio::awaitable<connection> registry::async_accept(forge::net::p2p::endpoint endpoint) {
   auto& selected = profile_for(state_->profiles, endpoint);
   co_return co_await selected.async_accept(std::move(endpoint));
}

} // namespace forge::net::p2p::direct

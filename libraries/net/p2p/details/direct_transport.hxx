#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <vector>

#include <boost/asio/awaitable.hpp>

#include "session_teardown.hxx"

namespace forge::net::p2p {

class cancellation_latch;
struct libp2p_identity_material;

} // namespace forge::net::p2p

namespace forge::net::p2p::detail {
class connection_gate;
}

namespace forge::net::p2p::direct {

struct connection {
   peer_id peer;
   forge::net::transport::session session;
   std::optional<forge::net::p2p::endpoint> local_endpoint;
   std::optional<forge::net::p2p::endpoint> remote_endpoint;
   std::optional<resource_manager::session_reservation> admission;
   std::shared_ptr<void> native_lifetime;
   peer_authentication authentication = peer_authentication::unverified;
};

struct profile {
   std::function<bool(const forge::net::p2p::endpoint&)> supports;
   std::function<bool()> listening;
   std::function<std::vector<forge::net::p2p::endpoint>()> local_endpoints;
   std::function<forge::net::p2p::endpoint(forge::net::p2p::endpoint)> listen;
   std::function<void()> stop;
   std::function<boost::asio::awaitable<void>()> async_stop;
   std::function<boost::asio::awaitable<connection>(forge::net::p2p::endpoint, const node::connect_options&,
                                                    std::shared_ptr<forge::net::p2p::cancellation_latch>,
                                                    std::shared_ptr<void>)>
       async_connect;
   std::function<boost::asio::awaitable<connection>(forge::net::p2p::endpoint)> async_accept;
};

class registry {
 public:
   registry(forge::asio::runtime& runtime, const node::options& options, const libp2p_identity_material& identity,
            resource_manager resources, std::shared_ptr<forge::net::p2p::detail::connection_gate> gate = {});
   ~registry();

   registry(const registry&) = delete;
   registry& operator=(const registry&) = delete;

   [[nodiscard]] bool listening() const noexcept;
   [[nodiscard]] std::optional<forge::net::p2p::endpoint> local_endpoint() const;
   [[nodiscard]] std::vector<forge::net::p2p::endpoint> local_endpoints() const;

   void add(profile value);
   [[nodiscard]] forge::net::p2p::endpoint listen(forge::net::p2p::endpoint endpoint);
   void stop() noexcept;
   [[nodiscard]] forge::net::p2p::detail::session_teardown::operation teardown_operation() const;

   boost::asio::awaitable<connection>
   async_connect(forge::net::p2p::endpoint endpoint, const node::connect_options& options,
                 std::shared_ptr<forge::net::p2p::cancellation_latch> cancellation = {},
                 std::shared_ptr<void> native_lifetime = {});
   boost::asio::awaitable<connection> async_accept(forge::net::p2p::endpoint endpoint);

 private:
   struct state;
   std::unique_ptr<state> state_;
};

void register_quic_profile(registry& value, forge::asio::runtime& runtime, const node::options& options,
                           resource_manager resources, std::shared_ptr<forge::net::p2p::detail::connection_gate> gate);
void register_tcp_profile(registry& value, forge::asio::runtime& runtime, const node::options& options,
                          const libp2p_identity_material& identity, resource_manager resources,
                          std::shared_ptr<forge::net::p2p::detail::connection_gate> gate);

} // namespace forge::net::p2p::direct

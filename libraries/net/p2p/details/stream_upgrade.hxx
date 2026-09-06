#pragma once

#include <chrono>
#include <functional>
#include <memory>
#include <optional>

#include <boost/asio/awaitable.hpp>

namespace forge::net::p2p {

struct libp2p_identity_material;
class cancellation_latch;

struct upgraded_session {
   peer_id peer;
   std::shared_ptr<forge::net::yamux::session> session;
   peer_authentication authentication = peer_authentication::unverified;
};

struct upgrade_callbacks {
   std::function<void(const peer_id&)> secured;
   std::function<void(const peer_id&)> established;
   std::function<void(const peer_id&)> upgraded;
};

boost::asio::awaitable<upgraded_session> upgrade_outbound_stream(forge::net::p2p::stream stream,
                                                                 const node::options& options,
                                                                 const libp2p_identity_material& identity,
                                                                 std::optional<peer_id> expected_peer,
                                                                 upgrade_callbacks callbacks = {});

boost::asio::awaitable<upgraded_session> upgrade_inbound_stream(forge::net::p2p::stream stream,
                                                                const node::options& options,
                                                                const libp2p_identity_material& identity,
                                                                std::optional<peer_id> expected_peer,
                                                                upgrade_callbacks callbacks = {});

struct tcp_upgrade_deadline {
   boost::asio::io_context* context = nullptr;
   std::chrono::milliseconds timeout{0};
   std::shared_ptr<cancellation_latch> cancel_current;
};

boost::asio::awaitable<upgraded_session> upgrade_outbound_tcp(forge::net::tcp::connection connection,
                                                              const node::options& options,
                                                              const libp2p_identity_material& identity,
                                                              std::optional<peer_id> expected_peer);

boost::asio::awaitable<upgraded_session> upgrade_inbound_tcp(forge::net::tcp::connection connection,
                                                             const node::options& options,
                                                             const libp2p_identity_material& identity,
                                                             std::optional<peer_id> expected_peer);

boost::asio::awaitable<upgraded_session>
upgrade_outbound_tcp(forge::net::tcp::connection connection, const node::options& options,
                     const libp2p_identity_material& identity, std::optional<peer_id> expected_peer,
                     tcp_upgrade_deadline deadline, upgrade_callbacks callbacks = {});

boost::asio::awaitable<upgraded_session>
upgrade_inbound_tcp(forge::net::tcp::connection connection, const node::options& options,
                    const libp2p_identity_material& identity, std::optional<peer_id> expected_peer,
                    tcp_upgrade_deadline deadline, upgrade_callbacks callbacks = {});

} // namespace forge::net::p2p

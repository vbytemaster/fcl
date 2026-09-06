#pragma once

namespace forge::net::p2p {

struct libp2p_identity_material;
struct upgraded_session;
struct upgrade_callbacks;

boost::asio::awaitable<upgraded_session> upgrade_relay_outbound_session(forge::net::p2p::stream stream,
                                                                        const node::options& options,
                                                                        const libp2p_identity_material& identity,
                                                                        const peer_id& expected_peer,
                                                                        upgrade_callbacks callbacks);

boost::asio::awaitable<upgraded_session> upgrade_relay_inbound_session(forge::net::p2p::stream stream,
                                                                       const node::options& options,
                                                                       const libp2p_identity_material& identity,
                                                                       const peer_id& expected_peer,
                                                                       upgrade_callbacks callbacks);

} // namespace forge::net::p2p

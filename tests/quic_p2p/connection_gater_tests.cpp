module;

#include <boost/test/unit_test.hpp>

#include <string>

module forge.net.p2p.node;

import forge.net.p2p.connection_gater;

namespace forge::net::p2p {
namespace {

class allowing_gater final : public connection_gater {};

class peer_denying_gater final : public connection_gater {
 public:
   bool intercept_peer_dial(const peer_id& peer) noexcept override {
      return peer.value != "denied";
   }
};

} // namespace

BOOST_AUTO_TEST_SUITE(connection_gater_tests)

BOOST_AUTO_TEST_CASE(connection_gater_allows_every_stage_by_default) {
   auto gater = allowing_gater{};
   const auto peer = peer_id{.value = "peer"};
   const auto endpoint = forge::net::p2p::endpoint{};
   const auto endpoints = connection_endpoints{.local = endpoint, .remote = endpoint};

   BOOST_CHECK(gater.intercept_peer_dial(peer));
   BOOST_CHECK(gater.intercept_address_dial(peer, endpoint));
   BOOST_CHECK(gater.intercept_accept(endpoints));
   BOOST_CHECK(gater.intercept_secured(connection_direction::inbound, peer, endpoints));
   BOOST_CHECK(gater.intercept_upgraded(connection_direction::outbound, peer, endpoints));
}

BOOST_AUTO_TEST_CASE(connection_gater_supports_single_stage_override) {
   auto gater = peer_denying_gater{};

   BOOST_CHECK(gater.intercept_peer_dial(peer_id{.value = "allowed"}));
   BOOST_CHECK(!gater.intercept_peer_dial(peer_id{.value = "denied"}));
   BOOST_CHECK(gater.intercept_address_dial(peer_id{.value = "denied"}, endpoint{}));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace forge::net::p2p

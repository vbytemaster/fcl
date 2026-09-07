module forge.net.p2p.connection_gater;

namespace forge::net::p2p {

connection_gater::~connection_gater() noexcept = default;

bool connection_gater::intercept_peer_dial(const peer_id&) noexcept {
   return true;
}

bool connection_gater::intercept_address_dial(const peer_id&, const endpoint&) noexcept {
   return true;
}

bool connection_gater::intercept_accept(const connection_endpoints&) noexcept {
   return true;
}

bool connection_gater::intercept_secured(connection_direction, const peer_id&, const connection_endpoints&) noexcept {
   return true;
}

bool connection_gater::intercept_upgraded(connection_direction, const peer_id&, const connection_endpoints&) noexcept {
   return true;
}

} // namespace forge::net::p2p

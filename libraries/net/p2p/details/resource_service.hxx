#pragma once

#include <string>

namespace forge::net::p2p::detail {

[[nodiscard]] std::string resource_service_id(const protocol_id& protocol, bool dht_profile);

} // namespace forge::net::p2p::detail

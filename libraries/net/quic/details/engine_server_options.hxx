#pragma once

extern "C++" {
namespace forge::net::quic::detail {

struct engine_server_options {
   std::string alpn = "forge-p2p/1";
   std::chrono::milliseconds handshake_timeout{10'000};
   std::chrono::milliseconds idle_timeout{30'000};
   engine_transport_limits limits{};
   engine_security_options security{};
   std::string certificate_pem;
   forge::crypto::core::secret_string private_key_pem;
   std::function<bool(const engine_endpoint& local, const engine_endpoint& remote)> inbound_connection_filter;
   std::function<std::shared_ptr<void>()> inbound_admission;
};

} // namespace forge::net::quic::detail
}

#pragma once

extern "C++" {
namespace forge::net::quic::detail {

struct engine_client_options {
   struct token_callbacks {
      std::function<std::optional<std::vector<std::uint8_t>>()> take;
      std::function<void(std::vector<std::uint8_t>)> store;
   };

   std::string alpn = "forge-p2p/1";
   std::chrono::milliseconds connect_timeout{10'000};
   std::chrono::milliseconds handshake_timeout{10'000};
   std::chrono::milliseconds idle_timeout{30'000};
   engine_transport_limits limits{};
   engine_security_options security{};
   std::string certificate_pem;
   forge::crypto::core::secret_string private_key_pem;
   std::optional<token_callbacks> client_tokens;
   std::function<bool(std::string_view)> test_failpoint;
   std::shared_ptr<void> connection_lifetime;
};

} // namespace forge::net::quic::detail
}

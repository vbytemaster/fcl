#pragma once

#include <mutex>
#include <optional>

namespace forge::net::p2p::direct::detail {

// Owns a native QUIC connection until the direct profile promotes it to a
// transport session. Cancellation can race policy checks without post()ing.
struct pending_quic_connection {
   void install(forge::net::quic::connection value) noexcept;
   [[nodiscard]] forge::net::quic::connection* get() noexcept;
   [[nodiscard]] forge::net::quic::connection take() noexcept;
   void request_cancel() noexcept;

 private:
   mutable std::mutex mutex_;
   std::optional<forge::net::quic::connection> value_;
};

} // namespace forge::net::p2p::direct::detail

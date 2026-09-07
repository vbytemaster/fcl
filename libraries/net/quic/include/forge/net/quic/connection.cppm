module;

#include <memory>
#include <optional>

#include <boost/asio/awaitable.hpp>

export module forge.net.quic.connection;

import forge.net.quic.metrics;
import forge.net.quic.security;
export import forge.net.quic.endpoint;
export import forge.net.quic.stream;

export namespace forge::net::quic {

namespace detail {
struct connection_handle;
struct connection_access;
} // namespace detail

class connection {
 public:
   connection();
   ~connection();

   connection(connection&&) noexcept;
   connection& operator=(connection&&) noexcept;

   connection(const connection&) = delete;
   connection& operator=(const connection&) = delete;

   [[nodiscard]] bool valid() const noexcept;
   [[nodiscard]] endpoint local_endpoint() const;
   [[nodiscard]] endpoint remote_endpoint() const;
   [[nodiscard]] connection_metrics metrics() const;
   [[nodiscard]] std::optional<peer_certificate> peer_certificate() const;

   boost::asio::awaitable<stream> async_open_stream();
   boost::asio::awaitable<stream> async_accept_stream();
   boost::asio::awaitable<void> async_close();
   void cancel();
   void request_cancel() noexcept;

 private:
   friend struct detail::connection_access;

   explicit connection(detail::connection_handle handle);

   struct impl;
   std::shared_ptr<impl> impl_;
};

namespace detail {

struct connection_access {
   static connection make(connection_handle handle);
   static std::shared_ptr<void> take_inbound_admission(connection& value) noexcept;
};

} // namespace detail

} // namespace forge::net::quic

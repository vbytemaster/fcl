module;

#include <memory>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>

export module forge.net.tcp.listener;

export import forge.net.tcp.connector;
export import forge.net.transport.listener;

export namespace forge::net::tcp {

class listener {
 public:
   listener();
   listener(boost::asio::any_io_executor executor, transport::endpoint local,
            transport::listen_options listen_options = {}, options tcp_options = {});
   ~listener();

   listener(listener&&) noexcept;
   listener& operator=(listener&&) noexcept;

   listener(const listener&) = delete;
   listener& operator=(const listener&) = delete;

   [[nodiscard]] bool valid() const noexcept;
   [[nodiscard]] transport::endpoint local_endpoint() const;

   boost::asio::awaitable<connection> async_accept_connection(std::shared_ptr<void> lifetime = {});
   boost::asio::awaitable<transport::stream_connection> async_accept();
   boost::asio::awaitable<void> async_close();
   void close();
   void cancel();

   [[nodiscard]] transport::stream_listener as_transport() const;

 private:
   struct impl;
   std::shared_ptr<impl> impl_;
};

} // namespace forge::net::tcp

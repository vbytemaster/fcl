#pragma once

namespace forge::net::yamux {

class session_model final : public transport::detail::session_concept {
 public:
   explicit session_model(session value);

   [[nodiscard]] bool valid() const noexcept override;
   boost::asio::awaitable<transport::stream> async_open_stream() override;
   boost::asio::awaitable<transport::stream> async_accept_stream() override;
   boost::asio::awaitable<void> async_close() override;
   void cancel() override;
   void request_cancel() noexcept override;

 private:
   session value_;
};

} // namespace forge::net::yamux

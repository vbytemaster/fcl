module;

#include <forge/exceptions/macros.hpp>

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>

module forge.net.yamux.session;

import forge.asio.gate;
import forge.asio.notification;

#include "details/session_impl.hxx"
#include "details/session_model.hxx"

namespace forge::net::yamux {

session::session() = default;

session::session(transport::stream stream, side session_side, options session_options)
    : impl_(std::make_shared<impl>(std::move(stream), session_side, session_options)) {}

session::~session() = default;
session::session(session&&) noexcept = default;
session& session::operator=(session&&) noexcept = default;

bool session::valid() const noexcept {
   return impl_ && impl_->valid();
}

boost::asio::awaitable<transport::stream> session::async_open_stream() {
   if (!impl_) {
      FORGE_THROW_EXCEPTION(exceptions::closed, "invalid yamux session");
   }
   co_return co_await impl_->async_open_stream();
}

boost::asio::awaitable<transport::stream> session::async_accept_stream() {
   if (!impl_) {
      FORGE_THROW_EXCEPTION(exceptions::closed, "invalid yamux session");
   }
   co_return co_await impl_->async_accept_stream();
}

boost::asio::awaitable<void> session::async_close() {
   if (!impl_) {
      co_return;
   }
   co_await impl_->async_close();
}

void session::cancel() {
   if (impl_) {
      impl_->cancel();
   }
}

void session::request_cancel() noexcept {
   if (impl_) {
      impl_->request_cancel();
   }
}

transport::session session::as_transport() && {
   return transport::detail::session_access::make(std::make_shared<session_model>(std::move(*this)));
}

transport::session make_session(transport::stream stream, side session_side, options session_options) {
   return session{std::move(stream), session_side, session_options}.as_transport();
}

} // namespace forge::net::yamux

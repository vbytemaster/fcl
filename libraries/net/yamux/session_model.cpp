module;

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

session_model::session_model(session value) : value_(std::move(value)) {}

bool session_model::valid() const noexcept {
   return value_.valid();
}

boost::asio::awaitable<transport::stream> session_model::async_open_stream() {
   co_return co_await value_.async_open_stream();
}

boost::asio::awaitable<transport::stream> session_model::async_accept_stream() {
   co_return co_await value_.async_accept_stream();
}

boost::asio::awaitable<void> session_model::async_close() {
   co_await value_.async_close();
}

void session_model::cancel() {
   value_.cancel();
}

void session_model::request_cancel() noexcept {
   value_.request_cancel();
}

} // namespace forge::net::yamux

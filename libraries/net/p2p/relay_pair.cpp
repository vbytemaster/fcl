module;

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <utility>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/error_code.hpp>

module forge.net.p2p.node;

import forge.net.p2p.identity;
import forge.net.p2p.resource_manager;
import forge.net.p2p.stream;

#include "details/relay_pair.hxx"

namespace forge::net::p2p::detail {

relay_pair::relay_pair(peer_id owner_value, forge::net::p2p::stream left_value, forge::net::p2p::stream right_value,
                       resource_manager::relay_reservation circuit_value, boost::asio::any_io_executor executor,
                       std::chrono::milliseconds duration, std::uint64_t byte_limit)
    : owner(std::move(owner_value)), left(std::move(left_value)), right(std::move(right_value)),
      circuit(std::move(circuit_value)), left_to_right(byte_limit), right_to_left(byte_limit),
      deadline_(std::make_shared<boost::asio::steady_timer>(boost::asio::make_strand(std::move(executor)), duration)) {}

bool relay_pair::mark_finished() noexcept {
   auto complete = false;
   {
      auto lock = std::scoped_lock{mutex_};
      if (finished_ < 2) {
         ++finished_;
      }
      complete = finished_ == 2;
   }
   if (complete) {
      cancel_deadline();
   }
   return complete;
}

boost::asio::awaitable<bool> relay_pair::async_wait_deadline() {
   auto deadline = deadline_;
   co_return co_await boost::asio::co_spawn(
       deadline->get_executor(),
       [this, deadline]() -> boost::asio::awaitable<bool> {
          {
             auto lock = std::scoped_lock{mutex_};
             if (deadline_cancelled_) {
                co_return false;
             }
          }
          auto error = boost::system::error_code{};
          co_await deadline->async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, error));
          co_return !error;
       },
       boost::asio::use_awaitable);
}

void relay_pair::cancel_streams() noexcept {
   try {
      left.cancel();
   } catch (...) {
   }
   try {
      right.cancel();
   } catch (...) {
   }
}

void relay_pair::cancel_deadline() noexcept {
   {
      auto lock = std::scoped_lock{mutex_};
      deadline_cancelled_ = true;
   }
   auto deadline = deadline_;
   try {
      boost::asio::dispatch(deadline->get_executor(), [deadline] {
         try {
            (void)deadline->cancel();
         } catch (...) {
         }
      });
   } catch (...) {
      try {
         (void)deadline->cancel();
      } catch (...) {
      }
   }
}

} // namespace forge::net::p2p::detail

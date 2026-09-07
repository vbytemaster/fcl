module;

#include <boost/test/unit_test.hpp>

#include <boost/asio/bind_cancellation_slot.hpp>
#include <boost/asio/cancellation_signal.hpp>
#include <boost/asio/cancellation_type.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/system/error_code.hpp>

#include <atomic>
#include <barrier>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <thread>
#include <utility>
#include <vector>

module forge.net.p2p.node;

import forge.asio.blocking;
import forge.asio.runtime;
import forge.crypto.asymmetric;
import forge.exceptions;
import forge.net.p2p.exceptions;
import forge.net.transport.session;

#include "../../libraries/net/p2p/details/direct_transport.hxx"
#include "../../libraries/net/p2p/details/cancellation_latch.hxx"
#include "../../libraries/net/p2p/details/libp2p_identity_material.hxx"
#include "../../libraries/net/p2p/details/operation_deadline.hxx"
#include "../../libraries/net/p2p/details/session_lifecycle.hxx"
#include "../../libraries/net/p2p/details/session_teardown.hxx"

namespace forge::net::p2p {
namespace {

bool wait_for_count(const std::atomic_size_t& value, std::size_t expected,
                    std::chrono::milliseconds timeout = std::chrono::seconds{2}) {
   const auto deadline = std::chrono::steady_clock::now() + timeout;
   while (value.load(std::memory_order_acquire) != expected && std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds{1});
   }
   return value.load(std::memory_order_acquire) == expected;
}

class throwing_cancel_session final : public forge::net::transport::detail::session_concept {
 public:
   [[nodiscard]] bool valid() const noexcept override {
      return open_.load(std::memory_order_acquire);
   }

   boost::asio::awaitable<forge::net::transport::stream> async_open_stream() override {
      co_return forge::net::transport::stream{};
   }

   boost::asio::awaitable<forge::net::transport::stream> async_accept_stream() override {
      co_return forge::net::transport::stream{};
   }

   boost::asio::awaitable<void> async_close() override {
      close_calls_.fetch_add(1, std::memory_order_release);
      open_.store(false, std::memory_order_release);
      co_return;
   }

   void cancel() override {
      cancel_calls_.fetch_add(1, std::memory_order_release);
      throw std::runtime_error{"expected throwing session cancel"};
   }

   [[nodiscard]] std::size_t cancel_calls() const noexcept {
      return cancel_calls_.load(std::memory_order_acquire);
   }

   [[nodiscard]] std::size_t close_calls() const noexcept {
      return close_calls_.load(std::memory_order_acquire);
   }

 private:
   std::atomic_bool open_{true};
   std::atomic_size_t cancel_calls_{0};
   std::atomic_size_t close_calls_{0};
};

BOOST_AUTO_TEST_CASE(p2p_session_rejection_stages_transport_cancel_after_owner_unlock) {
   auto owner_mutex = std::mutex{};
   auto cancel_calls = std::atomic_size_t{0};
   auto canceled_after_unlock = std::atomic_bool{false};
   auto closed = false;
   const auto cancel = [&] {
      cancel_calls.fetch_add(1, std::memory_order_release);
      if (owner_mutex.try_lock()) {
         canceled_after_unlock.store(true, std::memory_order_release);
         owner_mutex.unlock();
      }
   };

   {
      auto lock = std::scoped_lock{owner_mutex};
      detail::mark_rejected_session(closed);
      BOOST_TEST(closed);
      BOOST_TEST(cancel_calls.load(std::memory_order_acquire) == 0U);
   }
   cancel();

   BOOST_TEST(cancel_calls.load(std::memory_order_acquire) == 1U);
   BOOST_TEST(canceled_after_unlock.load(std::memory_order_acquire));
}

BOOST_AUTO_TEST_CASE(p2p_cancellation_latch_preserves_stop_before_arm_and_terminal_finish) {
   auto latch = cancellation_latch{};
   auto canceled = std::atomic_size_t{0};

   latch.request_stop();
   latch.arm([&] { canceled.fetch_add(1, std::memory_order_release); });
   latch.request_stop();
   latch.request_stop();
   latch.request_stop();
   BOOST_TEST(!latch.finish());
   latch.arm([&] { canceled.fetch_add(1, std::memory_order_release); });

   BOOST_TEST(canceled.load(std::memory_order_acquire) == 1U);
}

BOOST_AUTO_TEST_CASE(p2p_cancellation_latch_stop_before_throwing_arm_propagates_after_callback_accounting) {
   auto latch = cancellation_latch{};
   auto invoked = std::atomic_size_t{0};

   latch.request_stop();
   BOOST_CHECK_THROW(latch.arm([&] {
      invoked.fetch_add(1, std::memory_order_release);
      throw std::runtime_error{"injected cancellation failure"};
   }),
                     std::runtime_error);

   BOOST_TEST(invoked.load(std::memory_order_acquire) == 1U);
   BOOST_TEST(!latch.finish());
   latch.clear();
   BOOST_TEST(invoked.load(std::memory_order_acquire) == 1U);
}

BOOST_AUTO_TEST_CASE(p2p_cancellation_latch_races_arm_and_stop_with_one_cancel) {
   for (auto iteration = 0U; iteration < 64U; ++iteration) {
      auto latch = cancellation_latch{};
      auto canceled = std::atomic_size_t{0};
      auto start = std::barrier{2};
      auto stop = std::thread{[&] {
         start.arrive_and_wait();
         latch.request_stop();
      }};

      start.arrive_and_wait();
      latch.arm([&] { canceled.fetch_add(1, std::memory_order_release); });
      stop.join();
      latch.request_stop();
      BOOST_TEST(!latch.finish());

      BOOST_TEST(canceled.load(std::memory_order_acquire) == 1U);
   }
}

BOOST_AUTO_TEST_CASE(p2p_cancellation_latch_finish_waits_for_in_flight_cancel) {
   auto latch = cancellation_latch{};
   auto callback_entered = std::atomic_bool{false};
   auto release_callback = std::atomic_bool{false};
   auto finish_returned = std::atomic_bool{false};
   auto finish_result = std::atomic_bool{true};
   latch.arm([&] {
      callback_entered.store(true, std::memory_order_release);
      while (!release_callback.load(std::memory_order_acquire)) {
         std::this_thread::yield();
      }
   });

   auto stop = std::thread{[&] { latch.request_stop(); }};
   const auto callback_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
   while (!callback_entered.load(std::memory_order_acquire)) {
      BOOST_REQUIRE(std::chrono::steady_clock::now() < callback_deadline);
      std::this_thread::sleep_for(std::chrono::milliseconds{1});
   }
   auto finish = std::thread{[&] {
      finish_result.store(latch.finish(), std::memory_order_release);
      finish_returned.store(true, std::memory_order_release);
   }};
   std::this_thread::sleep_for(std::chrono::milliseconds{5});
   BOOST_TEST(!finish_returned.load(std::memory_order_acquire));

   release_callback.store(true, std::memory_order_release);
   stop.join();
   finish.join();
   BOOST_TEST(!finish_result.load(std::memory_order_acquire));
}

BOOST_AUTO_TEST_CASE(p2p_cancellation_latch_has_one_finish_stop_terminal_winner) {
   for (auto iteration = 0U; iteration < 64U; ++iteration) {
      auto latch = cancellation_latch{};
      auto canceled = std::atomic_size_t{0};
      auto start = std::barrier{2};
      latch.arm([&] { canceled.fetch_add(1, std::memory_order_release); });
      auto stop = std::thread{[&] {
         start.arrive_and_wait();
         latch.request_stop();
      }};

      start.arrive_and_wait();
      const auto completed = latch.finish();
      stop.join();
      latch.request_stop();

      BOOST_TEST(canceled.load(std::memory_order_acquire) == (completed ? 0U : 1U));
   }
}

BOOST_AUTO_TEST_CASE(p2p_operation_deadline_finish_waits_for_in_flight_cancel) {
   auto runtime = forge::asio::runtime{forge::asio::runtime_options{.worker_threads = 1}};
   auto deadline = operation_deadline{runtime.context(), std::chrono::seconds{5}};
   auto state_mutex = std::mutex{};
   auto state_changed = std::condition_variable{};
   auto callback_entered = false;
   auto release_callback = false;
   auto finish_attempting = false;
   auto finish_returned = false;
   auto finish_result = std::atomic_bool{false};
   auto stop_result = std::atomic_bool{false};
   deadline.arm([&] {
      auto lock = std::unique_lock{state_mutex};
      callback_entered = true;
      state_changed.notify_all();
      state_changed.wait(lock, [&] { return release_callback; });
   });

   auto stop = std::thread{[token = deadline.stopping(), &stop_result] {
      stop_result.store(token.request_stop(), std::memory_order_release);
   }};
   {
      auto lock = std::unique_lock{state_mutex};
      BOOST_REQUIRE(state_changed.wait_for(lock, std::chrono::seconds{2}, [&] { return callback_entered; }));
   }
   auto finish = std::thread{[&] {
      {
         auto lock = std::scoped_lock{state_mutex};
         finish_attempting = true;
      }
      state_changed.notify_all();
      finish_result.store(deadline.finish(), std::memory_order_release);
      {
         auto lock = std::scoped_lock{state_mutex};
         finish_returned = true;
      }
      state_changed.notify_all();
   }};

   {
      auto lock = std::unique_lock{state_mutex};
      BOOST_REQUIRE(state_changed.wait_for(lock, std::chrono::seconds{2}, [&] { return finish_attempting; }));
      const auto returned_while_callback_active =
          state_changed.wait_for(lock, std::chrono::milliseconds{100}, [&] { return finish_returned; });
      BOOST_TEST(!returned_while_callback_active);
      release_callback = true;
   }
   state_changed.notify_all();
   stop.join();
   finish.join();
   BOOST_TEST(stop_result.load(std::memory_order_acquire));
   BOOST_TEST(finish_returned);
   BOOST_TEST(finish_result.load(std::memory_order_acquire));
}

BOOST_AUTO_TEST_CASE(p2p_operation_deadline_finish_seals_concurrent_late_arm) {
   auto runtime = forge::asio::runtime{forge::asio::runtime_options{.worker_threads = 1}};

   for (auto iteration = 0U; iteration < 64U; ++iteration) {
      auto deadline = operation_deadline{runtime.context(), std::chrono::seconds{5}};
      BOOST_REQUIRE(deadline.stopping().request_stop());
      auto callbacks = std::atomic_size_t{0};
      auto start = std::barrier{3};
      auto finish_result = std::atomic_bool{false};
      auto finish = std::thread{[&] {
         start.arrive_and_wait();
         finish_result.store(deadline.finish(), std::memory_order_release);
      }};
      auto arm = std::thread{[&] {
         start.arrive_and_wait();
         deadline.arm([&] { callbacks.fetch_add(1, std::memory_order_release); });
      }};
      start.arrive_and_wait();
      finish.join();
      arm.join();

      BOOST_TEST(finish_result.load(std::memory_order_acquire));
      const auto sealed_count = callbacks.load(std::memory_order_acquire);
      BOOST_TEST(sealed_count <= 1U);
      deadline.arm([&] { callbacks.fetch_add(1, std::memory_order_release); });
      BOOST_TEST(callbacks.load(std::memory_order_acquire) == sealed_count);
   }
}

BOOST_AUTO_TEST_CASE(p2p_operation_deadline_cancel_callback_may_reenter_finish) {
   auto runtime = forge::asio::runtime{forge::asio::runtime_options{.worker_threads = 1}};
   auto deadline = operation_deadline{runtime.context(), std::chrono::seconds{5}};
   auto callback_finished = std::atomic_bool{false};
   auto finish_result = std::atomic_bool{false};
   auto stop_result = std::atomic_bool{false};
   deadline.arm([&] {
      finish_result.store(deadline.finish(), std::memory_order_release);
      callback_finished.store(true, std::memory_order_release);
   });

   auto stop = std::thread{[token = deadline.stopping(), &stop_result] {
      stop_result.store(token.request_stop(), std::memory_order_release);
   }};
   stop.join();
   BOOST_TEST(stop_result.load(std::memory_order_acquire));
   BOOST_TEST(callback_finished.load(std::memory_order_acquire));
   BOOST_TEST(finish_result.load(std::memory_order_acquire));
}

BOOST_AUTO_TEST_CASE(p2p_operation_deadline_timeout_before_arm_invokes_late_callback_once) {
   auto runtime = forge::asio::runtime{forge::asio::runtime_options{.worker_threads = 1}};
   auto deadline = operation_deadline{runtime.context(), std::chrono::milliseconds{10}};
   const auto timeout_limit = std::chrono::steady_clock::now() + std::chrono::seconds{2};
   while (!deadline.timed_out()) {
      BOOST_REQUIRE(std::chrono::steady_clock::now() < timeout_limit);
      std::this_thread::sleep_for(std::chrono::milliseconds{1});
   }

   auto callbacks = std::atomic_size_t{0};
   deadline.arm([&] { callbacks.fetch_add(1, std::memory_order_release); });
   deadline.arm([&] { callbacks.fetch_add(1, std::memory_order_release); });
   BOOST_TEST(callbacks.load(std::memory_order_acquire) == 1U);
   BOOST_TEST(!deadline.finish());
}

BOOST_AUTO_TEST_CASE(p2p_session_teardown_waits_for_started_transport_cleanup) {
   auto runtime = forge::asio::runtime{forge::asio::runtime_options{.worker_threads = 2}};
   auto release =
       std::make_shared<boost::asio::steady_timer>(runtime.context(), boost::asio::steady_timer::time_point::max());
   auto close_started = std::atomic_size_t{0};
   auto cancel_called = std::atomic_size_t{0};
   auto teardown = detail::session_teardown{runtime.context().get_executor()};

   auto operations = std::vector<detail::session_teardown::operation>{};
   for (auto remaining = 2U; remaining != 0U; --remaining) {
      operations.push_back(detail::session_teardown::operation{
          .close = [release, &close_started]() -> boost::asio::awaitable<void> {
             close_started.fetch_add(1, std::memory_order_release);
             auto error = boost::system::error_code{};
             co_await release->async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, error));
          },
          .cancel = [&cancel_called] { cancel_called.fetch_add(1, std::memory_order_release); },
      });
   }
   teardown.start(std::move(operations));

   const auto close_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
   while (close_started.load(std::memory_order_acquire) != 2U) {
      BOOST_REQUIRE(std::chrono::steady_clock::now() < close_deadline);
      std::this_thread::sleep_for(std::chrono::milliseconds{1});
   }

   auto cancellation = boost::asio::cancellation_signal{};
   auto stopped =
       boost::asio::co_spawn(runtime.context(), teardown.wait(),
                             boost::asio::bind_cancellation_slot(cancellation.slot(), boost::asio::use_future));
   const auto waiting_for_cleanup = stopped.wait_for(std::chrono::milliseconds{50}) == std::future_status::timeout;
   BOOST_TEST(waiting_for_cleanup);

   cancellation.emit(boost::asio::cancellation_type::total);
   const auto cancellation_did_not_bypass_cleanup =
       stopped.wait_for(std::chrono::milliseconds{50}) == std::future_status::timeout;
   BOOST_TEST(cancellation_did_not_bypass_cleanup);

   boost::asio::post(runtime.context(), [release] { release->cancel(); });
   const auto cleanup_completed = stopped.wait_for(std::chrono::seconds{2}) == std::future_status::ready;
   BOOST_REQUIRE(cleanup_completed);
   stopped.get();
   BOOST_TEST(cancel_called.load(std::memory_order_acquire) == 0U);
}

BOOST_AUTO_TEST_CASE(p2p_session_teardown_waits_for_tracked_background_operation) {
   auto runtime = forge::asio::runtime{forge::asio::runtime_options{.worker_threads = 2}};
   auto teardown = detail::session_teardown{runtime.context().get_executor()};
   auto tracked = teardown.track();
   BOOST_REQUIRE(tracked.active());

   teardown.start({});
   auto stopped = boost::asio::co_spawn(runtime.context(), teardown.wait(), boost::asio::use_future);
   const auto waits_for_background_operation =
       stopped.wait_for(std::chrono::milliseconds{50}) == std::future_status::timeout;
   BOOST_TEST(waits_for_background_operation);

   tracked.release();
   BOOST_REQUIRE(stopped.wait_for(std::chrono::seconds{2}) == std::future_status::ready);
   stopped.get();
}

BOOST_AUTO_TEST_CASE(p2p_session_teardown_cancels_tracked_background_operation) {
   auto runtime = forge::asio::runtime{forge::asio::runtime_options{.worker_threads = 2}};
   auto teardown = detail::session_teardown{runtime.context().get_executor()};
   auto blocked =
       std::make_shared<boost::asio::steady_timer>(runtime.context(), boost::asio::steady_timer::time_point::max());
   auto cancel_called = std::atomic_size_t{0};
   auto operation_started = std::atomic_bool{false};
   auto tracked = teardown.track([blocked, &cancel_called] {
      cancel_called.fetch_add(1, std::memory_order_release);
      blocked->cancel();
   });
   BOOST_REQUIRE(tracked.active());

   auto operation = boost::asio::co_spawn(
       runtime.context(),
       [blocked, &operation_started, tracked = std::move(tracked)]() mutable -> boost::asio::awaitable<void> {
          auto error = boost::system::error_code{};
          operation_started.store(true, std::memory_order_release);
          co_await blocked->async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, error));
          tracked.release();
       },
       boost::asio::use_future);

   const auto operation_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
   while (!operation_started.load(std::memory_order_acquire)) {
      BOOST_REQUIRE(std::chrono::steady_clock::now() < operation_deadline);
      std::this_thread::sleep_for(std::chrono::milliseconds{1});
   }
   teardown.start({});
   auto stopped = boost::asio::co_spawn(runtime.context(), teardown.wait(), boost::asio::use_future);

   BOOST_REQUIRE(stopped.wait_for(std::chrono::seconds{2}) == std::future_status::ready);
   stopped.get();
   BOOST_REQUIRE(operation.wait_for(std::chrono::seconds{2}) == std::future_status::ready);
   operation.get();
   BOOST_TEST(cancel_called.load(std::memory_order_acquire) == 1U);
}

BOOST_AUTO_TEST_CASE(p2p_noexcept_cancel_request_preserves_session_until_graceful_teardown) {
   auto runtime = forge::asio::runtime{forge::asio::runtime_options{.worker_threads = 2}};
   auto model = std::make_shared<throwing_cancel_session>();
   auto candidate = forge::net::transport::detail::session_access::make(model);
   auto teardown = detail::session_teardown{runtime.context().get_executor()};
   BOOST_CHECK_NO_THROW(detail::request_session_cancel(candidate));
   BOOST_TEST(model->cancel_calls() == 1U);
   BOOST_TEST(candidate.valid());

   auto ticket = teardown.track([&candidate] { detail::request_session_cancel(candidate); });
   BOOST_REQUIRE(ticket.active());

   teardown.start({});
   BOOST_TEST(model->cancel_calls() == 2U);
   BOOST_TEST(candidate.valid());

   auto stopped = boost::asio::co_spawn(runtime.context(), teardown.wait(), boost::asio::use_future);
   BOOST_CHECK(stopped.wait_for(std::chrono::milliseconds{50}) == std::future_status::timeout);

   forge::asio::blocking::run(runtime, candidate.async_close());
   BOOST_TEST(model->close_calls() == 1U);
   BOOST_TEST(!candidate.valid());
   ticket.release();

   const auto stopped_ready = stopped.wait_for(std::chrono::seconds{2}) == std::future_status::ready;
   BOOST_CHECK(stopped_ready);
   if (stopped_ready) {
      stopped.get();
   }
}

BOOST_AUTO_TEST_CASE(p2p_session_teardown_handles_concurrent_track_release_and_start) {
   auto runtime = forge::asio::runtime{forge::asio::runtime_options{.worker_threads = 2}};
   for (auto iteration = 0U; iteration < 1'000U; ++iteration) {
      auto teardown = detail::session_teardown{runtime.context().get_executor()};
      auto tracked = teardown.track();
      auto start = std::barrier{2};
      auto releaser = std::thread{[&] {
         start.arrive_and_wait();
         tracked.release();
      }};
      start.arrive_and_wait();
      teardown.start({});
      releaser.join();
      forge::asio::blocking::run(runtime, teardown.wait());
   }
}

BOOST_AUTO_TEST_CASE(p2p_operation_deadline_preserves_shutdown_winner_past_timeout) {
   auto runtime = forge::asio::runtime{forge::asio::runtime_options{.worker_threads = 1}};
   auto deadline = operation_deadline{runtime.context(), std::chrono::milliseconds{10}};
   auto canceled = std::atomic_size_t{0};
   auto stopping = deadline.stopping();

   BOOST_REQUIRE(stopping.request_stop());
   deadline.arm([&] { canceled.fetch_add(1, std::memory_order_release); });
   std::this_thread::sleep_for(std::chrono::milliseconds{50});

   BOOST_TEST(deadline.stopped());
   BOOST_TEST(!deadline.timed_out());
   BOOST_TEST(canceled.load(std::memory_order_acquire) == 1U);
   BOOST_TEST(deadline.finish());
}

BOOST_AUTO_TEST_CASE(p2p_operation_deadline_shutdown_cancels_armed_operation_once) {
   auto runtime = forge::asio::runtime{forge::asio::runtime_options{.worker_threads = 1}};
   auto deadline = operation_deadline{runtime.context(), std::chrono::seconds{1}};
   auto canceled = std::atomic_size_t{0};
   auto stopping = deadline.stopping();
   deadline.arm([&] { canceled.fetch_add(1, std::memory_order_release); });

   BOOST_REQUIRE(stopping.request_stop());
   BOOST_TEST(!stopping.request_stop());
   BOOST_TEST(canceled.load(std::memory_order_acquire) == 1U);
   BOOST_TEST(deadline.stopped());
   BOOST_TEST(!deadline.timed_out());
   BOOST_TEST(deadline.finish());
   BOOST_TEST(canceled.load(std::memory_order_acquire) == 1U);
}

BOOST_AUTO_TEST_CASE(p2p_operation_deadline_races_arm_and_stop_without_losing_cancel) {
   auto runtime = forge::asio::runtime{forge::asio::runtime_options{.worker_threads = 2}};
   for (auto iteration = 0U; iteration < 128U; ++iteration) {
      auto deadline = operation_deadline{runtime.context(), std::chrono::seconds{1}};
      auto canceled = std::atomic_size_t{0};
      auto stopping = deadline.stopping();
      auto start = std::barrier{3};
      auto stop_won = std::atomic_bool{false};
      auto arm = std::thread{[&] {
         start.arrive_and_wait();
         deadline.arm([&] { canceled.fetch_add(1, std::memory_order_release); });
      }};
      auto stop = std::thread{[&] {
         start.arrive_and_wait();
         stop_won.store(stopping.request_stop(), std::memory_order_release);
      }};

      start.arrive_and_wait();
      arm.join();
      stop.join();

      BOOST_TEST(stop_won.load(std::memory_order_acquire));
      BOOST_TEST(deadline.stopped());
      BOOST_TEST(!deadline.timed_out());
      BOOST_TEST(canceled.load(std::memory_order_acquire) == 1U);
      BOOST_TEST(deadline.finish());
   }
}

BOOST_AUTO_TEST_CASE(p2p_operation_deadline_races_finish_and_stop_with_one_terminal_winner) {
   auto runtime = forge::asio::runtime{forge::asio::runtime_options{.worker_threads = 2}};
   for (auto iteration = 0U; iteration < 128U; ++iteration) {
      auto deadline = operation_deadline{runtime.context(), std::chrono::seconds{1}};
      auto canceled = std::atomic_size_t{0};
      auto stopping = deadline.stopping();
      deadline.arm([&] { canceled.fetch_add(1, std::memory_order_release); });
      auto start = std::barrier{3};
      auto stop_won = std::atomic_bool{false};
      auto finish_result = std::atomic_bool{false};
      auto finish = std::thread{[&] {
         start.arrive_and_wait();
         finish_result.store(deadline.finish(), std::memory_order_release);
      }};
      auto stop = std::thread{[&] {
         start.arrive_and_wait();
         stop_won.store(stopping.request_stop(), std::memory_order_release);
      }};

      start.arrive_and_wait();
      finish.join();
      stop.join();

      const auto stopped = deadline.stopped();
      BOOST_TEST(finish_result.load(std::memory_order_acquire));
      BOOST_TEST(stop_won.load(std::memory_order_acquire) == stopped);
      BOOST_TEST(!deadline.timed_out());
      BOOST_TEST(canceled.load(std::memory_order_acquire) == (stopped ? 1U : 0U));
   }
}

BOOST_AUTO_TEST_CASE(p2p_operation_deadline_races_timeout_and_stop_with_one_cancel) {
   auto runtime = forge::asio::runtime{forge::asio::runtime_options{.worker_threads = 2}};
   for (auto iteration = 0U; iteration < 64U; ++iteration) {
      auto deadline = operation_deadline{runtime.context(), std::chrono::milliseconds{1}};
      auto canceled = std::atomic_size_t{0};
      auto stopping = deadline.stopping();
      deadline.arm([&] { canceled.fetch_add(1, std::memory_order_release); });
      auto start = std::barrier{2};
      auto stop_won = std::atomic_bool{false};
      auto stop = std::thread{[&] {
         start.arrive_and_wait();
         std::this_thread::sleep_for(std::chrono::milliseconds{1});
         stop_won.store(stopping.request_stop(), std::memory_order_release);
      }};

      start.arrive_and_wait();
      stop.join();
      BOOST_REQUIRE(wait_for_count(canceled, 1U));

      const auto stopped = deadline.stopped();
      const auto timed_out = deadline.timed_out();
      BOOST_TEST(stopped != timed_out);
      BOOST_TEST(stop_won.load(std::memory_order_acquire) == stopped);
      BOOST_TEST(canceled.load(std::memory_order_acquire) == 1U);
      BOOST_TEST(deadline.finish() == !timed_out);
   }
}

BOOST_AUTO_TEST_CASE(p2p_operation_deadline_preserves_timeout_winner_after_shutdown) {
   auto runtime = forge::asio::runtime{forge::asio::runtime_options{.worker_threads = 1}};
   auto deadline = operation_deadline{runtime.context(), std::chrono::milliseconds{10}};
   auto canceled = std::atomic_bool{false};
   auto stopping = deadline.stopping();
   deadline.arm([&] { canceled.store(true, std::memory_order_release); });

   const auto timeout_deadline = std::chrono::steady_clock::now() + std::chrono::seconds{2};
   while (!canceled.load(std::memory_order_acquire)) {
      BOOST_REQUIRE(std::chrono::steady_clock::now() < timeout_deadline);
      std::this_thread::sleep_for(std::chrono::milliseconds{1});
   }

   BOOST_TEST(deadline.timed_out());
   BOOST_TEST(!deadline.stopped());
   BOOST_TEST(!stopping.request_stop());
   BOOST_TEST(!deadline.finish());
}

BOOST_AUTO_TEST_CASE(p2p_direct_transport_teardown_continues_after_profile_failure) {
   auto runtime = forge::asio::runtime{forge::asio::runtime_options{.worker_threads = 2}};
   const auto options = node::options{};
   const auto identity = make_libp2p_identity_material(options);
   auto registry = direct::registry{runtime, options, identity, resource_manager{options.limits.resources}};
   auto failed_stop = std::atomic_size_t{0};
   auto next_stop = std::atomic_size_t{0};
   auto failed_async_stop = std::atomic_size_t{0};
   auto next_async_stop = std::atomic_size_t{0};

   const auto add_profile = [&](auto stop, auto async_stop) {
      registry.add(direct::profile{
          .supports = [](const endpoint&) { return false; },
          .listening = [] { return false; },
          .local_endpoints = [] { return std::vector<endpoint>{}; },
          .listen = [](endpoint value) { return value; },
          .stop = std::move(stop),
          .async_stop = std::move(async_stop),
          .async_connect = [](endpoint, const node::connect_options&, std::shared_ptr<cancellation_latch>,
                              std::shared_ptr<void>, direct::authenticated_admission_handler)
              -> boost::asio::awaitable<direct::connection> {
             co_return direct::connection{};
          },
          .async_accept = [](endpoint) -> boost::asio::awaitable<direct::connection> {
             co_return direct::connection{};
          },
      });
   };

   add_profile(
       [&] {
          failed_stop.fetch_add(1, std::memory_order_release);
          throw std::runtime_error{"expected stop failure"};
       },
       [&]() -> boost::asio::awaitable<void> {
          failed_async_stop.fetch_add(1, std::memory_order_release);
          throw std::runtime_error{"expected async stop failure"};
          co_return;
       });
   add_profile([&] { next_stop.fetch_add(1, std::memory_order_release); },
               [&]() -> boost::asio::awaitable<void> {
                  next_async_stop.fetch_add(1, std::memory_order_release);
                  co_return;
               });

   auto teardown = detail::session_teardown{runtime.context().get_executor()};
   auto operations = std::vector<detail::session_teardown::operation>{};
   operations.push_back(registry.teardown_operation());
   registry.stop();
   teardown.start(std::move(operations));
   forge::asio::blocking::run(runtime, teardown.wait());

   BOOST_TEST(failed_stop.load(std::memory_order_acquire) == 1U);
   BOOST_TEST(next_stop.load(std::memory_order_acquire) == 1U);
   BOOST_TEST(failed_async_stop.load(std::memory_order_acquire) == 1U);
   BOOST_TEST(next_async_stop.load(std::memory_order_acquire) == 1U);
}

BOOST_AUTO_TEST_CASE(p2p_direct_listener_stop_wins_after_accept_begins) {
   auto runtime = forge::asio::runtime{forge::asio::runtime_options{.worker_threads = 1}};
   const auto options = node::options{};
   const auto identity = make_libp2p_identity_material(options);
   auto registry = direct::registry{runtime, options, identity, resource_manager{options.limits.resources}};
   const auto requested = endpoint{.transport = {
                                       .host_type = endpoint::host_kind::ip4,
                                       .protocol = endpoint::protocol_kind::tcp,
                                       .host = "127.0.0.1",
                                       .port = 0,
                                   }};
   const auto local = registry.listen(requested);
   auto accepting = boost::asio::co_spawn(runtime.context(), registry.async_accept(local), boost::asio::use_future);
   auto accept_started = std::promise<void>{};
   auto accept_started_future = accept_started.get_future();
   boost::asio::post(runtime.context(), [&accept_started] { accept_started.set_value(); });
   const auto accept_entered = accept_started_future.wait_for(std::chrono::seconds{2}) == std::future_status::ready;

   auto blocker_entered = std::promise<void>{};
   auto blocker_entered_future = blocker_entered.get_future();
   auto release_blocker = std::promise<void>{};
   auto blocker_released = release_blocker.get_future().share();
   boost::asio::post(runtime.context(), [&blocker_entered, blocker_released] {
      blocker_entered.set_value();
      blocker_released.wait();
   });
   const auto runtime_blocked = blocker_entered_future.wait_for(std::chrono::seconds{2}) == std::future_status::ready;

   auto client = boost::asio::ip::tcp::socket{runtime.context()};
   auto connect_error = boost::system::error_code{};
   const auto address = boost::asio::ip::make_address(local.transport.host, connect_error);
   if (!connect_error) {
      client.connect(boost::asio::ip::tcp::endpoint{address, local.transport.port}, connect_error);
   }

   auto start = std::barrier{2};
   auto invalid_snapshot = std::atomic_bool{false};
   auto observer = std::thread{[&] {
      start.arrive_and_wait();
      for (auto remaining = 256U; remaining != 0U; --remaining) {
         const auto endpoints = registry.local_endpoints();
         if (endpoints.size() > 1U) {
            invalid_snapshot.store(true, std::memory_order_release);
         }
         static_cast<void>(registry.listening());
      }
   }};

   start.arrive_and_wait();
   registry.stop();
   release_blocker.set_value();
   observer.join();

   const auto accept_ready = accepting.wait_for(std::chrono::seconds{2}) == std::future_status::ready;
   auto accept_closed = false;
   if (accept_ready) {
      try {
         auto unexpected = accepting.get();
         unexpected.session.cancel();
      } catch (const forge::exceptions::base& error) {
         const auto code = exceptions::code_of(error);
         accept_closed = code && *code == exceptions::code::closed;
      }
   }
   auto close_error = boost::system::error_code{};
   client.close(close_error);

   BOOST_TEST(accept_entered);
   BOOST_TEST(runtime_blocked);
   BOOST_TEST(!connect_error);
   BOOST_TEST(!invalid_snapshot.load(std::memory_order_acquire));
   BOOST_TEST(!registry.listening());
   BOOST_TEST(registry.local_endpoints().empty());
   BOOST_TEST(accept_ready);
   BOOST_TEST(accept_closed);

   auto teardown = detail::session_teardown{runtime.context().get_executor()};
   auto operations = std::vector<detail::session_teardown::operation>{};
   operations.push_back(registry.teardown_operation());
   teardown.start(std::move(operations));
   forge::asio::blocking::run(runtime, teardown.wait());
}

} // namespace
} // namespace forge::net::p2p

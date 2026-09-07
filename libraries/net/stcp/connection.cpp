module;

#include <forge/exceptions/macros.hpp>

#include <atomic>
#include <cstdint>
#include <exception>
#include <memory>
#include <mutex>
#include <optional>
#include <stop_token>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/cancellation_state.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/system_error.hpp>
#include "details/handshake_deadline.hxx"

module forge.net.stcp.connection;

import forge.asio.gate;
import forge.asio.notification;
import forge.net.tls.context;
import forge.net.tls.exceptions;
import forge.net.transport.stream;

namespace forge::net::stcp {
namespace {

namespace asio = boost::asio;
using asio_tcp = boost::asio::ip::tcp;
using native_stream = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;

enum class connection_state : std::uint8_t {
   active,
   cancel_requested,
   close_requested,
   handed_off,
   closed,
};

[[nodiscard]] std::int64_t next_stream_id() noexcept {
   static auto next = std::atomic<std::int64_t>{1};
   return next.fetch_add(1, std::memory_order_relaxed);
}

[[noreturn]] void throw_invalid_options(std::string message) {
   FORGE_THROW_EXCEPTION(exceptions::invalid_options, std::move(message));
}

[[noreturn]] void throw_io_error(std::string message, const boost::system::error_code& error) {
   FORGE_THROW_EXCEPTION(exceptions::io_error, std::move(message), forge::exceptions::ctx("reason", error.message()));
}

[[noreturn]] void throw_handshake_failed(std::string message, const boost::system::error_code& error) {
   if (error == boost::asio::error::operation_aborted) {
      FORGE_THROW_EXCEPTION(exceptions::canceled, "stcp handshake canceled",
                            forge::exceptions::ctx("reason", error.message()));
   }
   FORGE_THROW_EXCEPTION(exceptions::handshake_failed, std::move(message),
                         forge::exceptions::ctx("reason", error.message()));
}

[[noreturn]] void throw_handshake_timeout(std::string message) {
   FORGE_THROW_EXCEPTION(exceptions::timeout, std::move(message));
}

[[noreturn]] void throw_verification_failed(std::string message) {
   FORGE_THROW_EXCEPTION(exceptions::verification_failed, std::move(message));
}

[[noreturn]] void throw_read_write_error(const boost::system::error_code& error) {
   if (error == boost::asio::error::operation_aborted) {
      FORGE_THROW_EXCEPTION(exceptions::canceled, "stcp connection operation canceled",
                            forge::exceptions::ctx("reason", error.message()));
   }
   if (error == boost::asio::error::eof || error == boost::asio::error::connection_reset ||
       error == boost::asio::error::broken_pipe || error == boost::asio::ssl::error::stream_truncated) {
      FORGE_THROW_EXCEPTION(exceptions::closed, "stcp connection closed",
                            forge::exceptions::ctx("reason", error.message()));
   }
   throw_io_error("stcp connection I/O failed", error);
}

void validate_common(std::size_t read_chunk_size) {
   if (read_chunk_size == 0) {
      throw_invalid_options("stcp read_chunk_size must be greater than zero");
   }
}

[[nodiscard]] tls::context_options make_tls_options(const client_options& options) {
   auto out = tls::context_options{};
   out.role = tls::endpoint_role::client;
   out.protocols = options.tls13_only ? tls::protocol_policy::tls13_only : tls::protocol_policy::system_default;
   out.verification = options.security.verify_peer ? tls::peer_verification::verify_peer : tls::peer_verification::none;
   out.certificate_chain_pem = options.certificate_pem;
   out.private_key_pem = options.private_key_pem;
   out.alpn_protocols = options.alpn_protocols;
   if (!options.security.trusted_ca_pem.empty()) {
      out.trust_anchors_pem.push_back(options.security.trusted_ca_pem);
      out.use_default_verify_paths = false;
   }
   return out;
}

[[nodiscard]] tls::context_options make_tls_options(const server_options& options) {
   auto out = tls::context_options{};
   out.role = tls::endpoint_role::server;
   out.protocols = options.tls13_only ? tls::protocol_policy::tls13_only : tls::protocol_policy::system_default;
   if (options.security.verify_peer) {
      out.verification = tls::peer_verification::require_peer_certificate;
   } else if (options.security.require_peer_certificate) {
      out.verification = tls::peer_verification::require_peer_certificate_for_application_verification;
   } else {
      out.verification = tls::peer_verification::none;
   }
   out.certificate_chain_pem = options.certificate_pem;
   out.private_key_pem = options.private_key_pem;
   out.alpn_protocols = options.alpn_protocols;
   out.use_default_verify_paths = options.security.verify_peer;
   if (!options.security.trusted_ca_pem.empty()) {
      out.trust_anchors_pem.push_back(options.security.trusted_ca_pem);
      out.use_default_verify_paths = false;
   }
   return out;
}

[[nodiscard]] tls::context_snapshot_ptr make_client_context(const client_options& options) {
   validate_common(options.read_chunk_size);
   try {
      return tls::make_context(make_tls_options(options));
   } catch (const forge::exceptions::base& error) {
      throw_invalid_options("invalid stcp TLS client options: " + error.message());
   }
}

[[nodiscard]] tls::context_snapshot_ptr make_server_context(const server_options& options) {
   validate_common(options.read_chunk_size);
   try {
      return tls::make_context(make_tls_options(options));
   } catch (const forge::exceptions::base& error) {
      throw_invalid_options("invalid stcp TLS server options: " + error.message());
   }
}

[[nodiscard]] transport::endpoint from_asio_endpoint(const asio_tcp::endpoint& endpoint) {
   const auto address = endpoint.address();
   return transport::endpoint{.host_type = address.is_v6() ? transport::endpoint::host_kind::ip6
                                                           : transport::endpoint::host_kind::ip4,
                              .protocol = transport::endpoint::protocol_kind::tcp,
                              .host = address.to_string(),
                              .port = endpoint.port()};
}

void configure_tls_client_stream(native_stream& stream, const client_options& options, std::string_view remote_host,
                                 const tls::context_snapshot& context) {
   try {
      tls::configure_client_stream(
          stream.native_handle(), context,
          {.sni = options.sni, .endpoint_host = std::string{remote_host}, .server_name = options.server_name});
   } catch (const forge::exceptions::base& error) {
      if (tls::exceptions::code_of(error)) {
         throw_invalid_options("invalid stcp TLS client stream options: " + error.message());
      }
      throw;
   }
}

void classify_tls_handshake_failure(native_stream& stream, const tls::context_snapshot& context) {
   try {
      tls::classify_handshake_failure(stream.native_handle(), context);
   } catch (const forge::exceptions::base& error) {
      if (tls::exceptions::code_of(error)) {
         throw_verification_failed("stcp TLS peer verification failed: " + error.message());
      }
      throw;
   }
}

void validate_tls_peer(native_stream& stream, const tls::context_snapshot& context, const security_options& security,
                       std::string_view expected_host) {
   try {
      tls::validate_peer(stream.native_handle(), context,
                         {.expected_host = security.verify_peer ? std::string{expected_host} : std::string{},
                          .expected_sha256_fingerprint = security.expected_sha256_fingerprint,
                          .verifier = security.verifier});
   } catch (const forge::exceptions::base& error) {
      if (tls::exceptions::code_of(error)) {
         throw_verification_failed("stcp TLS peer verification failed: " + error.message());
      }
      throw;
   }
}

void validate_handshake_timeout(std::chrono::milliseconds timeout) {
   if (timeout.count() <= 0) {
      throw_invalid_options("stcp handshake timeout must be greater than zero");
   }
}

void cancel_stream(native_stream& stream) noexcept {
   auto ignored = boost::system::error_code{};
   stream.lowest_layer().cancel(ignored);
   stream.lowest_layer().shutdown(asio_tcp::socket::shutdown_both, ignored);
   stream.lowest_layer().close(ignored);
}

void cancel_timer_noexcept(asio::steady_timer& timer) noexcept {
   try {
      timer.cancel();
   } catch (...) {
   }
}

enum class handshake_cancellation_state : std::uint8_t {
   active,
   canceled,
   terminal,
};

enum class io_stop_reason : std::uint8_t {
   none,
   closed,
   canceled,
};

struct io_gates {
   boost::asio::awaitable<forge::asio::gate::ticket> acquire(forge::asio::gate& gate) {
      try {
         co_return co_await gate.acquire();
      } catch (const forge::asio::exceptions::canceled&) {
         FORGE_THROW_EXCEPTION(exceptions::canceled, "stcp operation canceled while waiting for I/O");
      } catch (const forge::asio::exceptions::rejected&) {
         throw_stopped();
      }
   }

   void stop(io_stop_reason value) noexcept {
      auto expected = io_stop_reason::none;
      reason.compare_exchange_strong(expected, value, std::memory_order_release, std::memory_order_relaxed);
      read.close();
      write.close();
      terminal_requested.notify();
   }

   [[nodiscard]] bool stopped() const noexcept {
      return reason.load(std::memory_order_acquire) != io_stop_reason::none;
   }

   [[noreturn]] void throw_stopped() const {
      if (reason.load(std::memory_order_acquire) == io_stop_reason::canceled) {
         FORGE_THROW_EXCEPTION(exceptions::canceled, "stcp operation canceled while waiting for I/O");
      }
      FORGE_THROW_EXCEPTION(exceptions::closed, "stcp connection closed while waiting for I/O");
   }

   forge::asio::gate read;
   forge::asio::gate write;
   forge::asio::notification terminal_requested;
   std::atomic<io_stop_reason> reason{io_stop_reason::none};
};

[[noreturn]] void terminalize_io_error(native_stream& stream, io_gates& gates, const boost::system::error_code& error) {
   if (gates.stopped()) {
      cancel_stream(stream);
      gates.throw_stopped();
   }
   gates.stop(error == boost::asio::error::operation_aborted ? io_stop_reason::canceled : io_stop_reason::closed);
   cancel_stream(stream);
   throw_read_write_error(error);
}

[[noreturn]] void terminalize_closed(native_stream* stream, io_gates& gates, std::string_view message) {
   gates.stop(io_stop_reason::closed);
   if (stream) {
      cancel_stream(*stream);
   }
   FORGE_THROW_EXCEPTION(exceptions::closed, std::string{message});
}

boost::asio::awaitable<void> async_handshake(std::shared_ptr<native_stream> stream,
                                             asio::ssl::stream_base::handshake_type type,
                                             std::optional<std::chrono::milliseconds> timeout, std::stop_token stop) {
   auto strand = asio::make_strand(stream->lowest_layer().get_executor());
   co_await asio::co_spawn(
       strand,
       [stream = std::move(stream), strand, type, timeout, stop]() -> asio::awaitable<void> {
          if (stop.stop_requested()) {
             FORGE_THROW_EXCEPTION(exceptions::canceled, "stcp handshake canceled");
          }

          auto cancellation =
              std::make_shared<std::atomic<handshake_cancellation_state>>(handshake_cancellation_state::active);
          auto cancel_requested = std::make_shared<forge::asio::notification>();
          auto cancel_completed = std::make_shared<forge::asio::notification>();
          auto cancel_worker_error = std::make_shared<std::exception_ptr>();
          asio::co_spawn(
              strand,
              [stream, cancellation, cancel_requested]() -> asio::awaitable<void> {
                 static_cast<void>(co_await cancel_requested->async_wait(0));
                 if (cancellation->load(std::memory_order_acquire) == handshake_cancellation_state::canceled) {
                    cancel_stream(*stream);
                 }
              },
              [cancel_completed, cancel_worker_error](std::exception_ptr error) noexcept {
                 *cancel_worker_error = std::move(error);
                 cancel_completed->notify();
              });
          auto request_cancel = [cancellation, cancel_requested]() noexcept {
             auto expected = handshake_cancellation_state::active;
             if (cancellation->compare_exchange_strong(expected, handshake_cancellation_state::canceled,
                                                       std::memory_order_acq_rel, std::memory_order_acquire)) {
                cancel_requested->notify();
             }
          };
          using stop_callback_type = std::stop_callback<decltype(request_cancel)>;
          auto cancel_on_stop = std::optional<stop_callback_type>{};
          auto timer = std::shared_ptr<asio::steady_timer>{};
          auto terminal = std::shared_ptr<detail::handshake_deadline_state>{};
          auto error = boost::system::error_code{};
          auto primary_error = std::exception_ptr{};
          try {
             cancel_on_stop.emplace(stop, std::move(request_cancel));
             if (timeout) {
                validate_handshake_timeout(*timeout);
                timer = std::make_shared<asio::steady_timer>(co_await asio::this_coro::executor);
                terminal = std::make_shared<detail::handshake_deadline_state>();
                timer->expires_after(*timeout);
                timer->async_wait([stream, terminal](const boost::system::error_code& timer_error) {
                   if (timer_error) {
                      return;
                   }
                   if (!terminal->try_timeout()) {
                      return;
                   }
                   cancel_stream(*stream);
                });
             }

             co_await stream->async_handshake(type, asio::redirect_error(asio::use_awaitable, error));
          } catch (...) {
             primary_error = std::current_exception();
          }

          auto expected = handshake_cancellation_state::active;
          const auto completed = cancellation->compare_exchange_strong(
              expected, handshake_cancellation_state::terminal, std::memory_order_acq_rel, std::memory_order_acquire);
          const auto canceled = !completed && expected == handshake_cancellation_state::canceled;
          cancel_on_stop.reset();
          if (timer && primary_error) {
             cancel_timer_noexcept(*timer);
          }

          // From worker publication onward every exit joins it. Parent coroutine
          // cancellation must not interrupt this terminal cleanup.
          co_await asio::this_coro::reset_cancellation_state(asio::disable_cancellation{});
          cancel_requested->notify();
          auto join_error = std::exception_ptr{};
          while (cancel_completed->epoch() == 0) {
             try {
                // Completion is sticky; retry only a failed waiter setup and do
                // not expose the primary operation error before the worker exits.
                static_cast<void>(co_await cancel_completed->async_wait(0));
             } catch (...) {
                if (!join_error) {
                   join_error = std::current_exception();
                }
             }
          }
          if (!primary_error && join_error) {
             primary_error = std::move(join_error);
          }
          if (primary_error || *cancel_worker_error) {
             if (timer) {
                cancel_timer_noexcept(*timer);
             }
             if (primary_error) {
                std::rethrow_exception(primary_error);
             }
             std::rethrow_exception(*cancel_worker_error);
          }
          if (timer) {
             const auto completed_before_timeout = terminal->try_complete();
             cancel_timer_noexcept(*timer);
             if (!completed_before_timeout) {
                throw_handshake_timeout(type == asio::ssl::stream_base::client ? "stcp client handshake timed out"
                                                                               : "stcp server handshake timed out");
             }
          }
          if (canceled) {
             FORGE_THROW_EXCEPTION(exceptions::canceled, "stcp handshake canceled");
          }
          if (error) {
             throw_handshake_failed(type == asio::ssl::stream_base::client ? "stcp client handshake failed"
                                                                           : "stcp server handshake failed",
                                    error);
          }
       },
       asio::use_awaitable);
}

class stream_model final : public transport::detail::stream_concept {
 public:
   stream_model(tls::context_snapshot_ptr context, asio::strand<asio::any_io_executor> strand,
                std::shared_ptr<io_gates> gates, std::shared_ptr<forge::asio::notification> terminal_completed,
                std::size_t read_chunk_size, std::int64_t id, std::shared_ptr<void> lifetime)
       : context_(std::move(context)), strand_(std::move(strand)), gates_(std::move(gates)),
         read_chunk_size_(read_chunk_size), id_(id), terminal_completed_(std::move(terminal_completed)),
         lifetime_(std::move(lifetime)) {}

   ~stream_model() override {
      request_cancel();
   }

   [[nodiscard]] bool valid() const noexcept override {
      static_cast<void>(lifetime_);
      return stream_ && !gates_->stopped();
   }

   [[nodiscard]] std::int64_t id() const noexcept override {
      return id_;
   }

   void attach(std::shared_ptr<native_stream> stream) noexcept {
      stream_ = std::move(stream);
   }

   boost::asio::awaitable<void> async_write(std::span<const std::uint8_t> bytes) override {
      auto write_ticket = co_await gates_->acquire(gates_->write);
      auto stream = stream_;
      auto gates = gates_;
      co_await asio::co_spawn(
          strand_,
          [stream = std::move(stream), gates = std::move(gates), bytes]() -> asio::awaitable<void> {
             if (gates->stopped()) {
                gates->throw_stopped();
             }
             if (!stream || !stream->lowest_layer().is_open()) {
                terminalize_closed(stream.get(), *gates, "invalid stcp stream");
             }
             auto error = boost::system::error_code{};
             co_await asio::async_write(*stream, asio::buffer(bytes), asio::redirect_error(asio::use_awaitable, error));
             if (error) {
                terminalize_io_error(*stream, *gates, error);
             }
          },
          asio::use_awaitable);
   }

   boost::asio::awaitable<std::vector<std::uint8_t>> async_read() override {
      auto read_ticket = co_await gates_->acquire(gates_->read);
      auto out = std::vector<std::uint8_t>(read_chunk_size_);
      auto stream = stream_;
      auto gates = gates_;
      const auto size = co_await asio::co_spawn(
          strand_,
          [stream = std::move(stream), gates = std::move(gates),
           writable = std::span<std::uint8_t>{out}]() -> asio::awaitable<std::size_t> {
             if (gates->stopped()) {
                gates->throw_stopped();
             }
             if (!stream || !stream->lowest_layer().is_open()) {
                terminalize_closed(stream.get(), *gates, "invalid stcp stream");
             }
             auto error = boost::system::error_code{};
             const auto size = co_await stream->async_read_some(asio::buffer(writable),
                                                                asio::redirect_error(asio::use_awaitable, error));
             if (error) {
                terminalize_io_error(*stream, *gates, error);
             }
             co_return size;
          },
          asio::use_awaitable);
      out.resize(size);
      co_return out;
   }

   boost::asio::awaitable<transport::chunk> async_read_chunk() override {
      auto read_ticket = co_await gates_->acquire(gates_->read);
      auto builder = pool_.acquire(read_chunk_size_);
      auto writable = builder.writable();
      auto stream = stream_;
      auto gates = gates_;
      const auto size = co_await asio::co_spawn(
          strand_,
          [stream = std::move(stream), gates = std::move(gates), writable]() -> asio::awaitable<std::size_t> {
             if (gates->stopped()) {
                gates->throw_stopped();
             }
             if (!stream || !stream->lowest_layer().is_open()) {
                terminalize_closed(stream.get(), *gates, "invalid stcp stream");
             }
             auto error = boost::system::error_code{};
             const auto size = co_await stream->async_read_some(asio::buffer(writable),
                                                                asio::redirect_error(asio::use_awaitable, error));
             if (error) {
                terminalize_io_error(*stream, *gates, error);
             }
             co_return size;
          },
          asio::use_awaitable);
      co_return builder.commit(size);
   }

   boost::asio::awaitable<void> async_close() override {
      if (!stream_) {
         co_return;
      }
      gates_->stop(io_stop_reason::closed);
      static_cast<void>(co_await terminal_completed_->async_wait(0));
   }

   void cancel() override {
      request_cancel();
   }

   void request_cancel() noexcept {
      if (stream_) {
         gates_->stop(io_stop_reason::canceled);
      }
   }

 private:
   std::shared_ptr<native_stream> stream_;
   tls::context_snapshot_ptr context_;
   asio::strand<asio::any_io_executor> strand_;
   std::shared_ptr<io_gates> gates_;
   std::size_t read_chunk_size_ = 64 * 1024;
   transport::buffer_pool pool_;
   std::int64_t id_ = -1;
   std::shared_ptr<forge::asio::notification> terminal_completed_;
   std::shared_ptr<void> lifetime_;
};

} // namespace

struct connection::impl final : std::enable_shared_from_this<connection::impl> {
   impl(std::shared_ptr<native_stream> stream_value, tls::context_snapshot_ptr context_value,
        std::size_t read_chunk_size_value, std::shared_ptr<void> lifetime_value)
       : stream(std::move(stream_value)), context(std::move(context_value)),
         strand(asio::make_strand(stream->lowest_layer().get_executor())), gates(std::make_shared<io_gates>()),
         terminal_completed(std::make_shared<forge::asio::notification>()), read_chunk_size(read_chunk_size_value),
         id(next_stream_id()), lifetime(std::move(lifetime_value)) {
      auto error = boost::system::error_code{};
      local_value = from_asio_endpoint(stream->lowest_layer().local_endpoint(error));
      if (error) {
         throw_io_error("failed to read stcp local endpoint", error);
      }
      remote_value = from_asio_endpoint(stream->lowest_layer().remote_endpoint(error));
      if (error) {
         throw_io_error("failed to read stcp remote endpoint", error);
      }
      chain_value = tls::extract_peer_certificate_chain(stream->native_handle());
      if (!chain_value.certificates.empty()) {
         certificate_value = chain_value.certificates.front();
      }
      alpn_value = tls::selected_alpn(stream->native_handle());
   }

   void start_terminal_worker() {
      // This operation is created while the connection is published. It owns the
      // native stream across a later transport handoff and turns foreign-thread
      // cancellation into owner-strand socket access without allocating in cancel().
      auto current = stream;
      auto current_gates = gates;
      auto completed = terminal_completed;
      auto lifetime_value = lifetime;
      asio::co_spawn(
          strand,
          [current = std::move(current), current_gates = std::move(current_gates),
           lifetime_value = std::move(lifetime_value)]() -> asio::awaitable<void> {
             static_cast<void>(lifetime_value);
             try {
                static_cast<void>(co_await current_gates->terminal_requested.async_wait(0));
             } catch (...) {
                current_gates->stop(io_stop_reason::canceled);
             }
             cancel_stream(*current);
          },
          [completed = std::move(completed)](std::exception_ptr) noexcept { completed->notify(); });
   }

   [[nodiscard]] bool valid() const noexcept {
      const auto lock = std::scoped_lock{state_mutex};
      return state == connection_state::active;
   }

   [[nodiscard]] transport::endpoint local_endpoint() const {
      if (!valid()) {
         FORGE_THROW_EXCEPTION(exceptions::closed, "invalid stcp connection");
      }
      return local_value;
   }

   [[nodiscard]] transport::endpoint remote_endpoint() const {
      if (!valid()) {
         FORGE_THROW_EXCEPTION(exceptions::closed, "invalid stcp connection");
      }
      return remote_value;
   }

   boost::asio::awaitable<void> async_write(std::span<const std::uint8_t> bytes) {
      claim_operation();
      try {
         auto write_ticket = co_await gates->acquire(gates->write);
         auto self = shared_from_this();
         co_await asio::co_spawn(
             strand,
             [self = std::move(self), bytes]() -> asio::awaitable<void> {
                if (self->gates->stopped()) {
                   self->gates->throw_stopped();
                }
                if (!self->stream || !self->stream->lowest_layer().is_open()) {
                   self->mark_closed_from_io();
                   terminalize_closed(self->stream.get(), *self->gates, "invalid stcp connection");
                }
                auto error = boost::system::error_code{};
                co_await asio::async_write(*self->stream, asio::buffer(bytes),
                                           asio::redirect_error(asio::use_awaitable, error));
                if (error) {
                   self->mark_closed_from_io();
                   terminalize_io_error(*self->stream, *self->gates, error);
                }
             },
             asio::use_awaitable);
      } catch (...) {
         release_operation();
         throw;
      }
      release_operation();
   }

   boost::asio::awaitable<std::size_t> async_read_some(std::span<std::uint8_t> bytes) {
      claim_operation();
      try {
         auto read_ticket = co_await gates->acquire(gates->read);
         auto self = shared_from_this();
         const auto size = co_await asio::co_spawn(
             strand,
             [self = std::move(self), bytes]() -> asio::awaitable<std::size_t> {
                if (self->gates->stopped()) {
                   self->gates->throw_stopped();
                }
                if (!self->stream || !self->stream->lowest_layer().is_open()) {
                   self->mark_closed_from_io();
                   terminalize_closed(self->stream.get(), *self->gates, "invalid stcp connection");
                }
                auto error = boost::system::error_code{};
                const auto size = co_await self->stream->async_read_some(
                    asio::buffer(bytes), asio::redirect_error(asio::use_awaitable, error));
                if (error) {
                   self->mark_closed_from_io();
                   terminalize_io_error(*self->stream, *self->gates, error);
                }
                co_return size;
             },
             asio::use_awaitable);
         release_operation();
         co_return size;
      } catch (...) {
         release_operation();
         throw;
      }
   }

   boost::asio::awaitable<std::vector<std::uint8_t>> async_read() {
      claim_operation();
      try {
         auto read_ticket = co_await gates->acquire(gates->read);
         auto out = std::vector<std::uint8_t>(read_chunk_size);
         auto self = shared_from_this();
         const auto size = co_await asio::co_spawn(
             strand,
             [self = std::move(self), writable = std::span<std::uint8_t>{out}]() -> asio::awaitable<std::size_t> {
                if (self->gates->stopped()) {
                   self->gates->throw_stopped();
                }
                if (!self->stream || !self->stream->lowest_layer().is_open()) {
                   self->mark_closed_from_io();
                   terminalize_closed(self->stream.get(), *self->gates, "invalid stcp connection");
                }
                auto error = boost::system::error_code{};
                const auto size = co_await self->stream->async_read_some(
                    asio::buffer(writable), asio::redirect_error(asio::use_awaitable, error));
                if (error) {
                   self->mark_closed_from_io();
                   terminalize_io_error(*self->stream, *self->gates, error);
                }
                co_return size;
             },
             asio::use_awaitable);
         out.resize(size);
         release_operation();
         co_return out;
      } catch (...) {
         release_operation();
         throw;
      }
   }

   boost::asio::awaitable<void> async_close() {
      if (request_terminal(connection_state::close_requested)) {
         gates->stop(io_stop_reason::closed);
      }
      static_cast<void>(co_await terminal_completed->async_wait(0));
   }

   void cancel() noexcept {
      if (request_terminal(connection_state::cancel_requested)) {
         gates->stop(io_stop_reason::canceled);
      }
   }

   [[nodiscard]] transport::stream_connection into_transport_stream() {
      static_assert(std::is_nothrow_move_constructible_v<transport::stream_connection>);
      auto model =
          std::make_shared<stream_model>(context, strand, gates, terminal_completed, read_chunk_size, id, lifetime);
      auto weak = std::weak_ptr<stream_model>{model};
      auto result = transport::stream_connection{
          .local_endpoint = local_value,
          .remote_endpoint = remote_value,
          .stream = transport::detail::stream_access::make_cancelable(model,
                                                                      [weak = std::move(weak)]() noexcept {
                                                                         if (auto value = weak.lock()) {
                                                                            value->request_cancel();
                                                                         }
                                                                      }),
      };
      commit_handoff(model);
      return result;
   }

   [[nodiscard]] bool request_terminal(connection_state requested) noexcept {
      const auto lock = std::scoped_lock{state_mutex};
      if (state != connection_state::active) {
         return false;
      }
      state = requested;
      return true;
   }

   void mark_closed_from_io() noexcept {
      const auto lock = std::scoped_lock{state_mutex};
      if (state == connection_state::active || state == connection_state::cancel_requested ||
          state == connection_state::close_requested) {
         state = connection_state::closed;
      }
   }

   void commit_handoff(const std::shared_ptr<stream_model>& model) {
      const auto lock = std::scoped_lock{state_mutex};
      if (state != connection_state::active) {
         FORGE_THROW_EXCEPTION(exceptions::closed, "stcp connection cannot hand off a terminal stream");
      }
      if (active_operations != 0) {
         FORGE_THROW_EXCEPTION(exceptions::io_error, "stcp connection cannot hand off while I/O is active");
      }
      // Model, cancel callback, and result endpoints are fully allocated. The
      // remaining shared_ptr move and state commit are non-throwing.
      model->attach(std::move(stream));
      state = connection_state::handed_off;
   }

   void claim_operation() {
      const auto lock = std::scoped_lock{state_mutex};
      if (state == connection_state::cancel_requested) {
         FORGE_THROW_EXCEPTION(exceptions::canceled, "stcp connection canceled");
      }
      if (state != connection_state::active) {
         FORGE_THROW_EXCEPTION(exceptions::closed, "invalid stcp connection");
      }
      ++active_operations;
   }

   void release_operation() noexcept {
      const auto lock = std::scoped_lock{state_mutex};
      --active_operations;
   }

   std::shared_ptr<native_stream> stream;
   tls::context_snapshot_ptr context;
   asio::strand<asio::any_io_executor> strand;
   std::shared_ptr<io_gates> gates;
   std::shared_ptr<forge::asio::notification> terminal_completed;
   std::size_t read_chunk_size = 64 * 1024;
   std::int64_t id = -1;
   transport::endpoint local_value;
   transport::endpoint remote_value;
   std::optional<forge::net::stcp::peer_certificate> certificate_value;
   certificate_chain chain_value;
   std::string alpn_value;
   mutable std::mutex state_mutex;
   connection_state state = connection_state::active;
   std::size_t active_operations = 0;
   std::shared_ptr<void> lifetime;
};

connection::connection() = default;
connection::connection(native_token, std::shared_ptr<native_stream> stream, tls::context_snapshot_ptr context,
                       std::size_t read_chunk_size, std::shared_ptr<void> lifetime)
    : impl_(std::make_shared<impl>(std::move(stream), std::move(context), read_chunk_size, std::move(lifetime))) {
   impl_->start_terminal_worker();
}
connection::~connection() {
   if (impl_) {
      impl_->cancel();
   }
}
connection::connection(connection&&) noexcept = default;
connection& connection::operator=(connection&& other) noexcept {
   if (this != &other) {
      if (impl_) {
         impl_->cancel();
      }
      impl_ = std::move(other.impl_);
   }
   return *this;
}

bool connection::valid() const noexcept {
   return impl_ && impl_->valid();
}

transport::endpoint connection::local_endpoint() const {
   if (!valid()) {
      FORGE_THROW_EXCEPTION(exceptions::closed, "invalid stcp connection");
   }
   return impl_->local_endpoint();
}

transport::endpoint connection::remote_endpoint() const {
   if (!valid()) {
      FORGE_THROW_EXCEPTION(exceptions::closed, "invalid stcp connection");
   }
   return impl_->remote_endpoint();
}

std::optional<peer_certificate> connection::peer_certificate() const {
   if (!valid()) {
      FORGE_THROW_EXCEPTION(exceptions::closed, "invalid stcp connection");
   }
   return impl_->certificate_value;
}

certificate_chain connection::peer_certificate_chain() const {
   if (!valid()) {
      FORGE_THROW_EXCEPTION(exceptions::closed, "invalid stcp connection");
   }
   return impl_->chain_value;
}

std::string connection::selected_alpn() const {
   if (!valid()) {
      FORGE_THROW_EXCEPTION(exceptions::closed, "invalid stcp connection");
   }
   return impl_->alpn_value;
}

boost::asio::awaitable<void> connection::async_write(std::span<const std::uint8_t> bytes) {
   if (!impl_) {
      FORGE_THROW_EXCEPTION(exceptions::closed, "invalid stcp connection");
   }
   auto state = impl_;
   co_await state->async_write(bytes);
}

boost::asio::awaitable<std::size_t> connection::async_read_some(std::span<std::uint8_t> bytes) {
   if (!impl_) {
      FORGE_THROW_EXCEPTION(exceptions::closed, "invalid stcp connection");
   }
   auto state = impl_;
   co_return co_await state->async_read_some(bytes);
}

boost::asio::awaitable<std::vector<std::uint8_t>> connection::async_read() {
   if (!impl_) {
      FORGE_THROW_EXCEPTION(exceptions::closed, "invalid stcp connection");
   }
   auto state = impl_;
   co_return co_await state->async_read();
}

boost::asio::awaitable<void> connection::async_close() {
   if (!impl_) {
      co_return;
   }
   auto state = impl_;
   co_await state->async_close();
}

void connection::cancel() {
   if (impl_) {
      impl_->cancel();
   }
}

transport::stream_connection connection::into_transport_stream() && {
   if (!impl_) {
      FORGE_THROW_EXCEPTION(exceptions::closed, "invalid stcp connection");
   }
   return impl_->into_transport_stream();
}

boost::asio::awaitable<connection> async_upgrade_client(tcp::connection source, client_options options,
                                                        std::optional<std::chrono::milliseconds> timeout,
                                                        std::stop_token stop);
boost::asio::awaitable<connection> async_upgrade_server(tcp::connection source, server_options options,
                                                        std::optional<std::chrono::milliseconds> timeout,
                                                        std::stop_token stop);

boost::asio::awaitable<connection> async_upgrade_client(tcp::connection source, client_options options) {
   co_return co_await async_upgrade_client(std::move(source), std::move(options), std::nullopt, {});
}

boost::asio::awaitable<connection> async_upgrade_client(tcp::connection source, client_options options,
                                                        std::chrono::milliseconds timeout) {
   co_return co_await async_upgrade_client(std::move(source), std::move(options), std::optional{timeout}, {});
}

boost::asio::awaitable<connection> async_upgrade_client(tcp::connection source, client_options options,
                                                        std::stop_token stop) {
   co_return co_await async_upgrade_client(std::move(source), std::move(options), std::nullopt, stop);
}

boost::asio::awaitable<connection> async_upgrade_client(tcp::connection source, client_options options,
                                                        std::chrono::milliseconds timeout, std::stop_token stop) {
   co_return co_await async_upgrade_client(std::move(source), std::move(options), std::optional{timeout}, stop);
}

boost::asio::awaitable<connection> async_upgrade_client(tcp::connection source, client_options options,
                                                        std::optional<std::chrono::milliseconds> timeout,
                                                        std::stop_token stop) {
   if (!source.valid()) {
      FORGE_THROW_EXCEPTION(exceptions::closed, "invalid source tcp connection");
   }
   const auto remote = source.remote_endpoint();
   auto context = make_client_context(options);
   auto lifetime = std::shared_ptr<void>{};
   auto stream = tls::make_asio_stream(context, std::move(source).release_socket(lifetime));
   configure_tls_client_stream(*stream, options, remote.host, *context);

   try {
      co_await async_handshake(stream, asio::ssl::stream_base::client, timeout, stop);
   } catch (const exceptions::handshake_failed&) {
      classify_tls_handshake_failure(*stream, *context);
      throw;
   }
   const auto expected_host = options.server_name.empty() ? remote.host : options.server_name;
   validate_tls_peer(*stream, *context, options.security, expected_host);
   co_return connection{connection::native_token{}, std::move(stream), std::move(context), options.read_chunk_size,
                        std::move(lifetime)};
}

boost::asio::awaitable<connection> async_upgrade_server(tcp::connection source, server_options options) {
   co_return co_await async_upgrade_server(std::move(source), std::move(options), std::nullopt, {});
}

boost::asio::awaitable<connection> async_upgrade_server(tcp::connection source, server_options options,
                                                        std::chrono::milliseconds timeout) {
   co_return co_await async_upgrade_server(std::move(source), std::move(options), std::optional{timeout}, {});
}

boost::asio::awaitable<connection> async_upgrade_server(tcp::connection source, server_options options,
                                                        std::stop_token stop) {
   co_return co_await async_upgrade_server(std::move(source), std::move(options), std::nullopt, stop);
}

boost::asio::awaitable<connection> async_upgrade_server(tcp::connection source, server_options options,
                                                        std::chrono::milliseconds timeout, std::stop_token stop) {
   co_return co_await async_upgrade_server(std::move(source), std::move(options), std::optional{timeout}, stop);
}

boost::asio::awaitable<connection> async_upgrade_server(tcp::connection source, server_options options,
                                                        std::optional<std::chrono::milliseconds> timeout,
                                                        std::stop_token stop) {
   if (!source.valid()) {
      FORGE_THROW_EXCEPTION(exceptions::closed, "invalid source tcp connection");
   }
   auto context = make_server_context(options);
   auto lifetime = std::shared_ptr<void>{};
   auto stream = tls::make_asio_stream(context, std::move(source).release_socket(lifetime));
   co_await async_handshake(stream, asio::ssl::stream_base::server, timeout, stop);
   validate_tls_peer(*stream, *context, options.security, {});
   co_return connection{connection::native_token{}, std::move(stream), std::move(context), options.read_chunk_size,
                        std::move(lifetime)};
}

} // namespace forge::net::stcp

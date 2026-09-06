#include <boost/asio/awaitable.hpp>
#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/error.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/ssl/context.hpp>
#include <boost/asio/ssl/stream_base.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/core/tcp_stream.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/describe.hpp>
#include <boost/scope/scope_exit.hpp>
#include <boost/system/system_error.hpp>
#include <boost/test/unit_test.hpp>
#include <forge/api/core/macros.hpp>
#include <forge/exceptions/macros.hpp>
#include <forge/api/http/macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#include "../quic_p2p/libp2p_identity_fixture.hxx"

import forge.api.core.exceptions;
import forge.api.core.types;
import forge.api.core.descriptor;
import forge.api.core.error_projection;
import forge.api.core.handle;
import forge.api.core.connection;
import forge.api.core.registry;
import forge.api.core.binding;
import forge.api.core.dispatcher;
import forge.api.core.server_supplied;
import forge.api.core.trusted_invocation;
import forge.api.transport.exceptions;
import forge.api.transport.options;
import forge.api.transport.client;
import forge.api.transport.connection;
import forge.api.transport.server;
import forge.app.exceptions;
import forge.app.application;
import forge.app.events;
import forge.app.diagnostics;
import forge.app.signals;
import forge.app.plugin_context;
import forge.app.plugin;
import forge.app.plugin_registry;
import forge.app.application_shell;
import forge.app.application_builder;
import forge.app.runner;
import forge.app.daemon;
import forge.asio.blocking;
import forge.asio.compute;
import forge.asio.notification;
import forge.asio.runtime;
import forge.asio.task;
import forge.config.core.component;
import forge.config.core.document;
import forge.config.core.value;
import forge.config.core.decode;
import forge.crypto.asymmetric;
import forge.crypto.asymmetric.ed25519;
import forge.crypto.asymmetric.p256;
import forge.crypto.asymmetric.rsa;
import forge.crypto.asymmetric.secp256k1;
import forge.crypto.bls;
import forge.crypto.digest.sha256;
import forge.config.env;
import forge.api.http.binding;
import forge.net.http.base_url;
import forge.api.http.parameters;
import forge.net.http.body;
import forge.net.http.client;
import forge.net.http.connection;
import forge.net.http.exceptions;
import forge.net.http.assets;
import forge.net.http.file;
import forge.api.http.mapping;
import forge.net.http.middleware;
import forge.api.http.proxy;
import forge.net.http.router;
import forge.net.http.stream;
import forge.net.http.types;
import forge.net.http.upload;
import forge.net.p2p.exceptions;
import forge.net.p2p.identity;
import forge.net.p2p.endpoint;
import forge.net.p2p.envelope;
import forge.net.p2p.identify;
import forge.net.p2p.diagnostics;
import forge.net.p2p.discovery;
import forge.net.p2p.dht;
import forge.net.p2p.lifecycle;
import forge.net.p2p.rendezvous;
import forge.net.p2p.pubsub;
import forge.net.p2p.reachability;
import forge.net.p2p.hole_punch;
import forge.net.p2p.protocol;
import forge.net.p2p.message;
import forge.net.p2p.scoring;
import forge.net.p2p.relay;
import forge.net.p2p.resource_manager;
import forge.net.p2p.stream;
import forge.net.p2p.negotiation;
import forge.net.p2p.peer_store;
import forge.net.p2p.node;
import forge.api.p2p.authenticated_peer;
import forge.api.p2p.binding;
import forge.api.p2p.publication;
import forge.plugins.crypto.signer.types;
import forge.plugins.crypto.signer.exceptions;
import forge.plugins.crypto.signer.api;
import forge.plugins.crypto.signer.bls_api;
import forge.plugins.crypto.signer.plugin;
import forge.plugins.crypto.secrets.types;
import forge.plugins.crypto.secrets.api;
import forge.plugins.p2p.diagnostics.types;
import forge.plugins.p2p.diagnostics.exceptions;
import forge.plugins.p2p.diagnostics.api;
import forge.plugins.p2p.diagnostics.plugin;
import forge.plugins.p2p.pubsub.types;
import forge.plugins.p2p.pubsub.exceptions;
import forge.plugins.p2p.pubsub.api;
import forge.plugins.p2p.pubsub.plugin;
import forge.plugins.p2p.resolver.types;
import forge.plugins.p2p.resolver.exceptions;
import forge.plugins.p2p.resolver.api;
import forge.plugins.p2p.resolver.plugin;
import forge.plugins.p2p.node.types;
import forge.plugins.p2p.node.exceptions;
import forge.plugins.p2p.node.api;
import forge.plugins.p2p.node.plugin;
import forge.plugins.http.server.types;
import forge.plugins.http.server.exceptions;
import forge.plugins.http.server.middleware;
import forge.plugins.http.server.api;
import forge.plugins.http.server.plugin;
import forge.config.program_options;
import forge.raw.raw;
import forge.schema.diagnostic;
import forge.schema.value_kind;
import forge.schema.object;
import forge.schema.enums;
import forge.variant.value;
import forge.variant.conversion;
import forge.variant.containers;
import forge.variant.described;

#include "details/resolver_publication_race.hxx"

template <typename T>
concept accepts_raw_http_binding = requires(T& api, forge::api::http::binding_plan binding) {
   api.publish(std::move(binding), forge::plugins::http::server::publish_options{});
};

namespace raw_http = forge::net::http;
using raw_http_middleware = raw_http::middleware_descriptor;

template <typename T>
concept accepts_raw_http_middleware =
    requires(T& api, raw_http_middleware descriptor) { api.use(std::move(descriptor)); };

template <typename T>
concept accepts_asset_mount = requires(T& api, raw_http::asset_mount mount) { api.mount_assets(std::move(mount)); };

static_assert(!accepts_raw_http_binding<forge::plugins::http::server::api>);
static_assert(!accepts_raw_http_middleware<forge::plugins::http::server::api>);
static_assert(accepts_asset_mount<forge::plugins::http::server::api>);

[[nodiscard]] bool has_internal_forge_header(const forge::net::http::response& value) {
   for (const auto& header : value.headers()) {
      if (header.name.starts_with("X-FORGE-")) {
         return true;
      }
   }
   return false;
}

struct pubsub_payload {
   std::string text;
   std::uint32_t value = 0;

   bool operator==(const pubsub_payload&) const = default;
};
BOOST_DESCRIBE_STRUCT(pubsub_payload, (), (text, value))

struct operation_request {
   std::string request_id;
   std::string subject;
   std::uint64_t revision = 0;

   bool operator==(const operation_request&) const = default;
};
BOOST_DESCRIBE_STRUCT(operation_request, (), (request_id, subject, revision))

struct operation_receipt {
   std::string request_id;
   bool accepted = false;
   std::uint64_t applied_revision = 0;
   std::string authority;
   std::string evidence;

   bool operator==(const operation_receipt&) const = default;
};
BOOST_DESCRIBE_STRUCT(operation_receipt, (), (request_id, accepted, applied_revision, authority, evidence))

struct http_read_request {
   std::string ref;
   std::uint32_t offset = 0;
   std::uint32_t limit = 0;
};

struct http_write_request {
   std::string ref;
   std::string bytes;
};

struct http_chunk {
   std::string bytes;
};

struct http_stream_read_request {
   std::string ref;
};

struct peer_context_caller {
   forge::net::p2p::peer_id id;
};

struct peer_context_request {
   std::string value;
   peer_context_caller caller;
};

BOOST_DESCRIBE_STRUCT(http_read_request, (), (ref, offset, limit))
BOOST_DESCRIBE_STRUCT(http_write_request, (), (ref, bytes))
BOOST_DESCRIBE_STRUCT(http_chunk, (), (bytes))
BOOST_DESCRIBE_STRUCT(http_stream_read_request, (), (ref))
BOOST_DESCRIBE_STRUCT(peer_context_caller, (), (id))
BOOST_DESCRIBE_STRUCT(peer_context_request, (), (value, caller))

namespace forge::api::core {

template <> struct server_supplied<::peer_context_caller> {
   static constexpr bool required = true;

   static void reset(::peer_context_caller& value) {
      value = {};
   }

   [[nodiscard]] static bool apply(::peer_context_caller& value, const trusted_invocation& trusted) {
      const auto* peer = trusted.find<forge::api::p2p::authenticated_peer>();
      if (peer == nullptr) {
         return false;
      }
      value.id = peer->id;
      return true;
   }
};

} // namespace forge::api::core

namespace plugin_test_contract {

class node_test_api : public forge::api::core::contract<node_test_api, forge::api::core::surface::local |
                                                                           forge::api::core::surface::remote> {
 public:
   virtual ~node_test_api() = default;
   virtual boost::asio::awaitable<int> ping(int request) = 0;
};

class peer_context_test_api
    : public forge::api::core::contract<peer_context_test_api,
                                        forge::api::core::surface::local | forge::api::core::surface::remote> {
 public:
   virtual ~peer_context_test_api() = default;
   virtual boost::asio::awaitable<std::string> remote_peer(peer_context_request request) = 0;
};

class receipt_test_api : public forge::api::core::contract<receipt_test_api, forge::api::core::surface::local |
                                                                                 forge::api::core::surface::remote> {
 public:
   virtual ~receipt_test_api() = default;
   virtual boost::asio::awaitable<operation_receipt> apply(operation_request request) = 0;
};

class http_cache_api : public forge::api::core::contract<http_cache_api, forge::api::core::surface::local |
                                                                             forge::api::core::surface::remote> {
 public:
   virtual ~http_cache_api() = default;
   virtual boost::asio::awaitable<http_chunk> read(http_read_request request) = 0;
   virtual boost::asio::awaitable<http_chunk> write(http_write_request request) = 0;
};

class http_stream_api : public forge::api::core::contract<http_stream_api, forge::api::core::surface::local |
                                                                               forge::api::core::surface::remote> {
 public:
   virtual ~http_stream_api() = default;
   virtual boost::asio::awaitable<forge::net::http::streaming_response> download(http_stream_read_request request) = 0;
};

class http_empty_api : public forge::api::core::contract<http_empty_api, forge::api::core::surface::local |
                                                                             forge::api::core::surface::remote> {
 public:
   virtual ~http_empty_api() = default;
   virtual boost::asio::awaitable<forge::api::http::empty_response> clear(http_stream_read_request request) = 0;
};

class scripted_resolver_api
    : public forge::api::core::contract<scripted_resolver_api,
                                        forge::api::core::surface::local | forge::api::core::surface::remote> {
 public:
   virtual ~scripted_resolver_api() = default;
   virtual boost::asio::awaitable<forge::plugins::p2p::resolver::response>
   query(forge::plugins::p2p::resolver::query request) = 0;
};

} // namespace plugin_test_contract

FORGE_API(::plugin_test_contract::node_test_api, FORGE_API_CONTRACT("node.test", 1, 0), FORGE_API_METHOD(ping))
FORGE_API(::plugin_test_contract::peer_context_test_api, FORGE_API_CONTRACT("peer-context.test", 1, 0),
          FORGE_API_METHOD(remote_peer))
FORGE_API(::plugin_test_contract::receipt_test_api, FORGE_API_CONTRACT("receipt.test", 1, 0), FORGE_API_METHOD(apply))
FORGE_API(::plugin_test_contract::http_cache_api, FORGE_API_CONTRACT("cache", 1, 0), FORGE_API_METHOD(read),
          FORGE_API_METHOD(write))
FORGE_API(::plugin_test_contract::http_stream_api, FORGE_API_CONTRACT("stream-cache", 1, 0),
          FORGE_API_METHOD_TYPED(download, ::http_stream_read_request, ::forge::net::http::streaming_response))
FORGE_API(::plugin_test_contract::http_empty_api, FORGE_API_CONTRACT("empty-cache", 1, 0),
          FORGE_API_METHOD_TYPED(clear, ::http_stream_read_request, ::forge::api::http::empty_response))
FORGE_API(::plugin_test_contract::scripted_resolver_api,
          FORGE_API_CONTRACT("forge.plugins.p2p.resolver.protocol", 1, 0), FORGE_API_METHOD(query))

FORGE_HTTP_API(::plugin_test_contract::http_cache_api,
               FORGE_HTTP_GET(read, "/cache/chunks/:ref?offset={offset}&limit={limit}"),
               FORGE_HTTP_PUT(write, "/cache/chunks/:ref", created))
FORGE_HTTP_API(::plugin_test_contract::http_stream_api,
               FORGE_HTTP_GET(download, "/stream/:ref", FORGE_HTTP_RESPONSE_STREAM))
FORGE_HTTP_API(::plugin_test_contract::http_empty_api, FORGE_HTTP_DELETE(clear, "/empty/:ref", no_content))

namespace {

using plugin_test_contract::http_cache_api;
using plugin_test_contract::http_empty_api;
using plugin_test_contract::http_stream_api;
using plugin_test_contract::node_test_api;
using plugin_test_contract::peer_context_test_api;
using plugin_test_contract::receipt_test_api;
using plugin_test_contract::scripted_resolver_api;

namespace crypto_signer = forge::plugins::crypto::signer;
namespace crypto_secrets = forge::plugins::crypto::secrets;
namespace http_server = forge::plugins::http::server;

struct plugin_log {
   std::vector<std::string> entries;
};

struct route_install_gate {
   std::atomic_bool armed = false;
   std::atomic_size_t copies = 0;
   std::mutex mutex;
   std::condition_variable changed;
   bool blocked = false;
   bool released = false;
};

class blocking_route_handler {
 public:
   explicit blocking_route_handler(std::shared_ptr<route_install_gate> gate) : gate_{std::move(gate)} {}

   blocking_route_handler(const blocking_route_handler& other) : gate_{other.gate_} {
      if (!gate_ || !gate_->armed.load(std::memory_order_acquire) ||
          gate_->copies.fetch_add(1, std::memory_order_acq_rel) + 1 != 2) {
         return;
      }
      auto lock = std::unique_lock{gate_->mutex};
      gate_->blocked = true;
      gate_->changed.notify_all();
      gate_->changed.wait(lock, [&] { return gate_->released; });
   }

   blocking_route_handler& operator=(const blocking_route_handler&) = default;

   boost::asio::awaitable<void> operator()(forge::net::p2p::node::incoming_protocol_stream) const {
      co_return;
   }

 private:
   std::shared_ptr<route_install_gate> gate_;
};

[[nodiscard]] forge::net::p2p::peer_id test_peer(std::uint8_t seed) {
   return forge::net::p2p::make_peer_id(
       {.type = forge::net::p2p::public_key::type::ed25519, .data = std::vector<std::uint8_t>(32, seed)});
}

[[nodiscard]] forge::config::core::document
test_p2p_config(std::optional<forge::net::p2p::peer_id> peer = std::nullopt) {
   auto document = forge::config::core::document{};
   document.set("plugins.p2p.node.allow-insecure-test-mode", true);
   document.set("plugins.p2p.node.identity.certificate-secret", "p2p/test-certificate");
   document.set("plugins.p2p.node.identity.private-key-secret", "p2p/test-private-key");
   if (peer) {
      document.set("plugins.p2p.node.peer-id", peer->to_string());
   }
   return document;
}

[[nodiscard]] forge::config::core::value::object_type dht_profile_config(std::string kind, std::string mode,
                                                                         std::string protocol, bool peers = true,
                                                                         bool providers = true, bool values = true) {
   auto profile = forge::config::core::value::object_type{};
   profile.emplace("kind", std::move(kind));
   profile.emplace("mode", std::move(mode));
   profile.emplace("protocol", std::move(protocol));
   profile.emplace("peers", peers);
   profile.emplace("providers", providers);
   profile.emplace("values", values);
   return profile;
}

[[nodiscard]] forge::config::core::value::object_type rendezvous_point_config(std::string endpoint,
                                                                              std::vector<std::string> namespaces) {
   auto point = forge::config::core::value::object_type{};
   point.emplace("endpoint", std::move(endpoint));
   auto encoded_namespaces = forge::config::core::value::array_type{};
   encoded_namespaces.reserve(namespaces.size());
   for (auto& namespace_name : namespaces) {
      encoded_namespaces.emplace_back(std::move(namespace_name));
   }
   point.emplace("namespaces", std::move(encoded_namespaces));
   return point;
}

class p2p_test_dependency_plugin : public forge::app::plugin {
 public:
   explicit p2p_test_dependency_plugin(std::string id) : id_{std::move(id)} {}

   [[nodiscard]] forge::app::plugin_id id() const override {
      return forge::app::plugin_id{.value = id_};
   }

   [[nodiscard]] std::string version() const override {
      return "test";
   }

   boost::asio::awaitable<void> initialize(forge::app::plugin_context&) override {
      co_return;
   }

   boost::asio::awaitable<void> startup() override {
      co_return;
   }

   boost::asio::awaitable<void> shutdown() override {
      co_return;
   }

 private:
   std::string id_;
};

class p2p_test_secrets_api final : public crypto_secrets::api {
 public:
   boost::asio::awaitable<crypto_secrets::snapshot> status(crypto_secrets::query) override {
      co_return crypto_secrets::snapshot{.configured_secrets = 2};
   }

   boost::asio::awaitable<crypto_secrets::get_result> get_bytes(crypto_secrets::get_request request) override {
      const auto& identity = fixture();
      const auto* material = request.secret_id == "p2p/test-certificate"   ? &identity.certificate_pem
                             : request.secret_id == "p2p/test-private-key" ? &identity.private_key_pem
                                                                           : nullptr;
      if (material == nullptr) {
         throw std::runtime_error{"unknown P2P test secret"};
      }
      auto bytes = decltype(crypto_secrets::get_result{}.bytes){};
      bytes.reserve(material->size());
      for (const auto value : *material) {
         bytes.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(value)));
      }
      co_return crypto_secrets::get_result{.secret_id = std::move(request.secret_id), .bytes = std::move(bytes)};
   }

   boost::asio::awaitable<crypto_secrets::derive_result> derive_hkdf_sha256(crypto_secrets::derive_request) override {
      throw std::logic_error{"P2P test secrets do not implement derivation"};
      co_return crypto_secrets::derive_result{};
   }

   boost::asio::awaitable<crypto_secrets::aead_encrypt_result>
   encrypt_aes_gcm(crypto_secrets::aead_encrypt_request) override {
      throw std::logic_error{"P2P test secrets do not implement encryption"};
      co_return crypto_secrets::aead_encrypt_result{};
   }

   boost::asio::awaitable<crypto_secrets::aead_decrypt_result>
   decrypt_aes_gcm(crypto_secrets::aead_decrypt_request) override {
      throw std::logic_error{"P2P test secrets do not implement decryption"};
      co_return crypto_secrets::aead_decrypt_result{};
   }

 private:
   [[nodiscard]] static const forge::tests::p2p::identity_fixture& fixture() {
      static const auto value = forge::tests::p2p::make_identity_fixture("p2p-plugin-suite");
      return value;
   }
};

class p2p_test_secrets_plugin final : public p2p_test_dependency_plugin {
 public:
   p2p_test_secrets_plugin() : p2p_test_dependency_plugin{"forge.plugins.crypto.secrets"} {}

   boost::asio::awaitable<void> provide(forge::api::core::provider& provider) override {
      provider.install<crypto_secrets::api>(std::make_shared<p2p_test_secrets_api>());
      co_return;
   }
};

void register_p2p_stack(forge::app::plugin_registry& registry) {
   registry.register_plugin(forge::app::plugin_descriptor{
       .id = forge::app::plugin_id{.value = "forge.plugins.db.store"},
       .factory = [] { return std::make_unique<p2p_test_dependency_plugin>("forge.plugins.db.store"); },
   });
   registry.register_plugin(forge::app::plugin_descriptor{
       .id = forge::app::plugin_id{.value = "forge.plugins.crypto.secrets"},
       .factory = [] { return std::make_unique<p2p_test_secrets_plugin>(); },
   });
   registry.register_plugin(forge::plugins::p2p::node::descriptor());
}

class node_test_api_impl final : public node_test_api {
 public:
   boost::asio::awaitable<int> ping(int request) override {
      co_return request + 1;
   }
};

class offset_node_test_api_impl final : public node_test_api {
 public:
   explicit offset_node_test_api_impl(int offset) : offset_{offset} {}

   boost::asio::awaitable<int> ping(int request) override {
      co_return request + offset_;
   }

 private:
   int offset_ = 0;
};

[[nodiscard]] forge::api::core::binding_plan node_test_plan(const forge::api::core::registry& apis) {
   return forge::api::core::binding()
       .serve(apis)
       .export_api<node_test_api>({.id = {"node.test"}, .major = 1, .min_revision = 0})
       .build();
}

[[nodiscard]] forge::api::core::binding_plan peer_context_test_plan(const forge::api::core::registry& apis) {
   return forge::api::core::binding()
       .serve(apis)
       .export_api<peer_context_test_api>({.id = {"peer-context.test"}, .major = 1, .min_revision = 0})
       .build();
}

struct nonresponding_node_test_state {
   std::atomic_bool started{false};
   std::atomic_bool cancelled{false};
};

class nonresponding_node_test_api_impl final : public node_test_api {
 public:
   explicit nonresponding_node_test_api_impl(std::shared_ptr<nonresponding_node_test_state> state)
       : state_{std::move(state)} {}

   boost::asio::awaitable<int> ping(int request) override {
      auto timer = boost::asio::steady_timer{co_await boost::asio::this_coro::executor, std::chrono::seconds{2}};
      state_->started.store(true, std::memory_order_release);
      try {
         co_await timer.async_wait(boost::asio::use_awaitable);
      } catch (const boost::system::system_error& error) {
         if (error.code() == boost::asio::error::operation_aborted) {
            state_->cancelled.store(true, std::memory_order_release);
         }
         throw;
      }
      co_return request + 1;
   }

 private:
   std::shared_ptr<nonresponding_node_test_state> state_;
};

class peer_context_test_api_impl final : public peer_context_test_api {
 public:
   boost::asio::awaitable<std::string> remote_peer(peer_context_request request) override {
      co_return request.caller.id.to_string() + ":" + request.value;
   }
};

struct receipt_test_state {
   mutable std::mutex mutex;
   std::unordered_map<std::string, operation_receipt> receipts;
   std::size_t applied = 0;
};

class receipt_test_api_impl final : public receipt_test_api {
 public:
   explicit receipt_test_api_impl(std::shared_ptr<receipt_test_state> state) : state_{std::move(state)} {}

   boost::asio::awaitable<operation_receipt> apply(operation_request request) override {
      auto lock = std::scoped_lock{state_->mutex};
      if (const auto existing = state_->receipts.find(request.request_id); existing != state_->receipts.end()) {
         co_return existing->second;
      }

      const auto revision = ++state_->applied;
      auto receipt = operation_receipt{
          .request_id = request.request_id,
          .accepted = true,
          .applied_revision = revision,
          .authority = "receipt-test",
          .evidence = request.subject + ":" + std::to_string(request.revision) + ":" + std::to_string(revision),
      };
      auto [inserted, _] = state_->receipts.emplace(request.request_id, std::move(receipt));
      co_return inserted->second;
   }

 private:
   std::shared_ptr<receipt_test_state> state_;
};

class http_cache_api_impl final : public http_cache_api {
 public:
   boost::asio::awaitable<http_chunk> read(http_read_request request) override {
      co_return http_chunk{.bytes = request.ref + ":" + std::to_string(request.offset) + ":" +
                                    std::to_string(request.limit)};
   }

   boost::asio::awaitable<http_chunk> write(http_write_request request) override {
      co_return http_chunk{.bytes = request.ref + ":" + request.bytes};
   }
};

struct http_publish_state {
   std::string base_path;
   std::vector<std::string> middleware_events;
   bool short_circuit = false;
   bool replace_stream_after_next = false;
   bool empty_replace_stream_after_next = false;
   bool set_stream_content_type_after_next = false;
   bool append_cookies_after_next = false;
   std::atomic<unsigned> stream_calls = 0;
   std::atomic<unsigned> stream_chunks = 0;
};

struct http_asset_publish_state {
   std::filesystem::path root;
   std::string mount_path = "/admin";
};

[[nodiscard]] forge::app::application_shell_options http_asset_application_options(bool with_compute) {
   auto options = forge::app::application_shell_options{};
   if (with_compute) {
      options.compute = forge::asio::compute::pool::options{
          .worker_threads = 2,
          .max_pending_tasks = 16,
          .max_waiting_submissions = 16,
          .thread_name = "forge-http-asset-test",
      };
   }
   return options;
}

class http_stream_api_impl final : public http_stream_api {
 public:
   explicit http_stream_api_impl(std::shared_ptr<http_publish_state> state) : state_{std::move(state)} {}

   boost::asio::awaitable<forge::net::http::streaming_response> download(http_stream_read_request request) override {
      state_->stream_calls.fetch_add(1);
      auto chunks =
          std::make_shared<std::vector<std::string>>(std::vector<std::string>{"stream:", request.ref, ":payload"});
      auto index = std::make_shared<std::size_t>(0);
      auto state = state_;
      co_return forge::net::http::streaming_response::from_source(forge::net::http::streaming_response_options{
          .content_type = "text/plain",
          .body = [chunks, index,
                   state]() mutable -> boost::asio::awaitable<std::optional<forge::net::http::body_chunk>> {
             if (*index == chunks->size()) {
                co_return std::nullopt;
             }
             const auto& text = (*chunks)[(*index)++];
             auto bytes = std::vector<std::byte>(text.size());
             std::memcpy(bytes.data(), text.data(), text.size());
             state->stream_chunks.fetch_add(1);
             co_return forge::net::http::body_chunk{.bytes = std::move(bytes)};
          },
      });
   }

 private:
   std::shared_ptr<http_publish_state> state_;
};

class http_empty_api_impl final : public http_empty_api {
 public:
   boost::asio::awaitable<forge::api::http::empty_response> clear(http_stream_read_request) override {
      co_return forge::api::http::empty_response{.status_code = forge::net::http::status::no_content};
   }
};

class http_cache_publisher_plugin final : public forge::app::plugin {
 public:
   explicit http_cache_publisher_plugin(std::shared_ptr<http_publish_state> state) : state_{std::move(state)} {}

   [[nodiscard]] forge::app::plugin_id id() const override {
      return forge::app::plugin_id{.value = "http-cache-publisher"};
   }

   [[nodiscard]] std::string version() const override {
      return "1";
   }

   boost::asio::awaitable<void> initialize(forge::app::plugin_context& context) override {
      auto http = context.apis().get<http_server::api>(http_server::api::ref());
      co_await http->publish<http_cache_api>(http_server::publish_options{.base_path = state_->base_path});
   }

   boost::asio::awaitable<void> startup() override {
      co_return;
   }

   boost::asio::awaitable<void> shutdown() override {
      co_return;
   }

 private:
   std::shared_ptr<http_publish_state> state_;
};

class http_asset_publisher_plugin final : public forge::app::plugin {
 public:
   explicit http_asset_publisher_plugin(std::shared_ptr<http_asset_publish_state> state) : state_{std::move(state)} {}

   [[nodiscard]] forge::app::plugin_id id() const override {
      return forge::app::plugin_id{.value = "http-asset-publisher"};
   }

   [[nodiscard]] std::string version() const override {
      return "1";
   }

   boost::asio::awaitable<void> initialize(forge::app::plugin_context& context) override {
      auto http = context.apis().get<http_server::api>(http_server::api::ref());
      co_await http->mount_assets(raw_http::asset_mount{
          .path = state_->mount_path,
          .root = state_->root,
      });
   }

   boost::asio::awaitable<void> startup() override {
      co_return;
   }

   boost::asio::awaitable<void> shutdown() override {
      co_return;
   }

 private:
   std::shared_ptr<http_asset_publish_state> state_;
};

class http_stream_publisher_plugin final : public forge::app::plugin {
 public:
   explicit http_stream_publisher_plugin(std::shared_ptr<http_publish_state> state) : state_{std::move(state)} {}

   [[nodiscard]] forge::app::plugin_id id() const override {
      return forge::app::plugin_id{.value = "http-stream-publisher"};
   }

   [[nodiscard]] std::string version() const override {
      return "1";
   }

   boost::asio::awaitable<void> initialize(forge::app::plugin_context& context) override {
      auto http = context.apis().get<http_server::api>(http_server::api::ref());
      co_await http->publish<http_stream_api>(http_server::publish_options{.base_path = state_->base_path});
   }

   boost::asio::awaitable<void> startup() override {
      co_return;
   }

   boost::asio::awaitable<void> shutdown() override {
      co_return;
   }

 private:
   std::shared_ptr<http_publish_state> state_;
};

class http_empty_publisher_plugin final : public forge::app::plugin {
 public:
   explicit http_empty_publisher_plugin(std::shared_ptr<http_publish_state> state) : state_{std::move(state)} {}

   [[nodiscard]] forge::app::plugin_id id() const override {
      return forge::app::plugin_id{.value = "http-empty-publisher"};
   }

   [[nodiscard]] std::string version() const override {
      return "1";
   }

   boost::asio::awaitable<void> initialize(forge::app::plugin_context& context) override {
      auto http = context.apis().get<http_server::api>(http_server::api::ref());
      co_await http->publish<http_empty_api>(http_server::publish_options{.base_path = state_->base_path});
   }

   boost::asio::awaitable<void> startup() override {
      co_return;
   }

   boost::asio::awaitable<void> shutdown() override {
      co_return;
   }

 private:
   std::shared_ptr<http_publish_state> state_;
};

class http_middleware_plugin final : public forge::app::plugin {
 public:
   explicit http_middleware_plugin(std::shared_ptr<http_publish_state> state) : state_{std::move(state)} {}

   [[nodiscard]] forge::app::plugin_id id() const override {
      return forge::app::plugin_id{.value = "http-middleware"};
   }

   [[nodiscard]] std::string version() const override {
      return "1";
   }

   boost::asio::awaitable<void> initialize(forge::app::plugin_context& context) override {
      auto http = context.apis().get<http_server::api>(http_server::api::ref());
      auto state = state_;
      co_await http->use(http_server::middleware_descriptor{
          .id = "security",
          .phase = http_server::middleware_phase::security,
          .order = 10,
          .path_prefix = "/api",
          .handler = [state](const http_server::middleware_request& request, http_server::middleware_next next)
              -> boost::asio::awaitable<http_server::middleware_response> {
             state->middleware_events.push_back("security");
             if (state->short_circuit && !request.header("Authorization").has_value()) {
                co_return http_server::middleware_response::text(forge::net::http::status::unauthorized,
                                                                 "missing authorization");
             }
             co_return co_await next();
          },
      });
      co_await http->use(http_server::middleware_descriptor{
          .id = "before",
          .phase = http_server::middleware_phase::before_handler,
          .order = 20,
          .path_prefix = "/api",
          .handler = [state](const http_server::middleware_request&, http_server::middleware_next next)
              -> boost::asio::awaitable<http_server::middleware_response> {
             state->middleware_events.push_back("before");
             auto response = co_await next();
             if (state->replace_stream_after_next) {
                co_return http_server::middleware_response::text(forge::net::http::status::forbidden, "blocked");
             }
             if (state->empty_replace_stream_after_next) {
                response.set_status(forge::net::http::status::forbidden);
                response.clear_body();
                co_return response;
             }
             if (state->set_stream_content_type_after_next) {
                response.set_content_type("application/x-ndjson");
             }
             if (state->append_cookies_after_next) {
                response.append_header("Set-Cookie", "session=alpha; Path=/api; HttpOnly");
                response.append_header("Set-Cookie", "csrf=beta; Path=/api; Secure");
             }
             response.set_header("Server", "forge-test");
             co_return response;
          },
      });
   }

   boost::asio::awaitable<void> startup() override {
      co_return;
   }

   boost::asio::awaitable<void> shutdown() override {
      co_return;
   }

 private:
   std::shared_ptr<http_publish_state> state_;
};

class duplicate_http_cache_publisher_plugin final : public forge::app::plugin {
 public:
   [[nodiscard]] forge::app::plugin_id id() const override {
      return forge::app::plugin_id{.value = "duplicate-http-cache-publisher"};
   }

   [[nodiscard]] std::string version() const override {
      return "1";
   }

   boost::asio::awaitable<void> initialize(forge::app::plugin_context& context) override {
      auto http = context.apis().get<http_server::api>(http_server::api::ref());
      co_await http->publish<http_cache_api>(http_server::publish_options{.base_path = "/api"});
      co_await http->publish<http_cache_api>(http_server::publish_options{.base_path = "/api"});
   }

   boost::asio::awaitable<void> startup() override {
      co_return;
   }

   boost::asio::awaitable<void> shutdown() override {
      co_return;
   }
};

class late_http_publish_plugin final : public forge::app::plugin {
 public:
   [[nodiscard]] forge::app::plugin_id id() const override {
      return forge::app::plugin_id{.value = "late-http-publisher"};
   }

   [[nodiscard]] std::string version() const override {
      return "1";
   }

   boost::asio::awaitable<void> startup() override {
      auto http = context_->apis().get<http_server::api>(http_server::api::ref());
      co_await http->publish<http_cache_api>(http_server::publish_options{.base_path = "/late"});
   }

   boost::asio::awaitable<void> initialize(forge::app::plugin_context& context) override {
      context_ = &context;
      co_return;
   }

   boost::asio::awaitable<void> shutdown() override {
      co_return;
   }

 private:
   forge::app::plugin_context* context_ = nullptr;
};

class temp_directory {
 public:
   temp_directory() {
      path_ = std::filesystem::temp_directory_path() /
              ("forge-plugin-http-test-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
      std::filesystem::create_directories(path_);
   }

   ~temp_directory() {
      std::error_code ignored;
      std::filesystem::remove_all(path_, ignored);
   }

   [[nodiscard]] const std::filesystem::path& path() const noexcept {
      return path_;
   }

   void write(std::string_view name, std::string_view bytes) const {
      auto output = std::ofstream{path_ / std::string{name}, std::ios::binary};
      output << bytes;
   }

 private:
   std::filesystem::path path_;
};

struct received_pubsub_messages {
   mutable std::mutex mutex;
   std::vector<forge::plugins::p2p::pubsub::message> raw;
   std::vector<forge::plugins::p2p::pubsub::typed_message<pubsub_payload>> typed;
   std::size_t accepted = 0;
   std::size_t rejected = 0;
   std::size_t ignored = 0;

   void push(forge::plugins::p2p::pubsub::message value, forge::net::p2p::pubsub::validation_result result) {
      auto lock = std::scoped_lock{mutex};
      raw.push_back(std::move(value));
      switch (result) {
      case forge::net::p2p::pubsub::validation_result::accept:
         ++accepted;
         break;
      case forge::net::p2p::pubsub::validation_result::reject:
         ++rejected;
         break;
      case forge::net::p2p::pubsub::validation_result::ignore:
         ++ignored;
         break;
      case forge::net::p2p::pubsub::validation_result::retry:
         break;
      }
   }

   void push(forge::plugins::p2p::pubsub::typed_message<pubsub_payload> value) {
      auto lock = std::scoped_lock{mutex};
      typed.push_back(std::move(value));
   }

   [[nodiscard]] std::size_t raw_size() const {
      auto lock = std::scoped_lock{mutex};
      return raw.size();
   }

   [[nodiscard]] std::size_t typed_size() const {
      auto lock = std::scoped_lock{mutex};
      return typed.size();
   }
};

bool wait_for_count(const received_pubsub_messages& messages, std::size_t raw, std::size_t typed = 0,
                    std::chrono::milliseconds timeout = std::chrono::seconds{5}) {
   const auto deadline = std::chrono::steady_clock::now() + timeout;
   while (std::chrono::steady_clock::now() < deadline) {
      if (messages.raw_size() >= raw && messages.typed_size() >= typed) {
         return true;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds{25});
   }
   return messages.raw_size() >= raw && messages.typed_size() >= typed;
}

template <typename Predicate>
bool wait_for_pubsub_snapshot(const forge::plugins::p2p::pubsub::api& pubsub, Predicate predicate,
                              std::chrono::milliseconds timeout) {
   const auto deadline = std::chrono::steady_clock::now() + timeout;
   while (std::chrono::steady_clock::now() < deadline) {
      if (predicate(pubsub.snapshot())) {
         return true;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds{25});
   }
   return predicate(pubsub.snapshot());
}

bool wait_for_pubsub_peer(const forge::plugins::p2p::pubsub::api& pubsub, std::chrono::milliseconds timeout) {
   return wait_for_pubsub_snapshot(
       pubsub, [](const forge::plugins::p2p::pubsub::snapshot& snapshot) { return snapshot.core.peers > 0; }, timeout);
}

template <typename Predicate>
boost::asio::awaitable<bool> async_wait_for_condition(Predicate predicate, std::chrono::milliseconds timeout) {
   auto executor = co_await boost::asio::this_coro::executor;
   const auto deadline = std::chrono::steady_clock::now() + timeout;
   while (std::chrono::steady_clock::now() < deadline) {
      if (predicate()) {
         co_return true;
      }
      auto timer = boost::asio::steady_timer{executor, std::chrono::milliseconds{10}};
      co_await timer.async_wait(boost::asio::use_awaitable);
   }
   co_return predicate();
}

struct fake_pubsub_source_state {
   mutable std::mutex mutex;
   bool release_join = false;
   bool fail_join = false;
   std::size_t enable_calls = 0;
   std::size_t join_attempts = 0;
   std::size_t leave_attempts = 0;
   std::size_t joined_handlers = 0;

   [[nodiscard]] std::size_t joins() const {
      auto lock = std::scoped_lock{mutex};
      return join_attempts;
   }

   [[nodiscard]] bool released() const {
      auto lock = std::scoped_lock{mutex};
      return release_join;
   }

   void release(bool fail) {
      auto lock = std::scoped_lock{mutex};
      fail_join = fail;
      release_join = true;
   }
};

struct subscribe_task_result {
   mutable std::mutex mutex;
   bool done = false;
   std::exception_ptr error;
   std::optional<forge::plugins::p2p::pubsub::subscription> value;

   void complete(forge::plugins::p2p::pubsub::subscription subscription) {
      auto lock = std::scoped_lock{mutex};
      value = std::move(subscription);
      done = true;
   }

   void fail(std::exception_ptr exception) {
      auto lock = std::scoped_lock{mutex};
      error = std::move(exception);
      done = true;
   }

   [[nodiscard]] bool finished() const {
      auto lock = std::scoped_lock{mutex};
      return done;
   }

   [[nodiscard]] bool failed() const {
      auto lock = std::scoped_lock{mutex};
      return error != nullptr;
   }
};

class fake_pubsub_source final : public forge::plugins::p2p::node::pubsub_source {
 public:
   explicit fake_pubsub_source(std::shared_ptr<fake_pubsub_source_state> state) : state_{std::move(state)} {}

   void enable(forge::net::p2p::pubsub::options) override {
      auto lock = std::scoped_lock{state_->mutex};
      ++state_->enable_calls;
   }

   [[nodiscard]] forge::net::p2p::peer_id local_peer() const override {
      return forge::net::p2p::peer_id{.value = "fake-pubsub-peer"};
   }

   boost::asio::awaitable<forge::net::p2p::pubsub::message>
   async_publish_message(forge::net::p2p::pubsub::topic subject, std::vector<std::uint8_t> data,
                         forge::net::p2p::pubsub::publish_options) override {
      co_return forge::net::p2p::pubsub::message{
          .from = local_peer(),
          .data = std::move(data),
          .seqno = {1},
          .subject = std::move(subject),
      };
   }

   boost::asio::awaitable<forge::net::p2p::pubsub::subscription>
   async_join_topic(forge::net::p2p::pubsub::topic subject, forge::net::p2p::pubsub::handler) override {
      auto executor = co_await boost::asio::this_coro::executor;
      {
         auto lock = std::scoped_lock{state_->mutex};
         ++state_->join_attempts;
      }
      while (!state_->released()) {
         auto timer = boost::asio::steady_timer{executor, std::chrono::milliseconds{10}};
         co_await timer.async_wait(boost::asio::use_awaitable);
      }
      {
         auto lock = std::scoped_lock{state_->mutex};
         if (state_->fail_join) {
            FORGE_THROW_EXCEPTION(forge::plugins::p2p::pubsub::exceptions::handler_limit,
                                  "fake PubSub source join failed");
         }
         ++state_->joined_handlers;
      }
      co_return forge::net::p2p::pubsub::subscription{.subscribe = true, .subject = std::move(subject)};
   }

   boost::asio::awaitable<void> async_leave_topic(forge::net::p2p::pubsub::topic) override {
      auto lock = std::scoped_lock{state_->mutex};
      ++state_->leave_attempts;
      co_return;
   }

   forge::net::p2p::pubsub::snapshot snapshot() const override {
      return forge::net::p2p::pubsub::snapshot{};
   }

 private:
   std::shared_ptr<fake_pubsub_source_state> state_;
};

class fake_p2p_node_plugin final : public forge::app::plugin {
 public:
   explicit fake_p2p_node_plugin(std::shared_ptr<fake_pubsub_source_state> state) : state_{std::move(state)} {}

   [[nodiscard]] forge::app::plugin_id id() const override {
      return forge::app::plugin_id{.value = "forge.plugins.p2p.node"};
   }

   [[nodiscard]] std::string version() const override {
      return "test";
   }

   boost::asio::awaitable<void> provide(forge::api::core::provider& provider) override {
      provider.install<forge::plugins::p2p::node::pubsub_source>(std::make_shared<fake_pubsub_source>(state_));
      co_return;
   }

   boost::asio::awaitable<void> initialize(forge::app::plugin_context&) override {
      co_return;
   }

   boost::asio::awaitable<void> startup() override {
      co_return;
   }

   boost::asio::awaitable<void> shutdown() override {
      co_return;
   }

 private:
   std::shared_ptr<fake_pubsub_source_state> state_;
};

struct scripted_resolver_state {
   std::vector<forge::plugins::p2p::resolver::response> responses;
   std::size_t calls = 0;
};

class scripted_resolver_api_impl final : public scripted_resolver_api {
 public:
   explicit scripted_resolver_api_impl(std::shared_ptr<scripted_resolver_state> state) : state_{std::move(state)} {}

   boost::asio::awaitable<forge::plugins::p2p::resolver::response>
   query(forge::plugins::p2p::resolver::query) override {
      const auto index = std::min(state_->calls, state_->responses.size() - 1);
      ++state_->calls;
      co_return state_->responses[index];
   }

 private:
   std::shared_ptr<scripted_resolver_state> state_;
};

[[nodiscard]] forge::plugins::p2p::resolver::entry resolver_test_entry(std::string protocol) {
   return forge::plugins::p2p::resolver::entry{
       .id = {.value = "node.test"},
       .version = {.major = 1, .revision = 0},
       .protocol = std::move(protocol),
       .codec = {.value = "forge.raw"},
       .max_inflight = 64,
       .max_frame_size = 16 * 1024 * 1024,
       .methods = {forge::plugins::p2p::resolver::method{
           .name = "ping",
           .kind = forge::api::core::method_kind::unary,
       }},
   };
}

class route_publisher_plugin final : public forge::app::plugin {
 public:
   explicit route_publisher_plugin(plugin_log& log) : log_{&log} {}

   [[nodiscard]] forge::app::plugin_id id() const override {
      return forge::app::plugin_id{.value = "route-publisher"};
   }

   [[nodiscard]] std::string version() const override {
      return "1";
   }

   boost::asio::awaitable<void> initialize(forge::app::plugin_context& context) override {
      auto p2p = context.apis().get<forge::plugins::p2p::node::api>(
          {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});

      auto plan = forge::api::core::binding()
                      .serve(context.apis())
                      .export_api<node_test_api>({.id = {"node.test"}, .major = 1, .min_revision = 0})
                      .export_api<peer_context_test_api>({.id = {"peer-context.test"}, .major = 1, .min_revision = 0})
                      .build();
      publication_ = p2p->publish_api(std::move(plan), forge::net::p2p::protocol_id{.value = "/forge/api/node-test/1"});
      p2p->publish_protocol(
          forge::net::p2p::protocol_id{.value = "/forge/test/blob-transfer/1"},
          [](forge::net::p2p::node::incoming_protocol_stream) -> boost::asio::awaitable<void> { co_return; });
      log_->entries.push_back("routes.published");
      co_return;
   }

   boost::asio::awaitable<void> startup() override {
      log_->entries.push_back("routes.startup");
      co_return;
   }

   boost::asio::awaitable<void> shutdown() override {
      log_->entries.push_back("routes.shutdown");
      co_await publication_.async_close();
      co_return;
   }

 private:
   plugin_log* log_ = nullptr;
   forge::api::p2p::publication publication_;
};

class duplicate_route_plugin final : public forge::app::plugin {
 public:
   [[nodiscard]] forge::app::plugin_id id() const override {
      return forge::app::plugin_id{.value = "duplicate-route"};
   }

   [[nodiscard]] std::string version() const override {
      return "1";
   }

   boost::asio::awaitable<void> initialize(forge::app::plugin_context& context) override {
      auto p2p = context.apis().get<forge::plugins::p2p::node::api>(
          {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
      auto handler = [](forge::net::p2p::node::incoming_protocol_stream) -> boost::asio::awaitable<void> { co_return; };
      p2p->publish_protocol(forge::net::p2p::protocol_id{.value = "/forge/test/duplicate/1"}, handler);
      p2p->publish_protocol(forge::net::p2p::protocol_id{.value = "/forge/test/duplicate/1"}, handler);
      co_return;
   }

   boost::asio::awaitable<void> startup() override {
      co_return;
   }

   boost::asio::awaitable<void> shutdown() override {
      co_return;
   }
};

class resolver_route_publisher_plugin final : public forge::app::plugin {
 public:
   [[nodiscard]] forge::app::plugin_id id() const override {
      return forge::app::plugin_id{.value = "resolver-route-publisher"};
   }

   [[nodiscard]] std::string version() const override {
      return "1";
   }

   boost::asio::awaitable<void> initialize(forge::app::plugin_context& context) override {
      auto resolver = context.apis().get<forge::plugins::p2p::resolver::api>(
          {.id = {"forge.plugins.p2p.resolver"}, .major = 2, .min_revision = 0});

      auto plan = forge::api::core::binding()
                      .serve(context.apis())
                      .export_api<node_test_api>({.id = {"node.test"}, .major = 1, .min_revision = 0})
                      .build();
      publication_ =
          resolver->publish_api(std::move(plan), forge::net::p2p::protocol_id{.value = "/forge/api/node-test/1"});
      co_return;
   }

   boost::asio::awaitable<void> startup() override {
      co_return;
   }

   boost::asio::awaitable<void> shutdown() override {
      co_await publication_.async_close();
      co_return;
   }

 private:
   forge::api::p2p::publication publication_;
};

class duplicate_resolver_route_plugin final : public forge::app::plugin {
 public:
   [[nodiscard]] forge::app::plugin_id id() const override {
      return forge::app::plugin_id{.value = "duplicate-resolver-route"};
   }

   [[nodiscard]] std::string version() const override {
      return "1";
   }

   boost::asio::awaitable<void> initialize(forge::app::plugin_context& context) override {
      auto resolver = context.apis().get<forge::plugins::p2p::resolver::api>(
          {.id = {"forge.plugins.p2p.resolver"}, .major = 2, .min_revision = 0});
      auto plan = forge::api::core::binding()
                      .serve(context.apis())
                      .export_api<node_test_api>({.id = {"node.test"}, .major = 1, .min_revision = 0})
                      .build();
      publication_ = resolver->publish_api(plan, forge::net::p2p::protocol_id{.value = "/forge/api/node-test/1"});
      static_cast<void>(resolver->publish_api(
          std::move(plan), forge::net::p2p::protocol_id{.value = "/forge/api/node-test-duplicate/1"}));
      co_return;
   }

   boost::asio::awaitable<void> startup() override {
      co_return;
   }

   boost::asio::awaitable<void> shutdown() override {
      co_await publication_.async_close();
      co_return;
   }

 private:
   forge::api::p2p::publication publication_;
};

class resolver_custom_transport_route_plugin final : public forge::app::plugin {
 public:
   [[nodiscard]] forge::app::plugin_id id() const override {
      return forge::app::plugin_id{.value = "resolver-custom-transport-route"};
   }

   [[nodiscard]] std::string version() const override {
      return "1";
   }

   boost::asio::awaitable<void> initialize(forge::app::plugin_context& context) override {
      auto resolver = context.apis().get<forge::plugins::p2p::resolver::api>(
          {.id = {"forge.plugins.p2p.resolver"}, .major = 2, .min_revision = 0});
      auto plan = forge::api::core::binding()
                      .serve(context.apis())
                      .export_api<node_test_api>({.id = {"node.test"}, .major = 1, .min_revision = 0})
                      .build();
      publication_ =
          resolver->publish_api(std::move(plan), forge::net::p2p::protocol_id{.value = "/forge/api/node-test-custom/1"},
                                forge::plugins::p2p::resolver::publish_options{
                                    .transport =
                                        forge::api::transport::options{
                                            .codec = {.value = "forge.test.raw"},
                                            .max_inflight = 7,
                                            .max_frame_size = 512 * 1024,
                                        },
                                });
      co_return;
   }

   boost::asio::awaitable<void> startup() override {
      co_return;
   }

   boost::asio::awaitable<void> shutdown() override {
      co_await publication_.async_close();
      co_return;
   }

 private:
   forge::api::p2p::publication publication_;
};

class receipt_route_publisher_plugin final : public forge::app::plugin {
 public:
   [[nodiscard]] forge::app::plugin_id id() const override {
      return forge::app::plugin_id{.value = "receipt-route-publisher"};
   }

   [[nodiscard]] std::string version() const override {
      return "1";
   }

   boost::asio::awaitable<void> initialize(forge::app::plugin_context& context) override {
      auto resolver = context.apis().get<forge::plugins::p2p::resolver::api>(
          {.id = {"forge.plugins.p2p.resolver"}, .major = 2, .min_revision = 0});

      auto plan = forge::api::core::binding()
                      .serve(context.apis())
                      .export_api<receipt_test_api>({.id = {"receipt.test"}, .major = 1, .min_revision = 0})
                      .build();
      publication_ =
          resolver->publish_api(std::move(plan), forge::net::p2p::protocol_id{.value = "/forge/api/receipt-test/1"});
      co_return;
   }

   boost::asio::awaitable<void> startup() override {
      co_return;
   }

   boost::asio::awaitable<void> shutdown() override {
      co_await publication_.async_close();
      co_return;
   }

 private:
   forge::api::p2p::publication publication_;
};

class resolver_protocol_conflict_plugin final : public forge::app::plugin {
 public:
   [[nodiscard]] forge::app::plugin_id id() const override {
      return forge::app::plugin_id{.value = "resolver-protocol-conflict"};
   }

   [[nodiscard]] std::string version() const override {
      return "1";
   }

   boost::asio::awaitable<void> initialize(forge::app::plugin_context& context) override {
      auto p2p = context.apis().get<forge::plugins::p2p::node::api>(
          {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
      p2p->publish_protocol(
          forge::net::p2p::protocol_id{.value = "/forge/api/resolver/2"},
          [](forge::net::p2p::node::incoming_protocol_stream) -> boost::asio::awaitable<void> { co_return; });
      co_return;
   }

   boost::asio::awaitable<void> startup() override {
      co_return;
   }

   boost::asio::awaitable<void> shutdown() override {
      co_return;
   }
};

class scripted_resolver_plugin final : public forge::app::plugin {
 public:
   [[nodiscard]] forge::app::plugin_id id() const override {
      return forge::app::plugin_id{.value = "scripted-resolver"};
   }

   [[nodiscard]] std::string version() const override {
      return "1";
   }

   boost::asio::awaitable<void> initialize(forge::app::plugin_context& context) override {
      auto p2p = context.apis().get<forge::plugins::p2p::node::api>(
          {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
      auto plan = forge::api::core::binding()
                      .serve(context.apis())
                      .export_api<scripted_resolver_api>(
                          {.id = {"forge.plugins.p2p.resolver.protocol"}, .major = 1, .min_revision = 0})
                      .build();
      publication_ = p2p->publish_api(std::move(plan), forge::net::p2p::protocol_id{.value = "/forge/api/resolver/2"});
      co_return;
   }

   boost::asio::awaitable<void> startup() override {
      co_return;
   }

   boost::asio::awaitable<void> shutdown() override {
      co_await publication_.async_close();
      co_return;
   }

 private:
   forge::api::p2p::publication publication_;
};

class p2p_plugin_application final : public forge::app::application_shell {
 public:
   explicit p2p_plugin_application(plugin_log& log) : log_{&log} {}

 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      register_p2p_stack(registry);
      registry.register_plugin(forge::app::plugin_descriptor{
          .id = forge::app::plugin_id{.value = "route-publisher"},
          .dependencies = {forge::app::plugin_id{.value = "forge.plugins.p2p.node"}},
          .factory = [this] { return std::make_unique<route_publisher_plugin>(*log_); },
      });
   }

   boost::asio::awaitable<void> on_provide(forge::app::application_context& context) override {
      context.apis().install<node_test_api>(node_test_api::describe(), std::make_shared<node_test_api_impl>());
      context.apis().install<peer_context_test_api>(peer_context_test_api::describe(),
                                                    std::make_shared<peer_context_test_api_impl>());
      co_return;
   }

 private:
   plugin_log* log_ = nullptr;
};

class duplicate_p2p_plugin_application final : public forge::app::application_shell {
 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      register_p2p_stack(registry);
      registry.register_plugin(forge::app::plugin_descriptor{
          .id = forge::app::plugin_id{.value = "duplicate-route"},
          .dependencies = {forge::app::plugin_id{.value = "forge.plugins.p2p.node"}},
          .factory = [] { return std::make_unique<duplicate_route_plugin>(); },
      });
   }
};

class p2p_only_application final : public forge::app::application_shell {
 public:
   using forge::app::application_shell::application_shell;

 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      register_p2p_stack(registry);
   }
};

class diagnostics_application final : public forge::app::application_shell {
 public:
   using forge::app::application_shell::application_shell;

 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      register_p2p_stack(registry);
      registry.register_plugin(forge::plugins::p2p::diagnostics::descriptor());
   }
};

class pubsub_application final : public forge::app::application_shell {
 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      register_p2p_stack(registry);
      registry.register_plugin(forge::plugins::p2p::pubsub::descriptor());
   }
};

class fake_pubsub_application final : public forge::app::application_shell {
 public:
   explicit fake_pubsub_application(std::shared_ptr<fake_pubsub_source_state> state) : state_{std::move(state)} {}

 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      registry.register_plugin(forge::app::plugin_descriptor{
          .id = forge::app::plugin_id{.value = "forge.plugins.p2p.node"},
          .factory = [state = state_] { return std::make_unique<fake_p2p_node_plugin>(state); },
      });
      registry.register_plugin(forge::plugins::p2p::pubsub::descriptor());
   }

 private:
   std::shared_ptr<fake_pubsub_source_state> state_;
};

class resolver_plugin_application final : public forge::app::application_shell {
 public:
   explicit resolver_plugin_application(
       std::shared_ptr<node_test_api> node_api = std::make_shared<node_test_api_impl>())
       : node_api_{std::move(node_api)} {}

 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      register_p2p_stack(registry);
      registry.register_plugin(forge::plugins::p2p::resolver::descriptor());
      registry.register_plugin(forge::app::plugin_descriptor{
          .id = forge::app::plugin_id{.value = "resolver-route-publisher"},
          .dependencies = {forge::app::plugin_id{.value = "forge.plugins.p2p.resolver"}},
          .factory = [] { return std::make_unique<resolver_route_publisher_plugin>(); },
      });
   }

   boost::asio::awaitable<void> on_provide(forge::app::application_context& context) override {
      context.apis().install<node_test_api>(node_test_api::describe(), node_api_);
      context.apis().install<peer_context_test_api>(peer_context_test_api::describe(),
                                                    std::make_shared<peer_context_test_api_impl>());
      co_return;
   }

 private:
   std::shared_ptr<node_test_api> node_api_;
};

class resolver_only_application final : public forge::app::application_shell {
 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      register_p2p_stack(registry);
      registry.register_plugin(forge::plugins::p2p::resolver::descriptor());
   }
};

class resolver_publication_application final : public forge::app::application_shell {
 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      register_p2p_stack(registry);
      registry.register_plugin(forge::plugins::p2p::resolver::descriptor());
   }

   boost::asio::awaitable<void> on_provide(forge::app::application_context& context) override {
      context.apis().install<node_test_api>(node_test_api::describe(), std::make_shared<node_test_api_impl>());
      context.apis().install<peer_context_test_api>(peer_context_test_api::describe(),
                                                    std::make_shared<peer_context_test_api_impl>());
      co_return;
   }
};

class duplicate_resolver_plugin_application final : public forge::app::application_shell {
 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      register_p2p_stack(registry);
      registry.register_plugin(forge::plugins::p2p::resolver::descriptor());
      registry.register_plugin(forge::app::plugin_descriptor{
          .id = forge::app::plugin_id{.value = "duplicate-resolver-route"},
          .dependencies = {forge::app::plugin_id{.value = "forge.plugins.p2p.resolver"}},
          .factory = [] { return std::make_unique<duplicate_resolver_route_plugin>(); },
      });
   }

   boost::asio::awaitable<void> on_provide(forge::app::application_context& context) override {
      context.apis().install<node_test_api>(node_test_api::describe(), std::make_shared<node_test_api_impl>());
      context.apis().install<peer_context_test_api>(peer_context_test_api::describe(),
                                                    std::make_shared<peer_context_test_api_impl>());
      co_return;
   }
};

class resolver_custom_transport_application final : public forge::app::application_shell {
 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      register_p2p_stack(registry);
      registry.register_plugin(forge::plugins::p2p::resolver::descriptor());
      registry.register_plugin(forge::app::plugin_descriptor{
          .id = forge::app::plugin_id{.value = "resolver-custom-transport-route"},
          .dependencies = {forge::app::plugin_id{.value = "forge.plugins.p2p.resolver"}},
          .factory = [] { return std::make_unique<resolver_custom_transport_route_plugin>(); },
      });
   }

   boost::asio::awaitable<void> on_provide(forge::app::application_context& context) override {
      context.apis().install<node_test_api>(node_test_api::describe(), std::make_shared<node_test_api_impl>());
      context.apis().install<peer_context_test_api>(peer_context_test_api::describe(),
                                                    std::make_shared<peer_context_test_api_impl>());
      co_return;
   }
};

class receipt_resolver_application final : public forge::app::application_shell {
 public:
   explicit receipt_resolver_application(std::shared_ptr<receipt_test_state> state) : state_{std::move(state)} {}

 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      register_p2p_stack(registry);
      registry.register_plugin(forge::plugins::p2p::resolver::descriptor());
      registry.register_plugin(forge::app::plugin_descriptor{
          .id = forge::app::plugin_id{.value = "receipt-route-publisher"},
          .dependencies = {forge::app::plugin_id{.value = "forge.plugins.p2p.resolver"}},
          .factory = [] { return std::make_unique<receipt_route_publisher_plugin>(); },
      });
   }

   boost::asio::awaitable<void> on_provide(forge::app::application_context& context) override {
      context.apis().install<receipt_test_api>(receipt_test_api::describe(),
                                               std::make_shared<receipt_test_api_impl>(state_));
      co_return;
   }

 private:
   std::shared_ptr<receipt_test_state> state_;
};

class resolver_protocol_conflict_application final : public forge::app::application_shell {
 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      register_p2p_stack(registry);
      registry.register_plugin(forge::app::plugin_descriptor{
          .id = forge::app::plugin_id{.value = "resolver-protocol-conflict"},
          .dependencies = {forge::app::plugin_id{.value = "forge.plugins.p2p.node"}},
          .factory = [] { return std::make_unique<resolver_protocol_conflict_plugin>(); },
      });
      registry.register_plugin(forge::plugins::p2p::resolver::descriptor());
   }
};

class scripted_resolver_application final : public forge::app::application_shell {
 public:
   explicit scripted_resolver_application(std::shared_ptr<scripted_resolver_state> state) : state_{std::move(state)} {}

 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      register_p2p_stack(registry);
      registry.register_plugin(forge::app::plugin_descriptor{
          .id = forge::app::plugin_id{.value = "scripted-resolver"},
          .dependencies = {forge::app::plugin_id{.value = "forge.plugins.p2p.node"}},
          .factory = [] { return std::make_unique<scripted_resolver_plugin>(); },
      });
   }

   boost::asio::awaitable<void> on_provide(forge::app::application_context& context) override {
      context.apis().install<scripted_resolver_api>(scripted_resolver_api::describe(),
                                                    std::make_shared<scripted_resolver_api_impl>(state_));
      co_return;
   }

 private:
   std::shared_ptr<scripted_resolver_state> state_;
};

struct http_tls_secret_state {
   forge::tests::p2p::identity_fixture identity = forge::tests::p2p::make_identity_fixture("http-tls-plugin-suite");
   mutable std::mutex mutex;
   std::condition_variable changed;
   std::vector<std::string> purposes;
   bool reject_reads = false;
   bool block_reads = false;
   bool read_blocked = false;
   std::optional<std::string> certificate_override;
   std::optional<std::string> private_key_override;
   std::optional<std::string> client_ca_override;
   std::shared_ptr<boost::asio::steady_timer> blocked_read;
};

class http_tls_secrets_api final : public crypto_secrets::api {
 public:
   explicit http_tls_secrets_api(std::shared_ptr<http_tls_secret_state> state) : state_(std::move(state)) {}

   boost::asio::awaitable<crypto_secrets::snapshot> status(crypto_secrets::query) override {
      co_return crypto_secrets::snapshot{.configured_secrets = 3};
   }

   boost::asio::awaitable<crypto_secrets::get_result> get_bytes(crypto_secrets::get_request request) override {
      const auto executor = co_await boost::asio::this_coro::executor;
      auto material = std::string{};
      auto wait_for_release = false;
      auto release_gate = std::shared_ptr<boost::asio::steady_timer>{};
      {
         const auto lock = std::scoped_lock{state_->mutex};
         if (state_->reject_reads) {
            throw std::runtime_error{"configured HTTP TLS secret read rejected"};
         }
         if (request.secret_id == "http/test-certificate") {
            material = state_->certificate_override.value_or(state_->identity.certificate_pem);
         } else if (request.secret_id == "http/test-private-key") {
            material = state_->private_key_override.value_or(state_->identity.private_key_pem);
         } else if (request.secret_id == "http/test-client-ca") {
            material = state_->client_ca_override.value_or(state_->identity.certificate_pem);
         } else {
            throw std::runtime_error{"unknown HTTP TLS test secret"};
         }
         state_->purposes.push_back(request.purpose);
         if (state_->block_reads) {
            release_gate = std::make_shared<boost::asio::steady_timer>(executor);
            release_gate->expires_at((std::chrono::steady_clock::time_point::max)());
            state_->blocked_read = release_gate;
            state_->read_blocked = true;
            wait_for_release = true;
         }
      }
      state_->changed.notify_all();
      if (wait_for_release) {
         auto error = boost::system::error_code{};
         co_await release_gate->async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, error));
      }
      auto bytes = decltype(crypto_secrets::get_result{}.bytes){};
      bytes.reserve(material.size());
      for (const auto value : material) {
         bytes.push_back(static_cast<std::uint8_t>(static_cast<unsigned char>(value)));
      }
      co_return crypto_secrets::get_result{.secret_id = std::move(request.secret_id), .bytes = std::move(bytes)};
   }

   boost::asio::awaitable<crypto_secrets::derive_result> derive_hkdf_sha256(crypto_secrets::derive_request) override {
      throw std::logic_error{"HTTP TLS test secrets do not implement derivation"};
   }

   boost::asio::awaitable<crypto_secrets::aead_encrypt_result>
   encrypt_aes_gcm(crypto_secrets::aead_encrypt_request) override {
      throw std::logic_error{"HTTP TLS test secrets do not implement encryption"};
   }

   boost::asio::awaitable<crypto_secrets::aead_decrypt_result>
   decrypt_aes_gcm(crypto_secrets::aead_decrypt_request) override {
      throw std::logic_error{"HTTP TLS test secrets do not implement decryption"};
   }

 private:
   std::shared_ptr<http_tls_secret_state> state_;
};

class http_tls_secrets_plugin final : public forge::app::plugin {
 public:
   explicit http_tls_secrets_plugin(std::shared_ptr<http_tls_secret_state> state) : state_(std::move(state)) {}

   [[nodiscard]] forge::app::plugin_id id() const override {
      return {.value = "forge.plugins.crypto.secrets"};
   }

   [[nodiscard]] std::string version() const override {
      return "test";
   }

   boost::asio::awaitable<void> provide(forge::api::core::provider& provider) override {
      provider.install<crypto_secrets::api>(std::make_shared<http_tls_secrets_api>(state_));
      co_return;
   }

   boost::asio::awaitable<void> initialize(forge::app::plugin_context&) override {
      co_return;
   }

   boost::asio::awaitable<void> startup() override {
      co_return;
   }

   boost::asio::awaitable<void> shutdown() override {
      co_return;
   }

 private:
   std::shared_ptr<http_tls_secret_state> state_;
};

class http_tls_server_application final : public forge::app::application_shell {
 public:
   explicit http_tls_server_application(std::shared_ptr<http_tls_secret_state> state) : state_(std::move(state)) {}

 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      registry.register_plugin(forge::app::plugin_descriptor{
          .id = {.value = "forge.plugins.crypto.secrets"},
          .factory = [state = state_] { return std::make_unique<http_tls_secrets_plugin>(state); },
      });
      registry.register_plugin(http_server::descriptor());
   }

 private:
   std::shared_ptr<http_tls_secret_state> state_;
};

[[nodiscard]] bool plugin_tls_request_succeeds(std::uint16_t port) {
   try {
      namespace asio = boost::asio;
      namespace beast = boost::beast;
      namespace beast_http = boost::beast::http;
      auto io = asio::io_context{};
      auto context = asio::ssl::context{asio::ssl::context::tls_client};
      context.set_verify_mode(asio::ssl::verify_none);
      auto stream = beast::ssl_stream<beast::tcp_stream>{beast::tcp_stream{io}, context};
      beast::get_lowest_layer(stream).expires_after(std::chrono::seconds{2});
      beast::get_lowest_layer(stream).connect({asio::ip::make_address("127.0.0.1"), port});
      stream.handshake(asio::ssl::stream_base::client);

      auto request = beast_http::request<beast_http::empty_body>{beast_http::verb::get, "/", 11};
      request.set(beast_http::field::host, "127.0.0.1");
      beast_http::write(stream, request);
      auto buffer = beast::flat_buffer{};
      auto response = beast_http::response<beast_http::string_body>{};
      beast_http::read(stream, buffer, response);
      return response.result() == beast_http::status::not_found;
   } catch (...) {
      return false;
   }
}

class http_server_application final : public forge::app::application_shell {
 public:
   http_server_application(std::shared_ptr<http_publish_state> state, bool middleware = false)
       : state_{std::move(state)}, middleware_{middleware} {}

 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      registry.register_plugin(http_server::descriptor());
      if (middleware_) {
         registry.register_plugin(forge::app::plugin_descriptor{
             .id = forge::app::plugin_id{.value = "http-middleware"},
             .dependencies = {forge::app::plugin_id{.value = "forge.plugins.http.server"}},
             .factory = [state = state_] { return std::make_unique<http_middleware_plugin>(state); },
         });
      }
      registry.register_plugin(forge::app::plugin_descriptor{
          .id = forge::app::plugin_id{.value = "http-cache-publisher"},
          .dependencies = {forge::app::plugin_id{.value = "forge.plugins.http.server"}},
          .factory = [state = state_] { return std::make_unique<http_cache_publisher_plugin>(state); },
      });
   }

   boost::asio::awaitable<void> on_provide(forge::app::application_context& context) override {
      context.apis().install<http_cache_api>(http_cache_api::describe(), std::make_shared<http_cache_api_impl>());
      co_return;
   }

 private:
   std::shared_ptr<http_publish_state> state_;
   bool middleware_ = false;
};

class http_assets_server_application final : public forge::app::application_shell {
 public:
   http_assets_server_application(std::shared_ptr<http_publish_state> publish,
                                  std::shared_ptr<http_asset_publish_state> assets, bool with_compute = true)
       : forge::app::application_shell{http_asset_application_options(with_compute)}, publish_{std::move(publish)},
         assets_{std::move(assets)} {}

 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      registry.register_plugin(http_server::descriptor());
      registry.register_plugin(forge::app::plugin_descriptor{
          .id = forge::app::plugin_id{.value = "http-cache-publisher"},
          .dependencies = {forge::app::plugin_id{.value = "forge.plugins.http.server"}},
          .factory = [state = publish_] { return std::make_unique<http_cache_publisher_plugin>(state); },
      });
      registry.register_plugin(forge::app::plugin_descriptor{
          .id = forge::app::plugin_id{.value = "http-asset-publisher"},
          .dependencies = {forge::app::plugin_id{.value = "forge.plugins.http.server"}},
          .factory = [state = assets_] { return std::make_unique<http_asset_publisher_plugin>(state); },
      });
   }

   boost::asio::awaitable<void> on_provide(forge::app::application_context& context) override {
      context.apis().install<http_cache_api>(http_cache_api::describe(), std::make_shared<http_cache_api_impl>());
      co_return;
   }

 private:
   std::shared_ptr<http_publish_state> publish_;
   std::shared_ptr<http_asset_publish_state> assets_;
};

class http_stream_server_application final : public forge::app::application_shell {
 public:
   explicit http_stream_server_application(std::shared_ptr<http_publish_state> state) : state_{std::move(state)} {}

 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      registry.register_plugin(http_server::descriptor());
      registry.register_plugin(forge::app::plugin_descriptor{
          .id = forge::app::plugin_id{.value = "http-middleware"},
          .dependencies = {forge::app::plugin_id{.value = "forge.plugins.http.server"}},
          .factory = [state = state_] { return std::make_unique<http_middleware_plugin>(state); },
      });
      registry.register_plugin(forge::app::plugin_descriptor{
          .id = forge::app::plugin_id{.value = "http-stream-publisher"},
          .dependencies = {forge::app::plugin_id{.value = "forge.plugins.http.server"}},
          .factory = [state = state_] { return std::make_unique<http_stream_publisher_plugin>(state); },
      });
   }

   boost::asio::awaitable<void> on_provide(forge::app::application_context& context) override {
      context.apis().install<http_stream_api>(http_stream_api::describe(),
                                              std::make_shared<http_stream_api_impl>(state_));
      co_return;
   }

 private:
   std::shared_ptr<http_publish_state> state_;
};

class http_empty_server_application final : public forge::app::application_shell {
 public:
   explicit http_empty_server_application(std::shared_ptr<http_publish_state> state) : state_{std::move(state)} {}

 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      registry.register_plugin(http_server::descriptor());
      registry.register_plugin(forge::app::plugin_descriptor{
          .id = forge::app::plugin_id{.value = "http-middleware"},
          .dependencies = {forge::app::plugin_id{.value = "forge.plugins.http.server"}},
          .factory = [state = state_] { return std::make_unique<http_middleware_plugin>(state); },
      });
      registry.register_plugin(forge::app::plugin_descriptor{
          .id = forge::app::plugin_id{.value = "http-empty-publisher"},
          .dependencies = {forge::app::plugin_id{.value = "forge.plugins.http.server"}},
          .factory = [state = state_] { return std::make_unique<http_empty_publisher_plugin>(state); },
      });
   }

   boost::asio::awaitable<void> on_provide(forge::app::application_context& context) override {
      context.apis().install<http_empty_api>(http_empty_api::describe(), std::make_shared<http_empty_api_impl>());
      co_return;
   }

 private:
   std::shared_ptr<http_publish_state> state_;
};

class duplicate_http_server_application final : public forge::app::application_shell {
 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      registry.register_plugin(http_server::descriptor());
      registry.register_plugin(forge::app::plugin_descriptor{
          .id = forge::app::plugin_id{.value = "duplicate-http-cache-publisher"},
          .dependencies = {forge::app::plugin_id{.value = "forge.plugins.http.server"}},
          .factory = [] { return std::make_unique<duplicate_http_cache_publisher_plugin>(); },
      });
   }

   boost::asio::awaitable<void> on_provide(forge::app::application_context& context) override {
      context.apis().install<http_cache_api>(http_cache_api::describe(), std::make_shared<http_cache_api_impl>());
      co_return;
   }
};

class late_http_server_application final : public forge::app::application_shell {
 protected:
   void on_register_plugins(forge::app::plugin_registry& registry) override {
      registry.register_plugin(http_server::descriptor());
      registry.register_plugin(forge::app::plugin_descriptor{
          .id = forge::app::plugin_id{.value = "late-http-publisher"},
          .dependencies = {forge::app::plugin_id{.value = "forge.plugins.http.server"}},
          .factory = [] { return std::make_unique<late_http_publish_plugin>(); },
      });
   }

   boost::asio::awaitable<void> on_provide(forge::app::application_context& context) override {
      context.apis().install<http_cache_api>(http_cache_api::describe(), std::make_shared<http_cache_api_impl>());
      co_return;
   }
};

[[nodiscard]] const forge::config::core::field_descriptor&
require_field(const forge::config::core::component_descriptor& descriptor, std::string_view name) {
   const auto found = std::ranges::find_if(descriptor.fields, [&](const auto& field) { return field.name == name; });
   BOOST_REQUIRE(found != descriptor.fields.end());
   return *found;
}

[[nodiscard]] bool has_field(const forge::config::core::component_descriptor& descriptor, std::string_view name) {
   return std::ranges::any_of(descriptor.fields, [&](const auto& field) { return field.name == name; });
}

[[nodiscard]] std::uint16_t reserve_loopback_port() {
   auto io = boost::asio::io_context{};
   auto acceptor = boost::asio::ip::tcp::acceptor{io};
   acceptor.open(boost::asio::ip::tcp::v4());
   acceptor.bind({boost::asio::ip::make_address("127.0.0.1"), 0});
   const auto port = acceptor.local_endpoint().port();
   acceptor.close();
   return port;
}

[[nodiscard]] forge::config::core::value key_entry(std::string key_id, std::string private_key,
                                                   std::string input_profile, std::vector<std::string> purposes) {
   auto purpose_values = forge::config::core::value::array_type{};
   for (auto& purpose : purposes) {
      purpose_values.emplace_back(std::move(purpose));
   }

   auto object = forge::config::core::value::object_type{};
   object.emplace("id", forge::config::core::value{std::move(key_id)});
   object.emplace("private-key", forge::config::core::value{std::move(private_key)});
   object.emplace("input-profile", forge::config::core::value{std::move(input_profile)});
   object.emplace("purposes", forge::config::core::value{std::move(purpose_values)});
   return forge::config::core::value{std::move(object)};
}

[[nodiscard]] forge::config::core::value key_entry_without_purposes(std::string key_id, std::string private_key,
                                                                    std::string input_profile) {
   auto object = forge::config::core::value::object_type{};
   object.emplace("id", forge::config::core::value{std::move(key_id)});
   object.emplace("private-key", forge::config::core::value{std::move(private_key)});
   object.emplace("input-profile", forge::config::core::value{std::move(input_profile)});
   return forge::config::core::value{std::move(object)};
}

[[nodiscard]] forge::config::core::value bls_key_entry(std::string key_id, std::string private_key,
                                                       std::vector<std::string> purposes) {
   auto purpose_values = forge::config::core::value::array_type{};
   for (auto& purpose : purposes) {
      purpose_values.emplace_back(std::move(purpose));
   }

   auto object = forge::config::core::value::object_type{};
   object.emplace("id", forge::config::core::value{std::move(key_id)});
   object.emplace("private-key", forge::config::core::value{std::move(private_key)});
   object.emplace("purposes", forge::config::core::value{std::move(purpose_values)});
   return forge::config::core::value{std::move(object)};
}

[[nodiscard]] forge::config::core::document signer_config(std::vector<forge::config::core::value> keys,
                                                          std::vector<forge::config::core::value> bls_keys = {}) {
   auto document = forge::config::core::document{};
   document.set("plugins.crypto.signer.keys", forge::config::core::value::array_type(keys.begin(), keys.end()));
   if (!bls_keys.empty()) {
      document.set("plugins.crypto.signer.bls-keys",
                   forge::config::core::value::array_type(bls_keys.begin(), bls_keys.end()));
   }
   return document;
}

template <typename T>
concept has_metrics = requires(T& value) { value.metrics(); };

template <typename T>
concept has_peers = requires(T& value) { value.peers(); };

template <typename T>
concept has_pubsub_publish = requires(T& value) {
   value.publish(forge::net::p2p::pubsub::topic{.value = "topic"}, std::vector<std::uint8_t>{},
                 forge::plugins::p2p::pubsub::publish_options{});
};

template <typename T>
concept has_pubsub_subscribe = requires(T& value, forge::plugins::p2p::pubsub::handler handler) {
   value.subscribe(forge::net::p2p::pubsub::topic{.value = "topic"}, std::move(handler),
                   forge::plugins::p2p::pubsub::subscribe_options{});
};

static_assert(!has_metrics<forge::plugins::p2p::node::api>);
static_assert(!has_peers<forge::plugins::p2p::node::api>);
static_assert(!has_pubsub_publish<forge::plugins::p2p::node::api>);
static_assert(!has_pubsub_subscribe<forge::plugins::p2p::node::api>);
static_assert(forge::api::core::local_interface<crypto_signer::api>);
static_assert(!forge::api::core::remote_interface<crypto_signer::api>);

} // namespace

BOOST_AUTO_TEST_CASE(http_server_config_is_described_from_schema) {
   auto plugin = http_server::plugin{};
   const auto descriptor = plugin.describe_config();
   BOOST_REQUIRE(descriptor.has_value());
   BOOST_TEST(descriptor->section == "plugins.http.server");

   const auto& bind_address = require_field(*descriptor, "bind-address");
   BOOST_TEST(bind_address.has_default);
   BOOST_TEST(std::get<std::string>(bind_address.default_value.storage) == "127.0.0.1");

   const auto& port = require_field(*descriptor, "port");
   BOOST_TEST(port.has_default);
   BOOST_TEST(std::get<std::uint64_t>(port.default_value.storage) == 0U);

   const auto& base_path = require_field(*descriptor, "api-base-path");
   BOOST_TEST(base_path.has_default);
   BOOST_TEST(std::get<std::string>(base_path.default_value.storage) == "/");

   const auto& body_limit = require_field(*descriptor, "max-request-body-bytes");
   BOOST_TEST(body_limit.has_default);
   BOOST_TEST(std::get<std::uint64_t>(body_limit.default_value.storage) == 16U * 1024U * 1024U);

   BOOST_TEST(require_field(*descriptor, "max-header-bytes").has_default);
   BOOST_TEST(require_field(*descriptor, "read-timeout-ms").has_default);
   BOOST_TEST(require_field(*descriptor, "idle-timeout-ms").has_default);
   BOOST_TEST(require_field(*descriptor, "tls.mode").has_default);
   BOOST_TEST(require_field(*descriptor, "tls.certificate-chain-secret").has_default);
   BOOST_TEST(require_field(*descriptor, "tls.private-key-secret").has_default);
   BOOST_TEST(require_field(*descriptor, "tls.client-ca-secret").has_default);
   BOOST_TEST(require_field(*descriptor, "tls.handshake-timeout-ms").has_default);
   BOOST_TEST(require_field(*descriptor, "tls.max-pending-handshakes").has_default);
   BOOST_TEST(http_server::api::ref().major == 2U);
   BOOST_TEST(plugin.version() == "2.0.0");
}

BOOST_AUTO_TEST_CASE(http_server_rejects_invalid_schema_config) {
   auto plugin = http_server::plugin{};
   auto document = forge::config::core::document{};
   document.set("plugins.http.server.port", std::uint64_t{70000});

   auto runtime = forge::asio::runtime{};
   BOOST_CHECK_THROW(forge::asio::blocking::run(runtime, plugin.configure(forge::config::core::component_view{
                                                             document, "plugins.http.server"})),
                     http_server::exceptions::invalid_config);
}

BOOST_AUTO_TEST_CASE(http_server_plugin_rejects_invalid_api_base_path_during_configure) {
   auto runtime = forge::asio::runtime{};

   auto empty = http_server::plugin{};
   auto empty_document = forge::config::core::document{};
   empty_document.set("plugins.http.server.api-base-path", std::string{});
   BOOST_CHECK_THROW(forge::asio::blocking::run(runtime, empty.configure(forge::config::core::component_view{
                                                             empty_document, "plugins.http.server"})),
                     http_server::exceptions::invalid_config);

   auto relative = http_server::plugin{};
   auto relative_document = forge::config::core::document{};
   relative_document.set("plugins.http.server.api-base-path", std::string{"api"});
   BOOST_CHECK_THROW(forge::asio::blocking::run(runtime, relative.configure(forge::config::core::component_view{
                                                             relative_document, "plugins.http.server"})),
                     http_server::exceptions::invalid_config);
}

BOOST_AUTO_TEST_CASE(http_server_plugin_rejects_plaintext_non_loopback_and_incomplete_tls_config) {
   auto runtime = forge::asio::runtime{};

   auto plaintext = http_server::plugin{};
   auto plaintext_document = forge::config::core::document{};
   plaintext_document.set("plugins.http.server.bind-address", std::string{"0.0.0.0"});
   BOOST_CHECK_THROW(forge::asio::blocking::run(runtime, plaintext.configure(forge::config::core::component_view{
                                                             plaintext_document, "plugins.http.server"})),
                     http_server::exceptions::invalid_config);

   auto server_tls = http_server::plugin{};
   auto server_tls_document = forge::config::core::document{};
   server_tls_document.set("plugins.http.server.tls.mode", std::string{"server"});
   server_tls_document.set("plugins.http.server.tls.certificate-chain-secret", std::string{"certificate"});
   BOOST_CHECK_THROW(forge::asio::blocking::run(runtime, server_tls.configure(forge::config::core::component_view{
                                                             server_tls_document, "plugins.http.server"})),
                     http_server::exceptions::invalid_config);

   auto mutual_tls = http_server::plugin{};
   auto mutual_tls_document = forge::config::core::document{};
   mutual_tls_document.set("plugins.http.server.tls.mode", std::string{"mutual"});
   mutual_tls_document.set("plugins.http.server.tls.certificate-chain-secret", std::string{"certificate"});
   mutual_tls_document.set("plugins.http.server.tls.private-key-secret", std::string{"private-key"});
   BOOST_CHECK_THROW(forge::asio::blocking::run(runtime, mutual_tls.configure(forge::config::core::component_view{
                                                             mutual_tls_document, "plugins.http.server"})),
                     http_server::exceptions::invalid_config);
}

BOOST_AUTO_TEST_CASE(http_server_plugin_tls_requires_secrets_api_only_when_tls_is_enabled) {
   auto state = std::make_shared<http_publish_state>();
   auto app = http_server_application{state};
   auto config = forge::config::core::document{};
   config.set("plugins.http.server.tls.mode", std::string{"server"});
   config.set("plugins.http.server.tls.certificate-chain-secret", std::string{"http/test-certificate"});
   config.set("plugins.http.server.tls.private-key-secret", std::string{"http/test-private-key"});

   app.configure(config);
   BOOST_CHECK_THROW(forge::asio::blocking::run(app.runtime(), app.startup()), http_server::exceptions::startup_failed);
}

BOOST_AUTO_TEST_CASE(http_server_plugin_tls_reload_uses_distinct_secret_purposes_and_preserves_active_context) {
   auto state = std::make_shared<http_tls_secret_state>();
   auto app = http_tls_server_application{state};
   auto config = forge::config::core::document{};
   config.set("plugins.http.server.port", std::uint64_t{0});
   config.set("plugins.http.server.tls.mode", std::string{"mutual"});
   config.set("plugins.http.server.tls.certificate-chain-secret", std::string{"http/test-certificate"});
   config.set("plugins.http.server.tls.private-key-secret", std::string{"http/test-private-key"});
   config.set("plugins.http.server.tls.client-ca-secret", std::string{"http/test-client-ca"});

   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.startup());
   const auto api = app.apis().get<http_server::api>(http_server::api::ref());
   forge::asio::blocking::run(app.runtime(), api->reload_tls());

   auto purposes = std::vector<std::string>{};
   {
      const auto lock = std::scoped_lock{state->mutex};
      purposes = state->purposes;
   }
   BOOST_REQUIRE_EQUAL(purposes.size(), 6U);
   BOOST_TEST(purposes[0] == "http.server.tls.certificate-chain");
   BOOST_TEST(purposes[1] == "http.server.tls.private-key");
   BOOST_TEST(purposes[2] == "http.server.tls.client-ca");
   BOOST_TEST(purposes[3] == "http.server.tls.certificate-chain");
   BOOST_TEST(purposes[4] == "http.server.tls.private-key");
   BOOST_TEST(purposes[5] == "http.server.tls.client-ca");

   {
      const auto lock = std::scoped_lock{state->mutex};
      state->reject_reads = true;
   }
   BOOST_CHECK_THROW(forge::asio::blocking::run(app.runtime(), api->reload_tls()),
                     http_server::exceptions::tls_reload_failed);
   {
      const auto lock = std::scoped_lock{state->mutex};
      state->reject_reads = false;
   }
   BOOST_CHECK_NO_THROW(forge::asio::blocking::run(app.runtime(), api->reload_tls()));

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(http_server_plugin_tls_reload_preserves_live_context_and_cannot_publish_after_shutdown) {
   auto state = std::make_shared<http_tls_secret_state>();
   auto app = http_tls_server_application{state};
   const auto port = reserve_loopback_port();
   auto config = forge::config::core::document{};
   config.set("plugins.http.server.port", static_cast<std::uint64_t>(port));
   config.set("plugins.http.server.tls.mode", std::string{"server"});
   config.set("plugins.http.server.tls.certificate-chain-secret", std::string{"http/test-certificate"});
   config.set("plugins.http.server.tls.private-key-secret", std::string{"http/test-private-key"});

   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.startup());
   const auto api = app.apis().get<http_server::api>(http_server::api::ref());
   BOOST_REQUIRE(plugin_tls_request_succeeds(port));

   {
      const auto lock = std::scoped_lock{state->mutex};
      state->reject_reads = true;
   }
   BOOST_CHECK_THROW(forge::asio::blocking::run(app.runtime(), api->reload_tls()),
                     http_server::exceptions::tls_reload_failed);
   BOOST_CHECK(plugin_tls_request_succeeds(port));

   {
      const auto lock = std::scoped_lock{state->mutex};
      state->reject_reads = false;
      state->block_reads = true;
      state->read_blocked = false;
      state->blocked_read.reset();
   }
   auto reload = boost::asio::co_spawn(app.runtime().context(), api->reload_tls(), boost::asio::use_future);
   {
      auto lock = std::unique_lock{state->mutex};
      BOOST_REQUIRE(state->changed.wait_for(lock, std::chrono::seconds{2}, [&] { return state->read_blocked; }));
   }

   auto shutdown = boost::asio::co_spawn(app.runtime().context(), app.shutdown(), boost::asio::use_future);
   BOOST_REQUIRE(shutdown.wait_for(std::chrono::seconds{2}) == std::future_status::ready);

   auto blocked_read = std::shared_ptr<boost::asio::steady_timer>{};
   {
      const auto lock = std::scoped_lock{state->mutex};
      state->block_reads = false;
      blocked_read = std::move(state->blocked_read);
   }
   if (blocked_read) {
      blocked_read->cancel();
   }
   BOOST_CHECK_THROW(reload.get(), http_server::exceptions::tls_reload_failed);
   BOOST_CHECK_NO_THROW(shutdown.get());
}

BOOST_AUTO_TEST_CASE(http_server_plugin_tls_reload_rejects_malformed_material_and_keeps_live_context) {
   auto state = std::make_shared<http_tls_secret_state>();
   auto app = http_tls_server_application{state};
   const auto port = reserve_loopback_port();
   auto config = forge::config::core::document{};
   config.set("plugins.http.server.port", static_cast<std::uint64_t>(port));
   config.set("plugins.http.server.tls.mode", std::string{"server"});
   config.set("plugins.http.server.tls.certificate-chain-secret", std::string{"http/test-certificate"});
   config.set("plugins.http.server.tls.private-key-secret", std::string{"http/test-private-key"});

   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.startup());
   const auto api = app.apis().get<http_server::api>(http_server::api::ref());
   BOOST_REQUIRE(plugin_tls_request_succeeds(port));

   {
      const auto lock = std::scoped_lock{state->mutex};
      state->certificate_override = "not a PEM certificate";
   }
   BOOST_CHECK_THROW(forge::asio::blocking::run(app.runtime(), api->reload_tls()),
                     http_server::exceptions::tls_reload_failed);
   BOOST_CHECK(plugin_tls_request_succeeds(port));

   const auto other_identity = forge::tests::p2p::make_identity_fixture("http-tls-plugin-mismatched-key");
   {
      const auto lock = std::scoped_lock{state->mutex};
      state->certificate_override.reset();
      state->private_key_override = other_identity.private_key_pem;
   }
   BOOST_CHECK_THROW(forge::asio::blocking::run(app.runtime(), api->reload_tls()),
                     http_server::exceptions::tls_reload_failed);
   BOOST_CHECK(plugin_tls_request_succeeds(port));

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(http_server_plugin_publishes_typed_api_under_configured_base_path) {
   const auto port = reserve_loopback_port();
   auto state = std::make_shared<http_publish_state>();
   auto app = http_server_application{state};
   auto config = forge::config::core::document{};
   config.set("plugins.http.server.port", std::uint64_t{port});
   config.set("plugins.http.server.api-base-path", std::string{"/api"});

   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.startup());

   auto client = forge::net::http::client{
       app.runtime(), forge::net::http::parse_base_url("http://127.0.0.1:" + std::to_string(port) + "/api")};
   auto cache = forge::asio::blocking::run(app.runtime(), forge::api::http::remote<http_cache_api>(client));
   const auto chunk = forge::asio::blocking::run(
       app.runtime(), cache->read(http_read_request{.ref = "alpha", .offset = 7, .limit = 9}));
   BOOST_TEST(chunk.bytes == "alpha:7:9");

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(http_server_plugin_preserves_repeated_set_cookie_from_middleware) {
   const auto port = reserve_loopback_port();
   auto state = std::make_shared<http_publish_state>();
   state->append_cookies_after_next = true;
   auto app = http_server_application{state, true};
   auto config = forge::config::core::document{};
   config.set("plugins.http.server.port", std::uint64_t{port});
   config.set("plugins.http.server.api-base-path", std::string{"/api"});

   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.startup());

   auto client = forge::net::http::client{app.runtime(),
                                          forge::net::http::parse_base_url("http://127.0.0.1:" + std::to_string(port))};
   const auto response =
       forge::asio::blocking::run(app.runtime(), client.async_get("/api/cache/chunks/cookie?offset=0&limit=1"));
   auto cookies = std::vector<std::string>{};
   for (const auto& header : response.headers()) {
      if (forge::net::http::header_name_equal(header.name, "Set-Cookie")) {
         cookies.push_back(header.text);
      }
   }
   BOOST_TEST(cookies ==
                  (std::vector<std::string>{"session=alpha; Path=/api; HttpOnly", "csrf=beta; Path=/api; Secure"}),
              boost::test_tools::per_element());

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(http_server_plugin_mounts_assets_without_shadowing_a_narrow_api_prefix) {
   auto files = temp_directory{};
   files.write("index.html", "asset-console");
   const auto port = reserve_loopback_port();
   auto publish = std::make_shared<http_publish_state>();
   auto assets = std::make_shared<http_asset_publish_state>();
   assets->root = files.path();
   auto app = http_assets_server_application{publish, assets};
   auto config = forge::config::core::document{};
   config.set("plugins.http.server.port", std::uint64_t{port});
   config.set("plugins.http.server.api-base-path", std::string{"/admin-ui/v1"});

   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.startup());

   auto client = forge::net::http::client{app.runtime(),
                                          forge::net::http::parse_base_url("http://127.0.0.1:" + std::to_string(port))};
   const auto asset = forge::asio::blocking::run(app.runtime(), client.async_get("/admin/dashboard"));
   BOOST_TEST(static_cast<unsigned>(asset.result()) == static_cast<unsigned>(forge::net::http::status::ok));
   BOOST_TEST(asset.body() == "asset-console");
   const auto api_miss = forge::asio::blocking::run(app.runtime(), client.async_get("/admin-ui/v1/missing"));
   BOOST_TEST(static_cast<unsigned>(api_miss.result()) == static_cast<unsigned>(forge::net::http::status::not_found));

   auto api_client = forge::net::http::client{
       app.runtime(), forge::net::http::parse_base_url("http://127.0.0.1:" + std::to_string(port) + "/admin-ui/v1")};
   auto cache = forge::asio::blocking::run(app.runtime(), forge::api::http::remote<http_cache_api>(api_client));
   const auto chunk = forge::asio::blocking::run(
       app.runtime(), cache->read(http_read_request{.ref = "asset", .offset = 1, .limit = 2}));
   BOOST_TEST(chunk.bytes == "asset:1:2");

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(http_server_plugin_rejects_asset_publication_without_application_compute) {
   auto files = temp_directory{};
   files.write("index.html", "asset-console");
   auto publish = std::make_shared<http_publish_state>();
   auto assets = std::make_shared<http_asset_publish_state>();
   assets->root = files.path();
   auto app = http_assets_server_application{publish, assets, false};
   auto config = forge::config::core::document{};
   config.set("plugins.http.server.port", std::uint64_t{reserve_loopback_port()});

   app.configure(config);
   BOOST_CHECK_THROW(forge::asio::blocking::run(app.runtime(), app.startup()), http_server::exceptions::startup_failed);
}

BOOST_AUTO_TEST_CASE(http_server_plugin_rejects_root_api_prefix_overlapping_asset_mount_before_listener_start) {
   auto files = temp_directory{};
   files.write("index.html", "asset-console");
   auto publish = std::make_shared<http_publish_state>();
   auto assets = std::make_shared<http_asset_publish_state>();
   assets->root = files.path();
   auto app = http_assets_server_application{publish, assets};
   auto config = forge::config::core::document{};
   config.set("plugins.http.server.port", std::uint64_t{reserve_loopback_port()});
   config.set("plugins.http.server.api-base-path", std::string{"/"});

   app.configure(config);
   BOOST_CHECK_THROW(forge::asio::blocking::run(app.runtime(), app.startup()), forge::net::http::exceptions::conflict);
}

BOOST_AUTO_TEST_CASE(http_server_plugin_uses_publish_base_path_override) {
   const auto port = reserve_loopback_port();
   auto state = std::make_shared<http_publish_state>();
   state->base_path = "/custom";
   auto app = http_server_application{state};
   auto config = forge::config::core::document{};
   config.set("plugins.http.server.port", std::uint64_t{port});
   config.set("plugins.http.server.api-base-path", std::string{"/api"});

   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.startup());

   auto client = forge::net::http::client{
       app.runtime(), forge::net::http::parse_base_url("http://127.0.0.1:" + std::to_string(port) + "/custom")};
   auto cache = forge::asio::blocking::run(app.runtime(), forge::api::http::remote<http_cache_api>(client));
   const auto chunk =
       forge::asio::blocking::run(app.runtime(), cache->write(http_write_request{.ref = "beta", .bytes = "payload"}));
   BOOST_TEST(chunk.bytes == "beta:payload");

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(http_server_plugin_applies_middleware_order_and_short_circuit) {
   const auto port = reserve_loopback_port();
   auto state = std::make_shared<http_publish_state>();
   state->short_circuit = true;
   auto app = http_server_application{state, true};
   auto config = forge::config::core::document{};
   config.set("plugins.http.server.port", std::uint64_t{port});
   config.set("plugins.http.server.api-base-path", std::string{"/api"});

   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.startup());

   auto client = forge::net::http::client{app.runtime(),
                                          forge::net::http::parse_base_url("http://127.0.0.1:" + std::to_string(port))};
   const auto denied =
       forge::asio::blocking::run(app.runtime(), client.async_get("/api/cache/chunks/secure?offset=1&limit=1"));
   BOOST_TEST(static_cast<unsigned>(denied.result()) == static_cast<unsigned>(forge::net::http::status::unauthorized));
   BOOST_TEST(state->middleware_events == (std::vector<std::string>{"security"}), boost::test_tools::per_element());

   auto request = forge::net::http::request{};
   request.method(forge::net::http::method::get);
   request.target("/api/cache/chunks/secure?offset=1&limit=1");
   request.version(11);
   request.set(forge::net::http::field::authorization, "Bearer test");
   const auto allowed = forge::asio::blocking::run(app.runtime(), client.async_request(std::move(request)));
   BOOST_TEST(static_cast<unsigned>(allowed.result()) == static_cast<unsigned>(forge::net::http::status::ok));
   BOOST_TEST(std::string{allowed[forge::net::http::field::server]} == "forge-test");
   BOOST_TEST(state->middleware_events == (std::vector<std::string>{"security", "security", "before"}),
              boost::test_tools::per_element());

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(http_server_plugin_preserves_stream_framing_through_middleware) {
   const auto port = reserve_loopback_port();
   auto state = std::make_shared<http_publish_state>();
   state->base_path = "/api";
   auto app = http_stream_server_application{state};
   auto config = forge::config::core::document{};
   config.set("plugins.http.server.port", std::uint64_t{port});
   config.set("plugins.http.server.api-base-path", std::string{"/api"});

   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.startup());

   auto client = forge::net::http::client{app.runtime(),
                                          forge::net::http::parse_base_url("http://127.0.0.1:" + std::to_string(port))};
   auto request = forge::net::http::request{};
   request.method(forge::net::http::method::get);
   request.target("/api/stream/alpha");
   request.version(11);
   request.set(forge::net::http::field::authorization, "Bearer test");

   const auto response = forge::asio::blocking::run(app.runtime(), client.async_request(std::move(request)));

   BOOST_TEST(static_cast<unsigned>(response.result()) == static_cast<unsigned>(forge::net::http::status::ok));
   BOOST_TEST(response.body() == "stream:alpha:payload");
   BOOST_TEST(std::string{response[forge::net::http::field::server]} == "forge-test");
   const auto has_content_length = response.find(forge::net::http::field::content_length) != response.end();
   BOOST_TEST(!has_content_length);
   BOOST_TEST(std::string{response[forge::net::http::field::transfer_encoding]} == "chunked");
   BOOST_TEST(!has_internal_forge_header(response));
   BOOST_TEST(state->stream_calls.load() == 1U);
   BOOST_TEST(state->stream_chunks.load() == 3U);

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(http_server_plugin_stream_middleware_content_type_preserves_stream) {
   const auto port = reserve_loopback_port();
   auto state = std::make_shared<http_publish_state>();
   state->base_path = "/api";
   state->set_stream_content_type_after_next = true;
   auto app = http_stream_server_application{state};
   auto config = forge::config::core::document{};
   config.set("plugins.http.server.port", std::uint64_t{port});
   config.set("plugins.http.server.api-base-path", std::string{"/api"});

   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.startup());

   auto client = forge::net::http::client{app.runtime(),
                                          forge::net::http::parse_base_url("http://127.0.0.1:" + std::to_string(port))};
   auto request = forge::net::http::request{};
   request.method(forge::net::http::method::get);
   request.target("/api/stream/alpha");
   request.version(11);
   request.set(forge::net::http::field::authorization, "Bearer test");

   const auto response = forge::asio::blocking::run(app.runtime(), client.async_request(std::move(request)));

   BOOST_TEST(static_cast<unsigned>(response.result()) == static_cast<unsigned>(forge::net::http::status::ok));
   BOOST_TEST(response.body() == "stream:alpha:payload");
   BOOST_TEST(std::string{response[forge::net::http::field::content_type]} == "application/x-ndjson");
   BOOST_TEST(std::string{response[forge::net::http::field::server]} == "forge-test");
   const auto has_content_length = response.find(forge::net::http::field::content_length) != response.end();
   BOOST_TEST(!has_content_length);
   BOOST_TEST(std::string{response[forge::net::http::field::transfer_encoding]} == "chunked");
   BOOST_TEST(!has_internal_forge_header(response));
   BOOST_TEST(state->stream_calls.load() == 1U);
   BOOST_TEST(state->stream_chunks.load() == 3U);

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(http_server_plugin_preserves_absent_content_type_through_middleware) {
   const auto port = reserve_loopback_port();
   auto state = std::make_shared<http_publish_state>();
   state->base_path = "/api";
   auto app = http_empty_server_application{state};
   auto config = forge::config::core::document{};
   config.set("plugins.http.server.port", std::uint64_t{port});
   config.set("plugins.http.server.api-base-path", std::string{"/api"});

   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.startup());

   auto client = forge::net::http::client{app.runtime(),
                                          forge::net::http::parse_base_url("http://127.0.0.1:" + std::to_string(port))};
   auto request = forge::net::http::request{};
   request.method(forge::net::http::method::delete_);
   request.target("/api/empty/alpha");
   request.version(11);
   request.set(forge::net::http::field::authorization, "Bearer test");

   const auto response = forge::asio::blocking::run(app.runtime(), client.async_request(std::move(request)));

   BOOST_TEST(static_cast<unsigned>(response.result()) == static_cast<unsigned>(forge::net::http::status::no_content));
   BOOST_TEST(response.body().empty());
   const auto has_content_type = response.find(forge::net::http::field::content_type) != response.end();
   BOOST_TEST(!has_content_type);
   BOOST_TEST(!has_internal_forge_header(response));
   BOOST_TEST(std::string{response[forge::net::http::field::server]} == "forge-test");

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(http_server_plugin_stream_middleware_replacement_does_not_leak_original_body) {
   const auto port = reserve_loopback_port();
   auto state = std::make_shared<http_publish_state>();
   state->base_path = "/api";
   state->replace_stream_after_next = true;
   auto app = http_stream_server_application{state};
   auto config = forge::config::core::document{};
   config.set("plugins.http.server.port", std::uint64_t{port});
   config.set("plugins.http.server.api-base-path", std::string{"/api"});

   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.startup());

   auto client = forge::net::http::client{app.runtime(),
                                          forge::net::http::parse_base_url("http://127.0.0.1:" + std::to_string(port))};
   auto request = forge::net::http::request{};
   request.method(forge::net::http::method::get);
   request.target("/api/stream/alpha");
   request.version(11);
   request.set(forge::net::http::field::authorization, "Bearer test");

   const auto response = forge::asio::blocking::run(app.runtime(), client.async_request(std::move(request)));

   BOOST_TEST(static_cast<unsigned>(response.result()) == static_cast<unsigned>(forge::net::http::status::forbidden));
   BOOST_TEST(response.body() == "blocked");
   const auto has_transfer_encoding = response.find(forge::net::http::field::transfer_encoding) != response.end();
   BOOST_TEST(!has_transfer_encoding);
   BOOST_TEST(!has_internal_forge_header(response));
   BOOST_TEST(state->stream_calls.load() == 1U);
   BOOST_TEST(state->stream_chunks.load() == 0U);

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(http_server_plugin_empty_stream_middleware_replacement_clears_hidden_token) {
   const auto port = reserve_loopback_port();
   auto state = std::make_shared<http_publish_state>();
   state->base_path = "/api";
   state->empty_replace_stream_after_next = true;
   auto app = http_stream_server_application{state};
   auto config = forge::config::core::document{};
   config.set("plugins.http.server.port", std::uint64_t{port});
   config.set("plugins.http.server.api-base-path", std::string{"/api"});

   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.startup());

   auto client = forge::net::http::client{app.runtime(),
                                          forge::net::http::parse_base_url("http://127.0.0.1:" + std::to_string(port))};
   auto request = forge::net::http::request{};
   request.method(forge::net::http::method::get);
   request.target("/api/stream/alpha");
   request.version(11);
   request.set(forge::net::http::field::authorization, "Bearer test");

   const auto response = forge::asio::blocking::run(app.runtime(), client.async_request(std::move(request)));

   BOOST_TEST(static_cast<unsigned>(response.result()) == static_cast<unsigned>(forge::net::http::status::forbidden));
   BOOST_TEST(response.body().empty());
   const auto has_transfer_encoding = response.find(forge::net::http::field::transfer_encoding) != response.end();
   BOOST_TEST(!has_transfer_encoding);
   BOOST_TEST(!has_internal_forge_header(response));
   BOOST_TEST(state->stream_calls.load() == 1U);
   BOOST_TEST(state->stream_chunks.load() == 0U);

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(http_server_plugin_rejects_duplicate_publication_on_startup) {
   const auto port = reserve_loopback_port();
   auto app = duplicate_http_server_application{};
   auto config = forge::config::core::document{};
   config.set("plugins.http.server.port", std::uint64_t{port});

   app.configure(config);
   BOOST_CHECK_THROW(forge::asio::blocking::run(app.runtime(), app.startup()), forge::net::http::exceptions::conflict);
}

BOOST_AUTO_TEST_CASE(http_server_plugin_rejects_late_publication_after_startup_closed) {
   const auto port = reserve_loopback_port();
   auto app = late_http_server_application{};
   auto config = forge::config::core::document{};
   config.set("plugins.http.server.port", std::uint64_t{port});

   app.configure(config);
   BOOST_CHECK_THROW(forge::asio::blocking::run(app.runtime(), app.startup()),
                     http_server::exceptions::publication_closed);
}

BOOST_AUTO_TEST_CASE(crypto_signer_config_is_redacted_and_local_only) {
   auto plugin = crypto_signer::plugin{};
   const auto descriptor = plugin.describe_config();
   BOOST_REQUIRE(descriptor.has_value());
   BOOST_TEST(descriptor->section == "plugins.crypto.signer");

   const auto& keys = require_field(*descriptor, "keys");
   BOOST_TEST(keys.secret);
   BOOST_TEST(static_cast<int>(keys.kind) == static_cast<int>(forge::schema::value_kind::object_list));
   const auto& bls_keys = require_field(*descriptor, "bls-keys");
   BOOST_TEST(bls_keys.secret);
   BOOST_TEST(static_cast<int>(bls_keys.kind) == static_cast<int>(forge::schema::value_kind::object_list));
   const auto& removed_output_profile = require_field(*descriptor, "default-output-profile");
   BOOST_TEST(removed_output_profile.deprecated);
   BOOST_TEST(removed_output_profile.ingestion_only);

   auto registry = forge::config::core::component_registry{};
   registry.add(*descriptor);

   const auto key =
       forge::crypto::asymmetric::private_key::generate<forge::crypto::asymmetric::secp256k1::private_key>();
   auto document = signer_config(
       {key_entry("provider", forge::crypto::asymmetric::encoding::forge().format(key), "forge", {"storage.receipt"})});
   const auto redacted = forge::config::core::redact(document, registry);
   const auto* value = redacted.try_get("plugins.crypto.signer.keys");
   BOOST_REQUIRE(value != nullptr);
   const auto* text = std::get_if<std::string>(&value->storage);
   BOOST_REQUIRE(text != nullptr);
   BOOST_TEST(*text == "<redacted>");

   const auto bls_key = forge::crypto::bls::private_key::generate();
   auto bls_document = signer_config(
       {}, {bls_key_entry("finalizer", forge::crypto::bls::encoding::format(bls_key), {"chain.finality"})});
   const auto redacted_bls = forge::config::core::redact(bls_document, registry);
   const auto* bls_value = redacted_bls.try_get("plugins.crypto.signer.bls-keys");
   BOOST_REQUIRE(bls_value != nullptr);
   const auto* bls_text = std::get_if<std::string>(&bls_value->storage);
   BOOST_REQUIRE(bls_text != nullptr);
   BOOST_TEST(*bls_text == "<redacted>");
}

BOOST_AUTO_TEST_CASE(crypto_signer_config_decodes_through_public_schema) {
   const auto key =
       forge::crypto::asymmetric::private_key::generate<forge::crypto::asymmetric::secp256k1::private_key>();
   const auto bls_key = forge::crypto::bls::private_key::generate();
   const auto document = signer_config(
       {key_entry("provider", forge::crypto::asymmetric::encoding::forge().format(key), "forge", {"storage.receipt"})},
       {bls_key_entry("finalizer", forge::crypto::bls::encoding::format(bls_key), {"chain.finality"})});

   const auto decoded = forge::config::core::decode<crypto_signer::config>(document, "plugins.crypto.signer");
   BOOST_TEST(decoded.ok());
   BOOST_REQUIRE_EQUAL(decoded.value.keys.size(), 1U);
   BOOST_TEST(decoded.value.keys.front().id == "provider");
   BOOST_TEST(decoded.value.keys.front().input_profile == "forge");
   BOOST_REQUIRE_EQUAL(decoded.value.keys.front().purposes.size(), 1U);
   BOOST_TEST(decoded.value.keys.front().purposes.front() == "storage.receipt");
   BOOST_REQUIRE_EQUAL(decoded.value.bls_keys.size(), 1U);
   BOOST_TEST(decoded.value.bls_keys.front().id == "finalizer");
   BOOST_REQUIRE_EQUAL(decoded.value.bls_keys.front().purposes.size(), 1U);
   BOOST_TEST(decoded.value.bls_keys.front().purposes.front() == "chain.finality");
}

BOOST_AUTO_TEST_CASE(crypto_signer_rejects_removed_default_output_profile) {
   const auto key =
       forge::crypto::asymmetric::private_key::generate<forge::crypto::asymmetric::secp256k1::private_key>();
   auto document = signer_config(
       {key_entry("provider", forge::crypto::asymmetric::encoding::forge().format(key), "forge", {"api.auth"})});
   document.set("plugins.crypto.signer.default-output-profile", "forge");

   auto plugin = crypto_signer::plugin{};
   auto runtime = forge::asio::runtime{};
   BOOST_CHECK_THROW(forge::asio::blocking::run(runtime, plugin.configure(forge::config::core::component_view{
                                                             document, "plugins.crypto.signer"})),
                     crypto_signer::exceptions::invalid_config);

   const auto descriptor = plugin.describe_config();
   BOOST_REQUIRE(descriptor.has_value());
   auto registry = forge::config::core::component_registry{};
   registry.add(*descriptor);
   const auto from_env = forge::config::env::read_document("FORGE_PLUGINS_CRYPTO_SIGNER_DEFAULT_OUTPUT_PROFILE=forge\n",
                                                           registry, {.prefix = "FORGE"});
   BOOST_TEST(from_env.ok());
   BOOST_REQUIRE(from_env.value.try_get("plugins.crypto.signer.default-output-profile") != nullptr);
   BOOST_CHECK_THROW(forge::asio::blocking::run(runtime, plugin.configure(forge::config::core::component_view{
                                                             from_env.value, "plugins.crypto.signer"})),
                     crypto_signer::exceptions::invalid_config);

   const char* argv[] = {"tool", "--plugins.crypto.signer.default-output-profile=forge"};
   const auto from_cli = forge::config::program_options::parse(2, argv, registry);
   BOOST_TEST(from_cli.ok());
   BOOST_REQUIRE(from_cli.document.try_get("plugins.crypto.signer.default-output-profile") != nullptr);
   BOOST_CHECK_THROW(forge::asio::blocking::run(runtime, plugin.configure(forge::config::core::component_view{
                                                             from_cli.document, "plugins.crypto.signer"})),
                     crypto_signer::exceptions::invalid_config);

   const auto help = forge::config::program_options::help(registry, "FORGE options");
   BOOST_TEST(help.find("default-output-profile") == std::string::npos);
   const auto example = forge::config::env::write_example(registry, {.prefix = "FORGE"});
   BOOST_TEST(example.ok());
   BOOST_TEST(example.text.find("FORGE_PLUGINS_CRYPTO_SIGNER_DEFAULT_OUTPUT_PROFILE") == std::string::npos);
   const auto written = forge::config::env::write_document(from_env.value, registry, {.prefix = "FORGE"});
   BOOST_TEST(written.ok());
   BOOST_TEST(written.text.find("FORGE_PLUGINS_CRYPTO_SIGNER_DEFAULT_OUTPUT_PROFILE") == std::string::npos);
}

BOOST_AUTO_TEST_CASE(crypto_signer_structured_keys_are_not_cli_or_env_fields) {
   auto plugin = crypto_signer::plugin{};
   const auto descriptor = plugin.describe_config();
   BOOST_REQUIRE(descriptor.has_value());

   auto registry = forge::config::core::component_registry{};
   registry.add(*descriptor);

   const auto help = forge::config::program_options::help(registry, "FORGE options");
   BOOST_TEST(help.find("plugins.crypto.signer.keys") == std::string::npos);
   BOOST_TEST(help.find("plugins.crypto.signer.bls-keys") == std::string::npos);

   const char* argv[] = {"tool", "--plugins.crypto.signer.keys=provider"};
   const auto parsed = forge::config::program_options::parse(2, argv, registry);
   BOOST_TEST(!parsed.ok());
   BOOST_TEST(parsed.document.try_get("plugins.crypto.signer.keys") == nullptr);

   const auto key =
       forge::crypto::asymmetric::private_key::generate<forge::crypto::asymmetric::secp256k1::private_key>();
   const auto bls_key = forge::crypto::bls::private_key::generate();
   const auto document = signer_config(
       {key_entry("provider", forge::crypto::asymmetric::encoding::forge().format(key), "forge", {"storage.receipt"})},
       {bls_key_entry("finalizer", forge::crypto::bls::encoding::format(bls_key), {"chain.finality"})});

   const auto written = forge::config::env::write_document(document, registry, {.prefix = "FORGE"});
   BOOST_TEST(written.ok());
   BOOST_TEST(written.text.find("FORGE_PLUGINS_CRYPTO_SIGNER_KEYS") == std::string::npos);
   BOOST_TEST(written.text.find("FORGE_PLUGINS_CRYPTO_SIGNER_BLS_KEYS") == std::string::npos);

   const auto example = forge::config::env::write_example(registry, {.prefix = "FORGE"});
   BOOST_TEST(example.ok());
   BOOST_TEST(example.text.find("FORGE_PLUGINS_CRYPTO_SIGNER_KEYS") == std::string::npos);
   BOOST_TEST(example.text.find("FORGE_PLUGINS_CRYPTO_SIGNER_BLS_KEYS") == std::string::npos);

   const auto read = forge::config::env::read_document(
       "FORGE_PLUGINS_CRYPTO_SIGNER_KEYS=provider\n", registry,
       {.prefix = "FORGE", .unknown_variables = forge::config::env::unknown_variable_policy::error});
   BOOST_TEST(!read.ok());
   BOOST_REQUIRE_EQUAL(read.diagnostics.size(), 1U);
   BOOST_TEST(read.diagnostics.front().code == "env.unknown");
   BOOST_TEST(read.value.try_get("plugins.crypto.signer.keys") == nullptr);

   const auto bls_read = forge::config::env::read_document(
       "FORGE_PLUGINS_CRYPTO_SIGNER_BLS_KEYS=finalizer\n", registry,
       {.prefix = "FORGE", .unknown_variables = forge::config::env::unknown_variable_policy::error});
   BOOST_TEST(!bls_read.ok());
   BOOST_REQUIRE_EQUAL(bls_read.diagnostics.size(), 1U);
   BOOST_TEST(bls_read.diagnostics.front().code == "env.unknown");
   BOOST_TEST(bls_read.value.try_get("plugins.crypto.signer.bls-keys") == nullptr);
}

BOOST_AUTO_TEST_CASE(crypto_signer_rejects_malformed_private_key_without_leaking_secret) {
   auto plugin = crypto_signer::plugin{};
   const auto bad_key = std::string{"PVT_SECP256K1_not-a-valid-secret!!!!"};
   auto document = signer_config({key_entry("provider", bad_key, "forge", {"storage.receipt"})});

   auto runtime = forge::asio::runtime{};
   BOOST_CHECK_EXCEPTION(
       forge::asio::blocking::run(
           runtime, plugin.configure(forge::config::core::component_view{document, "plugins.crypto.signer"})),
       crypto_signer::exceptions::invalid_key, [&](const auto& error) {
          const auto text = std::string{error.what()};
          return text.find("provider") != std::string::npos && text.find(bad_key) == std::string::npos &&
                 text.find("not-a-valid-secret") == std::string::npos && text.find("base58_str") == std::string::npos;
       });
}

BOOST_AUTO_TEST_CASE(crypto_signer_rejects_malformed_bls_private_key_without_leaking_secret) {
   auto plugin = crypto_signer::plugin{};
   const auto bad_key = std::string{"PVT_BLS_not-a-valid-secret!!!!"};
   auto document = signer_config({}, {bls_key_entry("finalizer", bad_key, {"chain.finality"})});

   auto runtime = forge::asio::runtime{};
   BOOST_CHECK_EXCEPTION(forge::asio::blocking::run(runtime, plugin.configure(forge::config::core::component_view{
                                                                 document, "plugins.crypto.signer"})),
                         crypto_signer::exceptions::invalid_key, [&](const auto& error) {
                            const auto text = std::string{error.what()};
                            return text.find("finalizer") != std::string::npos &&
                                   text.find(bad_key) == std::string::npos &&
                                   text.find("not-a-valid-secret") == std::string::npos;
                         });
}

BOOST_AUTO_TEST_CASE(crypto_signer_rejects_empty_private_key_through_schema) {
   auto plugin = crypto_signer::plugin{};
   auto document = signer_config({key_entry("provider", "", "forge", {"storage.receipt"})});

   auto runtime = forge::asio::runtime{};
   BOOST_CHECK_EXCEPTION(forge::asio::blocking::run(runtime, plugin.configure(forge::config::core::component_view{
                                                                 document, "plugins.crypto.signer"})),
                         crypto_signer::exceptions::invalid_config, [](const auto& error) {
                            const auto text = std::string{error.what()};
                            return text.find("plugins.crypto.signer.keys[0].private-key") != std::string::npos &&
                                   text.find("schema.non_empty") != std::string::npos;
                         });
}

BOOST_AUTO_TEST_CASE(crypto_signer_requires_explicit_non_empty_purposes) {
   const auto key =
       forge::crypto::asymmetric::private_key::generate<forge::crypto::asymmetric::secp256k1::private_key>();
   const auto private_key = forge::crypto::asymmetric::encoding::forge().format(key);

   auto runtime = forge::asio::runtime{};

   auto missing = crypto_signer::plugin{};
   auto missing_document = signer_config({key_entry_without_purposes("missing", private_key, "forge")});
   BOOST_CHECK_THROW(forge::asio::blocking::run(runtime, missing.configure(forge::config::core::component_view{
                                                             missing_document, "plugins.crypto.signer"})),
                     crypto_signer::exceptions::invalid_config);

   auto empty = crypto_signer::plugin{};
   auto empty_document = signer_config({key_entry("empty", private_key, "forge", {})});
   BOOST_CHECK_THROW(forge::asio::blocking::run(runtime, empty.configure(forge::config::core::component_view{
                                                             empty_document, "plugins.crypto.signer"})),
                     crypto_signer::exceptions::invalid_config);

   auto blank = crypto_signer::plugin{};
   auto blank_document = signer_config({key_entry("blank", private_key, "forge", {""})});
   BOOST_CHECK_THROW(forge::asio::blocking::run(runtime, blank.configure(forge::config::core::component_view{
                                                             blank_document, "plugins.crypto.signer"})),
                     crypto_signer::exceptions::invalid_config);

   const auto bls_key = forge::crypto::bls::private_key::generate();
   auto bls_empty = crypto_signer::plugin{};
   auto bls_empty_document =
       signer_config({}, {bls_key_entry("finalizer", forge::crypto::bls::encoding::format(bls_key), {})});
   BOOST_CHECK_THROW(forge::asio::blocking::run(runtime, bls_empty.configure(forge::config::core::component_view{
                                                             bls_empty_document, "plugins.crypto.signer"})),
                     crypto_signer::exceptions::invalid_config);
}

BOOST_AUTO_TEST_CASE(crypto_signer_returns_typed_k1_result) {
   static_assert(std::same_as<decltype(std::declval<crypto_signer::response>().public_key),
                              forge::crypto::asymmetric::public_key>);
   static_assert(
       std::same_as<decltype(std::declval<crypto_signer::response>().signature), forge::crypto::asymmetric::signature>);

   const auto key =
       forge::crypto::asymmetric::private_key::generate<forge::crypto::asymmetric::secp256k1::private_key>();
   auto plugin = crypto_signer::plugin{};
   auto document = signer_config({key_entry("provider", forge::crypto::asymmetric::encoding::forge().format(key),
                                            "forge", {"storage.receipt", "storage.audit"})});

   auto runtime = forge::asio::runtime{};
   forge::asio::blocking::run(runtime,
                              plugin.configure(forge::config::core::component_view{document, "plugins.crypto.signer"}));

   auto apis = forge::api::core::registry{};
   auto provider = forge::api::core::installer{apis};
   forge::asio::blocking::run(runtime, plugin.provide(provider));

   auto api = apis.get<crypto_signer::api>(crypto_signer::api::ref());
   const auto digest = forge::crypto::digest::sha256::hash(std::string{"receipt-payload"});
   const auto response =
       forge::asio::blocking::run(runtime, api->sign(crypto_signer::request{
                                               .key_id = "provider",
                                               .purpose = "storage.receipt",
                                               .digest = digest,
                                               .required_algorithm = forge::crypto::asymmetric::algorithm::secp256k1,
                                           }));

   BOOST_TEST(response.key_id == "provider");
   BOOST_CHECK(response.public_key == key.get_public_key());
   BOOST_TEST(static_cast<int>(forge::crypto::asymmetric::type(response.signature)) ==
              static_cast<int>(forge::crypto::asymmetric::algorithm::secp256k1));

   const auto recovered = forge::crypto::asymmetric::recover(response.signature, digest, true);
   BOOST_CHECK(recovered == response.public_key);

   const auto unpacked_public_key =
       forge::raw::unpack<forge::crypto::asymmetric::public_key>(forge::raw::pack(response.public_key));
   const auto unpacked_signature =
       forge::raw::unpack<forge::crypto::asymmetric::signature>(forge::raw::pack(response.signature));
   BOOST_CHECK(unpacked_public_key == response.public_key);
   BOOST_CHECK(unpacked_signature == response.signature);

   const auto packed = forge::raw::pack(response);
   const auto unpacked = forge::raw::unpack<crypto_signer::response>(packed);
   BOOST_TEST(unpacked.key_id == response.key_id);
   BOOST_CHECK(unpacked.public_key == response.public_key);
   BOOST_CHECK(unpacked.signature == response.signature);

   const auto signature_text = forge::crypto::asymmetric::encoding::antelope().format(response.signature);
   BOOST_TEST(signature_text.starts_with("SIG_K1_"));
}

BOOST_AUTO_TEST_CASE(crypto_signer_bls_api_describes_proof_and_signs_message) {
   static_assert(std::same_as<decltype(std::declval<crypto_signer::bls_description>().public_key),
                              forge::crypto::bls::public_key>);
   static_assert(std::same_as<decltype(std::declval<crypto_signer::bls_description>().proof_of_possession),
                              forge::crypto::bls::signature>);
   static_assert(
       std::same_as<decltype(std::declval<crypto_signer::bls_response>().signature), forge::crypto::bls::signature>);

   const auto key = forge::crypto::bls::private_key::generate();
   auto plugin = crypto_signer::plugin{};
   auto document = signer_config({}, {bls_key_entry("finalizer", forge::crypto::bls::encoding::format(key),
                                                    {"chain.finality", "chain.finality.proof"})});

   auto runtime = forge::asio::runtime{};
   forge::asio::blocking::run(runtime,
                              plugin.configure(forge::config::core::component_view{document, "plugins.crypto.signer"}));

   auto apis = forge::api::core::registry{};
   auto provider = forge::api::core::installer{apis};
   forge::asio::blocking::run(runtime, plugin.provide(provider));
   auto api = apis.get<crypto_signer::bls_api>(crypto_signer::bls_api::ref());

   const auto description = forge::asio::blocking::run(runtime, api->describe("finalizer", "chain.finality.proof"));
   BOOST_TEST(description.key_id == "finalizer");
   BOOST_CHECK(description.public_key == key.get_public_key());
   BOOST_REQUIRE(
       forge::crypto::bls::verify_proof_of_possession(description.public_key, description.proof_of_possession));

   auto message = std::vector<std::uint8_t>{0x53, 0x70, 0x69, 0x6e, 0x65};
   const auto response = forge::asio::blocking::run(runtime, api->sign("finalizer", "chain.finality", message));
   BOOST_TEST(response.key_id == "finalizer");
   BOOST_CHECK(response.public_key == description.public_key);
   BOOST_TEST(forge::crypto::bls::verify(response.public_key, message, response.signature));

   const auto unpacked_description = forge::raw::unpack<crypto_signer::bls_description>(forge::raw::pack(description));
   const auto unpacked_response = forge::raw::unpack<crypto_signer::bls_response>(forge::raw::pack(response));
   BOOST_CHECK(unpacked_description.public_key == description.public_key);
   BOOST_CHECK(unpacked_description.proof_of_possession == description.proof_of_possession);
   BOOST_CHECK(unpacked_response.public_key == response.public_key);
   BOOST_CHECK(unpacked_response.signature == response.signature);
}

BOOST_AUTO_TEST_CASE(crypto_signer_bls_api_enforces_key_and_purpose) {
   const auto key = forge::crypto::bls::private_key::generate();
   auto plugin = crypto_signer::plugin{};
   auto document =
       signer_config({}, {bls_key_entry("finalizer", forge::crypto::bls::encoding::format(key), {"chain.finality"})});

   auto runtime = forge::asio::runtime{};
   forge::asio::blocking::run(runtime,
                              plugin.configure(forge::config::core::component_view{document, "plugins.crypto.signer"}));
   auto apis = forge::api::core::registry{};
   auto provider = forge::api::core::installer{apis};
   forge::asio::blocking::run(runtime, plugin.provide(provider));
   auto api = apis.get<crypto_signer::bls_api>(crypto_signer::bls_api::ref());

   BOOST_CHECK_THROW(forge::asio::blocking::run(runtime, api->describe("missing", "chain.finality")),
                     crypto_signer::exceptions::key_not_found);
   BOOST_CHECK_THROW(forge::asio::blocking::run(runtime, api->describe("finalizer", "chain.finality.proof")),
                     crypto_signer::exceptions::purpose_denied);
   BOOST_CHECK_THROW(forge::asio::blocking::run(
                         runtime, api->sign("finalizer", "chain.finality.proof", std::vector<std::uint8_t>{1})),
                     crypto_signer::exceptions::purpose_denied);
}

BOOST_AUTO_TEST_CASE(crypto_signer_apis_are_unavailable_after_stop) {
   const auto asymmetric_key =
       forge::crypto::asymmetric::private_key::generate<forge::crypto::asymmetric::secp256k1::private_key>();
   const auto bls_key = forge::crypto::bls::private_key::generate();
   auto plugin = crypto_signer::plugin{};
   auto document =
       signer_config({key_entry("producer", forge::crypto::asymmetric::encoding::forge().format(asymmetric_key),
                                "forge", {"chain.block"})},
                     {bls_key_entry("finalizer", forge::crypto::bls::encoding::format(bls_key), {"chain.finality"})});

   auto runtime = forge::asio::runtime{};
   forge::asio::blocking::run(runtime,
                              plugin.configure(forge::config::core::component_view{document, "plugins.crypto.signer"}));
   auto apis = forge::api::core::registry{};
   auto provider = forge::api::core::installer{apis};
   forge::asio::blocking::run(runtime, plugin.provide(provider));
   auto api = apis.get<crypto_signer::api>(crypto_signer::api::ref());
   auto bls_api = apis.get<crypto_signer::bls_api>(crypto_signer::bls_api::ref());

   plugin.request_stop();

   BOOST_CHECK_THROW(
       forge::asio::blocking::run(
           runtime, api->sign("producer", "chain.block", forge::crypto::digest::sha256::hash(std::string{"block"}))),
       crypto_signer::exceptions::unavailable);
   BOOST_CHECK_THROW(forge::asio::blocking::run(runtime, bls_api->describe("finalizer", "chain.finality")),
                     crypto_signer::exceptions::unavailable);
}

BOOST_AUTO_TEST_CASE(crypto_signer_algorithm_roundtrips_through_described_dto_paths) {
   const auto original = crypto_signer::options{
       .purpose = "api.auth",
       .required_algorithm = forge::crypto::asymmetric::algorithm::secp256k1,
   };

   auto encoded = forge::variant{};
   forge::to_variant(original, encoded);
   BOOST_TEST(encoded.get_object()["required_algorithm"].as_string() == "secp256k1");

   auto decoded = crypto_signer::options{};
   forge::from_variant(encoded, decoded);
   BOOST_TEST(decoded.purpose == original.purpose);
   BOOST_REQUIRE(decoded.required_algorithm.has_value());
   BOOST_TEST(static_cast<int>(*decoded.required_algorithm) == static_cast<int>(*original.required_algorithm));

   auto parsed = forge::crypto::asymmetric::algorithm::rsa;
   BOOST_TEST(forge::schema::enum_from_string("p256", parsed));
   BOOST_TEST(static_cast<int>(parsed) == static_cast<int>(forge::crypto::asymmetric::algorithm::p256));
}

BOOST_AUTO_TEST_CASE(crypto_signer_supports_p256_ed25519_and_rsa_binary_results) {
   const auto p256_key =
       forge::crypto::asymmetric::private_key::generate<forge::crypto::asymmetric::p256::private_key>();
   const auto ed25519_key =
       forge::crypto::asymmetric::private_key::generate<forge::crypto::asymmetric::ed25519::private_key>();
   const auto rsa_key = forge::crypto::asymmetric::private_key::generate<forge::crypto::asymmetric::rsa::private_key>();
   auto plugin = crypto_signer::plugin{};
   auto document = signer_config(
       {key_entry("p256", forge::crypto::asymmetric::encoding::forge().format(p256_key), "forge", {"api.auth"}),
        key_entry("ed25519", forge::crypto::asymmetric::encoding::forge().format(ed25519_key), "forge", {"api.auth"}),
        key_entry("rsa", forge::crypto::asymmetric::encoding::forge().format(rsa_key), "forge", {"api.auth"})});

   auto runtime = forge::asio::runtime{};
   forge::asio::blocking::run(runtime,
                              plugin.configure(forge::config::core::component_view{document, "plugins.crypto.signer"}));

   auto apis = forge::api::core::registry{};
   auto provider = forge::api::core::installer{apis};
   forge::asio::blocking::run(runtime, plugin.provide(provider));
   auto api = apis.get<crypto_signer::api>(crypto_signer::api::ref());

   const auto digest = forge::crypto::digest::sha256::hash(std::string{"auth-payload"});
   const auto check_raw_roundtrip = [](const crypto_signer::response& expected) {
      const auto public_key =
          forge::raw::unpack<forge::crypto::asymmetric::public_key>(forge::raw::pack(expected.public_key));
      const auto signature =
          forge::raw::unpack<forge::crypto::asymmetric::signature>(forge::raw::pack(expected.signature));
      const auto response = forge::raw::unpack<crypto_signer::response>(forge::raw::pack(expected));

      BOOST_CHECK(public_key == expected.public_key);
      BOOST_CHECK(signature == expected.signature);
      BOOST_TEST(response.key_id == expected.key_id);
      BOOST_CHECK(response.public_key == expected.public_key);
      BOOST_CHECK(response.signature == expected.signature);
   };

   const auto p256 =
       forge::asio::blocking::run(runtime, api->sign(crypto_signer::request{
                                               .key_id = "p256",
                                               .purpose = "api.auth",
                                               .digest = digest,
                                               .required_algorithm = forge::crypto::asymmetric::algorithm::p256,
                                           }));
   BOOST_CHECK(p256.public_key == p256_key.get_public_key());
   const auto p256_recovered = forge::crypto::asymmetric::recover(p256.signature, digest, true);
   BOOST_CHECK(p256_recovered == p256.public_key);
   check_raw_roundtrip(p256);

   const auto ed25519 =
       forge::asio::blocking::run(runtime, api->sign(crypto_signer::request{
                                               .key_id = "ed25519",
                                               .purpose = "api.auth",
                                               .digest = digest,
                                               .required_algorithm = forge::crypto::asymmetric::algorithm::ed25519,
                                           }));
   BOOST_CHECK(ed25519.public_key == ed25519_key.get_public_key());
   BOOST_TEST(forge::crypto::asymmetric::verify(ed25519.public_key, digest.to_uint8_span(), ed25519.signature));
   check_raw_roundtrip(ed25519);

   const auto rsa =
       forge::asio::blocking::run(runtime, api->sign(crypto_signer::request{
                                               .key_id = "rsa",
                                               .purpose = "api.auth",
                                               .digest = digest,
                                               .required_algorithm = forge::crypto::asymmetric::algorithm::rsa,
                                           }));
   BOOST_CHECK(rsa.public_key == rsa_key.get_public_key());
   BOOST_TEST(forge::crypto::asymmetric::verify(rsa.public_key, digest.to_uint8_span(), rsa.signature));
   check_raw_roundtrip(rsa);
}

BOOST_AUTO_TEST_CASE(crypto_signer_supports_custom_input_profile) {
   const auto key =
       forge::crypto::asymmetric::private_key::generate<forge::crypto::asymmetric::secp256k1::private_key>();
   auto profile = forge::crypto::asymmetric::profiles::forge();
   profile.id = "custom-input";
   const auto encoding = forge::crypto::asymmetric::encoding::from_profile(profile);
   auto plugin = crypto_signer::plugin{crypto_signer::plugin_options{.profiles = {profile}}};
   auto document = signer_config({key_entry("provider", encoding.format(key), "custom-input", {"api.auth"})});

   auto runtime = forge::asio::runtime{};
   forge::asio::blocking::run(runtime,
                              plugin.configure(forge::config::core::component_view{document, "plugins.crypto.signer"}));
   auto apis = forge::api::core::registry{};
   auto provider = forge::api::core::installer{apis};
   forge::asio::blocking::run(runtime, plugin.provide(provider));

   const auto result = forge::asio::blocking::run(
       runtime, apis.get<crypto_signer::api>(crypto_signer::api::ref())
                    ->sign("provider", "api.auth", forge::crypto::digest::sha256::hash(std::string{"payload"})));
   BOOST_CHECK(result.public_key == key.get_public_key());
}

BOOST_AUTO_TEST_CASE(crypto_signer_enforces_allowed_purpose_and_algorithm) {
   const auto key =
       forge::crypto::asymmetric::private_key::generate<forge::crypto::asymmetric::secp256k1::private_key>();
   auto plugin = crypto_signer::plugin{};
   auto document = signer_config(
       {key_entry("provider", forge::crypto::asymmetric::encoding::forge().format(key), "forge", {"storage.receipt"})});

   auto runtime = forge::asio::runtime{};
   forge::asio::blocking::run(runtime,
                              plugin.configure(forge::config::core::component_view{document, "plugins.crypto.signer"}));

   auto apis = forge::api::core::registry{};
   auto provider = forge::api::core::installer{apis};
   forge::asio::blocking::run(runtime, plugin.provide(provider));
   auto api = apis.get<crypto_signer::api>(crypto_signer::api::ref());
   const auto digest = forge::crypto::digest::sha256::hash(std::string{"receipt-payload"});

   BOOST_CHECK_THROW(forge::asio::blocking::run(runtime, api->sign(crypto_signer::request{
                                                             .key_id = "missing",
                                                             .purpose = "storage.receipt",
                                                             .digest = digest,
                                                         })),
                     crypto_signer::exceptions::key_not_found);

   BOOST_CHECK_THROW(forge::asio::blocking::run(runtime, api->sign(crypto_signer::request{
                                                             .key_id = "provider",
                                                             .purpose = "storage.audit",
                                                             .digest = digest,
                                                         })),
                     crypto_signer::exceptions::purpose_denied);

   BOOST_CHECK_THROW(
       forge::asio::blocking::run(runtime, api->sign(crypto_signer::request{
                                               .key_id = "provider",
                                               .purpose = "storage.receipt",
                                               .digest = digest,
                                               .required_algorithm = forge::crypto::asymmetric::algorithm::ed25519,
                                           })),
       crypto_signer::exceptions::unsupported_algorithm);

   auto unsupported = crypto_signer::plugin{};
   auto unsupported_document = signer_config(
       {key_entry("provider", forge::crypto::asymmetric::encoding::forge().format(key), "missing", {"api.auth"})});
   BOOST_CHECK_THROW(forge::asio::blocking::run(runtime, unsupported.configure(forge::config::core::component_view{
                                                             unsupported_document, "plugins.crypto.signer"})),
                     crypto_signer::exceptions::unsupported_profile);
}

BOOST_AUTO_TEST_CASE(p2p_node_plugin_config_is_described_from_public_schema) {
   auto plugin = forge::plugins::p2p::node::plugin{};
   const auto descriptor = plugin.describe_config();
   BOOST_REQUIRE(descriptor.has_value());
   BOOST_TEST(descriptor->section == "plugins.p2p.node");

   const auto& listen = require_field(*descriptor, "listen");
   BOOST_TEST(static_cast<int>(listen.kind) == static_cast<int>(forge::schema::value_kind::string_list));
   BOOST_TEST(listen.has_default);

   const auto& bootstrap = require_field(*descriptor, "bootstrap");
   BOOST_TEST(static_cast<int>(bootstrap.kind) == static_cast<int>(forge::schema::value_kind::string_list));
   BOOST_TEST(bootstrap.has_default);

   const auto& bootstrap_requirement = require_field(*descriptor, "bootstrap-requirement");
   BOOST_TEST(bootstrap_requirement.has_default);
   BOOST_TEST(std::get<std::string>(bootstrap_requirement.default_value.storage) == "allow-disconnected");

   const auto& bootstrap_startup_budget = require_field(*descriptor, "bootstrap-startup-budget-ms");
   BOOST_TEST(bootstrap_startup_budget.has_default);
   BOOST_TEST(std::get<std::uint64_t>(bootstrap_startup_budget.default_value.storage) == 10'000U);

   const auto& bootstrap_connect_timeout = require_field(*descriptor, "bootstrap-connect-timeout-ms");
   BOOST_TEST(bootstrap_connect_timeout.has_default);
   BOOST_TEST(std::get<std::uint64_t>(bootstrap_connect_timeout.default_value.storage) == 2'000U);

   const auto& bootstrap_parallelism = require_field(*descriptor, "bootstrap-max-parallel");
   BOOST_TEST(bootstrap_parallelism.has_default);
   BOOST_TEST(std::get<std::uint64_t>(bootstrap_parallelism.default_value.storage) == 4U);

   const auto& peer_store = require_field(*descriptor, "peer-store.store");
   BOOST_TEST(peer_store.has_default);
   BOOST_TEST(std::get<std::string>(peer_store.default_value.storage).empty());

   const auto& schema_policy = require_field(*descriptor, "peer-store.schema-policy");
   BOOST_TEST(schema_policy.has_default);
   BOOST_TEST(std::get<std::string>(schema_policy.default_value.storage) == "reset");

   const auto& dht_profiles = require_field(*descriptor, "dht.profiles");
   BOOST_TEST(static_cast<int>(dht_profiles.kind) == static_cast<int>(forge::schema::value_kind::object_list));
   BOOST_TEST(dht_profiles.has_default);

   const auto& topology_mode = require_field(*descriptor, "topology.mode");
   BOOST_TEST(topology_mode.has_default);
   BOOST_TEST(std::get<std::string>(topology_mode.default_value.storage) == "managed");
   BOOST_TEST(std::get<std::uint64_t>(require_field(*descriptor, "topology.peers.low").default_value.storage) == 128U);
   BOOST_TEST(std::get<std::uint64_t>(require_field(*descriptor, "topology.peers.target").default_value.storage) ==
              160U);
   BOOST_TEST(std::get<std::uint64_t>(require_field(*descriptor, "topology.peers.high").default_value.storage) == 192U);
   BOOST_TEST(
       std::get<std::uint64_t>(require_field(*descriptor, "topology.max-parallel-dials").default_value.storage) == 4U);

   const auto& rendezvous_role = require_field(*descriptor, "rendezvous.role");
   BOOST_TEST(rendezvous_role.has_default);
   BOOST_TEST(std::get<std::string>(rendezvous_role.default_value.storage) == "disabled");
   BOOST_TEST(static_cast<int>(require_field(*descriptor, "rendezvous.points").kind) ==
              static_cast<int>(forge::schema::value_kind::object_list));
   BOOST_TEST(std::get<bool>(require_field(*descriptor, "peer-exchange.enabled").default_value.storage));
   BOOST_TEST(std::get<std::uint64_t>(require_field(*descriptor, "peer-exchange.max-peers").default_value.storage) ==
              4U);

   const auto& certificate_secret = require_field(*descriptor, "identity.certificate-secret");
   BOOST_TEST(certificate_secret.has_default);
   BOOST_TEST(std::get<std::string>(certificate_secret.default_value.storage).empty());

   const auto& private_key_secret = require_field(*descriptor, "identity.private-key-secret");
   BOOST_TEST(private_key_secret.has_default);
   BOOST_TEST(std::get<std::string>(private_key_secret.default_value.storage).empty());
   BOOST_TEST(!has_field(*descriptor, "certificate-pem"));
   BOOST_TEST(!has_field(*descriptor, "private-key-pem"));

   const auto& max_inflight = require_field(*descriptor, "max-inflight-per-peer");
   BOOST_TEST(max_inflight.has_default);
   BOOST_TEST(std::get<std::uint64_t>(max_inflight.default_value.storage) == 64U);

   const auto& api_deadline = require_field(*descriptor, "api.deadline-ms");
   BOOST_TEST(api_deadline.has_default);
   BOOST_TEST(std::get<std::uint64_t>(api_deadline.default_value.storage) == 0U);

   const auto& api_frame_size = require_field(*descriptor, "api.max-frame-size");
   BOOST_TEST(api_frame_size.has_default);
   BOOST_TEST(std::get<std::uint64_t>(api_frame_size.default_value.storage) == 16U * 1024U * 1024U);

   const auto& insecure = require_field(*descriptor, "allow-insecure-test-mode");
   BOOST_TEST(insecure.has_default);
   BOOST_TEST(!std::get<bool>(insecure.default_value.storage));

   const auto& path_policy = require_field(*descriptor, "path.policy");
   BOOST_TEST(path_policy.has_default);
   BOOST_TEST(std::get<std::string>(path_policy.default_value.storage) == "direct-preferred");

   const auto& relay_trust = require_field(*descriptor, "relay.trust");
   BOOST_TEST(relay_trust.has_default);
   BOOST_TEST(std::get<std::string>(relay_trust.default_value.storage) == "known-only");

   BOOST_TEST(!has_field(*descriptor, "retry.max-attempts"));
   BOOST_TEST(!has_field(*descriptor, "retry.deadline-ms"));
   BOOST_TEST(!has_field(*descriptor, "maintenance.peer-exchange-interval-ms"));
}

BOOST_AUTO_TEST_CASE(p2p_node_plugin_publishes_safe_local_api_for_route_contributions) {
   auto log = plugin_log{};
   auto app = p2p_plugin_application{log};

   app.configure(test_p2p_config(test_peer(18)));
   forge::asio::blocking::run(app.runtime(), app.startup());

   BOOST_TEST(app.apis().describe({.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0}) != nullptr);
   BOOST_TEST(log.entries == (std::vector<std::string>{"routes.published", "routes.startup"}),
              boost::test_tools::per_element());

   forge::asio::blocking::run(app.runtime(), app.shutdown());
   BOOST_TEST(log.entries == (std::vector<std::string>{"routes.published", "routes.startup", "routes.shutdown"}),
              boost::test_tools::per_element());
}

BOOST_AUTO_TEST_CASE(p2p_node_plugin_rejects_duplicate_protocol_contributions_before_startup) {
   auto app = duplicate_p2p_plugin_application{};

   app.configure(test_p2p_config(test_peer(19)));
   BOOST_CHECK_THROW(forge::asio::blocking::run(app.runtime(), app.initialize()),
                     forge::plugins::p2p::node::exceptions::route_conflict);
}

BOOST_AUTO_TEST_CASE(p2p_node_api_rejects_facade_calls_before_initialize) {
   auto runtime = forge::asio::runtime{};
   auto plugin = forge::plugins::p2p::node::plugin{};
   auto apis = forge::api::core::registry{};
   auto provider = forge::api::core::installer{apis};
   forge::asio::blocking::run(runtime, plugin.provide(provider));

   auto p2p =
       apis.get<forge::plugins::p2p::node::api>({.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});

   BOOST_CHECK_THROW((void)p2p->local_peer(), forge::plugins::p2p::node::exceptions::plugin_not_initialized);
   BOOST_CHECK_THROW((void)p2p->local_endpoint(), forge::plugins::p2p::node::exceptions::plugin_not_initialized);
   BOOST_CHECK_THROW((void)p2p->local_endpoints(), forge::plugins::p2p::node::exceptions::plugin_not_initialized);
   BOOST_CHECK_THROW((void)p2p->network_info(), forge::plugins::p2p::node::exceptions::plugin_not_initialized);
   BOOST_CHECK_THROW(forge::asio::blocking::run(
                         runtime, p2p->remote<node_test_api>(
                                      test_peer(10), forge::net::p2p::protocol_id{.value = "/forge/api/node-test/1"})),
                     forge::plugins::p2p::node::exceptions::plugin_not_initialized);
}

BOOST_AUTO_TEST_CASE(p2p_node_plugin_listens_from_config_and_exposes_local_endpoints) {
   const auto local_peer = test_peer(20);
   auto config = test_p2p_config(local_peer);
   config.set("plugins.p2p.node.listen",
              forge::config::core::value::array_type{forge::config::core::value{"/ip4/127.0.0.1/udp/0/quic-v1"},
                                                     forge::config::core::value{"/ip4/127.0.0.1/tcp/0"}});

   auto app = p2p_only_application{};
   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.startup());

   const auto p2p = app.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   const auto endpoint = p2p->local_endpoint();
   BOOST_REQUIRE(endpoint.has_value());
   BOOST_CHECK_EQUAL(endpoint->transport.host, "127.0.0.1");
   BOOST_CHECK_NE(endpoint->transport.port, 0);
   BOOST_TEST(endpoint->peer->to_string() == local_peer.to_string());

   const auto endpoints = p2p->local_endpoints();
   BOOST_REQUIRE_EQUAL(endpoints.size(), 2U);
   BOOST_TEST(endpoints[0].peer->to_string() == local_peer.to_string());
   BOOST_TEST(endpoints[1].peer->to_string() == local_peer.to_string());

   const auto info = p2p->network_info();
   BOOST_TEST(info.local_peer.to_string() == local_peer.to_string());
   BOOST_TEST(info.started);
   BOOST_TEST(info.local_endpoints.size() == endpoints.size());

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_node_plugin_without_peer_id_does_not_inject_test_peer) {
   auto config = forge::config::core::document{};
   config.set("plugins.p2p.node.allow-insecure-test-mode", true);
   config.set("plugins.p2p.node.listen",
              forge::config::core::value::array_type{forge::config::core::value{"/ip4/127.0.0.1/tcp/0"}});

   auto app = p2p_only_application{};
   app.configure(config);
   BOOST_CHECK_THROW(forge::asio::blocking::run(app.runtime(), app.startup()),
                     forge::net::p2p::exceptions::invalid_options);
}

BOOST_AUTO_TEST_CASE(p2p_node_plugin_opens_remote_api_over_p2p_stream) {
   const auto server_peer = test_peer(30);
   auto server_config = test_p2p_config(server_peer);
   server_config.set("plugins.p2p.node.listen", forge::config::core::value::array_type{
                                                    forge::config::core::value{"/ip4/127.0.0.1/udp/0/quic-v1"}});

   auto log = plugin_log{};
   auto server = p2p_plugin_application{log};
   server.configure(server_config);
   forge::asio::blocking::run(server.runtime(), server.startup());

   auto server_p2p = server.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   const auto server_endpoint = server_p2p->local_endpoint();
   BOOST_REQUIRE(server_endpoint.has_value());

   const auto client_peer = test_peer(31);
   auto client_config = test_p2p_config(client_peer);
   client_config.set("plugins.p2p.node.bootstrap",
                     forge::config::core::value::array_type{forge::config::core::value{server_endpoint->to_string()}});

   auto client = p2p_only_application{};
   client.configure(client_config);
   forge::asio::blocking::run(client.runtime(), client.startup());

   auto client_p2p = client.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   auto remote = forge::asio::blocking::run(
       client.runtime(),
       client_p2p->remote<node_test_api>(server_p2p->local_peer(),
                                         forge::net::p2p::protocol_id{.value = "/forge/api/node-test/1"}));
   const auto response = forge::asio::blocking::run(client.runtime(), remote->ping(41));
   BOOST_TEST(response == 42);

   forge::asio::blocking::run(client.runtime(), client.shutdown());
   forge::asio::blocking::run(server.runtime(), server.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_typed_trusted_invocation_replaces_spoofed_peer_context) {
   auto runtime = forge::asio::runtime{};
   auto registry = forge::api::core::registry{};
   registry.install<peer_context_test_api>(peer_context_test_api::describe(),
                                           std::make_shared<peer_context_test_api_impl>());

   const auto authenticated = test_peer(232);
   const auto spoofed = test_peer(233);
   auto request = forge::api::core::frame{
       .kind = forge::api::core::frame_kind::request,
       .id = {.value = 901},
       .api = peer_context_test_api::ref(),
       .method = "remote_peer",
       .meta = {{
           .key = std::string{forge::api::core::p2p_remote_peer_metadata_key},
           .value = spoofed.to_string(),
       }},
       .codec = {.value = "forge.raw"},
       .payload = forge::api::core::pack_body(peer_context_request{
           .value = "probe",
           .caller = {.id = spoofed},
       }),
   };
   const auto trusted = forge::api::core::trusted_invocation_builder{}
                            .set(forge::api::p2p::authenticated_peer{.id = authenticated})
                            .build();

   const auto response = forge::asio::blocking::run(runtime, registry.dispatch_contextual(std::move(request), trusted));

   BOOST_REQUIRE(response.kind == forge::api::core::frame_kind::response);
   BOOST_TEST(forge::api::core::unpack_body<std::string>(response.payload) == authenticated.to_string() + ":probe");
   BOOST_TEST(forge::api::core::unpack_body<std::string>(response.payload) != spoofed.to_string() + ":probe");
}

BOOST_AUTO_TEST_CASE(p2p_publication_is_move_only_and_joins_concurrent_closers) {
   auto runtime = forge::asio::runtime{};

   auto destructor_closes = std::atomic_size_t{0};
   {
      auto publication = forge::api::p2p::detail::publication_access::make(
          runtime.context().get_executor(),
          [&destructor_closes] { destructor_closes.fetch_add(1, std::memory_order_relaxed); },
          []() -> boost::asio::awaitable<void> { co_return; }, [] { return true; });
      BOOST_TEST(publication.active());
   }
   BOOST_TEST(destructor_closes.load(std::memory_order_relaxed) == 1U);

   auto active_closes = std::atomic_size_t{0};
   auto active_owner = std::unique_ptr<forge::api::p2p::publication>{};
   active_owner = std::make_unique<forge::api::p2p::publication>(forge::api::p2p::detail::publication_access::make(
       runtime.context().get_executor(), [&active_closes] { active_closes.fetch_add(1, std::memory_order_relaxed); },
       []() -> boost::asio::awaitable<void> { co_return; },
       [&active_owner] {
          active_owner.reset();
          return true;
       }));
   BOOST_CHECK_NO_THROW(static_cast<void>(active_owner->active()));
   BOOST_TEST(!active_owner);
   BOOST_TEST(active_closes.load(std::memory_order_relaxed) == 1U);

   auto close_closes = std::atomic_size_t{0};
   auto close_owner = std::unique_ptr<forge::api::p2p::publication>{};
   close_owner = std::make_unique<forge::api::p2p::publication>(forge::api::p2p::detail::publication_access::make(
       runtime.context().get_executor(),
       [&close_closes, &close_owner] {
          close_closes.fetch_add(1, std::memory_order_relaxed);
          close_owner.reset();
       },
       []() -> boost::asio::awaitable<void> { co_return; }, [] { return true; }));
   BOOST_CHECK_NO_THROW(close_owner->close());
   BOOST_TEST(!close_owner);
   BOOST_TEST(close_closes.load(std::memory_order_relaxed) == 1U);

   struct close_state {
      std::atomic_size_t close_calls{0};
      std::atomic_size_t drain_calls{0};
      forge::asio::notification drain_entered;
      forge::asio::notification release_drain;
   };

   auto state = std::make_shared<close_state>();
   auto publication = forge::api::p2p::detail::publication_access::make(
       runtime.context().get_executor(), [state] { state->close_calls.fetch_add(1, std::memory_order_relaxed); },
       [state]() -> boost::asio::awaitable<void> {
          const auto release_epoch = state->release_drain.epoch();
          state->drain_calls.fetch_add(1, std::memory_order_relaxed);
          state->drain_entered.notify();
          co_await state->release_drain.async_wait(release_epoch);
       },
       [] { return true; });

   auto moved = std::move(publication);
   BOOST_TEST(!publication.active());
   BOOST_TEST(moved.active());
   moved.close();
   moved.close();
   BOOST_TEST(!moved.active());

   const auto drain_entered_epoch = state->drain_entered.epoch();
   auto first = boost::asio::co_spawn(runtime.context(), moved.async_close(), boost::asio::use_future);
   auto second = boost::asio::co_spawn(runtime.context(), moved.async_close(), boost::asio::use_future);
   auto third = boost::asio::co_spawn(runtime.context(), moved.async_close(), boost::asio::use_future);
   auto drain_entered =
       boost::asio::co_spawn(runtime.context(),
                             state->drain_entered.async_wait_until(
                                 drain_entered_epoch, std::chrono::steady_clock::now() + std::chrono::seconds{2}),
                             boost::asio::use_future);
   BOOST_REQUIRE(drain_entered.wait_for(std::chrono::seconds{3}) == std::future_status::ready);
   BOOST_REQUIRE(drain_entered.get() != drain_entered_epoch);
   BOOST_TEST(state->close_calls.load(std::memory_order_relaxed) == 1U);
   state->release_drain.notify();
   BOOST_REQUIRE(first.wait_for(std::chrono::seconds{2}) == std::future_status::ready);
   BOOST_REQUIRE(second.wait_for(std::chrono::seconds{2}) == std::future_status::ready);
   BOOST_REQUIRE(third.wait_for(std::chrono::seconds{2}) == std::future_status::ready);
   BOOST_CHECK_NO_THROW(first.get());
   BOOST_CHECK_NO_THROW(second.get());
   BOOST_CHECK_NO_THROW(third.get());
   BOOST_TEST(state->drain_calls.load(std::memory_order_relaxed) == 1U);
}

BOOST_AUTO_TEST_CASE(p2p_publication_move_assignment_transfers_new_owner_before_reentrant_old_close) {
   auto runtime = forge::asio::runtime{};
   auto old_close_calls = std::atomic_size_t{0};
   auto new_close_calls = std::atomic_size_t{0};
   auto owner = std::unique_ptr<forge::api::p2p::publication>{};

   auto replacement = forge::api::p2p::detail::publication_access::make(
       runtime.context().get_executor(),
       [&new_close_calls] { new_close_calls.fetch_add(1, std::memory_order_relaxed); },
       []() -> boost::asio::awaitable<void> { co_return; }, [] { return true; });
   owner = std::make_unique<forge::api::p2p::publication>(forge::api::p2p::detail::publication_access::make(
       runtime.context().get_executor(),
       [&old_close_calls, &owner] {
          old_close_calls.fetch_add(1, std::memory_order_relaxed);
          owner.reset();
       },
       []() -> boost::asio::awaitable<void> { co_return; }, [] { return true; }));

   BOOST_CHECK_NO_THROW(static_cast<void>(*owner = std::move(replacement)));
   BOOST_TEST(!owner);
   BOOST_TEST(old_close_calls.load(std::memory_order_relaxed) == 1U);
   BOOST_TEST(new_close_calls.load(std::memory_order_relaxed) == 1U);
}

BOOST_AUTO_TEST_CASE(p2p_publication_drain_uses_its_owner_runtime_after_first_caller_stops) {
   auto owner_runtime = forge::asio::runtime{forge::asio::runtime_options{.worker_threads = 1}};
   auto first_caller_runtime = forge::asio::runtime{forge::asio::runtime_options{.worker_threads = 1}};
   auto late_caller_runtime = forge::asio::runtime{forge::asio::runtime_options{.worker_threads = 1}};

   struct drain_state {
      std::atomic_size_t close_calls{0};
      std::atomic_size_t drain_calls{0};
      forge::asio::notification drain_entered;
      forge::asio::notification release_drain;
      forge::asio::notification drain_completed;
   };

   auto state = std::make_shared<drain_state>();
   auto publication = forge::api::p2p::detail::publication_access::make(
       owner_runtime.context().get_executor(), [state] { state->close_calls.fetch_add(1, std::memory_order_relaxed); },
       [state]() -> boost::asio::awaitable<void> {
          const auto release_epoch = state->release_drain.epoch();
          state->drain_calls.fetch_add(1, std::memory_order_relaxed);
          state->drain_entered.notify();
          co_await state->release_drain.async_wait(release_epoch);
          state->drain_completed.notify();
       },
       [] { return true; });

   const auto drain_entered_epoch = state->drain_entered.epoch();
   auto first =
       boost::asio::co_spawn(first_caller_runtime.context(), publication.async_close(), boost::asio::use_future);
   auto drain_entered =
       boost::asio::co_spawn(owner_runtime.context(),
                             state->drain_entered.async_wait_until(
                                 drain_entered_epoch, std::chrono::steady_clock::now() + std::chrono::seconds{2}),
                             boost::asio::use_future);
   BOOST_REQUIRE(drain_entered.wait_for(std::chrono::seconds{3}) == std::future_status::ready);
   BOOST_REQUIRE(drain_entered.get() != drain_entered_epoch);

   first_caller_runtime.stop();
   BOOST_CHECK(first.wait_for(std::chrono::milliseconds{50}) != std::future_status::ready);
   const auto drain_completed_epoch = state->drain_completed.epoch();
   state->release_drain.notify();
   auto drain_completed =
       boost::asio::co_spawn(owner_runtime.context(),
                             state->drain_completed.async_wait_until(
                                 drain_completed_epoch, std::chrono::steady_clock::now() + std::chrono::seconds{2}),
                             boost::asio::use_future);
   BOOST_REQUIRE(drain_completed.wait_for(std::chrono::seconds{3}) == std::future_status::ready);
   BOOST_REQUIRE(drain_completed.get() != drain_completed_epoch);

   auto late = boost::asio::co_spawn(late_caller_runtime.context(), publication.async_close(), boost::asio::use_future);
   BOOST_REQUIRE(late.wait_for(std::chrono::seconds{2}) == std::future_status::ready);
   BOOST_CHECK_NO_THROW(late.get());
   BOOST_TEST(state->close_calls.load(std::memory_order_relaxed) == 1U);
   BOOST_TEST(state->drain_calls.load(std::memory_order_relaxed) == 1U);

   BOOST_CHECK_THROW(static_cast<void>(forge::api::p2p::detail::publication_access::make(
                         boost::asio::any_io_executor{}, [] {}, []() -> boost::asio::awaitable<void> { co_return; },
                         [] { return true; })),
                     forge::api::core::exceptions::protocol_error);
}

BOOST_AUTO_TEST_CASE(p2p_node_publication_closed_before_startup_does_not_reserve_route) {
   const auto server_peer = test_peer(234);
   auto config = test_p2p_config(server_peer);
   config.set("plugins.p2p.node.listen",
              forge::config::core::value::array_type{forge::config::core::value{"/ip4/127.0.0.1/udp/0/quic-v1"}});
   auto server = p2p_only_application{};
   server.configure(config);
   forge::asio::blocking::run(server.runtime(), server.initialize());

   auto server_p2p = server.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   auto staged_apis = forge::api::core::registry{};
   staged_apis.install<node_test_api>(node_test_api::describe(), std::make_shared<node_test_api_impl>());
   const auto protocol = forge::net::p2p::protocol_id{.value = "/forge/api/publication-before-startup/1"};
   auto closed = server_p2p->publish_api(node_test_plan(staged_apis), protocol);
   BOOST_TEST(closed.active());
   closed.close();
   BOOST_TEST(!closed.active());

   forge::asio::blocking::run(server.runtime(), server.startup());
   auto active = server_p2p->publish_api(node_test_plan(staged_apis), protocol);
   BOOST_TEST(active.active());
   const auto endpoint = server_p2p->local_endpoint();
   BOOST_REQUIRE(endpoint.has_value());

   auto client_config = test_p2p_config(test_peer(235));
   client_config.set("plugins.p2p.node.bootstrap",
                     forge::config::core::value::array_type{forge::config::core::value{endpoint->to_string()}});
   auto client = p2p_only_application{};
   client.configure(client_config);
   forge::asio::blocking::run(client.runtime(), client.startup());
   auto client_p2p = client.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   auto remote = forge::asio::blocking::run(client.runtime(), client_p2p->remote<node_test_api>(server_peer, protocol));
   BOOST_TEST(forge::asio::blocking::run(client.runtime(), remote->ping(41)) == 42);

   forge::asio::blocking::run(client.runtime(), client.shutdown());
   forge::asio::blocking::run(server.runtime(), active.async_close());
   forge::asio::blocking::run(server.runtime(), server.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_node_publication_replacement_keeps_latest_generation) {
   const auto server_peer = test_peer(236);
   auto server_config = test_p2p_config(server_peer);
   server_config.set("plugins.p2p.node.listen", forge::config::core::value::array_type{
                                                    forge::config::core::value{"/ip4/127.0.0.1/udp/0/quic-v1"}});
   auto server = p2p_only_application{};
   server.configure(server_config);
   forge::asio::blocking::run(server.runtime(), server.startup());
   auto server_p2p = server.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   const auto endpoint = server_p2p->local_endpoint();
   BOOST_REQUIRE(endpoint.has_value());

   auto client_config = test_p2p_config(test_peer(237));
   client_config.set("plugins.p2p.node.bootstrap",
                     forge::config::core::value::array_type{forge::config::core::value{endpoint->to_string()}});
   auto client = p2p_only_application{};
   client.configure(client_config);
   forge::asio::blocking::run(client.runtime(), client.startup());
   auto client_p2p = client.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});

   auto first_apis = forge::api::core::registry{};
   first_apis.install<node_test_api>(node_test_api::describe(), std::make_shared<offset_node_test_api_impl>(1));
   auto second_apis = forge::api::core::registry{};
   second_apis.install<node_test_api>(node_test_api::describe(), std::make_shared<offset_node_test_api_impl>(100));
   const auto protocol = forge::net::p2p::protocol_id{.value = "/forge/api/publication-replacement/1"};
   auto first = server_p2p->publish_api(node_test_plan(first_apis), protocol);
   {
      auto remote =
          forge::asio::blocking::run(client.runtime(), client_p2p->remote<node_test_api>(server_peer, protocol));
      BOOST_TEST(forge::asio::blocking::run(client.runtime(), remote->ping(41)) == 42);
   }

   auto second = server_p2p->publish_api(node_test_plan(second_apis), protocol);
   BOOST_TEST(!first.active());
   BOOST_TEST(second.active());
   first.close();
   BOOST_TEST(second.active());
   {
      auto remote =
          forge::asio::blocking::run(client.runtime(), client_p2p->remote<node_test_api>(server_peer, protocol));
      BOOST_TEST(forge::asio::blocking::run(client.runtime(), remote->ping(41)) == 141);
   }

   forge::asio::blocking::run(client.runtime(), client.shutdown());
   forge::asio::blocking::run(server.runtime(), second.async_close());
   forge::asio::blocking::run(server.runtime(), server.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_node_publication_async_close_cancels_admitted_session) {
   const auto server_peer = test_peer(238);
   auto server_config = test_p2p_config(server_peer);
   server_config.set("plugins.p2p.node.listen", forge::config::core::value::array_type{
                                                    forge::config::core::value{"/ip4/127.0.0.1/udp/0/quic-v1"}});
   auto server = p2p_only_application{};
   server.configure(server_config);
   forge::asio::blocking::run(server.runtime(), server.startup());
   auto server_p2p = server.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   const auto endpoint = server_p2p->local_endpoint();
   BOOST_REQUIRE(endpoint.has_value());

   auto handler_state = std::make_shared<nonresponding_node_test_state>();
   auto apis = forge::api::core::registry{};
   apis.install<node_test_api>(node_test_api::describe(),
                               std::make_shared<nonresponding_node_test_api_impl>(handler_state));
   const auto protocol = forge::net::p2p::protocol_id{.value = "/forge/api/publication-drain/1"};
   auto publication = server_p2p->publish_api(node_test_plan(apis), protocol);

   auto client_config = test_p2p_config(test_peer(239));
   client_config.set("plugins.p2p.node.bootstrap",
                     forge::config::core::value::array_type{forge::config::core::value{endpoint->to_string()}});
   auto client = p2p_only_application{};
   client.configure(client_config);
   forge::asio::blocking::run(client.runtime(), client.startup());
   auto client_p2p = client.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   auto remote = forge::asio::blocking::run(client.runtime(), client_p2p->remote<node_test_api>(server_peer, protocol));
   auto call = boost::asio::co_spawn(client.runtime().context(), remote->ping(41), boost::asio::use_future);
   BOOST_REQUIRE(forge::asio::blocking::run(
       server.runtime(),
       async_wait_for_condition([&] { return handler_state->started.load(std::memory_order_acquire); },
                                std::chrono::seconds{2})));

   publication.close();
   BOOST_TEST(!publication.active());
   auto drained = boost::asio::co_spawn(server.runtime().context(), publication.async_close(), boost::asio::use_future);
   BOOST_REQUIRE(drained.wait_for(std::chrono::seconds{2}) == std::future_status::ready);
   BOOST_CHECK_NO_THROW(drained.get());
   BOOST_REQUIRE(forge::asio::blocking::run(
       server.runtime(),
       async_wait_for_condition([&] { return handler_state->cancelled.load(std::memory_order_acquire); },
                                std::chrono::seconds{2})));
   BOOST_REQUIRE(call.wait_for(std::chrono::seconds{2}) == std::future_status::ready);
   BOOST_CHECK_THROW(static_cast<void>(call.get()), std::exception);

   forge::asio::blocking::run(client.runtime(), client.shutdown());
   forge::asio::blocking::run(server.runtime(), server.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_resolver_publication_replacement_keeps_catalog_and_route_current) {
   const auto server_peer = test_peer(240);
   auto server_config = test_p2p_config(server_peer);
   server_config.set("plugins.p2p.node.listen", forge::config::core::value::array_type{
                                                    forge::config::core::value{"/ip4/127.0.0.1/udp/0/quic-v1"}});
   auto server = resolver_publication_application{};
   server.configure(server_config);
   forge::asio::blocking::run(server.runtime(), server.startup());
   auto resolver = server.apis().get<forge::plugins::p2p::resolver::api>(
       {.id = {"forge.plugins.p2p.resolver"}, .major = 2, .min_revision = 0});
   auto server_p2p = server.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   const auto endpoint = server_p2p->local_endpoint();
   BOOST_REQUIRE(endpoint.has_value());

   auto client_config = test_p2p_config(test_peer(241));
   client_config.set("plugins.p2p.node.bootstrap",
                     forge::config::core::value::array_type{forge::config::core::value{endpoint->to_string()}});
   auto client = p2p_only_application{};
   client.configure(client_config);
   forge::asio::blocking::run(client.runtime(), client.startup());
   auto client_p2p = client.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});

   const auto protocol = forge::net::p2p::protocol_id{.value = "/forge/api/resolver-publication/1"};
   auto first = resolver->publish_api(node_test_plan(server.apis()), protocol);
   const auto first_entries = resolver->local_apis();
   BOOST_REQUIRE_EQUAL(first_entries.size(), 1U);
   BOOST_TEST(first_entries.front().id.value == "node.test");
   {
      auto remote =
          forge::asio::blocking::run(client.runtime(), client_p2p->remote<node_test_api>(server_peer, protocol));
      BOOST_TEST(forge::asio::blocking::run(client.runtime(), remote->ping(41)) == 42);
   }

   auto second = resolver->publish_api(peer_context_test_plan(server.apis()), protocol);
   BOOST_TEST(!first.active());
   BOOST_TEST(second.active());
   const auto replacement_entries = resolver->local_apis();
   BOOST_REQUIRE_EQUAL(replacement_entries.size(), 1U);
   BOOST_TEST(replacement_entries.front().id.value == "peer-context.test");
   first.close();
   BOOST_TEST(second.active());
   BOOST_REQUIRE_EQUAL(resolver->local_apis().size(), 1U);
   {
      auto remote = forge::asio::blocking::run(client.runtime(),
                                               client_p2p->remote<peer_context_test_api>(server_peer, protocol));
      static_cast<void>(remote);
   }

   second.close();
   BOOST_TEST(resolver->local_apis().empty());
   forge::asio::blocking::run(server.runtime(), second.async_close());
   auto post_close_apis = forge::api::core::registry{};
   post_close_apis.install<node_test_api>(node_test_api::describe(), std::make_shared<node_test_api_impl>());
   auto post_close = server_p2p->publish_api(node_test_plan(post_close_apis), protocol);
   BOOST_TEST(post_close.active());

   forge::asio::blocking::run(client.runtime(), client.shutdown());
   forge::asio::blocking::run(server.runtime(), post_close.async_close());
   forge::asio::blocking::run(server.runtime(), server.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_resolver_repeated_publication_replacement_retires_before_shutdown) {
   auto server = resolver_publication_application{};
   server.configure(test_p2p_config(test_peer(243)));
   forge::asio::blocking::run(server.runtime(), server.startup());
   auto resolver = server.apis().get<forge::plugins::p2p::resolver::api>(
       {.id = {"forge.plugins.p2p.resolver"}, .major = 2, .min_revision = 0});

   const auto protocol = forge::net::p2p::protocol_id{.value = "/forge/api/resolver-replacement-bounded/1"};
   constexpr auto replacement_count = std::size_t{256};
   const auto before = server.scheduler().snapshot();
   auto publication = resolver->publish_api(node_test_plan(server.apis()), protocol);
   for (auto index = std::size_t{0}; index < replacement_count; ++index) {
      publication = resolver->publish_api(
          index % 2 == 0 ? peer_context_test_plan(server.apis()) : node_test_plan(server.apis()), protocol);
      BOOST_TEST(publication.active());
      BOOST_REQUIRE_EQUAL(resolver->local_apis().size(), 1U);
   }

   BOOST_REQUIRE(forge::asio::blocking::run(server.runtime(),
                                            async_wait_for_condition(
                                                [&] {
                                                   const auto metrics = server.scheduler().snapshot();
                                                   return metrics.submitted >= before.submitted + replacement_count &&
                                                          metrics.completed >= before.completed + replacement_count &&
                                                          metrics.pending == 0U && metrics.running_awaitable == 0U;
                                                },
                                                std::chrono::seconds{2})));

   publication.close();
   forge::asio::blocking::run(server.runtime(), publication.async_close());
   forge::asio::blocking::run(server.runtime(), server.shutdown());
   const auto after_shutdown = server.scheduler().snapshot();
   BOOST_TEST(after_shutdown.pending == 0U);
   BOOST_TEST(after_shutdown.running_awaitable == 0U);
}

BOOST_AUTO_TEST_CASE(p2p_resolver_rejected_retirement_drains_on_shutdown_without_poisoning_close) {
   auto barrier = std::make_shared<forge::tests::plugins::resolver_publish_barrier>();
   auto app = forge::tests::plugins::resolver_publication_race_application{barrier};
   forge::asio::blocking::run(app.runtime(), app.startup());
   auto resolver = app.apis().get<forge::plugins::p2p::resolver::api>(
       {.id = {"forge.plugins.p2p.resolver"}, .major = 2, .min_revision = 0});

   const auto protocol = std::string{"/forge/api/resolver-retirement-rejected/1"};
   auto publication =
       resolver->publish_api(node_test_plan(app.apis()), forge::net::p2p::protocol_id{.value = protocol});
   BOOST_TEST(publication.active());

   const auto before_rejection = app.scheduler().snapshot();
   app.scheduler().request_stop();
   publication.close();
   const auto after_rejection = app.scheduler().snapshot();

   BOOST_TEST(after_rejection.stopped);
   BOOST_TEST(after_rejection.rejected == before_rejection.rejected + 1U);
   BOOST_TEST(barrier->close_calls(protocol) == 1U);
   BOOST_TEST(barrier->drain_calls(protocol) == 0U);

   BOOST_CHECK_NO_THROW(forge::asio::blocking::run(app.runtime(), app.shutdown()));
   BOOST_TEST(barrier->drain_calls(protocol) == 1U);
   BOOST_CHECK_NO_THROW(forge::asio::blocking::run(app.runtime(), publication.async_close()));
   BOOST_TEST(barrier->drain_calls(protocol) == 1U);
}

BOOST_AUTO_TEST_CASE(p2p_resolver_canceled_accepted_retirement_falls_back_during_shutdown) {
   struct retirement_blocker_state {
      forge::asio::notification started;
      forge::asio::notification release;
   };

   auto barrier = std::make_shared<forge::tests::plugins::resolver_publish_barrier>();
   auto app = forge::tests::plugins::resolver_publication_race_application{
       barrier, forge::app::application_shell_options{
                    .runtime = forge::asio::runtime_options{.worker_threads = 2},
                    .scheduler =
                        forge::asio::task::scheduler::options{
                            .max_blocking_tasks = 1,
                            .max_awaitable_tasks = 1,
                            .max_pending_tasks = 4,
                        },
                }};
   forge::asio::blocking::run(app.runtime(), app.startup());
   auto resolver = app.apis().get<forge::plugins::p2p::resolver::api>(
       {.id = {"forge.plugins.p2p.resolver"}, .major = 2, .min_revision = 0});

   auto blocker_state = std::make_shared<retirement_blocker_state>();
   [[maybe_unused]] auto release_on_exit =
       boost::scope::scope_exit{[state = blocker_state] { state->release.notify(); }};
   const auto blocker_started_epoch = blocker_state->started.epoch();
   const auto release_epoch = blocker_state->release.epoch();
   auto blocker = app.scheduler().submit(forge::asio::task::awaitable{
       .priority = forge::asio::task::priority{100},
       .name = "resolver-retirement-blocker",
       .work = [state = blocker_state, release_epoch](forge::asio::task::context&) -> boost::asio::awaitable<void> {
          state->started.notify();
          co_await state->release.async_wait(release_epoch);
          co_return;
       },
   });
   BOOST_REQUIRE(blocker.accepted());
   auto blocker_entered =
       boost::asio::co_spawn(app.runtime().context(),
                             blocker_state->started.async_wait_until(
                                 blocker_started_epoch, std::chrono::steady_clock::now() + std::chrono::seconds{2}),
                             boost::asio::use_future);
   BOOST_REQUIRE(blocker_entered.wait_for(std::chrono::seconds{3}) == std::future_status::ready);
   BOOST_REQUIRE(blocker_entered.get() != blocker_started_epoch);

   const auto protocol = std::string{"/forge/api/resolver-retirement-canceled/1"};
   auto publication =
       resolver->publish_api(node_test_plan(app.apis()), forge::net::p2p::protocol_id{.value = protocol});
   publication.close();
   const auto queued = app.scheduler().snapshot();
   BOOST_TEST(queued.running_awaitable == 1U);
   BOOST_TEST(queued.pending == 1U);

   app.scheduler().request_stop();
   const auto canceled = app.scheduler().snapshot();
   BOOST_TEST(canceled.stopped);
   BOOST_TEST(canceled.pending == 0U);
   BOOST_TEST(canceled.canceled >= 1U);
   blocker_state->release.notify();
   BOOST_CHECK_NO_THROW(forge::asio::blocking::run(app.runtime(), blocker.wait()));

   BOOST_CHECK_NO_THROW(forge::asio::blocking::run(app.runtime(), app.shutdown()));
   BOOST_TEST(barrier->close_calls(protocol) == 1U);
   BOOST_TEST(barrier->drain_calls(protocol) == 1U);
}

BOOST_AUTO_TEST_CASE(p2p_resolver_rejected_retirement_backlog_fails_closed_before_new_child_publication) {
   auto barrier = std::make_shared<forge::tests::plugins::resolver_publish_barrier>();
   auto app = forge::tests::plugins::resolver_publication_race_application{barrier};
   auto config = forge::config::core::document{};
   config.set("plugins.p2p.resolver.max-apis-per-peer", std::uint64_t{2});
   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.startup());
   auto resolver = app.apis().get<forge::plugins::p2p::resolver::api>(
       {.id = {"forge.plugins.p2p.resolver"}, .major = 2, .min_revision = 0});

   const auto protocol = std::string{"/forge/api/resolver-retirement-backlog/1"};
   auto first = resolver->publish_api(node_test_plan(app.apis()), forge::net::p2p::protocol_id{.value = protocol});
   app.scheduler().request_stop();
   auto second =
       resolver->publish_api(peer_context_test_plan(app.apis()), forge::net::p2p::protocol_id{.value = protocol});
   auto third = resolver->publish_api(node_test_plan(app.apis()), forge::net::p2p::protocol_id{.value = protocol});

   BOOST_TEST(barrier->publish_calls(protocol) == 3U);
   BOOST_CHECK_THROW(static_cast<void>(resolver->publish_api(peer_context_test_plan(app.apis()),
                                                             forge::net::p2p::protocol_id{.value = protocol})),
                     forge::plugins::p2p::resolver::exceptions::protocol_error);
   BOOST_TEST(barrier->publish_calls(protocol) == 3U);
   BOOST_TEST(app.scheduler().snapshot().rejected == 2U);

   BOOST_CHECK_NO_THROW(forge::asio::blocking::run(app.runtime(), app.shutdown()));
   BOOST_TEST(barrier->close_calls(protocol) == 3U);
   BOOST_TEST(barrier->drain_calls(protocol) == 3U);
}

BOOST_AUTO_TEST_CASE(p2p_resolver_publish_racing_shutdown_returns_no_usable_publication) {
   auto barrier = std::make_shared<forge::tests::plugins::resolver_publish_barrier>();
   auto app = forge::tests::plugins::resolver_publication_race_application{barrier};
   forge::asio::blocking::run(app.runtime(), app.startup());
   auto resolver = app.apis().get<forge::plugins::p2p::resolver::api>(
       {.id = {"forge.plugins.p2p.resolver"}, .major = 2, .min_revision = 0});

   const auto race_protocol = std::string{"/forge/api/resolver-publish-race/1"};
   auto plan = node_test_plan(app.apis());
   auto failure = std::exception_ptr{};
   auto publication = std::optional<forge::api::p2p::publication>{};
   auto result_mutex = std::mutex{};
   barrier->arm();
   auto publisher = std::thread{[&] {
      try {
         auto published = resolver->publish_api(std::move(plan), forge::net::p2p::protocol_id{.value = race_protocol});
         const auto lock = std::scoped_lock{result_mutex};
         publication.emplace(std::move(published));
      } catch (...) {
         const auto lock = std::scoped_lock{result_mutex};
         failure = std::current_exception();
      }
   }};

   BOOST_REQUIRE(barrier->wait_until_entered(std::chrono::seconds{2}));
   app.request_stop();
   barrier->release();
   publisher.join();

   {
      const auto lock = std::scoped_lock{result_mutex};
      BOOST_TEST(!publication.has_value());
      BOOST_REQUIRE(failure);
      BOOST_CHECK_THROW(std::rethrow_exception(failure),
                        forge::plugins::p2p::resolver::exceptions::plugin_not_initialized);
   }
   BOOST_TEST(barrier->close_calls(race_protocol) == 1U);

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_publication_remains_safe_after_node_plugin_shutdown) {
   auto app = p2p_only_application{};
   app.configure(test_p2p_config(test_peer(242)));
   forge::asio::blocking::run(app.runtime(), app.startup());
   auto p2p = app.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   auto apis = forge::api::core::registry{};
   apis.install<node_test_api>(node_test_api::describe(), std::make_shared<node_test_api_impl>());
   auto publication = p2p->publish_api(node_test_plan(apis),
                                       forge::net::p2p::protocol_id{.value = "/forge/api/publication-shutdown/1"});
   BOOST_TEST(publication.active());

   forge::asio::blocking::run(app.runtime(), app.shutdown());
   BOOST_TEST(!publication.active());
   BOOST_CHECK_NO_THROW(forge::asio::blocking::run(app.runtime(), publication.async_close()));
   BOOST_CHECK_NO_THROW(forge::asio::blocking::run(app.runtime(), publication.async_close()));
}

BOOST_AUTO_TEST_CASE(p2p_node_plugin_rejects_invalid_typed_config_before_startup) {
   {
      auto config = test_p2p_config();
      config.set("plugins.p2p.node.max-inflight-per-peer", std::uint64_t{0});
      auto app = p2p_only_application{};
      BOOST_CHECK_THROW(app.configure(config), forge::plugins::p2p::node::exceptions::invalid_config);
   }

   {
      auto config = test_p2p_config();
      config.set("plugins.p2p.node.topology.peers.low", std::uint64_t{5});
      config.set("plugins.p2p.node.topology.peers.target", std::uint64_t{4});
      auto app = p2p_only_application{};
      BOOST_CHECK_THROW(app.configure(config), forge::plugins::p2p::node::exceptions::invalid_config);
   }

   {
      auto config = test_p2p_config();
      config.set("plugins.p2p.node.rendezvous.points",
                 forge::config::core::value::array_type{forge::config::core::value{rendezvous_point_config(
                     "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/" + test_peer(91).to_string(), {"forge.content"})}});
      auto app = p2p_only_application{};
      BOOST_CHECK_THROW(app.configure(config), forge::plugins::p2p::node::exceptions::invalid_config);
   }

   {
      auto config = test_p2p_config();
      config.set("plugins.p2p.node.rendezvous.role", std::string{"client"});
      config.set("plugins.p2p.node.rendezvous.points",
                 forge::config::core::value::array_type{forge::config::core::value{rendezvous_point_config(
                     "/ip4/127.0.0.1/udp/4001/quic-v1/p2p/" + test_peer(92).to_string(), {"forge.content"})}});
      auto app = p2p_only_application{};
      BOOST_CHECK_NO_THROW(app.configure(config));
   }

   {
      auto config = test_p2p_config();
      config.set("plugins.p2p.node.listen",
                 forge::config::core::value::array_type{forge::config::core::value{"127.0.0.1:0"}});
      auto app = p2p_only_application{};
      BOOST_CHECK_THROW(app.configure(config), forge::plugins::p2p::node::exceptions::invalid_config);
   }

   {
      auto config = test_p2p_config();
      config.set("plugins.p2p.node.api.max-frame-size", std::uint64_t{0});
      auto app = p2p_only_application{};
      BOOST_CHECK_THROW(app.configure(config), forge::plugins::p2p::node::exceptions::invalid_config);
   }

   {
      auto config = test_p2p_config();
      config.set("plugins.p2p.node.bootstrap", forge::config::core::value::array_type{
                                                   forge::config::core::value{"/ip4/127.0.0.1/tcp/1"},
                                               });
      auto app = p2p_only_application{};
      BOOST_CHECK_NO_THROW(app.configure(config));
   }

   {
      auto config = test_p2p_config();
      config.set("plugins.p2p.node.bootstrap-requirement", std::string{"always-online"});
      auto app = p2p_only_application{};
      BOOST_CHECK_THROW(app.configure(config), forge::plugins::p2p::node::exceptions::invalid_config);
   }

   {
      auto config = test_p2p_config();
      config.set("plugins.p2p.node.path.policy", std::string{"teleport"});
      auto app = p2p_only_application{};
      BOOST_CHECK_EXCEPTION(app.configure(config), forge::plugins::p2p::node::exceptions::invalid_config,
                            [](const auto& error) {
                               const auto text = std::string{error.what()};
                               return text.find("plugins.p2p.node.path.policy") != std::string::npos &&
                                      text.find("config.type") != std::string::npos;
                            });
   }

   {
      auto config = test_p2p_config();
      config.set("plugins.p2p.node.path.policy", std::string{"relay-only"});
      auto app = p2p_only_application{};
      BOOST_CHECK_NO_THROW(app.configure(config));
   }

   {
      auto config = test_p2p_config();
      config.set("plugins.p2p.node.relay.trust", std::string{"public-allowed"});
      auto app = p2p_only_application{};
      BOOST_CHECK_NO_THROW(app.configure(config));
   }

   {
      auto config = test_p2p_config();
      config.set("plugins.p2p.node.relay.trust", std::string{"everyone"});
      auto app = p2p_only_application{};
      BOOST_CHECK_EXCEPTION(app.configure(config), forge::plugins::p2p::node::exceptions::invalid_config,
                            [](const auto& error) {
                               const auto text = std::string{error.what()};
                               return text.find("plugins.p2p.node.relay.trust") != std::string::npos &&
                                      text.find("config.type") != std::string::npos;
                            });
   }

   {
      auto config = test_p2p_config();
      config.set("plugins.p2p.node.dht.profiles",
                 forge::config::core::value::array_type{
                     forge::config::core::value{dht_profile_config("amino-v1", "server", "/forge/not-amino/1.0.0")}});
      auto app = p2p_only_application{};
      BOOST_CHECK_THROW(app.configure(config), forge::plugins::p2p::node::exceptions::invalid_config);
   }

   {
      auto config = test_p2p_config();
      config.set("plugins.p2p.node.dht.profiles",
                 forge::config::core::value::array_type{forge::config::core::value{
                     dht_profile_config("custom", "server", "/forge/product/kad/1.0.0", true, true, true)}});
      auto app = p2p_only_application{};
      BOOST_CHECK_THROW(app.configure(config), forge::plugins::p2p::node::exceptions::invalid_config);
   }

   {
      auto config = test_p2p_config();
      const auto duplicate = dht_profile_config("custom", "client", "/forge/product/kad/1.0.0", true, true, false);
      config.set("plugins.p2p.node.dht.profiles",
                 forge::config::core::value::array_type{forge::config::core::value{duplicate},
                                                        forge::config::core::value{duplicate}});
      auto app = p2p_only_application{};
      BOOST_CHECK_THROW(app.configure(config), forge::plugins::p2p::node::exceptions::invalid_config);
   }
}

BOOST_AUTO_TEST_CASE(p2p_node_plugin_accepts_complete_amino_and_provider_only_custom_profiles) {
   auto config = test_p2p_config();
   config.set("plugins.p2p.node.dht.profiles",
              forge::config::core::value::array_type{
                  forge::config::core::value{dht_profile_config("amino-v1", "server", "/ipfs/kad/1.0.0")},
                  forge::config::core::value{
                      dht_profile_config("custom", "client", "/forge/content/providers/1.0.0", true, true, false)},
              });
   auto app = p2p_only_application{};
   BOOST_CHECK_NO_THROW(app.configure(config));
}

BOOST_AUTO_TEST_CASE(p2p_node_plugin_static_topology_starts_without_autonomous_discovery) {
   auto config = test_p2p_config(test_peer(93));
   config.set("plugins.p2p.node.topology.mode", std::string{"static-only"});
   auto app = p2p_only_application{};
   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.startup());

   const auto diagnostics = app.apis().get<forge::plugins::p2p::node::diagnostics_source>(
       {.id = {"forge.plugins.p2p.node.diagnostics_source"}, .major = 1, .min_revision = 0});
   const auto snapshot = diagnostics->snapshot();
   BOOST_TEST(snapshot.topology.mode == "static-only");
   BOOST_TEST(snapshot.topology.phase == "idle");
   BOOST_TEST(snapshot.topology.completed_refreshes == 0U);
   BOOST_TEST(!snapshot.topology.refresh_queued);
   BOOST_TEST(!snapshot.topology.refresh_in_flight);

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_node_plugin_normalizes_managed_topology_to_hard_session_capacity) {
   auto config = test_p2p_config(test_peer(94));
   config.set("plugins.p2p.node.max-sessions", std::uint64_t{1});
   auto app = p2p_only_application{};
   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.startup());

   const auto diagnostics = app.apis().get<forge::plugins::p2p::node::diagnostics_source>(
       {.id = {"forge.plugins.p2p.node.diagnostics_source"}, .major = 1, .min_revision = 0});
   const auto snapshot = diagnostics->snapshot();
   const auto topology = snapshot.topology;
   const auto& system = snapshot.effective_limits.system;
   BOOST_TEST(system.max_connections == 2U);
   BOOST_TEST(system.max_inbound_connections == 2U);
   BOOST_TEST(system.max_outbound_connections == 2U);
   BOOST_TEST(topology.low_watermark == 1U);
   BOOST_TEST(topology.target_watermark == 1U);
   BOOST_TEST(topology.high_watermark == 192U);

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_node_plugin_config_preserves_legacy_positional_prefix) {
   const auto value = forge::plugins::p2p::node::config{{}, {}, {"/ip4/127.0.0.1/tcp/4001"}};
   BOOST_REQUIRE_EQUAL(value.advertised_endpoints.size(), 1U);
   BOOST_TEST(value.advertised_endpoints.front() == "/ip4/127.0.0.1/tcp/4001");
   BOOST_TEST(static_cast<int>(value.bootstrap_requirement) ==
              static_cast<int>(forge::plugins::p2p::node::bootstrap_requirement::allow_disconnected));
}

BOOST_AUTO_TEST_CASE(p2p_diagnostics_plugin_config_is_described_from_public_schema) {
   auto plugin = forge::plugins::p2p::diagnostics::plugin{};
   const auto descriptor = plugin.describe_config();
   BOOST_REQUIRE(descriptor.has_value());
   BOOST_TEST(descriptor->section == "plugins.p2p.diagnostics");

   const auto& max_peers = require_field(*descriptor, "max-peers");
   BOOST_TEST(max_peers.has_default);
   BOOST_TEST(std::get<std::uint64_t>(max_peers.default_value.storage) > 0U);

   const auto& max_sessions = require_field(*descriptor, "max-sessions");
   BOOST_TEST(max_sessions.has_default);
   BOOST_TEST(std::get<std::uint64_t>(max_sessions.default_value.storage) > 0U);
}

BOOST_AUTO_TEST_CASE(p2p_diagnostics_api_rejects_facade_calls_before_initialize) {
   auto runtime = forge::asio::runtime{};
   auto plugin = forge::plugins::p2p::diagnostics::plugin{};
   auto apis = forge::api::core::registry{};
   auto provider = forge::api::core::installer{apis};
   forge::asio::blocking::run(runtime, plugin.provide(provider));

   auto diagnostics = apis.get<forge::plugins::p2p::diagnostics::api>(
       {.id = {"forge.plugins.p2p.diagnostics"}, .major = 1, .min_revision = 0});

   BOOST_CHECK_THROW((void)diagnostics->snapshot(),
                     forge::plugins::p2p::diagnostics::exceptions::plugin_not_initialized);
   BOOST_CHECK_THROW((void)diagnostics->network(),
                     forge::plugins::p2p::diagnostics::exceptions::plugin_not_initialized);
   BOOST_CHECK_THROW((void)diagnostics->resources(),
                     forge::plugins::p2p::diagnostics::exceptions::plugin_not_initialized);
   BOOST_CHECK_THROW((void)diagnostics->pubsub(), forge::plugins::p2p::diagnostics::exceptions::plugin_not_initialized);
   BOOST_CHECK_THROW((void)diagnostics->peers(), forge::plugins::p2p::diagnostics::exceptions::plugin_not_initialized);
   BOOST_CHECK_THROW((void)diagnostics->peer(test_peer(90)),
                     forge::plugins::p2p::diagnostics::exceptions::plugin_not_initialized);
}

BOOST_AUTO_TEST_CASE(p2p_diagnostics_plugin_reports_live_p2p_node_state) {
   const auto server_peer = test_peer(91);
   auto server_config = test_p2p_config(server_peer);
   server_config.set("plugins.p2p.node.listen", forge::config::core::value::array_type{
                                                    forge::config::core::value{"/ip4/127.0.0.1/udp/0/quic-v1"}});

   auto log = plugin_log{};
   auto server = p2p_plugin_application{log};
   server.configure(server_config);
   forge::asio::blocking::run(server.runtime(), server.startup());

   auto server_p2p = server.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   const auto server_endpoint = server_p2p->local_endpoint();
   BOOST_REQUIRE(server_endpoint.has_value());

   const auto client_peer = test_peer(92);
   auto client_config = test_p2p_config(client_peer);
   client_config.set("plugins.p2p.node.bootstrap",
                     forge::config::core::value::array_type{forge::config::core::value{server_endpoint->to_string()}});

   auto client = diagnostics_application{};
   client.configure(client_config);
   forge::asio::blocking::run(client.runtime(), client.startup());

   auto client_p2p = client.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   auto diagnostics = client.apis().get<forge::plugins::p2p::diagnostics::api>(
       {.id = {"forge.plugins.p2p.diagnostics"}, .major = 1, .min_revision = 0});

   auto remote = forge::asio::blocking::run(
       client.runtime(),
       client_p2p->remote<node_test_api>(server_p2p->local_peer(),
                                         forge::net::p2p::protocol_id{.value = "/forge/api/node-test/1"}));
   const auto response = forge::asio::blocking::run(client.runtime(), remote->ping(10));
   BOOST_TEST(response == 11);

   const auto snapshot = diagnostics->snapshot();
   BOOST_TEST(snapshot.network.local_peer.to_string() == client_p2p->local_peer().to_string());
   BOOST_TEST(snapshot.metrics.active_sessions >= 1U);
   BOOST_TEST(snapshot.resources.system.outbound_connections >= 1U);
   BOOST_REQUIRE(!snapshot.sessions.empty());
   BOOST_TEST(snapshot.sessions.front().remote_peer.to_string() == server_peer.to_string());
   BOOST_REQUIRE(!diagnostics->peers().empty());

   const auto server_record = diagnostics->peer(server_peer);
   BOOST_TEST(server_record.peer.to_string() == server_peer.to_string());
   BOOST_CHECK_THROW((void)diagnostics->peer(test_peer(93)), forge::plugins::p2p::diagnostics::exceptions::not_found);

   forge::asio::blocking::run(client.runtime(), client.shutdown());
   forge::asio::blocking::run(server.runtime(), server.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_node_plugin_maintains_bootstrap_session_after_peer_restart) {
   const auto server_peer = test_peer(112);
   auto server_config = test_p2p_config(server_peer);
   server_config.set("plugins.p2p.node.listen", forge::config::core::value::array_type{
                                                    forge::config::core::value{"/ip4/127.0.0.1/tcp/0"},
                                                });

   auto server = diagnostics_application{};
   server.configure(server_config);
   forge::asio::blocking::run(server.runtime(), server.startup());

   auto server_p2p = server.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   const auto server_endpoint = server_p2p->local_endpoint();
   BOOST_REQUIRE(server_endpoint.has_value());
   BOOST_TEST(server_endpoint->is_direct_tcp());
   BOOST_REQUIRE(server_endpoint->peer.has_value());
   const auto bootstrap_peer = *server_endpoint->peer;
   BOOST_TEST(bootstrap_peer.to_string() == server_peer.to_string());

   auto client_config = test_p2p_config(test_peer(113));
   client_config.set("plugins.p2p.node.bootstrap", forge::config::core::value::array_type{
                                                       forge::config::core::value{server_endpoint->to_string()},
                                                   });

   auto client = diagnostics_application{};
   client.configure(client_config);
   forge::asio::blocking::run(client.runtime(), client.startup());
   auto client_diagnostics = client.apis().get<forge::plugins::p2p::diagnostics::api>(
       {.id = {"forge.plugins.p2p.diagnostics"}, .major = 1, .min_revision = 0});

   const auto connected = forge::asio::blocking::run(
       client.runtime(),
       async_wait_for_condition(
           [&] {
              const auto snapshot = client_diagnostics->snapshot();
              return snapshot.metrics.active_sessions >= 1U && snapshot.metrics.sessions_opened >= 1U &&
                     std::ranges::any_of(snapshot.sessions, [](const auto& session) { return session.protected_peer; });
           },
           std::chrono::seconds{8}));
   const auto connected_snapshot = client_diagnostics->snapshot();
   BOOST_TEST_CONTEXT("opened=" << connected_snapshot.metrics.sessions_opened
                                << " closed=" << connected_snapshot.metrics.sessions_closed
                                << " active=" << connected_snapshot.metrics.active_sessions
                                << " protected=" << connected_snapshot.connections.protected_peers.size()) {
      BOOST_REQUIRE(connected);
   }

   auto replacement_endpoint = *server_endpoint;
   replacement_endpoint.peer.reset();
   forge::asio::blocking::run(server.runtime(), server.shutdown());

   const auto disconnected = forge::asio::blocking::run(
       client.runtime(),
       async_wait_for_condition([&] { return client_diagnostics->snapshot().metrics.active_sessions == 0U; },
                                std::chrono::seconds{5}));
   BOOST_REQUIRE(disconnected);

   auto replacement_config = test_p2p_config(server_peer);
   replacement_config.set("plugins.p2p.node.listen", forge::config::core::value::array_type{
                                                         forge::config::core::value{replacement_endpoint.to_string()},
                                                     });

   auto replacement = diagnostics_application{};
   replacement.configure(replacement_config);
   forge::asio::blocking::run(replacement.runtime(), replacement.startup());
   auto replacement_diagnostics = replacement.apis().get<forge::plugins::p2p::diagnostics::api>(
       {.id = {"forge.plugins.p2p.diagnostics"}, .major = 1, .min_revision = 0});

   const auto reconnected = forge::asio::blocking::run(
       client.runtime(),
       async_wait_for_condition(
           [&] {
              const auto snapshot = client_diagnostics->snapshot();
              return snapshot.metrics.active_sessions == 1U && snapshot.metrics.sessions_opened >= 2U &&
                     std::ranges::any_of(snapshot.sessions, [](const auto& session) { return session.protected_peer; });
           },
           std::chrono::seconds{12}));
   const auto reconnected_snapshot = client_diagnostics->snapshot();
   BOOST_TEST_CONTEXT("opened=" << reconnected_snapshot.metrics.sessions_opened
                                << " closed=" << reconnected_snapshot.metrics.sessions_closed
                                << " active=" << reconnected_snapshot.metrics.active_sessions
                                << " protected=" << reconnected_snapshot.connections.protected_peers.size()) {
      BOOST_TEST(reconnected);
   }

   forge::asio::blocking::run(client.runtime(), client.shutdown());
   const auto gracefully_closed = forge::asio::blocking::run(
       replacement.runtime(),
       async_wait_for_condition([&] { return replacement_diagnostics->snapshot().metrics.active_sessions == 0U; },
                                std::chrono::seconds{5}));
   BOOST_TEST(gracefully_closed);
   forge::asio::blocking::run(replacement.runtime(), replacement.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_node_plugin_preserves_stop_requested_before_node_startup) {
   auto config = test_p2p_config(test_peer(114));
   config.set("plugins.p2p.node.bootstrap", forge::config::core::value::array_type{
                                                forge::config::core::value{
                                                    "/ip4/127.0.0.1/tcp/1/p2p/" + test_peer(115).to_string(),
                                                },
                                            });

   auto app = p2p_only_application{forge::app::application_shell_options{
       .name = "p2p-stop-before-maintenance",
       .runtime = {.worker_threads = 2, .thread_name = "p2p-stop-before"},
   }};
   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.initialize());
   auto p2p = app.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});

   auto stop_thread = std::thread{[&] { app.request_stop(); }};
   stop_thread.join();

   const auto started = std::chrono::steady_clock::now();
   forge::asio::blocking::run(app.runtime(), app.startup());
   const auto elapsed = std::chrono::steady_clock::now() - started;

   BOOST_TEST(elapsed < std::chrono::seconds{2});
   BOOST_CHECK_THROW((void)p2p->local_endpoint(), forge::plugins::p2p::node::exceptions::plugin_not_initialized);
   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_node_plugin_stop_cannot_race_route_installation) {
   auto app = p2p_only_application{forge::app::application_shell_options{
       .name = "p2p-stop-during-route-install",
       .runtime = {.worker_threads = 2, .thread_name = "p2p-route-stop"},
   }};
   app.configure(test_p2p_config(test_peer(226)));
   forge::asio::blocking::run(app.runtime(), app.initialize());
   auto p2p = app.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});

   auto gate = std::make_shared<route_install_gate>();
   p2p->publish_protocol(forge::net::p2p::protocol_id{.value = "/forge/test/startup-stop-race/1"},
                         blocking_route_handler{gate});
   gate->copies.store(0, std::memory_order_release);
   gate->armed.store(true, std::memory_order_release);

   auto startup_failure = std::exception_ptr{};
   auto startup = std::thread{[&] {
      try {
         forge::asio::blocking::run(app.runtime(), app.startup());
      } catch (...) {
         startup_failure = std::current_exception();
      }
   }};

   auto blocked = false;
   {
      auto lock = std::unique_lock{gate->mutex};
      blocked = gate->changed.wait_for(lock, std::chrono::seconds{5}, [&] { return gate->blocked; });
   }
   app.request_stop();
   {
      auto lock = std::scoped_lock{gate->mutex};
      gate->released = true;
   }
   gate->changed.notify_all();
   startup.join();

   BOOST_REQUIRE(blocked);
   if (startup_failure) {
      std::rethrow_exception(startup_failure);
   }
   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_node_plugin_closes_route_publication_before_startup_suspends) {
   auto config = test_p2p_config(test_peer(224));
   config.set("plugins.p2p.node.bootstrap", forge::config::core::value::array_type{
                                                forge::config::core::value{
                                                    "/ip4/127.0.0.1/tcp/1/p2p/" + test_peer(225).to_string(),
                                                },
                                            });
   config.set("plugins.p2p.node.bootstrap-requirement", std::string{"require-connection"});
   config.set("plugins.p2p.node.bootstrap-startup-budget-ms", std::uint64_t{5'000});
   config.set("plugins.p2p.node.bootstrap-connect-timeout-ms", std::uint64_t{1'000});

   auto app = p2p_only_application{forge::app::application_shell_options{
       .name = "p2p-route-startup-boundary",
       .runtime = {.worker_threads = 2, .thread_name = "p2p-route-boundary"},
   }};
   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.initialize());
   auto p2p = app.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});

   auto startup_failure = std::exception_ptr{};
   auto startup = std::thread{[&] {
      try {
         forge::asio::blocking::run(app.runtime(), app.startup());
      } catch (...) {
         startup_failure = std::current_exception();
      }
   }};

   auto node_created = false;
   for (auto attempt = 0; attempt < 200 && !node_created; ++attempt) {
      try {
         static_cast<void>(p2p->local_peer());
         node_created = true;
      } catch (const forge::plugins::p2p::node::exceptions::plugin_not_initialized&) {
         std::this_thread::sleep_for(std::chrono::milliseconds{10});
      }
   }
   BOOST_REQUIRE(node_created);

   BOOST_CHECK_THROW(
       p2p->publish_protocol(
           forge::net::p2p::protocol_id{.value = "/forge/test/late-route/1"},
           [](forge::net::p2p::node::incoming_protocol_stream) -> boost::asio::awaitable<void> { co_return; }),
       forge::plugins::p2p::node::exceptions::route_conflict);

   app.request_stop();
   startup.join();
   if (startup_failure) {
      std::rethrow_exception(startup_failure);
   }
   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_node_plugin_cancels_bootstrap_sleep_from_an_external_thread) {
   const auto server_peer = test_peer(116);
   auto server_config = test_p2p_config(server_peer);
   server_config.set("plugins.p2p.node.listen", forge::config::core::value::array_type{
                                                    forge::config::core::value{"/ip4/127.0.0.1/tcp/0"},
                                                });

   auto server = diagnostics_application{};
   server.configure(server_config);
   forge::asio::blocking::run(server.runtime(), server.startup());

   auto server_p2p = server.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   const auto server_endpoint = server_p2p->local_endpoint();
   BOOST_REQUIRE(server_endpoint.has_value());

   auto client_config = test_p2p_config(test_peer(117));
   client_config.set("plugins.p2p.node.bootstrap", forge::config::core::value::array_type{
                                                       forge::config::core::value{server_endpoint->to_string()},
                                                   });

   auto client = diagnostics_application{forge::app::application_shell_options{
       .name = "p2p-cross-thread-stop",
       .runtime = {.worker_threads = 2, .thread_name = "p2p-cross-stop"},
   }};
   client.configure(client_config);
   forge::asio::blocking::run(client.runtime(), client.startup());

   auto server_diagnostics = server.apis().get<forge::plugins::p2p::diagnostics::api>(
       {.id = {"forge.plugins.p2p.diagnostics"}, .major = 1, .min_revision = 0});
   auto client_diagnostics = client.apis().get<forge::plugins::p2p::diagnostics::api>(
       {.id = {"forge.plugins.p2p.diagnostics"}, .major = 1, .min_revision = 0});
   BOOST_REQUIRE(forge::asio::blocking::run(
       server.runtime(),
       async_wait_for_condition([&] { return server_diagnostics->snapshot().metrics.active_sessions == 1U; },
                                std::chrono::seconds{5})));

   std::this_thread::sleep_for(std::chrono::milliseconds{100});
   auto stop_thread = std::thread{[&] { client.request_stop(); }};
   stop_thread.join();

   const auto requested_stop = client_diagnostics->snapshot();
   BOOST_TEST(static_cast<int>(requested_stop.lifecycle.phase) ==
              static_cast<int>(forge::net::p2p::lifecycle_phase::stopping));
   BOOST_TEST(requested_stop.metrics.active_sessions >= 1U);

   const auto started = std::chrono::steady_clock::now();
   forge::asio::blocking::run(client.runtime(), client.shutdown());
   const auto elapsed = std::chrono::steady_clock::now() - started;
   BOOST_TEST(elapsed < std::chrono::milliseconds{750});

   const auto disconnected_after_shutdown = forge::asio::blocking::run(
       server.runtime(),
       async_wait_for_condition([&] { return server_diagnostics->snapshot().metrics.active_sessions == 0U; },
                                std::chrono::seconds{5}));
   BOOST_TEST(disconnected_after_shutdown);

   forge::asio::blocking::run(server.runtime(), server.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_node_plugin_cancels_active_bootstrap_dial) {
   namespace asio = boost::asio;
   using asio_tcp = asio::ip::tcp;

   auto app = p2p_only_application{forge::app::application_shell_options{
       .name = "p2p-active-bootstrap-stop",
       .runtime = {.worker_threads = 2, .thread_name = "p2p-active-stop"},
   }};
   auto acceptor = std::make_shared<asio_tcp::acceptor>(app.runtime().context());
   acceptor->open(asio_tcp::v4());
   acceptor->bind({asio::ip::make_address("127.0.0.1"), 0});
   const auto port = acceptor->local_endpoint().port();

   auto config = test_p2p_config(test_peer(120));
   config.set("plugins.p2p.node.bootstrap",
              forge::config::core::value::array_type{
                  forge::config::core::value{
                      "/ip4/127.0.0.1/tcp/" + std::to_string(port) + "/p2p/" + test_peer(121).to_string(),
                  },
              });
   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.startup());

   acceptor->listen();
   auto socket = std::make_shared<asio_tcp::socket>(app.runtime().context());
   auto hold = std::make_shared<asio::steady_timer>(app.runtime().context());
   auto accepted = std::make_shared<std::promise<void>>();
   auto accepted_future = accepted->get_future();
   asio::co_spawn(
       app.runtime().context(),
       [acceptor, socket, hold, accepted]() -> asio::awaitable<void> {
          auto error = boost::system::error_code{};
          co_await acceptor->async_accept(*socket, asio::redirect_error(asio::use_awaitable, error));
          if (!error) {
             accepted->set_value();
             hold->expires_after(std::chrono::seconds{5});
             co_await hold->async_wait(asio::redirect_error(asio::use_awaitable, error));
          }
       },
       asio::detached);

   BOOST_REQUIRE(accepted_future.wait_for(std::chrono::seconds{3}) == std::future_status::ready);
   const auto started = std::chrono::steady_clock::now();
   forge::asio::blocking::run(app.runtime(), app.shutdown());
   const auto elapsed = std::chrono::steady_clock::now() - started;

   BOOST_TEST(elapsed < std::chrono::milliseconds{750});
   auto ignored = boost::system::error_code{};
   (void)hold->cancel();
   socket->close(ignored);
   acceptor->close(ignored);
}

BOOST_AUTO_TEST_CASE(p2p_node_plugin_rolls_back_strict_bootstrap_failure) {
   auto config = test_p2p_config(test_peer(118));
   config.set("plugins.p2p.node.bootstrap", forge::config::core::value::array_type{
                                                forge::config::core::value{
                                                    "/ip4/127.0.0.1/tcp/1/p2p/" + test_peer(119).to_string(),
                                                },
                                            });
   config.set("plugins.p2p.node.bootstrap-requirement", std::string{"require-connection"});
   config.set("plugins.p2p.node.bootstrap-startup-budget-ms", std::uint64_t{100});
   config.set("plugins.p2p.node.bootstrap-connect-timeout-ms", std::uint64_t{50});

   auto app = p2p_only_application{};
   app.configure(config);
   BOOST_CHECK_THROW(forge::asio::blocking::run(app.runtime(), app.startup()), forge::net::p2p::exceptions::timeout);

   const auto diagnostics = app.diagnostics().snapshot(app.events());
   const auto failed_plugin = std::ranges::find_if(
       diagnostics.plugins, [](const auto& plugin) { return plugin.id == "forge.plugins.p2p.node"; });
   BOOST_REQUIRE(failed_plugin != diagnostics.plugins.end());
   BOOST_TEST(static_cast<int>(failed_plugin->state) == static_cast<int>(forge::app::lifecycle_state::failed));
   BOOST_TEST(!failed_plugin->last_error.empty());
}

BOOST_AUTO_TEST_CASE(p2p_pubsub_plugin_config_is_described_from_public_schema) {
   auto plugin = forge::plugins::p2p::pubsub::plugin{};
   const auto descriptor = plugin.describe_config();
   BOOST_REQUIRE(descriptor.has_value());
   BOOST_TEST(descriptor->section == "plugins.p2p.pubsub");

   BOOST_TEST(require_field(*descriptor, "max-topics").has_default);
   BOOST_TEST(require_field(*descriptor, "max-handlers-per-topic").has_default);
   BOOST_TEST(require_field(*descriptor, "max-active-handlers").has_default);
   BOOST_TEST(require_field(*descriptor, "max-message-size").has_default);
   BOOST_TEST(require_field(*descriptor, "handler-deadline-ms").has_default);
   BOOST_TEST(require_field(*descriptor, "allowed-topics").has_default);
   BOOST_TEST(require_field(*descriptor, "denied-topics").has_default);
   BOOST_TEST(require_field(*descriptor, "sign-publishes").has_default);
}

BOOST_AUTO_TEST_CASE(p2p_pubsub_api_rejects_facade_calls_before_initialize) {
   auto runtime = forge::asio::runtime{};
   auto plugin = forge::plugins::p2p::pubsub::plugin{};
   auto apis = forge::api::core::registry{};
   auto provider = forge::api::core::installer{apis};
   forge::asio::blocking::run(runtime, plugin.provide(provider));

   auto pubsub =
       apis.get<forge::plugins::p2p::pubsub::api>({.id = {"forge.plugins.p2p.pubsub"}, .major = 1, .min_revision = 0});

   BOOST_CHECK_THROW((void)pubsub->snapshot(), forge::plugins::p2p::pubsub::exceptions::plugin_not_initialized);
   BOOST_CHECK_THROW((void)pubsub->subscriptions(), forge::plugins::p2p::pubsub::exceptions::plugin_not_initialized);
   BOOST_CHECK_THROW(
       forge::asio::blocking::run(
           runtime, pubsub->publish(forge::net::p2p::pubsub::topic{.value = "forge.before-init"}, {1, 2, 3})),
       forge::plugins::p2p::pubsub::exceptions::plugin_not_initialized);
}

BOOST_AUTO_TEST_CASE(p2p_pubsub_plugin_rejects_invalid_typed_config_before_startup) {
   {
      auto config = test_p2p_config();
      config.set("plugins.p2p.pubsub.max-topics", std::uint64_t{0});
      auto app = pubsub_application{};
      BOOST_CHECK_THROW(app.configure(config), forge::plugins::p2p::pubsub::exceptions::invalid_config);
   }
   {
      auto config = test_p2p_config();
      config.set("plugins.p2p.pubsub.handler-deadline-ms", std::uint64_t{0});
      auto app = pubsub_application{};
      BOOST_CHECK_THROW(app.configure(config), forge::plugins::p2p::pubsub::exceptions::invalid_config);
   }
}

BOOST_AUTO_TEST_CASE(p2p_pubsub_plugin_requests_core_pubsub_capability_before_startup) {
   auto config = test_p2p_config(test_peer(94));
   config.set("plugins.p2p.node.listen",
              forge::config::core::value::array_type{forge::config::core::value{"/ip4/127.0.0.1/udp/0/quic-v1"}});
   config.set("plugins.p2p.pubsub.sign-publishes", false);

   auto app = pubsub_application{};
   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.startup());

   auto pubsub = app.apis().get<forge::plugins::p2p::pubsub::api>(
       {.id = {"forge.plugins.p2p.pubsub"}, .major = 1, .min_revision = 0});
   auto subscription = forge::asio::blocking::run(
       app.runtime(), pubsub->subscribe(forge::net::p2p::pubsub::topic{.value = "forge.local"},
                                        [](forge::plugins::p2p::pubsub::message)
                                            -> boost::asio::awaitable<forge::net::p2p::pubsub::validation_result> {
                                           co_return forge::net::p2p::pubsub::validation_result::accept;
                                        }));

   BOOST_TEST(subscription.id != 0U);
   BOOST_TEST(pubsub->snapshot().core.topics == 1U);
   BOOST_TEST(pubsub->subscriptions().size() == 1U);

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_pubsub_plugin_omits_unverified_author_from_unsigned_messages) {
   auto source_state = std::make_shared<fake_pubsub_source_state>();
   auto app = fake_pubsub_application{source_state};
   forge::asio::blocking::run(app.runtime(), app.startup());

   auto pubsub = app.apis().get<forge::plugins::p2p::pubsub::api>(
       {.id = {"forge.plugins.p2p.pubsub"}, .major = 1, .min_revision = 0});
   const auto published = forge::asio::blocking::run(
       app.runtime(), pubsub->publish(forge::net::p2p::pubsub::topic{.value = "forge.fake.unsigned"}, {1, 2, 3},
                                      forge::plugins::p2p::pubsub::publish_options{.sign = false}));

   BOOST_TEST(published.source.to_string() == "fake-pubsub-peer");
   BOOST_TEST(!published.author.has_value());
   BOOST_TEST(published.data == (std::vector<std::uint8_t>{1, 2, 3}), boost::test_tools::per_element());

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_pubsub_plugin_serializes_first_join_per_topic) {
   auto source_state = std::make_shared<fake_pubsub_source_state>();
   auto app = fake_pubsub_application{source_state};
   forge::asio::blocking::run(app.runtime(), app.startup());

   auto pubsub = app.apis().get<forge::plugins::p2p::pubsub::api>(
       {.id = {"forge.plugins.p2p.pubsub"}, .major = 1, .min_revision = 0});
   const auto topic = forge::net::p2p::pubsub::topic{.value = "forge.fake.pending"};
   auto first = std::make_shared<subscribe_task_result>();
   auto second = std::make_shared<subscribe_task_result>();
   auto handler =
       [](forge::plugins::p2p::pubsub::message) -> boost::asio::awaitable<forge::net::p2p::pubsub::validation_result> {
      co_return forge::net::p2p::pubsub::validation_result::accept;
   };

   forge::asio::blocking::run(app.runtime(), [&]() -> boost::asio::awaitable<void> {
      auto executor = co_await boost::asio::this_coro::executor;
      boost::asio::co_spawn(
          executor,
          [pubsub, topic, first, handler]() mutable -> boost::asio::awaitable<void> {
             try {
                first->complete(co_await pubsub->subscribe(topic, handler));
             } catch (...) {
                first->fail(std::current_exception());
             }
          },
          boost::asio::detached);
      boost::asio::co_spawn(
          executor,
          [pubsub, topic, second, handler]() mutable -> boost::asio::awaitable<void> {
             try {
                second->complete(co_await pubsub->subscribe(topic, handler));
             } catch (...) {
                second->fail(std::current_exception());
             }
          },
          boost::asio::detached);

      BOOST_REQUIRE(
          co_await async_wait_for_condition([&] { return source_state->joins() == 1U; }, std::chrono::seconds{1}));
      auto settle_timer = boost::asio::steady_timer{executor, std::chrono::milliseconds{50}};
      co_await settle_timer.async_wait(boost::asio::use_awaitable);
      BOOST_TEST(!first->finished());
      BOOST_TEST(!second->finished());
      source_state->release(false);
      BOOST_REQUIRE(co_await async_wait_for_condition([&] { return first->finished() && second->finished(); },
                                                      std::chrono::seconds{1}));
   }());

   BOOST_TEST(!first->failed());
   BOOST_TEST(!second->failed());
   BOOST_TEST(source_state->joins() == 1U);
   BOOST_TEST(pubsub->snapshot().topics == 1U);
   BOOST_TEST(pubsub->subscriptions().size() == 2U);

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_pubsub_plugin_failed_first_join_clears_pending_topic) {
   auto source_state = std::make_shared<fake_pubsub_source_state>();
   auto app = fake_pubsub_application{source_state};
   forge::asio::blocking::run(app.runtime(), app.startup());

   auto pubsub = app.apis().get<forge::plugins::p2p::pubsub::api>(
       {.id = {"forge.plugins.p2p.pubsub"}, .major = 1, .min_revision = 0});
   const auto topic = forge::net::p2p::pubsub::topic{.value = "forge.fake.failed"};
   auto first = std::make_shared<subscribe_task_result>();
   auto second = std::make_shared<subscribe_task_result>();
   auto handler =
       [](forge::plugins::p2p::pubsub::message) -> boost::asio::awaitable<forge::net::p2p::pubsub::validation_result> {
      co_return forge::net::p2p::pubsub::validation_result::accept;
   };

   forge::asio::blocking::run(app.runtime(), [&]() -> boost::asio::awaitable<void> {
      auto executor = co_await boost::asio::this_coro::executor;
      boost::asio::co_spawn(
          executor,
          [pubsub, topic, first, handler]() mutable -> boost::asio::awaitable<void> {
             try {
                first->complete(co_await pubsub->subscribe(topic, handler));
             } catch (...) {
                first->fail(std::current_exception());
             }
          },
          boost::asio::detached);
      boost::asio::co_spawn(
          executor,
          [pubsub, topic, second, handler]() mutable -> boost::asio::awaitable<void> {
             try {
                second->complete(co_await pubsub->subscribe(topic, handler));
             } catch (...) {
                second->fail(std::current_exception());
             }
          },
          boost::asio::detached);

      BOOST_REQUIRE(
          co_await async_wait_for_condition([&] { return source_state->joins() == 1U; }, std::chrono::seconds{1}));
      source_state->release(true);
      BOOST_REQUIRE(co_await async_wait_for_condition([&] { return first->finished() && second->finished(); },
                                                      std::chrono::seconds{1}));
   }());

   BOOST_TEST(first->failed());
   BOOST_TEST(second->failed());
   BOOST_TEST(pubsub->snapshot().topics == 0U);
   BOOST_TEST(pubsub->subscriptions().empty());

   source_state->release(false);
   const auto retry = forge::asio::blocking::run(app.runtime(), pubsub->subscribe(topic, handler));
   BOOST_TEST(retry.subject.value == topic.value);
   BOOST_TEST(source_state->joins() == 2U);

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_pubsub_plugin_publishes_and_subscribes_raw_and_typed_messages) {
   const auto subscriber_peer = test_peer(95);
   auto subscriber_config = test_p2p_config(subscriber_peer);
   subscriber_config.set("plugins.p2p.node.listen", forge::config::core::value::array_type{
                                                        forge::config::core::value{"/ip4/127.0.0.1/udp/0/quic-v1"}});
   subscriber_config.set("plugins.p2p.pubsub.sign-publishes", false);

   auto subscriber = pubsub_application{};
   subscriber.configure(subscriber_config);
   forge::asio::blocking::run(subscriber.runtime(), subscriber.startup());

   auto subscriber_p2p = subscriber.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   const auto subscriber_endpoint = subscriber_p2p->local_endpoint();
   BOOST_REQUIRE(subscriber_endpoint.has_value());

   const auto publisher_peer = test_peer(96);
   auto publisher_config = test_p2p_config(publisher_peer);
   publisher_config.set("plugins.p2p.node.bootstrap", forge::config::core::value::array_type{forge::config::core::value{
                                                          subscriber_endpoint->to_string()}});
   publisher_config.set("plugins.p2p.pubsub.sign-publishes", false);

   auto publisher = pubsub_application{};
   publisher.configure(publisher_config);
   forge::asio::blocking::run(publisher.runtime(), publisher.startup());

   auto received = std::make_shared<received_pubsub_messages>();
   auto subscriber_pubsub = subscriber.apis().get<forge::plugins::p2p::pubsub::api>(
       {.id = {"forge.plugins.p2p.pubsub"}, .major = 1, .min_revision = 0});
   auto publisher_pubsub = publisher.apis().get<forge::plugins::p2p::pubsub::api>(
       {.id = {"forge.plugins.p2p.pubsub"}, .major = 1, .min_revision = 0});

   const auto raw_topic = forge::net::p2p::pubsub::topic{.value = "forge.plugins.raw"};
   const auto typed_topic = forge::net::p2p::pubsub::topic{.value = "forge.plugins.typed"};
   auto first = forge::asio::blocking::run(
       subscriber.runtime(),
       subscriber_pubsub->subscribe(raw_topic,
                                    [received](forge::plugins::p2p::pubsub::message message) mutable
                                        -> boost::asio::awaitable<forge::net::p2p::pubsub::validation_result> {
                                       received->push(std::move(message),
                                                      forge::net::p2p::pubsub::validation_result::accept);
                                       co_return forge::net::p2p::pubsub::validation_result::accept;
                                    }));
   auto second = forge::asio::blocking::run(
       subscriber.runtime(),
       subscriber_pubsub->subscribe(raw_topic,
                                    [received](forge::plugins::p2p::pubsub::message message) mutable
                                        -> boost::asio::awaitable<forge::net::p2p::pubsub::validation_result> {
                                       received->push(std::move(message),
                                                      forge::net::p2p::pubsub::validation_result::accept);
                                       co_return forge::net::p2p::pubsub::validation_result::accept;
                                    }));
   (void)forge::asio::blocking::run(
       subscriber.runtime(), subscriber_pubsub->subscribe<pubsub_payload>(
                                 typed_topic,
                                 [received](forge::plugins::p2p::pubsub::typed_message<pubsub_payload> message) mutable
                                     -> boost::asio::awaitable<forge::net::p2p::pubsub::validation_result> {
                                    received->push(std::move(message));
                                    co_return forge::net::p2p::pubsub::validation_result::accept;
                                 }));

   BOOST_TEST(first.subject.value == raw_topic.value);
   BOOST_TEST(second.id != first.id);
   BOOST_REQUIRE_MESSAGE(wait_for_pubsub_peer(*publisher_pubsub.shared(), std::chrono::seconds{5}),
                         "publisher did not learn a remote PubSub topic subscription");

   (void)forge::asio::blocking::run(publisher.runtime(),
                                    publisher_pubsub->publish(raw_topic, std::vector<std::uint8_t>{1, 2, 3, 4}));
   (void)forge::asio::blocking::run(
       publisher.runtime(), publisher_pubsub->publish(typed_topic, pubsub_payload{.text = "hello", .value = 7}));

   if (!wait_for_count(*received, 2, 1)) {
      const auto publisher_snapshot = publisher_pubsub->snapshot();
      const auto subscriber_snapshot = subscriber_pubsub->snapshot();
      BOOST_FAIL("pubsub plugin delivery did not finish; raw="
                 << received->raw_size() << " typed=" << received->typed_size()
                 << " publisher_core_peers=" << publisher_snapshot.core.peers
                 << " publisher_published=" << publisher_snapshot.core.messages_published
                 << " subscriber_core_received=" << subscriber_snapshot.core.messages_received
                 << " subscriber_core_delivered=" << subscriber_snapshot.core.messages_delivered
                 << " subscriber_core_invalid=" << subscriber_snapshot.core.invalid_messages
                 << " subscriber_plugin_delivered=" << subscriber_snapshot.messages_delivered
                 << " subscriber_plugin_failures=" << subscriber_snapshot.handler_failures
                 << " subscriber_plugin_dropped=" << subscriber_snapshot.messages_dropped);
   }
   {
      auto lock = std::scoped_lock{received->mutex};
      BOOST_TEST(received->raw.size() == 2U);
      BOOST_TEST(forge::net::p2p::valid_peer_id(received->raw.front().source));
      BOOST_TEST(received->raw.front().data == (std::vector<std::uint8_t>{1, 2, 3, 4}),
                 boost::test_tools::per_element());
      BOOST_TEST(received->typed.front().source.to_string() == received->raw.front().source.to_string());
      BOOST_TEST(received->typed.front().value.text == "hello");
      BOOST_TEST(received->typed.front().value.value == 7U);
   }

   forge::asio::blocking::run(subscriber.runtime(), subscriber_pubsub->unsubscribe(first));
   BOOST_TEST(subscriber_pubsub->subscriptions().size() == 2U);
   forge::asio::blocking::run(subscriber.runtime(), subscriber_pubsub->unsubscribe(second));
   BOOST_TEST(subscriber_pubsub->subscriptions().size() == 1U);

   forge::asio::blocking::run(publisher.runtime(), publisher.shutdown());
   forge::asio::blocking::run(subscriber.runtime(), subscriber.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_pubsub_plugin_aggregates_handler_results_and_deadlines) {
   const auto subscriber_peer = test_peer(98);
   auto subscriber_config = test_p2p_config(subscriber_peer);
   subscriber_config.set("plugins.p2p.node.listen", forge::config::core::value::array_type{
                                                        forge::config::core::value{"/ip4/127.0.0.1/udp/0/quic-v1"}});
   subscriber_config.set("plugins.p2p.pubsub.sign-publishes", false);

   auto subscriber = pubsub_application{};
   subscriber.configure(subscriber_config);
   forge::asio::blocking::run(subscriber.runtime(), subscriber.startup());

   auto subscriber_p2p = subscriber.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   const auto subscriber_endpoint = subscriber_p2p->local_endpoint();
   BOOST_REQUIRE(subscriber_endpoint.has_value());

   auto publisher_config = test_p2p_config(test_peer(99));
   publisher_config.set("plugins.p2p.node.bootstrap", forge::config::core::value::array_type{forge::config::core::value{
                                                          subscriber_endpoint->to_string()}});
   publisher_config.set("plugins.p2p.pubsub.sign-publishes", false);

   auto publisher = pubsub_application{};
   publisher.configure(publisher_config);
   forge::asio::blocking::run(publisher.runtime(), publisher.startup());

   auto received = std::make_shared<received_pubsub_messages>();
   auto subscriber_pubsub = subscriber.apis().get<forge::plugins::p2p::pubsub::api>(
       {.id = {"forge.plugins.p2p.pubsub"}, .major = 1, .min_revision = 0});
   auto publisher_pubsub = publisher.apis().get<forge::plugins::p2p::pubsub::api>(
       {.id = {"forge.plugins.p2p.pubsub"}, .major = 1, .min_revision = 0});

   const auto aggregate_topic = forge::net::p2p::pubsub::topic{.value = "forge.plugins.aggregate"};
   const auto timeout_topic = forge::net::p2p::pubsub::topic{.value = "forge.plugins.timeout"};
   const auto mixed_retry_topic = forge::net::p2p::pubsub::topic{.value = "forge.plugins.mixed-retry"};
   (void)forge::asio::blocking::run(
       subscriber.runtime(),
       subscriber_pubsub->subscribe(aggregate_topic,
                                    [received](forge::plugins::p2p::pubsub::message message) mutable
                                        -> boost::asio::awaitable<forge::net::p2p::pubsub::validation_result> {
                                       received->push(std::move(message),
                                                      forge::net::p2p::pubsub::validation_result::ignore);
                                       co_return forge::net::p2p::pubsub::validation_result::ignore;
                                    }));
   (void)forge::asio::blocking::run(
       subscriber.runtime(),
       subscriber_pubsub->subscribe(aggregate_topic,
                                    [](forge::plugins::p2p::pubsub::message)
                                        -> boost::asio::awaitable<forge::net::p2p::pubsub::validation_result> {
                                       throw forge::plugins::p2p::pubsub::exceptions::handler_limit{
                                           "test handler failure"};
                                    }));
   (void)forge::asio::blocking::run(
       subscriber.runtime(),
       subscriber_pubsub->subscribe(aggregate_topic,
                                    [received](forge::plugins::p2p::pubsub::message message) mutable
                                        -> boost::asio::awaitable<forge::net::p2p::pubsub::validation_result> {
                                       received->push(std::move(message),
                                                      forge::net::p2p::pubsub::validation_result::accept);
                                       co_return forge::net::p2p::pubsub::validation_result::accept;
                                    }));
   (void)forge::asio::blocking::run(
       subscriber.runtime(),
       subscriber_pubsub->subscribe(aggregate_topic,
                                    [received](forge::plugins::p2p::pubsub::message message) mutable
                                        -> boost::asio::awaitable<forge::net::p2p::pubsub::validation_result> {
                                       received->push(std::move(message),
                                                      forge::net::p2p::pubsub::validation_result::reject);
                                       co_return forge::net::p2p::pubsub::validation_result::reject;
                                    }));
   auto timeout_attempts = std::make_shared<std::atomic_uint64_t>(0);
   (void)forge::asio::blocking::run(
       subscriber.runtime(),
       subscriber_pubsub->subscribe(
           timeout_topic,
           [timeout_attempts](forge::plugins::p2p::pubsub::message)
               -> boost::asio::awaitable<forge::net::p2p::pubsub::validation_result> {
              if (timeout_attempts->fetch_add(1, std::memory_order_relaxed) == 0) {
                 auto timer = boost::asio::steady_timer{co_await boost::asio::this_coro::executor};
                 timer.expires_after(std::chrono::milliseconds{100});
                 co_await timer.async_wait(boost::asio::use_awaitable);
              }
              co_return forge::net::p2p::pubsub::validation_result::accept;
           },
           forge::plugins::p2p::pubsub::subscribe_options{.handler_deadline = std::chrono::milliseconds{10}}));
   auto mixed_retry_attempts = std::make_shared<std::atomic_uint64_t>(0);
   (void)forge::asio::blocking::run(
       subscriber.runtime(),
       subscriber_pubsub->subscribe(mixed_retry_topic,
                                    [mixed_retry_attempts](forge::plugins::p2p::pubsub::message)
                                        -> boost::asio::awaitable<forge::net::p2p::pubsub::validation_result> {
                                       if (mixed_retry_attempts->fetch_add(1, std::memory_order_relaxed) == 0) {
                                          co_return forge::net::p2p::pubsub::validation_result::retry;
                                       }
                                       co_return forge::net::p2p::pubsub::validation_result::accept;
                                    }));
   (void)forge::asio::blocking::run(
       subscriber.runtime(),
       subscriber_pubsub->subscribe(mixed_retry_topic,
                                    [](forge::plugins::p2p::pubsub::message)
                                        -> boost::asio::awaitable<forge::net::p2p::pubsub::validation_result> {
                                       co_return forge::net::p2p::pubsub::validation_result::accept;
                                    }));

   BOOST_REQUIRE_MESSAGE(wait_for_pubsub_peer(*publisher_pubsub.shared(), std::chrono::seconds{5}),
                         "publisher did not learn a remote PubSub topic subscription");

   (void)forge::asio::blocking::run(publisher.runtime(),
                                    publisher_pubsub->publish(aggregate_topic, std::vector<std::uint8_t>{9}));
   BOOST_REQUIRE_MESSAGE(wait_for_pubsub_snapshot(
                             *subscriber_pubsub.shared(),
                             [](const forge::plugins::p2p::pubsub::snapshot& snapshot) {
                                return snapshot.messages_rejected >= 1 && snapshot.handler_failures >= 1;
                             },
                             std::chrono::seconds{5}),
                         "PubSub handler aggregation did not finish");
   {
      auto lock = std::scoped_lock{received->mutex};
      BOOST_TEST(received->ignored == 1U);
      BOOST_TEST(received->accepted == 1U);
      BOOST_TEST(received->rejected == 1U);
   }

   (void)forge::asio::blocking::run(publisher.runtime(),
                                    publisher_pubsub->publish(timeout_topic, std::vector<std::uint8_t>{10}));
   BOOST_REQUIRE_MESSAGE(wait_for_pubsub_snapshot(
                             *subscriber_pubsub.shared(),
                             [](const forge::plugins::p2p::pubsub::snapshot& snapshot) {
                                return snapshot.messages_retried >= 1 && snapshot.messages_accepted >= 1 &&
                                       snapshot.handler_failures >= 2;
                             },
                             std::chrono::seconds{5}),
                         "PubSub handler timeout was not redelivered successfully");
   BOOST_TEST(timeout_attempts->load(std::memory_order_relaxed) == 2U);
   BOOST_TEST(subscriber_pubsub->snapshot().active_handlers == 0U);

   (void)forge::asio::blocking::run(publisher.runtime(),
                                    publisher_pubsub->publish(mixed_retry_topic, std::vector<std::uint8_t>{11}));
   BOOST_REQUIRE_MESSAGE(wait_for_pubsub_snapshot(
                             *subscriber_pubsub.shared(),
                             [](const forge::plugins::p2p::pubsub::snapshot& snapshot) {
                                return snapshot.messages_retried >= 2 && snapshot.messages_accepted >= 2;
                             },
                             std::chrono::seconds{5}),
                         "PubSub accept masked a transient sibling handler result");
   BOOST_TEST(mixed_retry_attempts->load(std::memory_order_relaxed) == 2U);

   forge::asio::blocking::run(publisher.runtime(), publisher.shutdown());
   forge::asio::blocking::run(subscriber.runtime(), subscriber.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_pubsub_plugin_enforces_topic_policy_and_handler_bounds) {
   auto config = test_p2p_config(test_peer(97));
   config.set("plugins.p2p.pubsub.sign-publishes", false);
   config.set("plugins.p2p.pubsub.max-handlers-per-topic", std::uint64_t{1});
   config.set("plugins.p2p.pubsub.max-message-size", std::uint64_t{4});
   config.set("plugins.p2p.pubsub.allowed-topics",
              forge::config::core::value::array_type{forge::config::core::value{"forge.allowed"}});
   config.set("plugins.p2p.pubsub.denied-topics",
              forge::config::core::value::array_type{forge::config::core::value{"forge.denied"}});

   auto app = pubsub_application{};
   app.configure(config);
   forge::asio::blocking::run(app.runtime(), app.startup());

   auto pubsub = app.apis().get<forge::plugins::p2p::pubsub::api>(
       {.id = {"forge.plugins.p2p.pubsub"}, .major = 1, .min_revision = 0});
   auto handler =
       [](forge::plugins::p2p::pubsub::message) -> boost::asio::awaitable<forge::net::p2p::pubsub::validation_result> {
      co_return forge::net::p2p::pubsub::validation_result::ignore;
   };

   auto subscription = forge::asio::blocking::run(
       app.runtime(), pubsub->subscribe(forge::net::p2p::pubsub::topic{.value = "forge.allowed"}, handler));
   BOOST_TEST(subscription.id != 0U);
   BOOST_CHECK_THROW(
       forge::asio::blocking::run(app.runtime(),
                                  pubsub->subscribe(forge::net::p2p::pubsub::topic{.value = "forge.allowed"}, handler)),
       forge::plugins::p2p::pubsub::exceptions::handler_limit);
   BOOST_CHECK_THROW(forge::asio::blocking::run(
                         app.runtime(), pubsub->publish(forge::net::p2p::pubsub::topic{.value = "forge.denied"}, {1})),
                     forge::plugins::p2p::pubsub::exceptions::topic_not_allowed);
   BOOST_CHECK_THROW(
       forge::asio::blocking::run(
           app.runtime(), pubsub->publish(forge::net::p2p::pubsub::topic{.value = "forge.allowed"}, {1, 2, 3, 4, 5})),
       forge::plugins::p2p::pubsub::exceptions::message_too_large);

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_api_resolver_plugin_config_is_described_from_public_schema) {
   auto plugin = forge::plugins::p2p::resolver::plugin{};
   const auto descriptor = plugin.describe_config();
   BOOST_REQUIRE(descriptor.has_value());
   BOOST_TEST(descriptor->section == "plugins.p2p.resolver");

   const auto& protocol = require_field(*descriptor, "protocol-id");
   BOOST_TEST(protocol.has_default);
   BOOST_TEST(std::get<std::string>(protocol.default_value.storage) == "/forge/api/resolver/2");

   const auto& cache_ttl = require_field(*descriptor, "cache-ttl-ms");
   BOOST_TEST(cache_ttl.has_default);
   BOOST_TEST(std::get<std::uint64_t>(cache_ttl.default_value.storage) > 0U);

   const auto& request_deadline = require_field(*descriptor, "request-deadline-ms");
   BOOST_TEST(request_deadline.has_default);
   BOOST_TEST(std::get<std::uint64_t>(request_deadline.default_value.storage) == 0U);

   const auto& max_peers = require_field(*descriptor, "max-cached-peers");
   BOOST_TEST(max_peers.has_default);
   BOOST_TEST(std::get<std::uint64_t>(max_peers.default_value.storage) > 0U);

   const auto& max_apis = require_field(*descriptor, "max-apis-per-peer");
   BOOST_TEST(max_apis.has_default);
   BOOST_TEST(std::get<std::uint64_t>(max_apis.default_value.storage) > 0U);
}

BOOST_AUTO_TEST_CASE(p2p_api_resolver_rejects_facade_calls_before_initialize) {
   auto runtime = forge::asio::runtime{};
   auto plugin = forge::plugins::p2p::resolver::plugin{};
   auto apis = forge::api::core::registry{};
   auto provider = forge::api::core::installer{apis};
   forge::asio::blocking::run(runtime, plugin.provide(provider));

   auto resolver = apis.get<forge::plugins::p2p::resolver::api>(
       {.id = {"forge.plugins.p2p.resolver"}, .major = 2, .min_revision = 0});

   auto plan = forge::api::core::binding().serve(apis).build();
   BOOST_CHECK_THROW(static_cast<void>(resolver->publish_api(
                         std::move(plan), forge::net::p2p::protocol_id{.value = "/forge/api/node-test/1"})),
                     forge::plugins::p2p::resolver::exceptions::plugin_not_initialized);
   BOOST_CHECK_THROW((void)resolver->local_apis(), forge::plugins::p2p::resolver::exceptions::plugin_not_initialized);
   BOOST_CHECK_THROW(forge::asio::blocking::run(runtime, resolver->peer_apis(test_peer(40))),
                     forge::plugins::p2p::resolver::exceptions::plugin_not_initialized);
}

BOOST_AUTO_TEST_CASE(p2p_api_resolver_rejects_invalid_typed_config_before_startup) {
   {
      auto config = test_p2p_config(test_peer(45));
      config.set("plugins.p2p.resolver.protocol-id", std::string{"forge/api/resolver/1"});
      auto app = resolver_only_application{};
      BOOST_CHECK_THROW(app.configure(config), forge::plugins::p2p::resolver::exceptions::invalid_config);
   }

   {
      auto config = test_p2p_config(test_peer(46));
      config.set("plugins.p2p.resolver.max-cached-peers", std::uint64_t{0});
      auto app = resolver_only_application{};
      BOOST_CHECK_THROW(app.configure(config), forge::plugins::p2p::resolver::exceptions::invalid_config);
   }
}

BOOST_AUTO_TEST_CASE(p2p_api_resolver_publishes_metadata_and_delegates_route_mounting) {
   auto app = resolver_plugin_application{};
   app.configure(test_p2p_config(test_peer(50)));
   forge::asio::blocking::run(app.runtime(), app.initialize());

   auto resolver = app.apis().get<forge::plugins::p2p::resolver::api>(
       {.id = {"forge.plugins.p2p.resolver"}, .major = 2, .min_revision = 0});
   const auto entries = resolver->local_apis();
   BOOST_REQUIRE_EQUAL(entries.size(), 1U);
   BOOST_TEST(entries.front().id.value == "node.test");
   BOOST_TEST(entries.front().version.major == 1U);
   BOOST_TEST(entries.front().version.revision == 0U);
   BOOST_TEST(entries.front().protocol == "/forge/api/node-test/1");
   BOOST_TEST(entries.front().codec.value == "forge.raw");
   BOOST_REQUIRE_EQUAL(entries.front().methods.size(), 1U);
   BOOST_TEST(entries.front().methods.front().name == "ping");
   BOOST_TEST(static_cast<int>(entries.front().methods.front().kind) ==
              static_cast<int>(forge::api::core::method_kind::unary));

   forge::asio::blocking::run(app.runtime(), app.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_api_resolver_rejects_duplicate_api_and_resolver_protocol_conflict) {
   {
      auto app = duplicate_resolver_plugin_application{};
      app.configure(test_p2p_config(test_peer(60)));
      BOOST_CHECK_THROW(forge::asio::blocking::run(app.runtime(), app.initialize()),
                        forge::plugins::p2p::resolver::exceptions::duplicate_api);
   }

   {
      auto app = resolver_protocol_conflict_application{};
      app.configure(test_p2p_config(test_peer(61)));
      BOOST_CHECK_THROW(forge::asio::blocking::run(app.runtime(), app.initialize()),
                        forge::plugins::p2p::resolver::exceptions::duplicate_api);
   }
}

BOOST_AUTO_TEST_CASE(p2p_api_resolver_resolves_remote_api_and_opens_typed_remote) {
   const auto server_peer = test_peer(70);
   auto server_config = test_p2p_config(server_peer);
   server_config.set("plugins.p2p.node.listen", forge::config::core::value::array_type{
                                                    forge::config::core::value{"/ip4/127.0.0.1/udp/0/quic-v1"}});

   auto server = resolver_plugin_application{};
   server.configure(server_config);
   forge::asio::blocking::run(server.runtime(), server.startup());

   auto server_p2p = server.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   const auto server_endpoint = server_p2p->local_endpoint();
   BOOST_REQUIRE(server_endpoint.has_value());

   auto client_config = test_p2p_config(test_peer(71));
   client_config.set("plugins.p2p.node.bootstrap",
                     forge::config::core::value::array_type{forge::config::core::value{server_endpoint->to_string()}});
   auto client = resolver_only_application{};
   client.configure(client_config);
   forge::asio::blocking::run(client.runtime(), client.startup());

   auto resolver = client.apis().get<forge::plugins::p2p::resolver::api>(
       {.id = {"forge.plugins.p2p.resolver"}, .major = 2, .min_revision = 0});
   const auto remote_entries = forge::asio::blocking::run(client.runtime(), resolver->peer_apis(server_peer));
   BOOST_REQUIRE_EQUAL(remote_entries.size(), 1U);
   BOOST_TEST(remote_entries.front().protocol == "/forge/api/node-test/1");

   auto resolved = forge::asio::blocking::run(
       client.runtime(), resolver->resolve(server_peer, {.id = {"node.test"}, .major = 1, .min_revision = 0}));
   BOOST_TEST(resolved.api.protocol == "/forge/api/node-test/1");

   auto remote = forge::asio::blocking::run(client.runtime(), resolver->remote<node_test_api>(server_peer));
   const auto response = forge::asio::blocking::run(client.runtime(), remote->ping(41));
   BOOST_TEST(response == 42);

   forge::asio::blocking::run(client.runtime(), client.shutdown());
   forge::asio::blocking::run(server.runtime(), server.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_api_resolver_remote_applies_request_deadline_when_node_default_is_unbounded) {
   const auto server_peer = test_peer(76);
   auto server_config = test_p2p_config(server_peer);
   server_config.set("plugins.p2p.node.listen", forge::config::core::value::array_type{
                                                    forge::config::core::value{"/ip4/127.0.0.1/udp/0/quic-v1"}});

   auto handler_state = std::make_shared<nonresponding_node_test_state>();
   auto server = resolver_plugin_application{std::make_shared<nonresponding_node_test_api_impl>(handler_state)};
   server.configure(server_config);
   forge::asio::blocking::run(server.runtime(), server.startup());

   auto server_p2p = server.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   const auto server_endpoint = server_p2p->local_endpoint();
   BOOST_REQUIRE(server_endpoint.has_value());

   auto client_config = test_p2p_config(test_peer(77));
   client_config.set("plugins.p2p.node.api.deadline-ms", std::uint64_t{0});
   client_config.set("plugins.p2p.resolver.request-deadline-ms", std::uint64_t{250});
   client_config.set("plugins.p2p.node.bootstrap",
                     forge::config::core::value::array_type{forge::config::core::value{server_endpoint->to_string()}});
   auto client = resolver_only_application{};
   client.configure(client_config);
   forge::asio::blocking::run(client.runtime(), client.startup());

   auto resolver = client.apis().get<forge::plugins::p2p::resolver::api>(
       {.id = {"forge.plugins.p2p.resolver"}, .major = 2, .min_revision = 0});
   auto remote = forge::asio::blocking::run(client.runtime(), resolver->remote<node_test_api>(server_peer));

   BOOST_CHECK_THROW(forge::asio::blocking::run(client.runtime(), remote->ping(41)),
                     forge::api::core::exceptions::deadline_exceeded);
   BOOST_TEST(handler_state->started.load(std::memory_order_acquire));
   BOOST_TEST(forge::asio::blocking::run(
       server.runtime(),
       async_wait_for_condition([&] { return handler_state->cancelled.load(std::memory_order_acquire); },
                                std::chrono::seconds{2})));

   forge::asio::blocking::run(client.runtime(), client.shutdown());
   forge::asio::blocking::run(server.runtime(), server.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_api_resolver_remote_honors_advertised_transport_options) {
   const auto server_peer = test_peer(72);
   auto server_config = test_p2p_config(server_peer);
   server_config.set("plugins.p2p.node.listen", forge::config::core::value::array_type{
                                                    forge::config::core::value{"/ip4/127.0.0.1/udp/0/quic-v1"}});

   auto server = resolver_custom_transport_application{};
   server.configure(server_config);
   forge::asio::blocking::run(server.runtime(), server.startup());

   auto server_p2p = server.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   const auto server_endpoint = server_p2p->local_endpoint();
   BOOST_REQUIRE(server_endpoint.has_value());

   auto client_config = test_p2p_config(test_peer(73));
   client_config.set("plugins.p2p.node.bootstrap",
                     forge::config::core::value::array_type{forge::config::core::value{server_endpoint->to_string()}});
   auto client = resolver_only_application{};
   client.configure(client_config);
   forge::asio::blocking::run(client.runtime(), client.startup());

   auto resolver = client.apis().get<forge::plugins::p2p::resolver::api>(
       {.id = {"forge.plugins.p2p.resolver"}, .major = 2, .min_revision = 0});
   const auto remote_entries = forge::asio::blocking::run(client.runtime(), resolver->peer_apis(server_peer));
   BOOST_REQUIRE_EQUAL(remote_entries.size(), 1U);
   BOOST_TEST(remote_entries.front().codec.value == "forge.test.raw");
   BOOST_TEST(remote_entries.front().max_inflight == 7U);
   BOOST_TEST(remote_entries.front().max_frame_size == 512U * 1024U);

   auto remote = forge::asio::blocking::run(client.runtime(), resolver->remote<node_test_api>(server_peer));
   const auto response = forge::asio::blocking::run(client.runtime(), remote->ping(41));
   BOOST_TEST(response == 42);

   forge::asio::blocking::run(client.runtime(), client.shutdown());
   forge::asio::blocking::run(server.runtime(), server.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_api_resolver_supports_receipt_based_product_api) {
   const auto server_peer = test_peer(74);
   auto server_config = test_p2p_config(server_peer);
   server_config.set("plugins.p2p.node.listen", forge::config::core::value::array_type{
                                                    forge::config::core::value{"/ip4/127.0.0.1/udp/0/quic-v1"}});

   auto server_state = std::make_shared<receipt_test_state>();
   auto server = receipt_resolver_application{server_state};
   server.configure(server_config);
   forge::asio::blocking::run(server.runtime(), server.startup());

   auto server_p2p = server.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   const auto server_endpoint = server_p2p->local_endpoint();
   BOOST_REQUIRE(server_endpoint.has_value());

   auto client_config = test_p2p_config(test_peer(75));
   client_config.set("plugins.p2p.node.bootstrap",
                     forge::config::core::value::array_type{forge::config::core::value{server_endpoint->to_string()}});
   auto client = resolver_only_application{};
   client.configure(client_config);
   forge::asio::blocking::run(client.runtime(), client.startup());

   auto resolver = client.apis().get<forge::plugins::p2p::resolver::api>(
       {.id = {"forge.plugins.p2p.resolver"}, .major = 2, .min_revision = 0});
   const auto resolved = forge::asio::blocking::run(
       client.runtime(), resolver->resolve(server_peer, {.id = {"receipt.test"}, .major = 1, .min_revision = 0}));
   BOOST_TEST(resolved.api.protocol == "/forge/api/receipt-test/1");

   auto remote = forge::asio::blocking::run(client.runtime(), resolver->remote<receipt_test_api>(server_peer));
   const auto request = operation_request{.request_id = "request-1", .subject = "neutral-operation", .revision = 7};

   const auto first = forge::asio::blocking::run(client.runtime(), remote->apply(request));
   BOOST_TEST(first.accepted);
   BOOST_TEST(first.request_id == request.request_id);
   BOOST_TEST(first.applied_revision == 1U);
   BOOST_TEST(first.authority == "receipt-test");
   BOOST_TEST(first.evidence == "neutral-operation:7:1");

   const auto repeated = forge::asio::blocking::run(client.runtime(), remote->apply(request));
   BOOST_TEST(repeated.request_id == first.request_id);
   BOOST_TEST(repeated.accepted == first.accepted);
   BOOST_TEST(repeated.applied_revision == first.applied_revision);
   BOOST_TEST(repeated.authority == first.authority);
   BOOST_TEST(repeated.evidence == first.evidence);
   {
      auto lock = std::scoped_lock{server_state->mutex};
      BOOST_TEST(server_state->applied == 1U);
      BOOST_TEST(server_state->receipts.size() == 1U);
   }

   forge::asio::blocking::run(client.runtime(), client.shutdown());
   forge::asio::blocking::run(server.runtime(), server.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_api_resolver_enforces_version_compatibility) {
   const auto server_peer = test_peer(80);
   auto server_config = test_p2p_config(server_peer);
   server_config.set("plugins.p2p.node.listen", forge::config::core::value::array_type{
                                                    forge::config::core::value{"/ip4/127.0.0.1/udp/0/quic-v1"}});

   auto server = resolver_plugin_application{};
   server.configure(server_config);
   forge::asio::blocking::run(server.runtime(), server.startup());

   auto server_p2p = server.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   const auto server_endpoint = server_p2p->local_endpoint();
   BOOST_REQUIRE(server_endpoint.has_value());

   auto client_config = test_p2p_config(test_peer(81));
   client_config.set("plugins.p2p.node.bootstrap",
                     forge::config::core::value::array_type{forge::config::core::value{server_endpoint->to_string()}});
   auto client = resolver_only_application{};
   client.configure(client_config);
   forge::asio::blocking::run(client.runtime(), client.startup());

   auto resolver = client.apis().get<forge::plugins::p2p::resolver::api>(
       {.id = {"forge.plugins.p2p.resolver"}, .major = 2, .min_revision = 0});
   BOOST_CHECK_NO_THROW(forge::asio::blocking::run(
       client.runtime(), resolver->resolve(server_peer, {.id = {"node.test"}, .major = 1, .min_revision = 0})));
   BOOST_CHECK_THROW(
       forge::asio::blocking::run(
           client.runtime(), resolver->resolve(server_peer, {.id = {"node.test"}, .major = 1, .min_revision = 10})),
       forge::plugins::p2p::resolver::exceptions::incompatible_api);

   forge::asio::blocking::run(client.runtime(), client.shutdown());
   forge::asio::blocking::run(server.runtime(), server.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_api_resolver_rejects_malformed_remote_metadata_without_caching_it) {
   const auto server_peer = test_peer(85);
   auto bad = resolver_test_entry("/forge/api/node-test/1");
   auto duplicate = forge::plugins::p2p::resolver::response{.apis = {bad, bad}};
   auto good = forge::plugins::p2p::resolver::response{
       .apis = {resolver_test_entry("/forge/api/node-test/1")},
   };
   auto state = std::make_shared<scripted_resolver_state>(
       scripted_resolver_state{.responses = {std::move(duplicate), std::move(good)}});

   auto server_config = test_p2p_config(server_peer);
   server_config.set("plugins.p2p.node.listen", forge::config::core::value::array_type{
                                                    forge::config::core::value{"/ip4/127.0.0.1/udp/0/quic-v1"}});

   auto server = scripted_resolver_application{state};
   server.configure(server_config);
   forge::asio::blocking::run(server.runtime(), server.startup());

   auto server_p2p = server.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   const auto server_endpoint = server_p2p->local_endpoint();
   BOOST_REQUIRE(server_endpoint.has_value());

   auto client_config = test_p2p_config(test_peer(86));
   client_config.set("plugins.p2p.node.bootstrap",
                     forge::config::core::value::array_type{forge::config::core::value{server_endpoint->to_string()}});
   auto client = resolver_only_application{};
   client.configure(client_config);
   forge::asio::blocking::run(client.runtime(), client.startup());

   auto resolver = client.apis().get<forge::plugins::p2p::resolver::api>(
       {.id = {"forge.plugins.p2p.resolver"}, .major = 2, .min_revision = 0});
   BOOST_CHECK_THROW(forge::asio::blocking::run(client.runtime(), resolver->peer_apis(server_peer)),
                     forge::plugins::p2p::resolver::exceptions::protocol_error);
   const auto entries = forge::asio::blocking::run(client.runtime(), resolver->peer_apis(server_peer));
   BOOST_REQUIRE_EQUAL(entries.size(), 1U);
   BOOST_TEST(state->calls == 2U);

   forge::asio::blocking::run(client.runtime(), client.shutdown());
   forge::asio::blocking::run(server.runtime(), server.shutdown());
}

BOOST_AUTO_TEST_CASE(p2p_api_resolver_cache_ttl_and_force_refresh_are_behavioral) {
   const auto server_peer = test_peer(90);
   auto server_config = test_p2p_config(server_peer);
   server_config.set("plugins.p2p.node.listen", forge::config::core::value::array_type{
                                                    forge::config::core::value{"/ip4/127.0.0.1/udp/0/quic-v1"}});

   auto server = resolver_plugin_application{};
   server.configure(server_config);
   forge::asio::blocking::run(server.runtime(), server.startup());

   auto server_p2p = server.apis().get<forge::plugins::p2p::node::api>(
       {.id = {"forge.plugins.p2p.node"}, .major = 2, .min_revision = 0});
   const auto server_endpoint = server_p2p->local_endpoint();
   BOOST_REQUIRE(server_endpoint.has_value());

   auto client_config = test_p2p_config(test_peer(91));
   client_config.set("plugins.p2p.node.bootstrap",
                     forge::config::core::value::array_type{forge::config::core::value{server_endpoint->to_string()}});
   client_config.set("plugins.p2p.resolver.cache-ttl-ms", std::uint64_t{200});
   auto client = resolver_only_application{};
   client.configure(client_config);
   forge::asio::blocking::run(client.runtime(), client.startup());

   auto resolver = client.apis().get<forge::plugins::p2p::resolver::api>(
       {.id = {"forge.plugins.p2p.resolver"}, .major = 2, .min_revision = 0});
   BOOST_REQUIRE_EQUAL(forge::asio::blocking::run(client.runtime(), resolver->peer_apis(server_peer)).size(), 1U);

   forge::asio::blocking::run(server.runtime(), server.shutdown());
   BOOST_REQUIRE_EQUAL(forge::asio::blocking::run(client.runtime(), resolver->peer_apis(server_peer)).size(), 1U);

   BOOST_CHECK_THROW(
       forge::asio::blocking::run(client.runtime(), resolver->peer_apis(server_peer, {.force_refresh = true})),
       forge::exceptions::base);

   std::this_thread::sleep_for(std::chrono::milliseconds{250});
   BOOST_CHECK_THROW(forge::asio::blocking::run(client.runtime(), resolver->peer_apis(server_peer)),
                     forge::exceptions::base);

   forge::asio::blocking::run(client.runtime(), client.shutdown());
}

module;

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <cstdint>
#include <limits>
#include <string>
#include <thread>
#include <utility>
#include <vector>

module forge.net.p2p.node;

import forge.net.p2p.resource_manager;

namespace forge::net::p2p {
namespace {

[[nodiscard]] peer_id test_peer(std::string value) {
   return peer_id{.value = std::move(value)};
}

[[nodiscard]] protocol_id test_protocol(std::string value) {
   return protocol_id{.value = std::move(value)};
}

template <typename T>
concept has_legacy_stream_limit = requires(T value) { value.max_streams; };

template <typename T>
concept has_queued_bytes_reservation = requires(T value) { value.reserve_queued_bytes(1U); };

template <typename T>
concept has_relay_stream_reservation = requires(T value) { value.reserve_relay_stream(); };

template <typename T>
concept has_operational_dials = requires(T value) { value.reserve_dial(); };

template <typename T>
concept has_pair_scopes = requires(T value) {
   value.protocol_peer;
   value.service_peer;
};

} // namespace

static_assert(!has_legacy_stream_limit<resource_manager::limits>);
static_assert(!has_queued_bytes_reservation<resource_manager>);
static_assert(!has_relay_stream_reservation<resource_manager>);
static_assert(has_operational_dials<resource_manager>);
static_assert(has_pair_scopes<resource_manager::limits>);

BOOST_AUTO_TEST_SUITE(resource_manager_ledger_tests)

BOOST_AUTO_TEST_CASE(resource_manager_charges_peer_before_protocol_negotiation) {
   auto manager = resource_manager{resource_manager::limits{
       .peer = {.max_inbound_streams = 1, .max_streams = 1},
   }};
   auto stream = manager.reserve_stream(test_peer("unnegotiated-peer"), resource_manager::session_direction::inbound);
   BOOST_REQUIRE(stream);
   BOOST_TEST(!stream->bound());
   BOOST_TEST(!stream->service_bound());

   const auto current = manager.current();
   BOOST_TEST(current.system.inbound_streams == 1U);
   BOOST_TEST(current.transient.inbound_streams == 1U);
   BOOST_TEST(current.peers.inbound_streams == 1U);
   BOOST_TEST(current.streams.inbound_streams == 1U);
   BOOST_TEST(current.protocols.inbound_streams == 0U);
   BOOST_TEST(current.active_peer_scopes == 1U);
   BOOST_TEST(!manager.reserve_stream(test_peer("unnegotiated-peer"), resource_manager::session_direction::inbound));
}

BOOST_AUTO_TEST_CASE(resource_manager_binds_protocol_then_service_in_distinct_atomic_steps) {
   auto manager = resource_manager{};
   auto stream = manager.reserve_stream(test_peer("staged-peer"), resource_manager::session_direction::outbound);
   BOOST_REQUIRE(stream);
   BOOST_REQUIRE(stream->bind_protocol(test_protocol("/staged/1")));
   BOOST_TEST(stream->bound());
   BOOST_TEST(!stream->service_bound());
   auto protocol_bound = manager.current();
   BOOST_TEST(protocol_bound.transient.outbound_streams == 0U);
   BOOST_TEST(protocol_bound.peers.outbound_streams == 1U);
   BOOST_TEST(protocol_bound.protocols.outbound_streams == 1U);
   BOOST_TEST(protocol_bound.protocol_peers.outbound_streams == 1U);
   BOOST_TEST(protocol_bound.services.outbound_streams == 0U);

   BOOST_REQUIRE(stream->bind_service("identify"));
   BOOST_TEST(stream->service_bound());
   const auto service_bound = manager.current();
   BOOST_TEST(service_bound.services.outbound_streams == 1U);
   BOOST_TEST(service_bound.service_peers.outbound_streams == 1U);
   BOOST_TEST(service_bound.active_service_scopes == 1U);
   BOOST_TEST(service_bound.active_service_peer_scopes == 1U);
}

BOOST_AUTO_TEST_CASE(resource_manager_migrates_session_children_from_transient_to_peer) {
   auto manager = resource_manager{resource_manager::limits{
       .transient = {.max_memory = 4, .max_file_descriptors = 1},
       .connection = {.max_file_descriptors = 2},
   }};
   auto session = manager.reserve_session(resource_manager::session_direction::outbound);
   BOOST_REQUIRE(session);
   auto memory = session->reserve_memory(4);
   auto descriptors = session->reserve_file_descriptors(1);
   BOOST_REQUIRE(memory);
   BOOST_REQUIRE(descriptors);
   BOOST_REQUIRE(session->establish(
       {.peer = test_peer("session-peer"), .direction = resource_manager::session_direction::outbound}));
   BOOST_TEST(session->established());
   const auto established = manager.current();
   BOOST_TEST(established.transient.memory == 0U);
   BOOST_TEST(established.transient.file_descriptors == 0U);
   BOOST_TEST(established.peers.memory == 4U);
   BOOST_TEST(established.peers.file_descriptors == 1U);
   BOOST_TEST(established.connections.memory == 4U);
   BOOST_TEST(established.connections.file_descriptors == 1U);

   auto memory_after_migration = session->reserve_memory(2);
   auto descriptors_after_migration = session->reserve_file_descriptors(1);
   BOOST_REQUIRE(memory_after_migration);
   BOOST_REQUIRE(descriptors_after_migration);
   BOOST_TEST(manager.current().peers.memory == 6U);
   BOOST_TEST(manager.current().peers.file_descriptors == 2U);

   session.reset();
   BOOST_TEST(manager.current().connections.outbound_connections == 0U);
   BOOST_TEST(manager.current().system.memory == 6U);
   memory.reset();
   descriptors.reset();
   memory_after_migration.reset();
   descriptors_after_migration.reset();
   BOOST_TEST(manager.current().system.memory == 0U);
   BOOST_TEST(manager.current().system.file_descriptors == 0U);
}

BOOST_AUTO_TEST_CASE(resource_manager_isolates_protocol_peer_and_service_peer_limits) {
   auto manager = resource_manager{resource_manager::limits{
       .protocol_peer = {.max_streams = 1},
       .service_peer = {.max_streams = 1},
   }};
   auto first = manager.reserve_stream(test_peer("peer-a"), resource_manager::session_direction::outbound);
   BOOST_REQUIRE(first);
   BOOST_REQUIRE(first->bind_protocol(test_protocol("/shared/1")));

   auto protocol_rejected = manager.reserve_stream(test_peer("peer-a"), resource_manager::session_direction::outbound);
   BOOST_REQUIRE(protocol_rejected);
   BOOST_TEST(!protocol_rejected->bind_protocol(test_protocol("/shared/1")));
   BOOST_TEST(!protocol_rejected->bound());
   BOOST_REQUIRE(protocol_rejected->bind_protocol(test_protocol("/other/1")));

   auto other_peer = manager.reserve_stream(test_peer("peer-b"), resource_manager::session_direction::outbound);
   BOOST_REQUIRE(other_peer);
   BOOST_REQUIRE(other_peer->bind_protocol(test_protocol("/shared/1")));

   BOOST_REQUIRE(first->bind_service("shared-service"));
   BOOST_TEST(!protocol_rejected->bind_service("shared-service"));
   BOOST_TEST(!protocol_rejected->service_bound());
   BOOST_REQUIRE(other_peer->bind_service("shared-service"));
   BOOST_TEST(manager.current().active_protocol_peer_scopes == 3U);
   BOOST_TEST(manager.current().active_service_peer_scopes == 2U);
}

BOOST_AUTO_TEST_CASE(resource_manager_rejects_and_retries_staged_migrations_without_partial_accounting) {
   auto protocol_manager = resource_manager{resource_manager::limits{
       .protocol = {.max_memory = 3},
   }};
   auto first = protocol_manager.reserve_stream(test_peer("protocol-a"), resource_manager::session_direction::outbound);
   BOOST_REQUIRE(first);
   auto first_memory = first->reserve_memory(3);
   BOOST_REQUIRE(first_memory);
   BOOST_REQUIRE(first->bind_protocol(test_protocol("/limited/1")));

   auto second =
       protocol_manager.reserve_stream(test_peer("protocol-b"), resource_manager::session_direction::outbound);
   BOOST_REQUIRE(second);
   auto second_memory = second->reserve_memory(2);
   BOOST_REQUIRE(second_memory);
   const auto before_protocol = protocol_manager.current();
   BOOST_TEST(!second->bind_protocol(test_protocol("/limited/1")));
   const auto after_protocol = protocol_manager.current();
   BOOST_TEST(!second->bound());
   BOOST_TEST(after_protocol.system.memory == before_protocol.system.memory);
   BOOST_TEST(after_protocol.transient.memory == before_protocol.transient.memory);
   BOOST_TEST(after_protocol.protocols.memory == before_protocol.protocols.memory);
   BOOST_TEST(after_protocol.denied_scope_migrations == before_protocol.denied_scope_migrations + 1U);
   BOOST_REQUIRE(second->bind_protocol(test_protocol("/retry/1")));

   auto service_manager = resource_manager{resource_manager::limits{
       .service = {.max_memory = 3},
   }};
   auto service_first =
       service_manager.reserve_stream(test_peer("service-a"), resource_manager::session_direction::outbound);
   BOOST_REQUIRE(service_first);
   auto service_first_memory = service_first->reserve_memory(3);
   BOOST_REQUIRE(service_first_memory);
   BOOST_REQUIRE(service_first->bind_protocol(test_protocol("/service-a/1")));
   BOOST_REQUIRE(service_first->bind_service("limited-service"));

   auto service_second =
       service_manager.reserve_stream(test_peer("service-b"), resource_manager::session_direction::outbound);
   BOOST_REQUIRE(service_second);
   auto service_second_memory = service_second->reserve_memory(2);
   BOOST_REQUIRE(service_second_memory);
   BOOST_REQUIRE(service_second->bind_protocol(test_protocol("/service-b/1")));
   const auto before_service = service_manager.current();
   BOOST_TEST(!service_second->bind_service("limited-service"));
   const auto after_service = service_manager.current();
   BOOST_TEST(!service_second->service_bound());
   BOOST_TEST(after_service.services.memory == before_service.services.memory);
   BOOST_TEST(after_service.service_peers.memory == before_service.service_peers.memory);
   BOOST_REQUIRE(service_second->bind_service("retry-service"));
}

BOOST_AUTO_TEST_CASE(resource_manager_accessors_are_serialized_with_same_handle_transition) {
   auto manager = resource_manager{};
   auto stream = manager.reserve_stream(test_peer("concurrent-peer"), resource_manager::session_direction::outbound);
   BOOST_REQUIRE(stream);
   auto start = std::atomic_bool{false};
   auto protocol_bound = std::atomic_bool{false};
   auto observed_bound = std::atomic_bool{false};
   auto writer = std::thread{[&] {
      while (!start.load(std::memory_order_acquire)) {
      }
      protocol_bound.store(stream->bind_protocol(test_protocol("/concurrent/1")), std::memory_order_release);
   }};
   auto reader = std::thread{[&] {
      start.store(true, std::memory_order_release);
      for (auto attempt = 0; attempt < 1'000; ++attempt) {
         observed_bound.store(observed_bound.load(std::memory_order_relaxed) || stream->bound(),
                              std::memory_order_relaxed);
         static_cast<void>(stream->service_bound());
      }
   }};
   writer.join();
   reader.join();
   BOOST_TEST(protocol_bound.load(std::memory_order_acquire));
   BOOST_TEST(stream->bound());
   const auto observed_or_bound = observed_bound.load(std::memory_order_relaxed) || stream->bound();
   BOOST_TEST(observed_or_bound);
}

BOOST_AUTO_TEST_CASE(resource_manager_has_one_scope_limit_authority_and_progressive_memory_admission) {
   auto defaults = resource_manager{};
   const auto& configured = defaults.configured_limits();
   constexpr auto mib = 1024U * 1024U;
   BOOST_TEST(configured.system.max_memory == 128U * mib);
   BOOST_TEST(configured.system.max_file_descriptors == 256U);
   BOOST_TEST(configured.system.max_streams == 4096U);
   BOOST_TEST(configured.transient.max_memory == 32U * mib);
   BOOST_TEST(configured.transient.max_file_descriptors == 64U);
   BOOST_TEST(configured.transient.max_connections == 2048U);
   BOOST_TEST(configured.peer.max_memory == 64U * mib);
   BOOST_TEST(configured.peer.max_file_descriptors == 4U);
   BOOST_TEST(configured.peer.max_connections == 4U);
   BOOST_TEST(configured.peer.max_streams == 256U);
   BOOST_TEST(configured.protocol.max_memory == 64U * mib);
   BOOST_TEST(configured.protocol.max_inbound_streams == 512U);
   BOOST_TEST(configured.protocol.max_outbound_streams == 2048U);
   BOOST_TEST(configured.protocol.max_streams == 2048U);
   BOOST_TEST(configured.protocol_peer.max_memory == 16U * mib);
   BOOST_TEST(configured.protocol_peer.max_inbound_streams == 64U);
   BOOST_TEST(configured.protocol_peer.max_outbound_streams == 128U);
   BOOST_TEST(configured.protocol_peer.max_streams == 256U);
   BOOST_TEST(configured.service.max_memory == 64U * mib);
   BOOST_TEST(configured.service.max_inbound_streams == 1024U);
   BOOST_TEST(configured.service.max_outbound_streams == 4096U);
   BOOST_TEST(configured.service.max_streams == 4096U);
   BOOST_TEST(configured.service_peer.max_memory == 16U * mib);
   BOOST_TEST(configured.service_peer.max_inbound_streams == 128U);
   BOOST_TEST(configured.service_peer.max_outbound_streams == 256U);
   BOOST_TEST(configured.service_peer.max_streams == 256U);
   BOOST_TEST(configured.connection.max_memory == 32U * mib);
   BOOST_TEST(configured.connection.max_file_descriptors == 1U);
   BOOST_TEST(configured.connection.max_inbound_connections == 1U);
   BOOST_TEST(configured.connection.max_outbound_connections == 1U);
   BOOST_TEST(configured.connection.max_connections == 1U);
   BOOST_TEST(configured.stream.max_memory == 16U * mib);
   BOOST_TEST(configured.stream.max_inbound_streams == 1U);
   BOOST_TEST(configured.stream.max_outbound_streams == 1U);
   BOOST_TEST(configured.stream.max_streams == 1U);
   BOOST_TEST(configured.max_dial_attempts == 1024U);
   BOOST_TEST(configured.max_dial_attempts_per_peer == 16U);
   BOOST_TEST(configured.max_relay_reservations == 1024U);
   BOOST_TEST(configured.max_malformed_messages_per_peer == 64U);

   auto manager = resource_manager{resource_manager::limits{
       .system = {.max_memory = 100},
   }};
   auto lifecycle = manager.reserve_lifecycle();
   BOOST_REQUIRE(lifecycle);
   auto low = lifecycle->reserve_memory(39, resource_manager::memory_priority::low);
   BOOST_REQUIRE(low);
   BOOST_TEST(!lifecycle->reserve_memory(1, resource_manager::memory_priority::low));
   auto medium = lifecycle->reserve_memory(20, resource_manager::memory_priority::medium);
   BOOST_REQUIRE(medium);
   BOOST_TEST(!lifecycle->reserve_memory(1, resource_manager::memory_priority::medium));
   auto high = lifecycle->reserve_memory(20, resource_manager::memory_priority::high);
   BOOST_REQUIRE(high);
   BOOST_TEST(!lifecycle->reserve_memory(1, resource_manager::memory_priority::high));
   auto always = lifecycle->reserve_memory(21, resource_manager::memory_priority::always);
   BOOST_REQUIRE(always);
   BOOST_TEST(!lifecycle->reserve_memory(1, resource_manager::memory_priority::always));
   BOOST_TEST(manager.current().system.memory == 100U);
   BOOST_TEST(manager.current().denied_memory == 4U);

   constexpr auto unlimited_memory = (std::numeric_limits<std::uint64_t>::max)();
   auto unlimited = resource_manager{resource_manager::limits{
       .system = {.max_memory = unlimited_memory},
   }};
   auto unlimited_lifecycle = unlimited.reserve_lifecycle();
   BOOST_REQUIRE(unlimited_lifecycle);
   auto unlimited_low = unlimited_lifecycle->reserve_memory(unlimited_memory, resource_manager::memory_priority::low);
   BOOST_REQUIRE(unlimited_low);
}

BOOST_AUTO_TEST_CASE(resource_manager_enforces_directional_and_total_scope_dimensions) {
   auto inbound_connections = resource_manager{resource_manager::limits{
       .system = {.max_inbound_connections = 1},
   }};
   auto inbound_connection = inbound_connections.reserve_session(resource_manager::session_direction::inbound);
   BOOST_REQUIRE(inbound_connection);
   BOOST_TEST(!inbound_connections.reserve_session(resource_manager::session_direction::inbound));
   auto inbound_allows_outbound = inbound_connections.reserve_session(resource_manager::session_direction::outbound);
   BOOST_REQUIRE(inbound_allows_outbound);

   auto outbound_connections = resource_manager{resource_manager::limits{
       .system = {.max_outbound_connections = 1},
   }};
   auto outbound_connection = outbound_connections.reserve_session(resource_manager::session_direction::outbound);
   BOOST_REQUIRE(outbound_connection);
   BOOST_TEST(!outbound_connections.reserve_session(resource_manager::session_direction::outbound));
   auto outbound_allows_inbound = outbound_connections.reserve_session(resource_manager::session_direction::inbound);
   BOOST_REQUIRE(outbound_allows_inbound);

   auto total_connections = resource_manager{resource_manager::limits{
       .system = {.max_connections = 1},
   }};
   auto total_connection = total_connections.reserve_session(resource_manager::session_direction::inbound);
   BOOST_REQUIRE(total_connection);
   BOOST_TEST(!total_connections.reserve_session(resource_manager::session_direction::outbound));

   auto inbound_streams = resource_manager{resource_manager::limits{
       .system = {.max_inbound_streams = 1},
   }};
   auto inbound_stream =
       inbound_streams.reserve_stream(test_peer("inbound-a"), resource_manager::session_direction::inbound);
   BOOST_REQUIRE(inbound_stream);
   BOOST_TEST(!inbound_streams.reserve_stream(test_peer("inbound-b"), resource_manager::session_direction::inbound));
   auto inbound_allows_outbound_stream =
       inbound_streams.reserve_stream(test_peer("inbound-c"), resource_manager::session_direction::outbound);
   BOOST_REQUIRE(inbound_allows_outbound_stream);

   auto outbound_streams = resource_manager{resource_manager::limits{
       .system = {.max_outbound_streams = 1},
   }};
   auto outbound_stream =
       outbound_streams.reserve_stream(test_peer("outbound-a"), resource_manager::session_direction::outbound);
   BOOST_REQUIRE(outbound_stream);
   BOOST_TEST(!outbound_streams.reserve_stream(test_peer("outbound-b"), resource_manager::session_direction::outbound));
   auto outbound_allows_inbound_stream =
       outbound_streams.reserve_stream(test_peer("outbound-c"), resource_manager::session_direction::inbound);
   BOOST_REQUIRE(outbound_allows_inbound_stream);

   auto total_streams = resource_manager{resource_manager::limits{
       .system = {.max_streams = 1},
   }};
   auto total_stream = total_streams.reserve_stream(test_peer("total-a"), resource_manager::session_direction::inbound);
   BOOST_REQUIRE(total_stream);
   BOOST_TEST(!total_streams.reserve_stream(test_peer("total-b"), resource_manager::session_direction::outbound));
}

BOOST_AUTO_TEST_CASE(resource_manager_separates_policy_rejection_from_invalid_and_runtime_failures) {
   auto manager = resource_manager{resource_manager::limits{
       .system = {.max_memory = 1},
   }};
   auto lifecycle = manager.reserve_lifecycle();
   BOOST_REQUIRE(lifecycle);
   auto held = lifecycle->reserve_memory(1);
   BOOST_REQUIRE(held);
   const auto before_limit = manager.current();
   BOOST_TEST(!lifecycle->reserve_memory(1));
   const auto after_limit = manager.current();
   BOOST_TEST(after_limit.denied == before_limit.denied + 1U);
   BOOST_TEST(after_limit.denied_memory == before_limit.denied_memory + 1U);
   BOOST_TEST(after_limit.runtime_failures == before_limit.runtime_failures);

   auto stream = manager.reserve_stream(test_peer("invalid-transition"), resource_manager::session_direction::outbound);
   BOOST_REQUIRE(stream);
   const auto before_invalid = manager.current();
   BOOST_TEST(!stream->bind_service("service-before-protocol"));
   const auto after_invalid = manager.current();
   BOOST_TEST(after_invalid.denied == before_invalid.denied);
   BOOST_TEST(after_invalid.invalid_transitions == before_invalid.invalid_transitions + 1U);
   BOOST_TEST(after_invalid.runtime_failures == before_invalid.runtime_failures);
}

BOOST_AUTO_TEST_CASE(resource_manager_preserves_independent_operational_budgets) {
   auto manager = resource_manager{resource_manager::limits{
       .max_dial_attempts = 2,
       .max_dial_attempts_per_peer = 1,
       .max_relay_reservations = 1,
       .max_malformed_messages_per_peer = 1,
   }};

   auto first_dial = manager.reserve_dial();
   BOOST_REQUIRE(first_dial);
   BOOST_REQUIRE(first_dial->bind(test_peer("dial-peer-a")));
   auto second_dial = manager.reserve_dial();
   BOOST_REQUIRE(second_dial);
   BOOST_TEST(!second_dial->bind(test_peer("dial-peer-a")));
   BOOST_REQUIRE(second_dial->bind(test_peer("dial-peer-b")));
   BOOST_TEST(!manager.reserve_dial());
   const auto dials = manager.current();
   BOOST_TEST(dials.active_dials == 2U);
   BOOST_TEST(dials.dial_attempt_scopes == 2U);
   BOOST_TEST(dials.denied_dials == 2U);

   auto relay = manager.reserve_relay(resource_manager::scope{
       .peer = test_peer("relay-peer-a"),
       .protocol = test_protocol("/relay/1"),
   });
   BOOST_REQUIRE(relay);
   BOOST_TEST(!manager.reserve_relay(test_peer("relay-peer-b")));
   const auto relays = manager.current();
   BOOST_TEST(relays.active_relay_reservations == 1U);
   BOOST_TEST(relays.relay_reservation_scopes == 1U);
   BOOST_TEST(relays.denied_relays == 1U);
   relay.reset();
   auto retried_relay = manager.reserve_relay(test_peer("relay-peer-b"));
   BOOST_REQUIRE(retried_relay);

   BOOST_REQUIRE(manager.record_malformed(resource_manager::scope{
       .peer = test_peer("malformed-peer-a"),
       .protocol = test_protocol("/malformed/1"),
   }));
   BOOST_TEST(!manager.record_malformed(test_peer("malformed-peer-a")));
   BOOST_REQUIRE(manager.record_malformed(test_peer("malformed-peer-b")));
   const auto malformed = manager.current();
   BOOST_TEST(malformed.malformed_scopes == 2U);
   BOOST_TEST(malformed.denied_malformed == 1U);

   auto zero = resource_manager{resource_manager::limits{
       .max_dial_attempts = 0,
       .max_relay_reservations = 0,
       .max_malformed_messages_per_peer = 0,
   }};
   BOOST_TEST(!zero.reserve_dial());
   BOOST_TEST(!zero.reserve_relay(test_peer("zero-relay")));
   BOOST_TEST(!zero.record_malformed(test_peer("zero-malformed")));
   const auto zero_limits = zero.current();
   BOOST_TEST(zero_limits.denied == 3U);
   BOOST_TEST(zero_limits.denied_dials == 1U);
   BOOST_TEST(zero_limits.denied_relays == 1U);
   BOOST_TEST(zero_limits.denied_malformed == 1U);
   BOOST_TEST(zero_limits.invalid_transitions == 0U);

   auto zero_per_peer = resource_manager{resource_manager::limits{
       .max_dial_attempts = 1,
       .max_dial_attempts_per_peer = 0,
   }};
   auto zero_per_peer_dial = zero_per_peer.reserve_dial();
   BOOST_REQUIRE(zero_per_peer_dial);
   BOOST_TEST(!zero_per_peer_dial->bind(test_peer("zero-dial-peer")));
   const auto zero_per_peer_limits = zero_per_peer.current();
   BOOST_TEST(zero_per_peer_limits.denied == 1U);
   BOOST_TEST(zero_per_peer_limits.denied_dials == 1U);
   BOOST_TEST(zero_per_peer_limits.invalid_transitions == 0U);

   auto invalid = resource_manager{};
   auto invalid_dial = invalid.reserve_dial();
   BOOST_REQUIRE(invalid_dial);
   BOOST_TEST(!invalid_dial->bind(test_peer("")));
   BOOST_TEST(!invalid.reserve_relay(test_peer("")));
   BOOST_TEST(!invalid.record_malformed(test_peer("")));
   const auto invalid_operations = invalid.current();
   BOOST_TEST(invalid_operations.denied == 0U);
   BOOST_TEST(invalid_operations.invalid_transitions == 3U);
}

BOOST_AUTO_TEST_CASE(resource_manager_children_survive_parent_facades_and_check_overflow) {
   constexpr auto maximum_memory = (std::numeric_limits<std::uint64_t>::max)();
   constexpr auto maximum_descriptors = (std::numeric_limits<std::size_t>::max)();
   auto manager = resource_manager{resource_manager::limits{
       .system = {.max_memory = maximum_memory, .max_file_descriptors = maximum_descriptors},
       .connection = {.max_memory = maximum_memory, .max_file_descriptors = maximum_descriptors},
   }};
   auto session = manager.reserve_session(resource_manager::session_direction::outbound);
   BOOST_REQUIRE(session);
   auto memory = session->reserve_memory(maximum_memory);
   auto descriptors = session->reserve_file_descriptors(maximum_descriptors);
   BOOST_REQUIRE(memory);
   BOOST_REQUIRE(descriptors);
   BOOST_TEST(!session->reserve_memory(1));
   BOOST_TEST(!session->reserve_file_descriptors(1));
   session.reset();
   BOOST_TEST(manager.current().system.memory == maximum_memory);
   BOOST_TEST(manager.current().system.file_descriptors == maximum_descriptors);
   memory.reset();
   descriptors.reset();
   BOOST_TEST(manager.current().system.memory == 0U);
   BOOST_TEST(manager.current().system.file_descriptors == 0U);
}

BOOST_AUTO_TEST_CASE(resource_manager_serializes_concurrent_reservations) {
   auto manager = resource_manager{resource_manager::limits{
       .system = {.max_memory = 16},
   }};
   auto exceeded = std::atomic_bool{false};
   auto workers = std::vector<std::thread>{};
   workers.reserve(8);
   for (auto worker = 0; worker < 8; ++worker) {
      workers.emplace_back([&] {
         for (auto attempt = 0; attempt < 100; ++attempt) {
            auto lifecycle = manager.reserve_lifecycle();
            if (!lifecycle) {
               continue;
            }
            auto memory = lifecycle->reserve_memory(1);
            if (memory && manager.current().system.memory > 16U) {
               exceeded.store(true, std::memory_order_relaxed);
            }
         }
      });
   }
   for (auto& worker : workers) {
      worker.join();
   }
   BOOST_TEST(!exceeded.load(std::memory_order_relaxed));
   BOOST_TEST(manager.current().system.memory == 0U);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace forge::net::p2p

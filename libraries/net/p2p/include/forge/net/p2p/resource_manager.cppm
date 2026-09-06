module;

#include <boost/describe.hpp>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>

export module forge.net.p2p.resource_manager;

import forge.net.p2p.identity;
import forge.net.p2p.protocol;

export namespace forge::net::p2p {

class resource_manager {
 public:
   // Matches libp2p rcmgr admission: floor((priority + 1) * max_memory / 256).
   // A max_memory of uint64_t max remains unlimited at every priority.
   enum class memory_priority : std::uint8_t {
      low = 101,
      medium = 152,
      high = 203,
      always = 255,
   };

   struct scope_limits {
      std::uint64_t max_memory = (std::numeric_limits<std::uint64_t>::max)();
      std::size_t max_file_descriptors = (std::numeric_limits<std::size_t>::max)();
      std::size_t max_inbound_connections = (std::numeric_limits<std::size_t>::max)();
      std::size_t max_outbound_connections = (std::numeric_limits<std::size_t>::max)();
      std::size_t max_connections = (std::numeric_limits<std::size_t>::max)();
      std::size_t max_inbound_streams = (std::numeric_limits<std::size_t>::max)();
      std::size_t max_outbound_streams = (std::numeric_limits<std::size_t>::max)();
      std::size_t max_streams = (std::numeric_limits<std::size_t>::max)();
   };

   struct scope_totals {
      std::uint64_t memory = 0;
      std::size_t file_descriptors = 0;
      std::size_t inbound_connections = 0;
      std::size_t outbound_connections = 0;
      std::size_t inbound_streams = 0;
      std::size_t outbound_streams = 0;
   };

   struct limits {
      // Forge keeps fixed system concurrency until donor-style AutoScale is
      // available. Transient and subordinate scopes use the donor base limits.
      scope_limits system{
          .max_memory = 128 * 1024 * 1024,
          .max_file_descriptors = 256,
          .max_inbound_connections = 1024,
          .max_outbound_connections = 1024,
          .max_connections = 2048,
          .max_inbound_streams = 4096,
          .max_outbound_streams = 4096,
          .max_streams = 4096,
      };
      scope_limits transient{
          .max_memory = 32 * 1024 * 1024,
          .max_file_descriptors = 64,
          .max_inbound_connections = 32,
          .max_outbound_connections = 64,
          .max_connections = 64,
          .max_inbound_streams = 128,
          .max_outbound_streams = 256,
          .max_streams = 256,
      };
      scope_limits peer{
          .max_memory = 64 * 1024 * 1024,
          .max_file_descriptors = 4,
          .max_inbound_connections = 8,
          .max_outbound_connections = 8,
          .max_connections = 8,
          .max_inbound_streams = 256,
          .max_outbound_streams = 512,
          .max_streams = 512,
      };
      scope_limits protocol{
          .max_memory = 64 * 1024 * 1024,
          .max_inbound_streams = 512,
          .max_outbound_streams = 2048,
          .max_streams = 2048,
      };
      scope_limits service{
          .max_memory = 64 * 1024 * 1024,
          .max_inbound_streams = 1024,
          .max_outbound_streams = 4096,
          .max_streams = 4096,
      };
      scope_limits protocol_peer{
          .max_memory = 16 * 1024 * 1024,
          .max_inbound_streams = 64,
          .max_outbound_streams = 128,
          .max_streams = 256,
      };
      scope_limits service_peer{
          .max_memory = 16 * 1024 * 1024,
          .max_inbound_streams = 128,
          .max_outbound_streams = 256,
          .max_streams = 256,
      };
      scope_limits connection{
          .max_memory = 32 * 1024 * 1024,
          .max_file_descriptors = 1,
          .max_inbound_connections = 1,
          .max_outbound_connections = 1,
          .max_connections = 1,
      };
      scope_limits stream{
          .max_memory = 16 * 1024 * 1024,
          .max_inbound_streams = 1,
          .max_outbound_streams = 1,
          .max_streams = 1,
      };
      std::size_t max_dial_attempts = 1024;
      std::size_t max_dial_attempts_per_peer = 16;
      std::size_t max_relay_reservations = 1024;
      std::size_t max_malformed_messages_per_peer = 64;
   };

   enum class session_direction { inbound, outbound };

   // Operational context only; stream admission is owned by scope limits.
   struct scope {
      peer_id peer;
      protocol_id protocol;
   };

   struct session_scope {
      peer_id peer;
      session_direction direction = session_direction::outbound;
   };

   struct snapshot {
      scope_totals system;
      scope_totals transient;
      scope_totals peers;
      scope_totals protocols;
      scope_totals services;
      scope_totals protocol_peers;
      scope_totals service_peers;
      scope_totals connections;
      scope_totals streams;
      std::size_t active_peer_scopes = 0;
      std::size_t active_protocol_scopes = 0;
      std::size_t active_service_scopes = 0;
      std::size_t active_protocol_peer_scopes = 0;
      std::size_t active_service_peer_scopes = 0;
      std::size_t active_dials = 0;
      std::size_t active_relay_reservations = 0;
      std::size_t dial_attempt_scopes = 0;
      std::size_t relay_reservation_scopes = 0;
      std::size_t malformed_scopes = 0;
      std::uint64_t denied = 0;
      std::uint64_t denied_connections = 0;
      std::uint64_t denied_streams = 0;
      std::uint64_t denied_memory = 0;
      std::uint64_t denied_file_descriptors = 0;
      std::uint64_t denied_scope_migrations = 0;
      std::uint64_t denied_dials = 0;
      std::uint64_t denied_relays = 0;
      std::uint64_t denied_malformed = 0;
      std::uint64_t invalid_transitions = 0;
      std::uint64_t runtime_failures = 0;
   };

   class lifecycle_reservation;
   class session_reservation;
   class dial_reservation;
   class stream_reservation;
   class relay_reservation;
   class memory_reservation;
   class file_descriptor_reservation;

   resource_manager();
   explicit resource_manager(limits value);
   ~resource_manager();

   [[nodiscard]] const limits& configured_limits() const noexcept;
   [[nodiscard]] snapshot current() const noexcept;
   [[nodiscard]] std::optional<lifecycle_reservation> reserve_lifecycle() noexcept;
   [[nodiscard]] std::optional<session_reservation> reserve_session(session_direction direction) noexcept;
   [[nodiscard]] std::optional<dial_reservation> reserve_dial() noexcept;
   [[nodiscard]] std::optional<dial_reservation> reserve_dial(peer_id peer) noexcept;
   [[nodiscard]] std::optional<stream_reservation> reserve_stream(peer_id peer, session_direction direction) noexcept;
   [[nodiscard]] std::optional<relay_reservation> reserve_relay(peer_id peer) noexcept;
   [[nodiscard]] std::optional<relay_reservation> reserve_relay(scope value) noexcept;
   [[nodiscard]] bool record_malformed(peer_id peer) noexcept;
   [[nodiscard]] bool record_malformed(scope value) noexcept;

 private:
   struct state;
   struct ledger;
   struct dial_ledger;
   std::shared_ptr<state> state_;
};

class resource_manager::lifecycle_reservation {
 public:
   lifecycle_reservation() noexcept;
   ~lifecycle_reservation();
   lifecycle_reservation(lifecycle_reservation&&) noexcept;
   lifecycle_reservation& operator=(lifecycle_reservation&&) noexcept;
   lifecycle_reservation(const lifecycle_reservation&) = delete;
   lifecycle_reservation& operator=(const lifecycle_reservation&) = delete;

   [[nodiscard]] bool active() const noexcept;
   [[nodiscard]] std::optional<memory_reservation>
   reserve_memory(std::uint64_t bytes, memory_priority priority = memory_priority::always) noexcept;
   [[nodiscard]] std::optional<file_descriptor_reservation> reserve_file_descriptors(std::size_t count) noexcept;
   void release() noexcept;

 private:
   friend class resource_manager;
   lifecycle_reservation(std::shared_ptr<state> owner, std::shared_ptr<ledger> ledger) noexcept;

   std::shared_ptr<state> owner_;
   std::shared_ptr<ledger> ledger_;
};

class resource_manager::session_reservation {
 public:
   session_reservation() noexcept;
   ~session_reservation();
   session_reservation(session_reservation&&) noexcept;
   session_reservation& operator=(session_reservation&&) noexcept;
   session_reservation(const session_reservation&) = delete;
   session_reservation& operator=(const session_reservation&) = delete;

   [[nodiscard]] bool active() const noexcept;
   [[nodiscard]] bool established() const noexcept;
   [[nodiscard]] bool establish(session_scope value) noexcept;
   [[nodiscard]] std::optional<memory_reservation>
   reserve_memory(std::uint64_t bytes, memory_priority priority = memory_priority::always) noexcept;
   [[nodiscard]] std::optional<file_descriptor_reservation> reserve_file_descriptors(std::size_t count) noexcept;
   void release() noexcept;

 private:
   friend class resource_manager;
   session_reservation(std::shared_ptr<state> owner, std::shared_ptr<ledger> ledger) noexcept;

   std::shared_ptr<state> owner_;
   std::shared_ptr<ledger> ledger_;
};

class resource_manager::dial_reservation {
 public:
   dial_reservation() noexcept;
   ~dial_reservation();
   dial_reservation(dial_reservation&&) noexcept;
   dial_reservation& operator=(dial_reservation&&) noexcept;
   dial_reservation(const dial_reservation&) = delete;
   dial_reservation& operator=(const dial_reservation&) = delete;

   [[nodiscard]] bool active() const noexcept;
   [[nodiscard]] bool bound() const noexcept;
   [[nodiscard]] bool bind(peer_id peer) noexcept;
   void release() noexcept;

 private:
   friend class resource_manager;
   dial_reservation(std::shared_ptr<state> owner, std::shared_ptr<dial_ledger> ledger) noexcept;

   std::shared_ptr<state> owner_;
   std::shared_ptr<dial_ledger> ledger_;
};

class resource_manager::stream_reservation {
 public:
   stream_reservation() noexcept;
   ~stream_reservation();
   stream_reservation(stream_reservation&&) noexcept;
   stream_reservation& operator=(stream_reservation&&) noexcept;
   stream_reservation(const stream_reservation&) = delete;
   stream_reservation& operator=(const stream_reservation&) = delete;

   [[nodiscard]] bool active() const noexcept;
   [[nodiscard]] bool bound() const noexcept;
   [[nodiscard]] bool service_bound() const noexcept;
   [[nodiscard]] bool bind_protocol(protocol_id value) noexcept;
   [[nodiscard]] bool bind_service(std::string value) noexcept;
   [[nodiscard]] std::optional<memory_reservation>
   reserve_memory(std::uint64_t bytes, memory_priority priority = memory_priority::always) noexcept;
   [[nodiscard]] std::optional<file_descriptor_reservation> reserve_file_descriptors(std::size_t count) noexcept;
   void release() noexcept;

 private:
   friend class resource_manager;
   stream_reservation(std::shared_ptr<state> owner, std::shared_ptr<ledger> ledger) noexcept;

   std::shared_ptr<state> owner_;
   std::shared_ptr<ledger> ledger_;
};

class resource_manager::relay_reservation {
 public:
   relay_reservation() noexcept;
   ~relay_reservation();
   relay_reservation(relay_reservation&&) noexcept;
   relay_reservation& operator=(relay_reservation&&) noexcept;
   relay_reservation(const relay_reservation&) = delete;
   relay_reservation& operator=(const relay_reservation&) = delete;

   [[nodiscard]] bool active() const noexcept;
   void release() noexcept;

 private:
   friend class resource_manager;
   relay_reservation(std::shared_ptr<state> owner, peer_id peer) noexcept;

   std::shared_ptr<state> owner_;
   peer_id peer_;
};

class resource_manager::memory_reservation {
 public:
   memory_reservation() noexcept;
   ~memory_reservation();
   memory_reservation(memory_reservation&&) noexcept;
   memory_reservation& operator=(memory_reservation&&) noexcept;
   memory_reservation(const memory_reservation&) = delete;
   memory_reservation& operator=(const memory_reservation&) = delete;

   [[nodiscard]] bool active() const noexcept;
   [[nodiscard]] std::uint64_t bytes() const noexcept;
   void release() noexcept;

 private:
   friend class lifecycle_reservation;
   friend class session_reservation;
   friend class stream_reservation;
   memory_reservation(std::shared_ptr<state> owner, std::shared_ptr<ledger> ledger, std::uint64_t bytes) noexcept;

   std::shared_ptr<state> owner_;
   std::shared_ptr<ledger> ledger_;
   std::uint64_t bytes_ = 0;
};

class resource_manager::file_descriptor_reservation {
 public:
   file_descriptor_reservation() noexcept;
   ~file_descriptor_reservation();
   file_descriptor_reservation(file_descriptor_reservation&&) noexcept;
   file_descriptor_reservation& operator=(file_descriptor_reservation&&) noexcept;
   file_descriptor_reservation(const file_descriptor_reservation&) = delete;
   file_descriptor_reservation& operator=(const file_descriptor_reservation&) = delete;

   [[nodiscard]] bool active() const noexcept;
   [[nodiscard]] std::size_t count() const noexcept;
   void release() noexcept;

 private:
   friend class lifecycle_reservation;
   friend class session_reservation;
   friend class stream_reservation;
   file_descriptor_reservation(std::shared_ptr<state> owner, std::shared_ptr<ledger> ledger,
                               std::size_t count) noexcept;

   std::shared_ptr<state> owner_;
   std::shared_ptr<ledger> ledger_;
   std::size_t count_ = 0;
};

} // namespace forge::net::p2p

BOOST_DESCRIBE_STRUCT(forge::net::p2p::resource_manager::scope_limits, (),
                      (max_memory, max_file_descriptors, max_inbound_connections, max_outbound_connections,
                       max_connections, max_inbound_streams, max_outbound_streams, max_streams))
BOOST_DESCRIBE_STRUCT(forge::net::p2p::resource_manager::scope_totals, (),
                      (memory, file_descriptors, inbound_connections, outbound_connections, inbound_streams,
                       outbound_streams))
BOOST_DESCRIBE_STRUCT(forge::net::p2p::resource_manager::limits, (),
                      (system, transient, peer, protocol, service, protocol_peer, service_peer, connection, stream,
                       max_dial_attempts, max_dial_attempts_per_peer, max_relay_reservations,
                       max_malformed_messages_per_peer))

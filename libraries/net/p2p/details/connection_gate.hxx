#pragma once

namespace forge::net::p2p {
namespace detail {

enum class connection_gater_stage : std::size_t {
   peer_dial,
   address_dial,
   accept,
   secured,
   upgraded,
   count,
};

class connection_gate final {
 public:
   explicit connection_gate(std::shared_ptr<connection_gater> value) noexcept;

   void peer_dial(const peer_id& peer) const;
   void address_dial(const peer_id& peer, const endpoint& address) const;
   void accept(const endpoint& local, const endpoint& remote) const;
   void secured(connection_direction direction, const peer_id& peer, const endpoint& local,
                const endpoint& remote) const;
   void upgraded(connection_direction direction, const peer_id& peer, const endpoint& local,
                 const endpoint& remote) const;

   [[nodiscard]] std::uint64_t denied(connection_gater_stage stage) const noexcept;

 private:
   [[noreturn]] void reject(connection_gater_stage stage) const;

   std::shared_ptr<connection_gater> value_;
   mutable std::array<std::atomic<std::uint64_t>, static_cast<std::size_t>(connection_gater_stage::count)> denied_{};
};

} // namespace detail
} // namespace forge::net::p2p

module;

#include <forge/exceptions/macros.hpp>

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>

module forge.net.p2p.node;

import forge.net.p2p.connection_gater;
import forge.net.p2p.exceptions;

#include "details/connection_gate.hxx"

namespace forge::net::p2p::detail {
namespace {

[[nodiscard]] constexpr std::size_t index(connection_gater_stage stage) noexcept {
   return static_cast<std::size_t>(stage);
}

} // namespace

connection_gate::connection_gate(std::shared_ptr<connection_gater> value) noexcept : value_(std::move(value)) {}

void connection_gate::peer_dial(const peer_id& peer) const {
   if (value_ && !value_->intercept_peer_dial(peer)) {
      reject(connection_gater_stage::peer_dial);
   }
}

void connection_gate::address_dial(const peer_id& peer, const endpoint& address) const {
   if (value_ && !value_->intercept_address_dial(peer, address)) {
      reject(connection_gater_stage::address_dial);
   }
}

void connection_gate::accept(const endpoint& local, const endpoint& remote) const {
   if (value_ && !value_->intercept_accept(connection_endpoints{.local = local, .remote = remote})) {
      reject(connection_gater_stage::accept);
   }
}

void connection_gate::secured(connection_direction direction, const peer_id& peer, const endpoint& local,
                              const endpoint& remote) const {
   if (value_ && !value_->intercept_secured(direction, peer, connection_endpoints{.local = local, .remote = remote})) {
      reject(connection_gater_stage::secured);
   }
}

void connection_gate::upgraded(connection_direction direction, const peer_id& peer, const endpoint& local,
                               const endpoint& remote) const {
   if (value_ && !value_->intercept_upgraded(direction, peer, connection_endpoints{.local = local, .remote = remote})) {
      reject(connection_gater_stage::upgraded);
   }
}

std::uint64_t connection_gate::denied(connection_gater_stage stage) const noexcept {
   return denied_[index(stage)].load(std::memory_order_relaxed);
}

[[noreturn]] void connection_gate::reject(connection_gater_stage stage) const {
   denied_[index(stage)].fetch_add(1, std::memory_order_relaxed);
   FORGE_THROW_EXCEPTION(exceptions::connection_rejected, "P2P connection gater rejected connection");
}

} // namespace forge::net::p2p::detail

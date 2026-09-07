#pragma once

namespace forge::net::p2p::detail {

[[nodiscard]] constexpr bool remote_peer_attributable_failure(exceptions::code kind, bool stopped) noexcept {
   if (kind == exceptions::code::timeout) {
      return true;
   }
   if (stopped) {
      return false;
   }
   switch (kind) {
   case exceptions::code::invalid_options:
   case exceptions::code::invalid_identity:
   case exceptions::code::duplicate_protocol:
   case exceptions::code::backpressure_rejected:
   case exceptions::code::connection_rejected:
   case exceptions::code::canceled:
   case exceptions::code::internal:
   case exceptions::code::sequence_exhausted:
   case exceptions::code::durability_uncertain:
      return false;
   default:
      return true;
   }
}

} // namespace forge::net::p2p::detail

#pragma once

#include <atomic>
#include <map>
#include <memory>

namespace forge::net::p2p::detail {

[[nodiscard]] constexpr bool suppress_inbound_handshake_failure(exceptions::code kind, bool node_stopped) noexcept {
   return node_stopped && (kind == exceptions::code::closed || kind == exceptions::code::canceled);
}

constexpr void mark_rejected_session(bool& closed) noexcept {
   closed = true;
}

inline void mark_rejected_session(std::atomic_bool& closed) noexcept {
   closed.store(true);
}

template <typename Id, typename Session>
bool erase_current_session(std::map<Id, std::shared_ptr<Session>>& sessions, const std::shared_ptr<Session>& session) {
   const auto it = sessions.find(session->id);
   if (it == sessions.end() || it->second != session) {
      return false;
   }
   sessions.erase(it);
   return true;
}

template <typename Session> void mark_rejected_session(const std::shared_ptr<Session>& session) noexcept {
   if (!session) {
      return;
   }
   mark_rejected_session(session->closed);
}

template <typename Connection> void request_session_cancel(Connection& connection) noexcept {
   connection.request_cancel();
}

template <typename Session> void cancel_marked_session(const std::shared_ptr<Session>& session) noexcept {
   if (!session) {
      return;
   }
   request_session_cancel(session->connection);
}

template <typename Session> void cancel_rejected_session(const std::shared_ptr<Session>& session) noexcept {
   mark_rejected_session(session);
   cancel_marked_session(session);
}

} // namespace forge::net::p2p::detail

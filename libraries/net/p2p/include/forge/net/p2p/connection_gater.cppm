export module forge.net.p2p.connection_gater;

export import forge.net.p2p.endpoint;
export import forge.net.p2p.identity;

export namespace forge::net::p2p {

enum class connection_direction {
   inbound,
   outbound,
};

struct connection_endpoints {
   endpoint local;
   endpoint remote;
};

class connection_gater {
 public:
   virtual ~connection_gater() noexcept = 0;

   [[nodiscard]] virtual bool intercept_peer_dial(const peer_id& peer) noexcept;
   [[nodiscard]] virtual bool intercept_address_dial(const peer_id& peer, const endpoint& address) noexcept;
   [[nodiscard]] virtual bool intercept_accept(const connection_endpoints& endpoints) noexcept;
   [[nodiscard]] virtual bool intercept_secured(connection_direction direction, const peer_id& peer,
                                                const connection_endpoints& endpoints) noexcept;
   [[nodiscard]] virtual bool intercept_upgraded(connection_direction direction, const peer_id& peer,
                                                 const connection_endpoints& endpoints) noexcept;
};

} // namespace forge::net::p2p

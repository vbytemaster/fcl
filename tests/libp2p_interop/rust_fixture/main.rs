use std::{
    collections::HashSet,
    error::Error,
    fs,
    net::Ipv4Addr,
    num::NonZeroUsize,
    path::PathBuf,
    time::{Duration, Instant},
};

use futures::{AsyncReadExt, AsyncWriteExt, StreamExt};
use libp2p::kad::store::RecordStore;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, SwarmBuilder, autonat, dcutr, gossipsub, identify, identity,
    kad,
    multiaddr::Protocol,
    noise, ping, relay, rendezvous,
    swarm::{NetworkBehaviour, SwarmEvent},
    tcp, tls, yamux,
};
use libp2p_stream as raw_stream;
use rand::rngs::OsRng;
use serde_json::json;

const PUBSUB_TOPIC: &str = "forge.pubsub.interop";
const PUBSUB_PAYLOAD: &[u8] = b"forge-gossipsub-live";

#[derive(Debug, Default)]
struct Options {
    command: String,
    scenario: String,
    peer_id: String,
    addr: String,
    relay_addr: String,
    relay_peer_id: String,
    ready_file: PathBuf,
    stop_file: PathBuf,
    result_file: PathBuf,
    seed_file: PathBuf,
    seed_peer_id: String,
    seed_addr: String,
    target_peer_id: String,
    payload: String,
    transport: String,
    expected_messages: usize,
}

#[derive(NetworkBehaviour)]
struct Behaviour {
    autonat: autonat::v2::server::Behaviour,
    relay: relay::Behaviour,
    relay_client: relay::client::Behaviour,
    kad: kad::Behaviour<kad::store::MemoryStore>,
    rendezvous_server: rendezvous::server::Behaviour,
    rendezvous_client: rendezvous::client::Behaviour,
    gossipsub: gossipsub::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    dcutr: dcutr::Behaviour,
    stream: raw_stream::Behaviour,
}

#[derive(Debug)]
struct RendezvousRegisterDiscoverEvidence {
    wire_registration_count: usize,
    record_sequence: u64,
    record_address_count: usize,
    registered_ttl_seconds: u64,
    discovered_ttl_seconds: u64,
    cookie_bytes: usize,
}

#[derive(Debug)]
struct RendezvousLifecycleEvidence {
    initial_ttl_seconds: u64,
    updated_ttl_seconds: u64,
    renewed_ttl_seconds: u64,
    initial_record_sequence: u64,
    updated_record_sequence: u64,
    renewed_record_sequence: u64,
    pre_unregister_record_sequence: u64,
    initial_cookie_bytes: usize,
    delta_cookie_bytes: usize,
    initial_visible_count: usize,
    updated_visible_count: usize,
    renewed_visible_after_original_expiry: bool,
    renewed_visible_count: usize,
    expired_registration_count: usize,
    pre_unregister_count: usize,
    final_registration_count: usize,
}

#[derive(Debug)]
struct RelayReservationEvidence {
    accepted: bool,
    relay_peer_id: String,
    client_peer_id: String,
    circuit_addr: String,
    renewal: bool,
}

const RENDEZVOUS_LIFECYCLE_MIN_TTL_SECONDS: u64 = 2;
const RENDEZVOUS_LIFECYCLE_MAX_TTL_SECONDS: u64 = 3;
const RENDEZVOUS_LIFECYCLE_TIMING_MARGIN: Duration = Duration::from_millis(200);

fn parse_args() -> Result<Options, Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let mut out = Options::default();
    out.command = args.next().ok_or("missing command")?;
    while let Some(key) = args.next() {
        let value = args
            .next()
            .ok_or_else(|| format!("missing value for {key}"))?;
        match key.as_str() {
            "--scenario" => out.scenario = value,
            "--peer-id" => out.peer_id = value,
            "--addr" => out.addr = value,
            "--relay-addr" => out.relay_addr = value,
            "--relay-peer-id" => out.relay_peer_id = value,
            "--ready-file" => out.ready_file = PathBuf::from(value),
            "--stop-file" => out.stop_file = PathBuf::from(value),
            "--result-file" => out.result_file = PathBuf::from(value),
            "--seed-file" => out.seed_file = PathBuf::from(value),
            "--seed-peer-id" => out.seed_peer_id = value,
            "--seed-addr" => out.seed_addr = value,
            "--target-peer-id" => out.target_peer_id = value,
            "--payload" => out.payload = value,
            "--transport" => out.transport = value,
            "--expected-messages" => out.expected_messages = value.parse()?,
            "--store-dir" | "--features" => {}
            _ => return Err(format!("unknown argument {key}").into()),
        }
    }
    if out.payload.is_empty() {
        out.payload = String::from_utf8_lossy(PUBSUB_PAYLOAD).to_string();
    }
    if out.transport.is_empty() {
        out.transport = "quic".to_string();
    }
    if out.expected_messages == 0 {
        out.expected_messages = 1;
    }
    Ok(out)
}

fn write_json(path: &PathBuf, value: serde_json::Value) -> Result<(), Box<dyn Error>> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec(&value)?)?;
    Ok(())
}

fn behaviour_for(
    key: &identity::Keypair,
    relay_client: relay::client::Behaviour,
    scenario: &str,
) -> Behaviour {
    let peer = key.public().to_peer_id();
    let mut kad_config = kad::Config::new(StreamProtocol::new("/ipfs/kad/1.0.0"));
    kad_config.set_query_timeout(Duration::from_secs(10));
    let mut kad_behaviour =
        kad::Behaviour::with_config(peer, kad::store::MemoryStore::new(peer), kad_config);
    kad_behaviour.set_mode(Some(kad::Mode::Server));
    Behaviour {
        autonat: autonat::v2::server::Behaviour::new(OsRng),
        relay: relay::Behaviour::new(peer, Default::default()),
        relay_client,
        kad: kad_behaviour,
        rendezvous_server: rendezvous::server::Behaviour::new(
            if scenario == "rendezvous_lifecycle" {
                rendezvous::server::Config::default()
                    .with_min_ttl(1)
                    .with_max_ttl(3)
            } else {
                rendezvous::server::Config::default()
            },
        ),
        rendezvous_client: rendezvous::client::Behaviour::new(key.clone()),
        gossipsub: gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(key.clone()),
            gossipsub::ConfigBuilder::default()
                .protocol_id_prefix("/meshsub")
                .validation_mode(gossipsub::ValidationMode::Strict)
                .build()
                .expect("valid gossipsub config"),
        )
        .expect("valid gossipsub behaviour"),
        ping: ping::Behaviour::new(ping::Config::new()),
        identify: identify::Behaviour::new(identify::Config::new_with_signed_peer_record(
            "/forge-interop/0.1.0".into(),
            key,
        )),
        dcutr: dcutr::Behaviour::new(peer),
        stream: raw_stream::Behaviour::new(),
    }
}

async fn new_swarm(
    transport: &str,
    scenario: &str,
) -> Result<libp2p::Swarm<Behaviour>, Box<dyn Error>> {
    let key = identity::Keypair::generate_ed25519();
    let mut swarm = match transport {
        "quic" | "" => SwarmBuilder::with_existing_identity(key)
            .with_tokio()
            .with_quic()
            .with_relay_client(noise::Config::new, yamux::Config::default)?
            .with_behaviour(|key, relay_client| behaviour_for(key, relay_client, scenario))?
            .build(),
        "tcp" => SwarmBuilder::with_existing_identity(key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_relay_client(noise::Config::new, yamux::Config::default)?
            .with_behaviour(|key, relay_client| behaviour_for(key, relay_client, scenario))?
            .build(),
        "tcp-tls" => SwarmBuilder::with_existing_identity(key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                tls::Config::new,
                yamux::Config::default,
            )?
            .with_relay_client(noise::Config::new, yamux::Config::default)?
            .with_behaviour(|key, relay_client| behaviour_for(key, relay_client, scenario))?
            .build(),
        other => return Err(format!("unsupported transport {other}").into()),
    };

    let listen_addr = if transport == "tcp" || transport == "tcp-tls" {
        Multiaddr::empty()
            .with(Protocol::Ip4(Ipv4Addr::LOCALHOST))
            .with(Protocol::Tcp(0))
    } else {
        Multiaddr::empty()
            .with(Protocol::Ip4(Ipv4Addr::LOCALHOST))
            .with(Protocol::Udp(0))
            .with(Protocol::QuicV1)
    };
    swarm.listen_on(listen_addr)?;
    Ok(swarm)
}

fn dht_provider_key() -> kad::RecordKey {
    kad::RecordKey::new(&[
        0x12, 0x20, 0x2e, 0xaa, 0xd0, 0x06, 0x69, 0x42, 0x0a, 0xc7, 0x3a, 0x56, 0xd9, 0x80, 0xb7,
        0x9d, 0xeb, 0x2d, 0x2e, 0x3f, 0xb6, 0x86, 0x6d, 0x1c, 0xac, 0x9e, 0x37, 0x3f, 0x5e, 0x5d,
        0x4a, 0x62, 0xad, 0xf9,
    ])
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if value.len() % 2 != 0 {
        return Err("hex fixture has odd length".into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)?;
            Ok(u8::from_str_radix(text, 16)?)
        })
        .collect()
}

fn is_dht_value_scenario(scenario: &str) -> bool {
    scenario == "dht_pk_put_get" || scenario == "dht_ipns_put_get"
}

fn dht_value_fixture(scenario: &str) -> Result<(kad::RecordKey, Vec<u8>), Box<dyn Error>> {
    const IDENTITY_MULTIHASH: &str =
        "00240801122079b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664";
    let (prefix, value) = match scenario {
        "dht_pk_put_get" => (
            "2f706b2f",
            "0801122079b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664".to_string(),
        ),
        "dht_ipns_put_get" => (
            "2f69706e732f",
            [
                "0a1f2f697066732f6261666b716163336a6f627868676964736e3572777734796b1240b7be19b36e1955d2e1ccddd889d25c",
                "4eaef61aa72763bc44db9696697be7587e35d2efb2a625e7ac19b05f8c348086114103ee042a5a4041683e39c4ac0c460118",
                "00221e323033302d30312d30325430333a30343a30352e3132333435363738395a28073080f092cbdd0842408904024a1b09",
                "b52636334f17b9098f648f9a00214e6c6c89bb954c01300b00f54d085ddcacbe42952f2f819d70a48ff453d13329bb775d66",
                "e5a4b6165c38a40a4a76a56354544c1b00000045d964b8006556616c7565581f2f697066732f6261666b716163336a6f6278",
                "68676964736e3572777734796b6853657175656e6365076856616c6964697479581e323033302d30312d30325430333a30343a",
                "30352e3132333435363738395a6c56616c69646974795479706500",
            ]
            .concat(),
        ),
        other => return Err(format!("unknown DHT value fixture {other}").into()),
    };
    let key = decode_hex(&format!("{prefix}{IDENTITY_MULTIHASH}"))?;
    Ok((kad::RecordKey::new(&key), decode_hex(&value)?))
}

fn transport_addr(mut address: Multiaddr) -> Multiaddr {
    if matches!(address.iter().last(), Some(Protocol::P2p(_))) {
        let _ = address.pop();
    }
    address
}

fn observed_quic_transport(endpoint: &libp2p::core::ConnectedPoint) -> Option<&'static str> {
    endpoint
        .get_remote_address()
        .iter()
        .any(|protocol| matches!(protocol, Protocol::QuicV1))
        .then_some("/quic-v1")
}

async fn reserve_relay_address(
    swarm: &mut libp2p::Swarm<Behaviour>,
    relay_peer: PeerId,
    relay_addr: Multiaddr,
) -> Result<RelayReservationEvidence, Box<dyn Error>> {
    let client_peer = *swarm.local_peer_id();
    let base_circuit_addr = transport_addr(relay_addr)
        .with(Protocol::P2p(relay_peer))
        .with(Protocol::P2pCircuit);
    let expected_circuit_addr = base_circuit_addr.clone().with(Protocol::P2p(client_peer));
    let relay_listener_id = swarm.listen_on(base_circuit_addr)?;
    let mut accepted_renewal = None;
    let mut observed_circuit_addr = None;
    let deadline = tokio::time::sleep(Duration::from_secs(20));
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            _ = &mut deadline => {
                return Err("timed out waiting for relay reservation acceptance and circuit address".into());
            }
            event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { listener_id, address, .. }
                    if listener_id == relay_listener_id && address == expected_circuit_addr =>
                {
                    swarm.add_external_address(address.clone());
                    observed_circuit_addr = Some(address.to_string());
                }
                SwarmEvent::Behaviour(BehaviourEvent::RelayClient(
                    relay::client::Event::ReservationReqAccepted {
                        relay_peer_id,
                        renewal,
                        ..
                    },
                )) if relay_peer_id == relay_peer => {
                    if renewal {
                        return Err("initial relay reservation unexpectedly reported renewal=true".into());
                    }
                    accepted_renewal = Some(renewal);
                }
                other => {
                    eprintln!("rust relay reservation event: {other:?}");
                }
            },
        }
        if let (Some(renewal), Some(circuit_addr)) =
            (accepted_renewal, observed_circuit_addr.take())
        {
            return Ok(RelayReservationEvidence {
                accepted: true,
                relay_peer_id: relay_peer.to_string(),
                client_peer_id: client_peer.to_string(),
                circuit_addr,
                renewal,
            });
        }
    }
}

async fn read_frame<S>(stream: &mut S) -> Result<Vec<u8>, Box<dyn Error>>
where
    S: futures::AsyncRead + Unpin,
{
    let mut shift = 0u32;
    let mut size = 0usize;
    loop {
        let mut single = [0u8; 1];
        stream.read_exact(&mut single).await?;
        let byte = single[0];
        size |= usize::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 28 {
            return Err("frame varint is too large".into());
        }
    }
    if size == 0 || size > 256 * 1024 {
        return Err(format!("invalid frame size {size}").into());
    }
    let mut payload = vec![0; size];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn write_frame<S>(stream: &mut S, payload: &[u8]) -> Result<(), Box<dyn Error>>
where
    S: futures::AsyncWrite + Unpin,
{
    let mut value = payload.len();
    let mut prefix = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        prefix.push(byte);
        if value == 0 {
            break;
        }
    }
    stream.write_all(&prefix).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    Ok(())
}

fn spawn_incoming_stream_echo(
    swarm: &mut libp2p::Swarm<Behaviour>,
    protocol: &'static str,
) -> Result<(), Box<dyn Error>> {
    let mut control = swarm.behaviour().stream.new_control();
    let mut incoming = control.accept(StreamProtocol::new(protocol))?;
    tokio::spawn(async move {
        while let Some((_, mut stream)) = incoming.next().await {
            let payload = match read_frame(&mut stream).await.ok() {
                Some(value) => value,
                None => {
                    let _ = stream.close().await;
                    continue;
                }
            };
            let _ = write_frame(&mut stream, &payload).await;
            let _ = stream.close().await;
        }
    });
    Ok(())
}

async fn open_required_stream(
    swarm: &mut libp2p::Swarm<Behaviour>,
    peer: PeerId,
    protocol: &'static str,
) -> Result<(), Box<dyn Error>> {
    let mut control = swarm.behaviour().stream.new_control();
    let mut open = Box::pin(control.open_stream(peer, StreamProtocol::new(protocol)));
    let deadline = tokio::time::sleep(Duration::from_secs(15));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            result = &mut open => {
                let mut stream = result?;
                stream.close().await?;
                return Ok(());
            }
            _ = &mut deadline => {
                return Err(format!("timed out opening {protocol}").into());
            }
            event = swarm.select_next_some() => {
                if let SwarmEvent::NewListenAddr { address, .. } = event {
                    swarm.add_external_address(address);
                }
            }
        }
    }
}

async fn open_echo_stream_direct(
    swarm: &mut libp2p::Swarm<Behaviour>,
    peer: PeerId,
    payload: &[u8],
) -> Result<usize, Box<dyn Error>> {
    let mut control = swarm.behaviour().stream.new_control();
    let mut open =
        Box::pin(control.open_stream(peer, StreamProtocol::new("/forge/interop/relay-echo/1")));
    let deadline = tokio::time::sleep(Duration::from_secs(15));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            result = &mut open => {
                let mut stream = result?;
                write_frame(&mut stream, payload).await?;
                let echoed = read_frame(&mut stream).await?;
                stream.close().await?;
                if echoed != payload {
                    return Err("echo mismatch".into());
                }
                return Ok(echoed.len());
            }
            _ = &mut deadline => {
                return Err("timed out opening echo stream".into());
            }
            event = swarm.select_next_some() => {
                if let SwarmEvent::NewListenAddr { address, .. } = event {
                    swarm.add_external_address(address);
                }
            }
        }
    }
}

async fn expect_unknown_stream_rejection(
    swarm: &mut libp2p::Swarm<Behaviour>,
    peer: PeerId,
    protocol: &'static str,
) -> Result<String, Box<dyn Error>> {
    let mut control = swarm.behaviour().stream.new_control();
    let mut open = Box::pin(control.open_stream(peer, StreamProtocol::new(protocol)));
    let deadline = tokio::time::sleep(Duration::from_secs(15));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            result = &mut open => {
                match result {
                    Ok(mut stream) => {
                        let _ = stream.close().await;
                        return Err(format!("{protocol} unexpectedly opened").into());
                    }
                    Err(error) => return Ok(error.to_string()),
                }
            }
            _ = &mut deadline => {
                return Err(format!("timed out waiting for {protocol} rejection").into());
            }
            event = swarm.select_next_some() => {
                if let SwarmEvent::NewListenAddr { address, .. } = event {
                    swarm.add_external_address(address);
                }
            }
        }
    }
}

struct DhtFindPeerEvidence {
    closest_peers: usize,
    requests: u32,
    successes: u32,
    failures: u32,
}

async fn wait_dht_remote_ready(
    swarm: &mut libp2p::Swarm<Behaviour>,
    remote_peer: PeerId,
) -> Result<(), Box<dyn Error>> {
    let mut routing_admitted = false;
    let mut amino_advertised = false;
    let deadline = tokio::time::sleep(Duration::from_secs(20));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => {
                return Err(format!(
                    "timed out waiting for Kademlia readiness: routing_admitted={routing_admitted}, \
                     amino_advertised={amino_advertised}"
                ).into());
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::RoutingUpdated {
                        peer,
                        ..
                    })) if peer == remote_peer => {
                        routing_admitted = true;
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                        peer_id,
                        info,
                        ..
                    })) if peer_id == remote_peer => {
                        amino_advertised = info
                            .protocols
                            .iter()
                            .any(|protocol| protocol.as_ref() == "/ipfs/kad/1.0.0");
                    }
                    SwarmEvent::NewListenAddr { address, .. } => swarm.add_external_address(address),
                    _ => {}
                }
                if routing_admitted && amino_advertised {
                    return Ok(());
                }
            }
        }
    }
}

async fn wait_dht_find_peer(
    swarm: &mut libp2p::Swarm<Behaviour>,
    remote_peer: PeerId,
) -> Result<DhtFindPeerEvidence, Box<dyn Error>> {
    let mut query = None;
    let mut routing_admitted = false;
    let mut amino_advertised = false;
    let deadline = tokio::time::sleep(Duration::from_secs(20));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return Err("timed out waiting for Kademlia routing admission or closest peers".into()),
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::RoutingUpdated {
                        peer,
                        ..
                    })) if peer == remote_peer => {
                        routing_admitted = true;
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                        peer_id,
                        info,
                        ..
                    })) if peer_id == remote_peer => {
                        amino_advertised = info
                            .protocols
                            .iter()
                            .any(|protocol| protocol.as_ref() == "/ipfs/kad/1.0.0");
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        id: event_id,
                        result: kad::QueryResult::GetClosestPeers(Ok(ok)),
                        stats,
                        ..
                    })) if Some(event_id) == query => {
                        if !ok.peers.iter().any(|peer| peer.peer_id == remote_peer) {
                            return Err("Kademlia closest peers result omitted the queried Forge peer".into());
                        }
                        if stats.num_requests() == 0 || stats.num_successes() == 0 || stats.num_failures() != 0 {
                            return Err(format!(
                                "Kademlia query evidence was incomplete: requests={}, successes={}, failures={}",
                                stats.num_requests(),
                                stats.num_successes(),
                                stats.num_failures(),
                            ).into());
                        }
                        return Ok(DhtFindPeerEvidence {
                            closest_peers: ok.peers.len(),
                            requests: stats.num_requests(),
                            successes: stats.num_successes(),
                            failures: stats.num_failures(),
                        });
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        id: event_id,
                        result: kad::QueryResult::GetClosestPeers(Err(error)),
                        ..
                    })) if Some(event_id) == query => {
                        return Err(format!("Kademlia closest peers failed: {error:?}").into());
                    }
                    SwarmEvent::NewListenAddr { address, .. } => swarm.add_external_address(address),
                    _ => {}
                }
                if routing_admitted && amino_advertised && query.is_none() {
                    query = Some(swarm.behaviour_mut().kad.get_closest_peers(remote_peer));
                }
            }
        }
    }
}

struct DhtHiddenPeerEvidence {
    target_dialed: bool,
    target_connected: bool,
    routing_updated: bool,
    address_count: usize,
    followup_exact_rpc: bool,
    closest_peers: usize,
}

async fn wait_dht_hidden_peer(
    swarm: &mut libp2p::Swarm<Behaviour>,
    target_peer: PeerId,
) -> Result<DhtHiddenPeerEvidence, Box<dyn Error>> {
    if swarm.is_connected(&target_peer) {
        return Err("hidden target was connected before the Kademlia query".into());
    }
    if swarm.behaviour_mut().kad.kbuckets().any(|bucket| {
        bucket
            .iter()
            .any(|entry| entry.node.key.preimage() == &target_peer)
    }) {
        return Err("hidden target was present in Kademlia kbuckets before the query".into());
    }

    let initial_query = swarm.behaviour_mut().kad.get_closest_peers(target_peer);
    let deadline = tokio::time::sleep(Duration::from_secs(20));
    tokio::pin!(deadline);
    let mut initial_complete = false;
    let mut target_dial_connections = Vec::new();
    let mut target_dialed = false;
    let mut target_connected = false;
    let mut routing_updated = false;
    let mut address_count = 0usize;
    let mut closest_peers = 0usize;
    let mut followup_query = None;

    loop {
        tokio::select! {
            _ = &mut deadline => return Err(format!(
                "timed out waiting for hidden Kademlia peer: initial_complete={initial_complete}, \
                 target_dialed={target_dialed}, target_connected={target_connected}, \
                 routing_updated={routing_updated}, address_count={address_count}, \
                 followup_query_started={}, closest_peers={closest_peers}",
                followup_query.is_some(),
            ).into()),
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Dialing {
                        peer_id,
                        connection_id,
                    } => {
                        eprintln!(
                            "rust-hidden-dht dialing: peer_id={peer_id:?}, connection_id={connection_id:?}"
                        );
                        if peer_id.as_ref() == Some(&target_peer) {
                            target_dialed = true;
                            if !target_dial_connections.contains(&connection_id) {
                                target_dial_connections.push(connection_id);
                            }
                        }
                    }
                    SwarmEvent::ConnectionEstablished {
                        peer_id,
                        connection_id,
                        endpoint,
                        ..
                    } if peer_id == target_peer => {
                        const EVENT: &str = "rust-hidden-dht target connected";
                        let observed_target_dial = target_dial_connections.contains(&connection_id);
                        eprintln!(
                            "{EVENT}: connection_id={connection_id:?}, endpoint={endpoint:?}, \
                             observed_target_dial={observed_target_dial}"
                        );
                        if observed_target_dial {
                            target_connected = true;
                        }
                    }
                    SwarmEvent::OutgoingConnectionError {
                        peer_id,
                        connection_id,
                        error,
                    } if peer_id.as_ref() == Some(&target_peer)
                        || target_dial_connections.contains(&connection_id) =>
                    {
                        eprintln!(
                            "rust-hidden-dht target dial failed: peer_id={peer_id:?}, \
                             connection_id={connection_id:?}, error={error:?}"
                        );
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::RoutingUpdated {
                        peer,
                        addresses,
                        ..
                    })) if peer == target_peer => {
                        address_count = addresses.len();
                        routing_updated = address_count > 0;
                        eprintln!(
                            "rust-hidden-dht target routing updated: address_count={address_count}"
                        );
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetClosestPeers(Ok(ok)),
                        step,
                        ..
                    })) if id == initial_query && step.last => {
                        initial_complete = true;
                        closest_peers = ok.peers.len();
                        eprintln!(
                            "rust-hidden-dht initial query completed: id={id:?}, \
                             closest_peers={closest_peers}"
                        );
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetClosestPeers(Err(error)),
                        ..
                    })) if id == initial_query => {
                        eprintln!("rust-hidden-dht initial query failed: id={id:?}, error={error:?}");
                        return Err(format!("hidden Kademlia lookup failed: {error:?}").into());
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetClosestPeers(Ok(ok)),
                        ..
                    })) if Some(id) == followup_query => {
                        let found_target = ok.peers.iter().any(|peer| peer.peer_id == target_peer);
                        eprintln!(
                            "rust-hidden-dht follow-up query completed: id={id:?}, \
                             closest_peers={}, found_target={found_target}",
                            ok.peers.len(),
                        );
                        if !found_target {
                            return Err("follow-up Kademlia query did not contain the hidden target".into());
                        }
                        return Ok(DhtHiddenPeerEvidence {
                            target_dialed,
                            target_connected,
                            routing_updated,
                            address_count,
                            followup_exact_rpc: true,
                            closest_peers,
                        });
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetClosestPeers(Err(error)),
                        ..
                    })) if Some(id) == followup_query => {
                        eprintln!("rust-hidden-dht follow-up query failed: id={id:?}, error={error:?}");
                        return Err(format!("follow-up Kademlia query failed: {error:?}").into());
                    }
                    SwarmEvent::NewListenAddr { address, .. } => swarm.add_external_address(address),
                    _ => {}
                }

                if initial_complete
                    && target_dialed
                    && target_connected
                    && routing_updated
                    && followup_query.is_none()
                {
                    followup_query = Some(
                        swarm
                            .behaviour_mut()
                            .kad
                            .get_n_closest_peers(target_peer, NonZeroUsize::new(1).unwrap()),
                    );
                }
            }
        }
    }
}

async fn wait_dht_provide_find_provider(
    swarm: &mut libp2p::Swarm<Behaviour>,
    local_peer: PeerId,
) -> Result<usize, Box<dyn Error>> {
    let key = dht_provider_key();
    let provide_id = swarm.behaviour_mut().kad.start_providing(key.clone())?;
    let deadline = tokio::time::sleep(Duration::from_secs(30));
    tokio::pin!(deadline);
    let mut providing = false;
    loop {
        tokio::select! {
            _ = &mut deadline => return Err("timed out waiting for Kademlia provider proof".into()),
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::StartProviding(result),
                        ..
                    })) if id == provide_id => {
                        result?;
                        providing = true;
                        let _ = swarm.behaviour_mut().kad.get_providers(key.clone());
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        result: kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders { providers, .. })),
                        ..
                    })) if providing => {
                        if providers.contains(&local_peer) {
                            return Ok(providers.len());
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        result: kad::QueryResult::GetProviders(Err(error)),
                        ..
                    })) if providing => return Err(format!("Kademlia providers failed: {error:?}").into()),
                    SwarmEvent::NewListenAddr { address, .. } => swarm.add_external_address(address),
                    _ => {}
                }
            }
        }
    }
}

async fn wait_dht_put_get(
    swarm: &mut libp2p::Swarm<Behaviour>,
    scenario: &str,
    operation: &str,
) -> Result<usize, Box<dyn Error>> {
    let (key, expected) = dht_value_fixture(scenario)?;
    let mut put_id = None;
    let mut get_id = None;
    if operation == "get_only" {
        get_id = Some(swarm.behaviour_mut().kad.get_record(key.clone()));
    } else {
        put_id = Some(swarm.behaviour_mut().kad.put_record(
            kad::Record::new(key.clone(), expected.clone()),
            kad::Quorum::One,
        )?);
    }
    let deadline = tokio::time::sleep(Duration::from_secs(30));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return Err("timed out waiting for Kademlia value proof".into()),
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::PutRecord(result),
                        ..
                    })) if Some(id) == put_id => {
                        result?;
                        if operation == "put_only" {
                            return Ok(expected.len());
                        }
                        get_id = Some(swarm.behaviour_mut().kad.get_record(key.clone()));
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(found))),
                        ..
                    })) if Some(id) == get_id => {
                        if found.record.key != key || found.record.value != expected {
                            return Err("Kademlia GetRecord returned a different value".into());
                        }
                        return Ok(found.record.value.len());
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetRecord(Err(error)),
                        ..
                    })) if Some(id) == get_id => {
                        return Err(format!("Kademlia GetRecord failed: {error:?}").into());
                    }
                    SwarmEvent::NewListenAddr { address, .. } => swarm.add_external_address(address),
                    _ => {}
                }
            }
        }
    }
}

async fn wait_rendezvous_register_discover(
    swarm: &mut libp2p::Swarm<Behaviour>,
    remote_peer: PeerId,
) -> Result<RendezvousRegisterDiscoverEvidence, Box<dyn Error>> {
    let namespace = rendezvous::Namespace::new("forge.discovery".to_string())?;
    let local_peer = *swarm.local_peer_id();
    let mut expected_addresses = swarm
        .external_addresses()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    if expected_addresses.is_empty() {
        let deadline = tokio::time::sleep(Duration::from_secs(20));
        tokio::pin!(deadline);
        while expected_addresses.is_empty() {
            tokio::select! {
                _ = &mut deadline => return Err("rendezvous registration has no confirmed local address".into()),
                event = swarm.select_next_some() => match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        swarm.add_external_address(address);
                        expected_addresses = swarm
                            .external_addresses()
                            .map(ToString::to_string)
                            .collect();
                    }
                    _ => {}
                }
            }
        }
    }
    expected_addresses.sort();
    swarm
        .behaviour_mut()
        .rendezvous_client
        .register(namespace.clone(), remote_peer, None)?;
    let deadline = tokio::time::sleep(Duration::from_secs(30));
    tokio::pin!(deadline);
    let mut registered = false;
    loop {
        tokio::select! {
            _ = &mut deadline => return Err("timed out waiting for rendezvous register/discover".into()),
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(BehaviourEvent::RendezvousClient(
                        rendezvous::client::Event::Registered { rendezvous_node, ttl, .. },
                    )) if rendezvous_node == remote_peer => {
                        if ttl != 7_200 {
                            return Err(format!("rendezvous register returned TTL {ttl}, expected 7200").into());
                        }
                        registered = true;
                        swarm.behaviour_mut().rendezvous_client.discover(
                            Some(namespace.clone()),
                            None,
                            Some(10),
                            remote_peer,
                        );
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::RendezvousClient(
                        rendezvous::client::Event::Discovered { rendezvous_node, registrations, cookie },
                    )) if registered && rendezvous_node == remote_peer => {
                        if registrations.len() != 1 {
                            return Err(format!("rendezvous discover returned {} registrations, expected one", registrations.len()).into());
                        }
                        let registration = registrations.into_iter().next().expect("one registration is present");
                        let mut record_addresses = registration
                            .record
                            .addresses()
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>();
                        record_addresses.sort();
                        if registration.namespace.to_string() != "forge.discovery"
                            || registration.record.peer_id() != local_peer
                            || registration.record.seq() == 0
                            || record_addresses != expected_addresses
                            || registration.ttl != 7_200
                        {
                            return Err("rendezvous signed record did not match local peer, namespace, addresses or TTL".into());
                        }
                        let cookie_bytes = cookie.into_wire_encoding().len();
                        if cookie_bytes == 0 {
                            return Err("rendezvous discover returned an empty cookie".into());
                        }
                        return Ok(RendezvousRegisterDiscoverEvidence {
                            wire_registration_count: 1,
                            record_sequence: registration.record.seq(),
                            record_address_count: record_addresses.len(),
                            registered_ttl_seconds: 7_200,
                            discovered_ttl_seconds: registration.ttl,
                            cookie_bytes,
                        });
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::RendezvousClient(
                        rendezvous::client::Event::RegisterFailed { error, .. },
                    )) => return Err(format!("rendezvous register failed: {error:?}").into()),
                    SwarmEvent::NewListenAddr { address, .. } => swarm.add_external_address(address),
                    _ => {}
                }
            }
        }
    }
}

async fn wait_rendezvous_registered(
    swarm: &mut libp2p::Swarm<Behaviour>,
    remote_peer: PeerId,
) -> Result<u64, Box<dyn Error>> {
    let deadline = tokio::time::sleep(Duration::from_secs(20));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return Err("timed out waiting for rendezvous registration".into()),
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(BehaviourEvent::RendezvousClient(
                    rendezvous::client::Event::Registered { rendezvous_node, ttl, .. },
                )) if rendezvous_node == remote_peer => {
                    if ttl == 0 || ttl > 3 {
                        return Err(format!("rendezvous server returned unbounded TTL {ttl}").into());
                    }
                    return Ok(ttl);
                }
                SwarmEvent::Behaviour(BehaviourEvent::RendezvousClient(
                    rendezvous::client::Event::RegisterFailed { error, .. },
                )) => return Err(format!("rendezvous register failed: {error:?}").into()),
                SwarmEvent::NewListenAddr { address, .. } => swarm.add_external_address(address),
                _ => {}
            }
        }
    }
}

async fn wait_rendezvous_discovered(
    swarm: &mut libp2p::Swarm<Behaviour>,
    remote_peer: PeerId,
) -> Result<(Vec<rendezvous::Registration>, rendezvous::Cookie), Box<dyn Error>> {
    let deadline = tokio::time::sleep(Duration::from_secs(20));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return Err("timed out waiting for rendezvous discovery".into()),
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(BehaviourEvent::RendezvousClient(
                    rendezvous::client::Event::Discovered { rendezvous_node, registrations, cookie },
                )) if rendezvous_node == remote_peer => return Ok((registrations, cookie)),
                SwarmEvent::Behaviour(BehaviourEvent::RendezvousClient(
                    rendezvous::client::Event::DiscoverFailed { error, .. },
                )) => return Err(format!("rendezvous discover failed: {error:?}").into()),
                SwarmEvent::NewListenAddr { address, .. } => swarm.add_external_address(address),
                _ => {}
            }
        }
    }
}

fn rendezvous_lifecycle_ttl(ttl: u64, stage: &str) -> Result<Duration, Box<dyn Error>> {
    if !(RENDEZVOUS_LIFECYCLE_MIN_TTL_SECONDS..=RENDEZVOUS_LIFECYCLE_MAX_TTL_SECONDS).contains(&ttl)
    {
        return Err(format!(
            "rendezvous {stage} TTL {ttl} cannot support bounded renewal evidence"
        )
        .into());
    }
    Ok(Duration::from_secs(ttl))
}

fn rendezvous_expiry_deadline(
    registered_at: Instant,
    ttl: Duration,
    stage: &str,
) -> Result<Instant, Box<dyn Error>> {
    registered_at
        .checked_add(ttl)
        .and_then(|expiry| expiry.checked_sub(RENDEZVOUS_LIFECYCLE_TIMING_MARGIN))
        .ok_or_else(|| -> Box<dyn Error> {
            format!("rendezvous {stage} expiry deadline overflowed").into()
        })
}

async fn sleep_until_monotonic(deadline: Instant) {
    let now = Instant::now();
    if now < deadline {
        tokio::time::sleep(deadline.duration_since(now)).await;
    }
}

fn rendezvous_registration_count(
    registrations: &[rendezvous::Registration],
    peer: PeerId,
    sequence: u64,
    endpoint: Option<&Multiaddr>,
) -> usize {
    registrations
        .iter()
        .filter(|registration| {
            registration.record.peer_id() == peer
                && registration.record.seq() == sequence
                && endpoint
                    .is_none_or(|expected| registration.record.addresses().contains(expected))
        })
        .count()
}

fn rendezvous_peer_registration_count(
    registrations: &[rendezvous::Registration],
    peer: PeerId,
) -> usize {
    registrations
        .iter()
        .filter(|registration| registration.record.peer_id() == peer)
        .count()
}

async fn wait_rendezvous_lifecycle(
    swarm: &mut libp2p::Swarm<Behaviour>,
    remote_peer: PeerId,
) -> Result<RendezvousLifecycleEvidence, Box<dyn Error>> {
    let namespace = rendezvous::Namespace::new("forge.discovery".to_string())?;
    let local_peer = *swarm.local_peer_id();
    swarm
        .behaviour_mut()
        .rendezvous_client
        .register(namespace.clone(), remote_peer, Some(3))?;
    let initial_ttl = wait_rendezvous_registered(swarm, remote_peer).await?;
    let _ = rendezvous_lifecycle_ttl(initial_ttl, "initial")?;
    swarm.behaviour_mut().rendezvous_client.discover(
        Some(namespace.clone()),
        None,
        Some(10),
        remote_peer,
    );
    let (initial_registrations, initial_cookie) =
        wait_rendezvous_discovered(swarm, remote_peer).await?;
    let initial = initial_registrations
        .iter()
        .find(|registration| registration.record.peer_id() == local_peer)
        .ok_or("initial signed legacy peer record was not discoverable")?;
    let initial_sequence = initial.record.seq();
    let initial_visible_count =
        rendezvous_registration_count(&initial_registrations, local_peer, initial_sequence, None);
    if initial_visible_count != 1 {
        return Err(
            "rendezvous initial discovery did not contain exactly one matching record".into(),
        );
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    let updated_address = Multiaddr::empty()
        .with(Protocol::Ip4(Ipv4Addr::LOCALHOST))
        .with(Protocol::Udp(20_001))
        .with(Protocol::QuicV1);
    swarm.add_external_address(updated_address.clone());
    let updated_requested_at = Instant::now();
    swarm.behaviour_mut().rendezvous_client.register(
        namespace.clone(),
        remote_peer,
        Some(initial_ttl),
    )?;
    let updated_ttl = wait_rendezvous_registered(swarm, remote_peer).await?;
    let updated_confirmed_at = Instant::now();
    let updated_ttl_duration = rendezvous_lifecycle_ttl(updated_ttl, "updated")?;
    swarm.behaviour_mut().rendezvous_client.discover(
        Some(namespace.clone()),
        Some(initial_cookie.clone()),
        Some(10),
        remote_peer,
    );
    let (delta_registrations, delta_cookie) =
        wait_rendezvous_discovered(swarm, remote_peer).await?;
    let updated = delta_registrations
        .iter()
        .find(|registration| registration.record.peer_id() == local_peer)
        .ok_or("rendezvous cookie delta did not contain the updated peer record")?;
    let updated_sequence = updated.record.seq();
    if updated_sequence <= initial_sequence
        || !updated.record.addresses().contains(&updated_address)
        || delta_cookie == initial_cookie
    {
        return Err(
            "rendezvous update did not advance sequence, address and cookie together".into(),
        );
    }
    let updated_visible_count = rendezvous_registration_count(
        &delta_registrations,
        local_peer,
        updated_sequence,
        Some(&updated_address),
    );
    if updated_visible_count != 1 {
        return Err("rendezvous cookie delta did not contain exactly one updated record".into());
    }

    let original_renewal_deadline =
        rendezvous_expiry_deadline(updated_requested_at, updated_ttl_duration, "original")?;
    let renewal_due = updated_confirmed_at + updated_ttl_duration / 2;
    if renewal_due >= original_renewal_deadline {
        return Err("rendezvous original TTL left no bounded renewal window".into());
    }
    sleep_until_monotonic(renewal_due).await;
    let renewed_requested_at = Instant::now();
    if renewed_requested_at >= original_renewal_deadline {
        return Err("rendezvous renewal started after original expiry window".into());
    }
    swarm.behaviour_mut().rendezvous_client.register(
        namespace.clone(),
        remote_peer,
        Some(updated_ttl),
    )?;
    let renewed_ttl = wait_rendezvous_registered(swarm, remote_peer).await?;
    let renewed_confirmed_at = Instant::now();
    let renewed_ttl_duration = rendezvous_lifecycle_ttl(renewed_ttl, "renewed")?;
    if renewed_confirmed_at >= original_renewal_deadline {
        return Err("rendezvous renewal was not confirmed before original expiry".into());
    }

    let original_expiry_latest = updated_confirmed_at + updated_ttl_duration;
    let renewed_visibility_time = original_expiry_latest + RENDEZVOUS_LIFECYCLE_TIMING_MARGIN;
    let renewed_visibility_deadline =
        rendezvous_expiry_deadline(renewed_requested_at, renewed_ttl_duration, "renewed")?;
    if renewed_visibility_time >= renewed_visibility_deadline {
        return Err("rendezvous TTL left no bounded post-expiry renewal proof window".into());
    }
    sleep_until_monotonic(renewed_visibility_time).await;
    let renewed_visibility_started_at = Instant::now();
    if renewed_visibility_started_at >= renewed_visibility_deadline {
        return Err("rendezvous renewal visibility probe started after renewed expiry".into());
    }
    swarm.behaviour_mut().rendezvous_client.discover(
        Some(namespace.clone()),
        None,
        Some(10),
        remote_peer,
    );
    let (renewed_registrations, _) = wait_rendezvous_discovered(swarm, remote_peer).await?;
    let renewed_visibility_completed_at = Instant::now();
    if renewed_visibility_completed_at >= renewed_visibility_deadline {
        return Err("rendezvous renewal visibility probe completed after renewed expiry".into());
    }
    let renewed = renewed_registrations
        .iter()
        .find(|registration| {
            registration.record.peer_id() == local_peer
                && registration.record.addresses().contains(&updated_address)
        })
        .ok_or("rendezvous renewed record was not visible after original expiry")?;
    let renewed_sequence = renewed.record.seq();
    if renewed_sequence <= updated_sequence {
        return Err("rendezvous renewal did not advance the signed peer record sequence".into());
    }
    let renewed_visible_count = rendezvous_registration_count(
        &renewed_registrations,
        local_peer,
        renewed_sequence,
        Some(&updated_address),
    );
    if renewed_visible_count != 1 {
        return Err(
            "rendezvous renewal discovery did not contain exactly one renewed record".into(),
        );
    }

    sleep_until_monotonic(
        renewed_confirmed_at + renewed_ttl_duration + RENDEZVOUS_LIFECYCLE_TIMING_MARGIN,
    )
    .await;
    swarm.behaviour_mut().rendezvous_client.discover(
        Some(namespace.clone()),
        None,
        Some(10),
        remote_peer,
    );
    let (expired_registrations, _) = wait_rendezvous_discovered(swarm, remote_peer).await?;
    let expired_registration_count =
        rendezvous_peer_registration_count(&expired_registrations, local_peer);
    if expired_registration_count != 0 {
        return Err("rendezvous registration survived its returned TTL".into());
    }

    let pre_unregister_requested_at = Instant::now();
    swarm.behaviour_mut().rendezvous_client.register(
        namespace.clone(),
        remote_peer,
        Some(renewed_ttl),
    )?;
    let pre_unregister_ttl = wait_rendezvous_registered(swarm, remote_peer).await?;
    let pre_unregister_ttl_duration =
        rendezvous_lifecycle_ttl(pre_unregister_ttl, "pre-unregister")?;
    let pre_unregister_deadline = rendezvous_expiry_deadline(
        pre_unregister_requested_at,
        pre_unregister_ttl_duration,
        "pre-unregister",
    )?;
    swarm.behaviour_mut().rendezvous_client.discover(
        Some(namespace.clone()),
        None,
        Some(10),
        remote_peer,
    );
    let (pre_unregister_registrations, _) = wait_rendezvous_discovered(swarm, remote_peer).await?;
    let pre_unregister = pre_unregister_registrations
        .iter()
        .find(|registration| {
            registration.record.peer_id() == local_peer
                && registration.record.addresses().contains(&updated_address)
        })
        .ok_or("rendezvous registration was not visible before unregister")?;
    let pre_unregister_sequence = pre_unregister.record.seq();
    if pre_unregister_sequence <= renewed_sequence {
        return Err(
            "rendezvous pre-unregister registration did not advance the signed peer record sequence".into(),
        );
    }
    let pre_unregister_count = rendezvous_registration_count(
        &pre_unregister_registrations,
        local_peer,
        pre_unregister_sequence,
        Some(&updated_address),
    );
    if pre_unregister_count != 1 {
        return Err(
            "rendezvous pre-unregister discovery did not contain exactly one matching record"
                .into(),
        );
    }
    swarm
        .behaviour_mut()
        .rendezvous_client
        .unregister(namespace.clone(), remote_peer);
    swarm
        .behaviour_mut()
        .rendezvous_client
        .discover(Some(namespace), None, Some(10), remote_peer);
    let (final_registrations, _) = wait_rendezvous_discovered(swarm, remote_peer).await?;
    if Instant::now() >= pre_unregister_deadline {
        return Err("rendezvous unregister proof exceeded the registration TTL window".into());
    }
    let final_registration_count =
        rendezvous_peer_registration_count(&final_registrations, local_peer);
    if final_registration_count != 0 {
        return Err("rendezvous unregister did not remove the confirmed registration".into());
    }
    Ok(RendezvousLifecycleEvidence {
        initial_ttl_seconds: initial_ttl,
        updated_ttl_seconds: updated_ttl,
        renewed_ttl_seconds: renewed_ttl,
        initial_record_sequence: initial_sequence,
        updated_record_sequence: updated_sequence,
        renewed_record_sequence: renewed_sequence,
        pre_unregister_record_sequence: pre_unregister_sequence,
        initial_cookie_bytes: initial_cookie.into_wire_encoding().len(),
        delta_cookie_bytes: delta_cookie.into_wire_encoding().len(),
        initial_visible_count,
        updated_visible_count,
        renewed_visible_after_original_expiry: true,
        renewed_visible_count,
        expired_registration_count,
        pre_unregister_count,
        final_registration_count,
    })
}

async fn wait_gossipsub_peer_and_publish(
    swarm: &mut libp2p::Swarm<Behaviour>,
    remote_peer: PeerId,
    payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    let topic = gossipsub::IdentTopic::new(PUBSUB_TOPIC);
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    let deadline = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return Err("timed out waiting for gossipsub subscription exchange".into()),
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(
                        gossipsub::Event::Subscribed { peer_id, topic: subscribed_topic },
                    )) if peer_id == remote_peer && subscribed_topic == topic.hash() => {
                        swarm.behaviour_mut().gossipsub.publish(topic.clone(), payload)?;
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        return Ok(());
                    }
                    SwarmEvent::NewListenAddr { address, .. } => swarm.add_external_address(address),
                    _ => {}
                }
            }
        }
    }
}

async fn listen(opts: Options) -> Result<(), Box<dyn Error>> {
    let mut swarm = new_swarm(&opts.transport, &opts.scenario).await?;
    spawn_incoming_stream_echo(&mut swarm, "/forge/interop/relay-echo/1")?;
    if opts.scenario == "gossipsub_publish" || opts.scenario == "gossipsub_mixed_mesh_stress" {
        let topic = gossipsub::IdentTopic::new(PUBSUB_TOPIC);
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    }
    let peer = *swarm.local_peer_id();
    let mut ready = false;
    let mut seeded = false;
    let mut dht_seed_dial_started = false;
    let mut dht_seed_query = None;
    let dht_seed_peer = if opts.scenario == "dht_hidden_find_peer" && !opts.seed_peer_id.is_empty()
    {
        Some(opts.seed_peer_id.parse::<PeerId>()?)
    } else {
        None
    };
    let mut payloads = HashSet::<String>::new();
    let mut duplicates = 0usize;
    let expected_record = if is_dht_value_scenario(&opts.scenario) {
        Some(dht_value_fixture(&opts.scenario)?)
    } else {
        None
    };
    let mut record_reported = false;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if ready && !record_reported {
                    if let Some((key, expected)) = &expected_record {
                        let found = swarm
                            .behaviour_mut()
                            .kad
                            .store_mut()
                            .get(key)
                            .is_some_and(|record| record.value == *expected);
                        if found {
                            write_json(
                                &opts.result_file,
                                json!({
                                    "implementation": "rust",
                                    "role": "listener",
                                    "scenario": opts.scenario,
                                    "status": "ok",
                                    "record_persisted": true
                                }),
                            )?;
                            record_reported = true;
                        }
                    }
                }
                if ready && !seeded && opts.scenario == "gossipsub_mixed_mesh_stress" && opts.seed_file.exists() {
                    let seeds = fs::read_to_string(&opts.seed_file)?;
                    for line in seeds.lines().filter(|line| !line.is_empty()) {
                        if let Ok(address) = line.parse::<Multiaddr>() {
                            if !address.to_string().contains(&peer.to_string()) {
                                let _ = swarm.dial(address);
                            }
                        }
                    }
                    seeded = true;
                }
                if ready && !seeded && !dht_seed_dial_started && opts.scenario == "dht_hidden_find_peer" {
                    let seed_peer = dht_seed_peer.ok_or("dht_hidden_find_peer routing listener requires --seed-peer-id")?;
                    if opts.seed_addr.is_empty() || opts.result_file.as_os_str().is_empty() {
                        return Err("dht_hidden_find_peer routing listener requires --seed-addr and --result-file".into());
                    }
                    let seed_addr = opts.seed_addr.parse::<Multiaddr>()?;
                    if !seed_addr.to_string().contains(&seed_peer.to_string()) {
                        return Err("dht_hidden_find_peer seed address does not contain the supplied peer id".into());
                    }
                    swarm.dial(seed_addr)?;
                    dht_seed_dial_started = true;
                }
                if ready && opts.stop_file.exists() {
                    if opts.scenario == "gossipsub_mixed_mesh_stress" {
                        let status = if payloads.len() >= opts.expected_messages && duplicates == 0 {
                            "ok"
                        } else {
                            "mismatch"
                        };
                        write_json(
                            &opts.result_file,
                            json!({
                                "implementation": "rust",
                                "scenario": "gossipsub_mixed_mesh_stress",
                                "status": status,
                                "received": payloads.len(),
                                "expected": opts.expected_messages,
                                "duplicates": duplicates,
                                "payloads": payloads.iter().cloned().collect::<Vec<_>>()
                            }),
                        )?;
                    }
                    return Ok(());
                }
            }
            event = swarm.select_next_some() => {
                eprintln!("rust-listen event: {event:?}");
                match event {
                    SwarmEvent::NewListenAddr { address, .. } => {
                        swarm.add_external_address(address.clone());
                        if !ready {
                            write_json(&opts.ready_file, json!({
                                "implementation": "rust",
                                "role": "listener",
                                "peer_id": peer.to_string(),
                                "listen_addrs": [format!("{address}/p2p/{peer}")],
                                "transport": opts.transport.clone(),
                                "status": "ready"
                            }))?;
                            ready = true;
                        }
                    }
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. }
                        if opts.scenario == "dht_hidden_find_peer" &&
                            dht_seed_peer.is_some_and(|seed_peer| seed_peer == peer_id) =>
                    {
                        swarm.behaviour_mut().kad.add_address(&peer_id, transport_addr(endpoint.get_remote_address().clone()));
                        dht_seed_query = Some(swarm.behaviour_mut().kad.get_closest_peers(PeerId::random()));
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetClosestPeers(Ok(_)),
                        ..
                    })) if opts.scenario == "dht_hidden_find_peer" && Some(id) == dht_seed_query => {
                        let seed_peer = dht_seed_peer.ok_or("missing DHT seed peer")?;
                        write_json(
                            &opts.result_file,
                            json!({
                                "implementation": "rust",
                                "role": "routing_listener",
                                "scenario": opts.scenario,
                                "status": "ok",
                                "seed_peer_id": seed_peer.to_string(),
                                "authenticated_seed": true,
                                "dht_queries_delta": 1,
                                "negotiated_protocol": "/ipfs/kad/1.0.0"
                            }),
                        )?;
                        seeded = true;
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Kad(kad::Event::OutboundQueryProgressed {
                        id,
                        result: kad::QueryResult::GetClosestPeers(Err(error)),
                        ..
                    })) if opts.scenario == "dht_hidden_find_peer" && Some(id) == dht_seed_query => {
                        return Err(format!("DHT seed query failed: {error:?}").into());
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(
                        gossipsub::Event::Message {
                            propagation_source,
                            message,
                            ..
                        },
                    )) if opts.scenario == "gossipsub_publish" => {
                            let status = if message.data == PUBSUB_PAYLOAD { "ok" } else { "mismatch" };
                            write_json(
                                &opts.result_file,
                                json!({
                                    "implementation": "rust",
                                    "scenario": "gossipsub_publish",
                                    "status": status,
                                    "topic": message.topic.to_string(),
                                    "payload": String::from_utf8_lossy(&message.data).to_string(),
                                    "propagation_source": propagation_source.to_string(),
                                    "source": message.source.map(|peer| peer.to_string()).unwrap_or_default()
                                }),
                            )?;
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Gossipsub(
                        gossipsub::Event::Message { message, .. },
                    )) if opts.scenario == "gossipsub_mixed_mesh_stress" => {
                        let payload = String::from_utf8_lossy(&message.data).to_string();
                        if !payloads.insert(payload) {
                            duplicates += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn dial(opts: Options) -> Result<(), Box<dyn Error>> {
    let mut swarm = new_swarm(&opts.transport, &opts.scenario).await?;
    let remote_peer: PeerId = opts.peer_id.parse()?;
    let remote: Multiaddr = opts.addr.parse()?;
    if opts.scenario == "gossipsub_publish" {
        let topic = gossipsub::IdentTopic::new(PUBSUB_TOPIC);
        swarm.behaviour_mut().gossipsub.subscribe(&topic)?;
    }
    swarm.dial(remote.clone())?;
    let started = Instant::now();
    let mut connected = false;
    let mut ping_ok = false;
    let mut identify_count = 0usize;
    let mut identify_signed_record = false;
    let mut authenticated_remote_peer_id = None;
    let mut negotiated_transport = None;
    while started.elapsed() < Duration::from_secs(20) {
        match swarm.select_next_some().await {
            SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } if peer_id == remote_peer => {
                eprintln!("rust-dial connected: {peer_id}");
                connected = true;
                authenticated_remote_peer_id = Some(peer_id.to_string());
                negotiated_transport = observed_quic_transport(&endpoint);
                swarm
                    .behaviour_mut()
                    .kad
                    .add_address(&remote_peer, transport_addr(remote.clone()));
                if opts.scenario != "ping" && opts.scenario != "identify" {
                    break;
                }
            }
            SwarmEvent::NewListenAddr { address, .. } => {
                swarm.add_external_address(address);
            }
            SwarmEvent::Behaviour(BehaviourEvent::Ping(ping::Event { peer, result, .. }))
                if peer == remote_peer =>
            {
                eprintln!("rust-dial ping: {result:?}");
                ping_ok = result.is_ok();
                if opts.scenario == "ping" {
                    break;
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                peer_id,
                info,
                ..
            })) if peer_id == remote_peer => {
                eprintln!("rust-dial identify: protocols={}", info.protocols.len());
                identify_count = info.protocols.len();
                identify_signed_record = info.signed_peer_record.is_some();
                if opts.scenario == "identify" {
                    break;
                }
            }
            other => {
                eprintln!("rust-dial event: {other:?}");
            }
        }
    }
    if !connected {
        return Err("connection was not established".into());
    }
    if matches!(
        opts.scenario.as_str(),
        "dht_provide_find_provider" | "dht_pk_put_get" | "dht_ipns_put_get"
    ) {
        wait_dht_remote_ready(&mut swarm, remote_peer).await?;
    }
    match opts.scenario.as_str() {
        "ping" if !ping_ok => return Err("ping did not complete".into()),
        "identify" if identify_count == 0 => return Err("identify did not return protocols".into()),
        "autonatv2" => {
            open_required_stream(&mut swarm, remote_peer, "/libp2p/autonat/2/dial-request").await?;
        }
        "relay_reserve" => {
            let reservation =
                reserve_relay_address(&mut swarm, remote_peer, remote.clone()).await?;
            write_json(
                &opts.result_file,
                json!({
                    "implementation": "rust",
                    "role": "dialer",
                    "scenario": opts.scenario,
                    "status": "ok",
                    "negotiated_transport": negotiated_transport,
                    "authenticated_remote_peer_id": authenticated_remote_peer_id,
                    "relay_reservation_accepted": reservation.accepted,
                    "relay_reservation_relay_peer_id": reservation.relay_peer_id,
                    "relay_reservation_client_peer_id": reservation.client_peer_id,
                    "relay_reservation_circuit_addr": reservation.circuit_addr,
                    "relay_reservation_renewal": reservation.renewal
                }),
            )?;
            return Ok(());
        }
        "echo" | "echo_large" => {
            let payload = if opts.scenario == "echo_large" {
                (0..192 * 1024)
                    .map(|index| (index % 251) as u8)
                    .collect::<Vec<_>>()
            } else {
                opts.payload.as_bytes().to_vec()
            };
            let bytes = open_echo_stream_direct(&mut swarm, remote_peer, &payload).await?;
            write_json(
                &opts.result_file,
                json!({
                    "implementation": "rust",
                    "role": "dialer",
                    "scenario": opts.scenario,
                    "status": "ok",
                    "protocol": "/forge/interop/relay-echo/1",
                    "payload_bytes": bytes,
                    "echo_ok": true
                }),
            )?;
            return Ok(());
        }
        "dcutr" => {
            open_required_stream(&mut swarm, remote_peer, "/libp2p/dcutr").await?;
        }
        "dht_find_peer" => {
            let evidence = wait_dht_find_peer(&mut swarm, remote_peer).await?;
            write_json(
                &opts.result_file,
                json!({
                    "implementation": "rust",
                    "role": "dialer",
                    "scenario": opts.scenario,
                    "status": "ok",
                    "closest_peers": evidence.closest_peers,
                    "query_requests": evidence.requests,
                    "query_successes": evidence.successes,
                    "query_failures": evidence.failures
                }),
            )?;
            return Ok(());
        }
        "dht_hidden_find_peer" => {
            let target_peer: PeerId = opts.target_peer_id.parse()?;
            if target_peer == remote_peer {
                return Err("hidden target must differ from the known routing peer".into());
            }
            let evidence = wait_dht_hidden_peer(&mut swarm, target_peer).await?;
            write_json(
                &opts.result_file,
                json!({
                    "implementation": "rust",
                    "role": "dialer",
                    "scenario": opts.scenario,
                    "status": "ok",
                    "preexisting_target": false,
                    "found_peer": target_peer.to_string(),
                    "target_dialed": evidence.target_dialed,
                    "target_connected": evidence.target_connected,
                    "routing_updated": evidence.routing_updated,
                    "address_count": evidence.address_count,
                    "followup_exact_rpc": evidence.followup_exact_rpc,
                    "closest_peers": evidence.closest_peers,
                    "dht_queries_delta": 1,
                    "negotiated_protocol": "/ipfs/kad/1.0.0"
                }),
            )?;
            return Ok(());
        }
        "dht_provide_find_provider" => {
            let local_peer = *swarm.local_peer_id();
            let count = wait_dht_provide_find_provider(&mut swarm, local_peer).await?;
            write_json(
                &opts.result_file,
                json!({
                    "implementation": "rust",
                    "role": "dialer",
                    "scenario": opts.scenario,
                    "status": "ok",
                    "provider_count": count
                }),
            )?;
            return Ok(());
        }
        "dht_pk_put_get" | "dht_ipns_put_get" => {
            let bytes = wait_dht_put_get(&mut swarm, &opts.scenario, &opts.payload).await?;
            let operation = match opts.payload.as_str() {
                "put_only" => "put_only",
                "get_only" => "get_only",
                _ => "put_get",
            };
            write_json(
                &opts.result_file,
                json!({
                    "implementation": "rust",
                    "role": "dialer",
                    "scenario": opts.scenario,
                    "status": "ok",
                    "operation": operation,
                    "remote_get": operation == "get_only",
                    "value_bytes": bytes
                }),
            )?;
            return Ok(());
        }
        "rendezvous_register_discover" => {
            let evidence = wait_rendezvous_register_discover(&mut swarm, remote_peer).await?;
            write_json(
                &opts.result_file,
                json!({
                    "implementation": "rust",
                    "role": "dialer",
                    "scenario": opts.scenario,
                    "status": "ok",
                    "negotiated_protocol": "/rendezvous/1.0.0",
                    "wire_registration_count": evidence.wire_registration_count,
                    "signed_peer_record_valid": true,
                    "matching_peer_record": true,
                    "record_sequence": evidence.record_sequence,
                    "record_address_count": evidence.record_address_count,
                    "registered_ttl_seconds": evidence.registered_ttl_seconds,
                    "discovered_ttl_seconds": evidence.discovered_ttl_seconds,
                    "cookie_bytes": evidence.cookie_bytes
                }),
            )?;
            return Ok(());
        }
        "rendezvous_lifecycle" => {
            let evidence = wait_rendezvous_lifecycle(&mut swarm, remote_peer).await?;
            write_json(
                &opts.result_file,
                json!({
                    "implementation": "rust",
                    "role": "dialer",
                    "scenario": opts.scenario,
                    "status": "ok",
                    "negotiated_protocol": "/rendezvous/1.0.0",
                    "legacy_signed_peer_record": true,
                    "initial_ttl_seconds": evidence.initial_ttl_seconds,
                    "updated_ttl_seconds": evidence.updated_ttl_seconds,
                    "renewed_ttl_seconds": evidence.renewed_ttl_seconds,
                    "initial_record_sequence": evidence.initial_record_sequence,
                    "updated_record_sequence": evidence.updated_record_sequence,
                    "renewed_record_sequence": evidence.renewed_record_sequence,
                    "pre_unregister_record_sequence": evidence.pre_unregister_record_sequence,
                    "initial_cookie_bytes": evidence.initial_cookie_bytes,
                    "delta_cookie_bytes": evidence.delta_cookie_bytes,
                    "cookie_changed": true,
                    "initial_visible_count": evidence.initial_visible_count,
                    "updated_visible_count": evidence.updated_visible_count,
                    "renewed_visible_after_original_expiry": evidence.renewed_visible_after_original_expiry,
                    "renewed_visible_count": evidence.renewed_visible_count,
                    "expired_registration_count": evidence.expired_registration_count,
                    "pre_unregister_count": evidence.pre_unregister_count,
                    "final_registration_count": evidence.final_registration_count
                }),
            )?;
            return Ok(());
        }
        "gossipsub_publish" | "gossipsub_mixed_mesh_stress" => {
            wait_gossipsub_peer_and_publish(&mut swarm, remote_peer, opts.payload.as_bytes())
                .await?;
            write_json(
                &opts.result_file,
                json!({
                    "implementation": "rust",
                    "role": "dialer",
                    "scenario": opts.scenario,
                    "status": "ok",
                    "topic": PUBSUB_TOPIC,
                    "payload": opts.payload,
                    "payload_bytes": opts.payload.len(),
                    "mesh_peer": true
                }),
            )?;
            return Ok(());
        }
        "unknown_protocol" => {
            let error = expect_unknown_stream_rejection(
                &mut swarm,
                remote_peer,
                "/forge/interop/unknown/1",
            )
            .await?;
            write_json(
                &opts.result_file,
                json!({
                    "implementation": "rust",
                    "role": "dialer",
                    "scenario": opts.scenario,
                    "status": "ok",
                    "expected_error": error
                }),
            )?;
            return Ok(());
        }
        _ => {}
    }
    write_json(
        &opts.result_file,
        json!({
            "implementation": "rust",
            "role": "dialer",
            "scenario": opts.scenario,
            "status": "ok",
            "ping_ok": ping_ok,
            "protocol_count": identify_count,
            "signed_peer_record": identify_signed_record,
            "negotiated_transport": negotiated_transport,
            "authenticated_remote_peer_id": authenticated_remote_peer_id
        }),
    )
}

async fn destination(opts: Options) -> Result<(), Box<dyn Error>> {
    let mut swarm = new_swarm(&opts.transport, &opts.scenario).await?;
    spawn_incoming_stream_echo(&mut swarm, "/forge/interop/relay-echo/1")?;
    let peer = *swarm.local_peer_id();
    let relay_addr: Multiaddr = opts.relay_addr.parse()?;
    swarm.listen_on(relay_addr.clone().with(Protocol::P2pCircuit))?;
    let started = Instant::now();
    let mut relay_addrs = Vec::new();
    let mut reservation = false;
    while started.elapsed() < Duration::from_secs(30) {
        let event = swarm.select_next_some().await;
        eprintln!("rust-destination event: {:?}", event);
        match event {
            SwarmEvent::NewListenAddr { address, .. } => {
                swarm.add_external_address(address.clone());
                if address.to_string().contains("p2p-circuit") {
                    relay_addrs.push(address.to_string());
                    reservation = true;
                }
            }
            SwarmEvent::ExternalAddrConfirmed { address } => {
                if address.to_string().contains("p2p-circuit") {
                    relay_addrs.push(address.to_string());
                    reservation = true;
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::RelayClient(
                relay::client::Event::ReservationReqAccepted { .. },
            )) => {
                reservation = true;
                if relay_addrs.is_empty() {
                    relay_addrs.push(
                        relay_addr
                            .clone()
                            .with(Protocol::P2pCircuit)
                            .with(Protocol::P2p(peer))
                            .to_string(),
                    );
                }
                if !relay_addrs.is_empty() {
                    break;
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received {
                info,
                ..
            })) => {
                swarm.add_external_address(info.observed_addr);
            }
            _ => {}
        }
    }
    if !reservation || relay_addrs.is_empty() {
        return Err("relay reservation was not established".into());
    }
    write_json(
        &opts.ready_file,
        json!({
            "implementation": "rust",
            "role": "destination",
            "peer_id": peer.to_string(),
            "relay_addrs": relay_addrs,
            "relay_peer_id": opts.relay_peer_id,
            "native_relay_transport": true,
            "status": "ready"
        }),
    )?;
    loop {
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                if opts.stop_file.exists() {
                    return Ok(());
                }
            }
            event = swarm.select_next_some() => {
                if let SwarmEvent::NewListenAddr { address, .. } = event {
                    swarm.add_external_address(address);
                }
            }
        }
    }
}

async fn open_echo_stream(
    swarm: &mut libp2p::Swarm<Behaviour>,
    peer: PeerId,
    expect_direct_upgrade: bool,
) -> Result<bool, Box<dyn Error>> {
    let mut control = swarm.behaviour().stream.new_control();
    let mut open =
        Box::pin(control.open_stream(peer, StreamProtocol::new("/forge/interop/relay-echo/1")));
    let deadline = tokio::time::sleep(Duration::from_secs(30));
    tokio::pin!(deadline);
    let mut direct_upgrade = false;
    loop {
        tokio::select! {
            result = &mut open => {
                let mut stream = result?;
                write_frame(&mut stream, b"relay-echo").await?;
                let echoed = read_frame(&mut stream).await?;
                stream.close().await?;
                if echoed != b"relay-echo" {
                    return Err("relay echo mismatch".into());
                }
                if expect_direct_upgrade && !direct_upgrade {
                    let settle = tokio::time::sleep(Duration::from_secs(5));
                    tokio::pin!(settle);
                    loop {
                        tokio::select! {
                            _ = &mut settle => return Ok(direct_upgrade),
                                event = swarm.select_next_some() => {
                                    if let SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } = event {
                                        if peer_id == peer && !format!("{endpoint:?}").contains("P2pCircuit") {
                                            return Ok(true);
                                        }
                                    }
                                }
                        }
                    }
                }
                return Ok(direct_upgrade);
            }
            _ = &mut deadline => {
                return Err("timed out opening relay echo stream".into());
            }
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id, endpoint, .. } if peer_id == peer => {
                        if !format!("{endpoint:?}").contains("P2pCircuit") {
                            direct_upgrade = true;
                        }
                    }
                    SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                        swarm.add_external_address(info.observed_addr);
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn dial_and_wait(
    swarm: &mut libp2p::Swarm<Behaviour>,
    peer: PeerId,
    address: Multiaddr,
) -> Result<(), Box<dyn Error>> {
    swarm.dial(address)?;
    let deadline = tokio::time::sleep(Duration::from_secs(20));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => return Err("timed out connecting relay".into()),
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::ConnectionEstablished { peer_id, .. } if peer_id == peer => return Ok(()),
                    SwarmEvent::Behaviour(BehaviourEvent::Identify(identify::Event::Received { info, .. })) => {
                        swarm.add_external_address(info.observed_addr);
                    }
                    _ => {}
                }
            }
        }
    }
}

async fn dial_relay(opts: Options) -> Result<(), Box<dyn Error>> {
    let mut swarm = new_swarm(&opts.transport, &opts.scenario).await?;
    let target_peer: PeerId = opts.peer_id.parse()?;
    let relay_peer: PeerId = opts.relay_peer_id.parse()?;
    let relay_addr: Multiaddr = opts.relay_addr.parse()?;
    dial_and_wait(&mut swarm, relay_peer, relay_addr.clone()).await?;
    let target_addr = relay_addr
        .with(Protocol::P2pCircuit)
        .with(Protocol::P2p(target_peer));
    swarm.dial(target_addr.clone())?;
    let direct_upgrade = open_echo_stream(
        &mut swarm,
        target_peer,
        opts.scenario == "dcutr_relay_topology",
    )
    .await?;
    if opts.scenario == "dcutr_relay_topology" && !direct_upgrade {
        return Err("DCUtR did not produce a direct connection".into());
    }
    write_json(
        &opts.result_file,
        json!({
            "implementation": "rust",
            "role": "relay_dialer",
            "scenario": opts.scenario,
            "status": "ok",
            "relay_peer": relay_peer.to_string(),
            "target_peer": target_peer.to_string(),
            "relayed_addr": target_addr.to_string(),
            "relay_echo": true,
            "direct_upgrade": direct_upgrade
        }),
    )
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let opts = parse_args()?;
    match opts.command.as_str() {
        "listen" => listen(opts).await,
        "destination" => destination(opts).await,
        "dial" => dial(opts).await,
        "dial-relay" => dial_relay(opts).await,
        _ => Err(format!("unknown command {}", opts.command).into()),
    }
}

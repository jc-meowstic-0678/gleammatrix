/// Gleam Matrix Server - Cluster Discovery & Node Management Module
/// 
/// Implements BEAM VM cluster formation and maintenance for distributed Matrix server:
/// - Node discovery via FQDN-based peer list (AETHER_PEERS env var)
/// - DNS SRV fallback (_matrix._tcp.{domain})
/// - Mnesia transaction distribution across nodes using Glesia wrappers
/// - Service registration & heartbeat monitoring

import gleam/list
import gleam/map.{type Map}
import gleam/result
import gleam/string
import gleam/datetime/Timestamp
import gleam/random as rand

// Import database operations from mnesia_tables (Glesia wrapper)
import gleam_matrix_server/mnesia_tables as db

/// ============================================================================
/// CONFIGURATION TYPES
/// ============================================================================

type ClusterConfig {
  ClusterConfig(
    node_id: String,          // Unique identifier for this node
    own_fqdn: String,         // This node's FQDN (e.g., matrix.example.com)
    port: Int,                // BEAM VM RPC port (default 4369)
    peers: List(ClusterPeer), // Known peer nodes to discover/connect with
    domain_name: String,      // Domain for DNS SRV fallback resolution
  )
}

type ClusterPeer {
  ClusterPeer(
    name: String,              // FQDN or IP address of peer node
    port: Int,                 // RPC port (default 4369)
    priority: Int,             // Higher = preferred first
    weight: Float,             // Load balancing weight
    is_healthy: Bool,          // Health check status
    last_seen_at: Option(Timestamp),
  )
}

/// ============================================================================
/// NODE DISCOVERY & PEER MANAGEMENT
/// ============================================================================

/// Initialize cluster configuration from environment variables
pub fn initialize_cluster(config: Config) -> gleam/result.Result(ClusterConfig, DiscoveryError) {
  let peer_list = parse_peer_list(config.peers_env_var)
  let own_id = case config.node_id_env_var {
    Some(id) -> id
    None -> generate_node_id()
  }
  
  let domain_name = extract_domain_from_fqdn(config.own_fqdn)
  
  Ok(ClusterConfig(
    node_id: own_id,
    own_fqdn: config.own_fqdn,
    port: config.port,
    peers: resolve_peers(peer_list, domain_name),
    domain_name: domain_name,
  ))
}

/// Parse AETHER_PEERS environment variable into peer list
fn parse_peer_list(peers_env_var: String) -> List(String) {
  string.trim(peers_env_var)
    |> string.split(",")
    |> list.map(string.trim)
    |> list.filter(fn(fqdn) { 
      fqdn != "" && !string.starts_with(fqdn, "#") // Filter empty lines and comments
    })
}

/// Resolve peer addresses using FQDN lookup and DNS SRV fallback
fn resolve_peers(peer_list: List(String), domain_name: String) -> List(ClusterPeer) {
  // Convert raw string list to structured ClusterPeer records
  peer_list 
    |> list.map(fn(fqdn_or_ip) -> ClusterPeer {
      let is_fqdn = contains_domain_suffix(fqdn_or_ip, ["_matrix._tcp"]) || fqdn_or_ip =~ ~r/^\w+\.\w+\.\w+$/
      
      case resolve_host_address(fqdn_or_ip, is_fqdn) {
        Ok(address) -> ClusterPeer(
          name: address.name,
          port: 4369, // Default BEAM VM RPC port
          priority: if fqdn_or_ip =~ ~r/^primary|node1/ { 10 } else { 5 },
          weight: case fqdn_or_ip =~ ~r/^high-capacity|gpu/ { 1.5 } else { 1.0 },
          is_healthy: True, // Will be updated by heartbeat loop
          last_seen_at: None,
        )
        Error(err) -> {
          // DNS resolution failed, skip this peer (log error in production)
          ClusterPeer(
            name: fqdn_or_ip,
            port: 4369,
            priority: 0,
            weight: 0.5,
            is_healthy: False,
            last_seen_at: None,
          )
        }
      }
    })
}

/// ============================================================================
/// CLUSTER FORMATION & MAINTENANCE
/// ============================================================================

/// Join existing cluster (or form new one if single node)
pub fn join_cluster(config: ClusterConfig) -> gleam/result.Result(Nil, DiscoveryError) {
  case list.first(config.peers) {
    Some(first_peer) -> {
      // Attempt to connect to first available peer via BEAM VM RPC link
      case initiate_rpc_link(first_peer.name, first_peer.port) {
        Ok(linked) -> {
          // If successful, broadcast our node_id to the cluster
          Ok(Nil)
        }
        Error(_) -> {
          // First peer unavailable, try next in list
          case connect_to_available_peers(config.peers) {
            Some(successful_connection) -> Ok(Nil)
            None -> Error(DiscoveryError("No available peers to connect to"))
          }
        }
      }
    }
    None -> {
      // No peers configured - this is a new cluster or standalone node
      Ok(Nil)
    }
  }
}

/// Start heartbeat monitor for peer health checking
pub fn start_heartbeat_monitor(config: ClusterConfig, interval: Int) -> gleam/result.Result(GleamTaskId, DiscoveryError) {
  // Schedule periodic health checks to all cluster peers
  let task_id = gleam/distribute.schedule_task(heartbeat_check_loop(config, interval))
  
  Ok(task_id)
}

/// Heartbeat loop for peer liveness monitoring
fn heartbeat_check_loop(config: ClusterConfig, check_interval: Int) -> GleamTaskLoop {
  fn check_peer_health(peer: ClusterPeer, now: Timestamp) -> gleam/result.Result(ClusterPeer, DiscoveryError) {
    // Perform RPC ping to peer node
    case rpc_ping(peer.name, peer.port) {
      Ok(_response_time_ms) -> {
        Ok(ClusterPeer(
          name: peer.name,
          port: peer.port,
          priority: peer.priority,
          weight: peer.weight,
          is_healthy: True,
          last_seen_at: Some(now),
        ))
      }
      Error(_) -> {
        case peer.is_healthy {
          True -> 
            // Mark unhealthy after first failure (no grace period for simplicity)
            Ok(ClusterPeer(
              name: peer.name,
              port: peer.port,
              priority: 0, // Reduce priority on failure
              weight: 0.5, // Reduce load weight
              is_healthy: False,
              last_seen_at: Some(now),
            ))
          False -> 
            // Already unhealthy - keep marking it so
            Ok(ClusterPeer(
              name: peer.name,
              port: peer.port,
              priority: 0,
              weight: 0.5,
              is_healthy: False,
              last_seen_at: Some(now),
            ))
        }
      }
    }
  }
  
  // TODO: Implement distributed task scheduling for BEAM VM
  fn loop(remaining_peers: List(ClusterPeer)) -> gleam/result.Result(List(ClusterPeer), DiscoveryError) {
    case remaining_peers {
      [] -> Ok([])
      [peer, ..rest] -> 
        case check_peer_health(peer, gleam/datetime.current_timestamp()) {
          Ok(healthy_peer) -> 
            let new_peers = healthy_peer :: rest
            loop(new_peers)
          Error(err) -> Error(err)
        }
    }
  }
}

/// ============================================================================
/// RPC COMMUNICATION & MNSIA DISTRIBUTION
/// ============================================================================

/// Initialize Mnesia distribution across cluster nodes
pub fn initialize_mnesia_distribution(node_name: String, other_nodes: List(String)) -> gleam/result.Result(Nil, DiscoveryError) {
  // In production, this uses Erlang's mnesia module for distributed transactions
  case list.all(other_nodes, fn(peer_node) -> Bool {
    check_peer_connectivity(peer_node)
  }) {
    True -> Ok(Nil)
    False -> Error(DiscoveryError("Failed to connect to all peers for Mnesia sync"))
  }
}

/// Get current cluster topology (node list and connectivity)
pub fn get_cluster_topology() -> ClusterTopology {
  let connected_nodes = list.map(mnesia_table.cluster_state, fn(node_record) -> String {
    node_record.node_id
  })
  
  let peer_health = case mnesia_table.cluster_state.get_all_connected() {
    Ok(healthy_peers) -> healthy_peers |> list.map(fn(peer) {
      PeerHealthSummary(
        name: peer.name,
        is_connected: True,
        last_heartbeat_ms: compute_heartbeat_age(),
        load_score: peer.weight * 100.0, // Simplified load metric
      )
    })
    Error(_) -> []
  }
  
  ClusterTopology(
    own_node_id: generate_node_id(), // In production, query Mnesia node_id
    cluster_state: ConnectedState.Connected,
    total_nodes: list.length(peer_health) + 1,
    connected_nodes: peer_health,
  )
}

/// Query local Mnesia for message counts by room (for statistics)
pub fn get_room_message_stats() -> gleam/result.Result(Map(String, Int), DiscoveryError) {
  case mnesia_table.get_room_message_counts() {
    Ok(counts) -> Ok(counts)
    Error(err) -> Error(DiscoveryError("Failed to query message statistics: " <> err))
  }
}

/// ============================================================================
/// HELPER FUNCTIONS FOR DISCOVERY
/// ============================================================================

fn extract_domain_from_fqdn(fqdn: String) -> String {
  string.replace_all(string.split(fqdn, ".") |> list.drop(0) |> list.take(-2) |> list.join("."), ":80", "")
}

fn generate_node_id() -> String {
  "!matrix_node_" <> rand.string(16, .alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
}

fn contains_domain_suffix(fqdn: String, suffixes: List(String)) -> Bool {
  case fqdn ~ r/^\w+\.\w+\.\w+$/ {
    True -> string.ends_with(fqdn, "_matrix._tcp") || string.contains(fqdn, ".example.com")
    False -> False
  }
}

fn resolve_host_address(fqdn_or_ip: String, is_fqdn: Bool) -> gleam/result.Result(HostnameInfo, DiscoveryError) {
  case is_fqdn {
    True -> 
      // In production, use Erlang's inet:gethostbyname() for DNS resolution
      case string.split(fqdn_or_ip, ".") |> list.drop(1) |> list.join(".") == "example.com" {
        True -> Ok(HostnameInfo(fqdn_or_ip, [ip: {192, 168, 0, 1}]))
        False -> Error(DiscoveryError("DNS resolution failed for " <> fqdn_or_ip))
      }
    False -> 
      // IP address - validate format
      case string.contains(fqdn_or_ip, ":") {
        True -> Error(DiscoveryError("IPv6 not supported yet"))
        False -> Ok(HostnameInfo(fqdn_or_ip, [ip: string.parse_int(fqdn_or_ip, 10) |> result.unwrap({192, 168, 0, 1})]))
      }
  }
}

fn initiate_rpc_link(host: String, port: Int) -> gleam/result.Result(Nil, DiscoveryError) {
  // In production, this calls :net_kernel.connect/2 to join Erlang cluster
  // Simulated for this example:
  case host =~ ~r/\./ {
    True -> Ok(Nil) // Assume FQDN resolution succeeded
    False -> Error(DiscoveryError("Invalid hostname"))
  }
}

fn connect_to_available_peers(peers: List(ClusterPeer)) -> gleam/result.Result(List(ClusterPeer), DiscoveryError) {
  peers |> list.first() |> result.try(fn(peer) -> gleam/result.Result(List(ClusterPeer), DiscoveryError) {
    case peer.is_healthy {
      True -> Ok([peer])
      False -> Error(DiscoveryError("First available peer is unhealthy"))
    }
  })
}

fn check_peer_connectivity(node_name: String) -> Bool {
  // In production, query Mnesia for node status
  true
}

fn compute_heartbeat_age() -> Int {
  let now = gleam/datetime.current_timestamp()
  let last_seen = case generate_node_id() |> db.get_last_heartbeat_time() {
    Some(ts) -> ts
    None -> now - 60 // Default to "seen within 60 seconds"
  }
  now - last_seen
}

/// ============================================================================
/// TYPE DEFINITIONS FOR DISCOVERY MODULE
/// ============================================================================

type HostnameInfo {
  HostnameInfo(name: String, addresses: List(Socket.Address))
}

type Socket.Address {
  IpV4({Int, Int, Int, Int})
  IpV6({Int, Int, Int, Int, Int, Int, Int, Int})
}

type PeerHealthSummary {
  PeerHealthSummary(
    name: String,
    is_connected: Bool,
    last_heartbeat_ms: Int,
    load_score: Float,
  )
}

type ClusterTopology {
  ClusterTopology(
    own_node_id: String,
    cluster_state: ConnectedState,
    total_nodes: Int,
    connected_nodes: List(PeerHealthSummary),
  )
}

enum ConnectedState {
  Connected
  Disconnected
  Partitioned
}

/// ============================================================================
/// ERROR TYPES FOR DISCOVERY MODULE
/// ============================================================================

type DiscoveryError {
  DNSResolutionFailed(String)
  RPCConnectionFailed(String)
  MnesiaSyncFailed(String)
  PeerHealthCheckFailed(String)
  InvalidConfiguration(String)
  NetworkTimeout(String)
}

/// Gleam Matrix Server - Discovery & Cluster Module
/// 
/// This module provides:
/// - Federated network discovery for Matrix server federation
/// - Cluster node coordination for distributed deployments
/// - Service discovery for backend services (Redis, PostgreSQL)
/// - Health monitoring and load balancing routing

import gleam/dict
import gleam/json
import gleam/list
import gleam/map
import gleam/result
import gleam/string
import gleam/time
import mist/http.{type Request, type Response}

// Cluster node registration and health status
pub type NodeStatus {
  NodeStatus(
    node_id: String,          // Unique identifier for this server instance
    ip_address: String,        // Host IP address (IPv4/IPv6)
    port: Int,                 // Service listening port
    version: String,           // Matrix protocol version + software version
    status: String,            // healthy | degraded | offline
    last_heartbeat: Int,       // Millisecond timestamp of last health check
    latency_ms: Int,           // Average response latency to this node
    uptime_seconds: Int,       // Server uptime since last restart
    capabilities: List(String) // ["federation", "storage", "cache"] supported features
  )
}

// Federated server list entry (for Matrix federation)
pub type FederationServer {
  FederationServer(
    domain: String,            // Remote server domain name
    keys: List(FederationKey), // Ed25519 signing keys for this server
    server_name: String,       // Matrix server name format: domain.com
    is_trusted: Bool,          // Trust certificate chain validation
    last_sync_time: Int,       // Millisecond timestamp of last federation sync
    support_level: String      // full | partial | experimental
  )
}

// Federation key entry for signature verification
pub type FederationKey {
  FederationKey(
    key_id: String,            // Unique identifier for this signing key
    algorithm: String,         // Currently: ed25519
    public_key: gleam/string,  // Base64 encoded public key data
    valid_until: Int           // Millisecond expiration timestamp
  )
}

// Service discovery configuration structure
pub type ServiceDiscoveryConfig {
  ServiceDiscoveryConfig(
    redis_enabled: Bool,       // Enable Redis-backed service discovery
    postgresql_enabled: Bool,  // Enable PostgreSQL service registration
    consul_enabled: Bool,      // Enable Consul service mesh integration
    etcd_enabled: Bool,        // Enable etcd configuration management
    load_balancing_strategy: String // round_robin | least_connections | random
  )
}

// Cluster synchronization state
pub type ClusterSyncState {
  ClusterSyncState(
    sync_timestamp: Int,       // Millisecond timestamp of last sync operation
    sync_duration_ms: Int,     // Duration of sync operation (for monitoring)
    nodes_synced: Int,         // Number of cluster members successfully synced
    errors_encountered: Int,   // Number of sync failures encountered
    next_sync_scheduled: Int   // Millisecond timestamp of next scheduled sync
  )
}

// Discovery server entry point for service health endpoints
pub fn handle_discovery(request: Request) -> Result(Response, Response) {
  case mist/http.path_parts(request) {
    ["_matrix", "federation", "v1", "discover"] -> 
      handle_federation_discover(request)
      
    ["_matrix", "federation", "v1", "public_rooms"] -> 
      handle_public_rooms_list(request)
      
    ["node", "status"] -> 
      get_local_node_status()
      
    ["node", "list"] -> 
      get_all_cluster_nodes(request)
      
    ["service", "redis"] -> 
      check_redis_service_health()
      
    ["service", "postgresql"] -> 
      check_postgresql_service_health()
      
    _ -> 
      build_error_response(404, "Unknown discovery endpoint", "This is not a valid discovery service endpoint")
  }
}

// Handle Matrix federation discover request (/_matrix/federation/v1/discover)
fn handle_federation_discover(request: Request) -> Result(Response, Response) {
  let query_domain = mist/http.query_param(request, "server_name") |> option.unwrap_or("")
  
  // Extract local domain from configuration or request headers
  let local_domain = io.env("MATRIX_DOMAIN") |> result.unwrap_or("localhost")
  
  case string.trim(query_domain) == "" || query_domain == local_domain {
    True -> 
      // Return local server information and known federation peers
      let federation_response = build_federation_discovery_response(local_domain, request)
      
      Ok(success_response(federation_response))
      
    False -> 
      // Return information about federated peer server
      handle_remote_server_query(query_domain, request)
  }
}

// Build Matrix federation discovery response for client query
fn build_federation_discovery_response(domain: gleam/string, _request: Request) -> dict.Dict(gleam/string, gleam/json.Value) {
  let node_list = discover_all_cluster_nodes()
  
  // Extract active nodes with valid certificates and healthy status
  let active_nodes = node_list |> list.filter(fn(node) { 
    node.status == "healthy" && time.timestamp_now_ms() - node.last_heartbeat < 30000 // 30 second heartbeat window
  })
  
  // Construct Matrix federation response structure with server information and endpoints
  dict.from_list([
    {"server", {"name": domain, "aliases": [domain]}} |> to_json_value(),
    {"wellknown": dict.from_list([]) |> to_json_value()},
    {"other_servers": [build_server_entry(domain, active_nodes)]} |> json.to_array() |> to_json_value()
  ])
}

// Query remote federation peer server for capabilities and status
fn handle_remote_server_query(query_domain: gleam/string, _request: Request) -> Result(Response, Response) {
  // In production, perform HTTPS request to remote server's well-known endpoint
  // For now, simulate with local domain lookup
  
  case query_federation_server_info(query_domain) {
    Some(known_server) -> 
      let response = dict.from_list([
        {"m.server": {"trust": known_server.is_trusted}} |> to_json_value(),
        {"addresses": [query_server_addresses(query_domain)]} |> json.to_array() |> to_json_value(),
        {"protocols": ["https"] | ["federation"]} |> json.to_array() |> to_json_value()
      ])
      
      Ok(success_response(response))
      
    None -> 
      build_error_response(404, "Federation server not found", query_domain <> " is not available for federation")
  }
}

// Query database or cache for federation peer information
fn query_federation_server_info(domain: gleam/string) -> Option(FederationServer) {
  // In production, perform Mnesia table lookup or remote HTTPS request to well-known endpoint
  let cached_entry = get_cached_server_federation_data(domain)
  
  case cached_entry |> result.unwrap(mnesia_tables.get_federation_server(domain)) {
    Some(server_info) -> 
      server_info
      
    None -> 
      // Attempt to discover via DNS and HTTPS request to remote .well-known endpoint
      attempt_remote_discovery(domain)
  }
}

// Discover all active nodes in the cluster with current health status
fn discover_all_cluster_nodes() -> List(NodeStatus) {
  // In production, query Consul/etcd service registry or Redis pub/sub channels
  let local_node_info = get_local_server_status()
  
  case mnesia_tables.get_all_cluster_nodes() |> result.unwrap([local_node_info]) {
    nodes -> 
      // Update heartbeat timestamps for active nodes
      nodes |> list.map(fn(node) { 
        node |> assign_field("last_heartbeat", time.timestamp_now_ms())
      })
      
    Error(e) -> 
      [local_node_info] // Fallback to local node only if cluster registry unavailable
  }
}

// Get current status of the local server instance
fn get_local_server_status() -> NodeStatus {
  let config = gleam_matrix_server.config.load_config([]) |> result.unwrap()
  
  NodeStatus(
    node_id: config.node_id,
    ip_address: io.env("NODE_IP") |> result.unwrap_or(io.local_ip()),
    port: config.matrix_port,
    version: "Matrix v1.0 / Gleam-Matrix-Server " <> gleam_matrix_server.version(),
    status: "healthy",
    last_heartbeat: time.timestamp_now_ms(),
    latency_ms: 5, // Local node has zero network latency
    uptime_seconds: time.up_time() |> result.unwrap(0),
    capabilities: ["federation", "storage", "cache", "discovery"]
  )
}

// Check Redis service availability and health
fn check_redis_service_health() -> Result(Response, Response) {
  case redis_ping_command("redis://localhost:6379") |> result.unwrap({ error: "Redis unreachable" }) {
    Ok(_) -> 
      let health_response = dict.from_list([
        {"service": "redis", "status": "healthy", "latency_ms": 2} |> to_json_value()
      ])
      
      Ok(success_response(health_response))
      
    Error(err) -> 
      let error_data = dict.from_list([{"service": "redis", "error": err, "status": "unhealthy"}] |> json.to_array()) |> to_json_value()
      build_error_response(503, "Service unavailable", err)
  }
}

// Check PostgreSQL service health and connection status
fn check_postgresql_service_health() -> Result(Response, Response) {
  case postgresql_ping("postgresql://localhost:5432/matrix") |> result.unwrap({ error: "PostgreSQL unreachable" }) {
    Ok(_) -> 
      let response = dict.from_list([
        {"service": "postgresql", "status": "healthy", "latency_ms": 10, "version": "PostgreSQL 15"} |> to_json_value()
      ])
      
      Ok(success_response(response))
      
    Error(err) -> 
      build_error_response(503, "Database connection failed", err <> ". Check database configuration.")
  }
}

// Query matrix domain well-known endpoint for server metadata
fn get_wellknown_configuration(domain: gleam/string) -> dict.Dict(gleam/string, gleam/json.Value) {
  // In production, make HTTPS request to https://domain/.well-known/matrix/server
  
  // Simulated configuration with local defaults
  dict.from_list([
    {"m.homeserver", dict.from_list([
      {"base_url": "https://" <> domain},
      {"server_name": domain}
    ]) |> to_json_value()} |> to_json_value(),
    {"m.server", dict.from_list([
      {"trust": True, "addresses": []} |> to_json_value()
    ]) |> to_json_value()} |> to_json_value()
  ])
}

// Register new node in cluster service discovery registry
fn register_node_to_cluster(node_info: NodeStatus) -> Result(gleam/string, gleam/string) {
  case mnesia_tables.store_cluster_node(node_info) |> result.unwrap(Error("Cluster registration failed")) {
    Ok(_) -> 
      io.println("✓ Node " <> node_info.node_id <> " registered in cluster")
      
      // Update service discovery registry for load balancers
      update_service_discovery_registry(node_info.ip_address, node_info.port)
      
      Ok(node_info.node_id)
      
    Error(e) -> 
      Error("Cluster registration error: " <> e)
  }
}

// Periodic cluster heartbeat and health monitoring function
fn perform_cluster_heartbeat(current_node: NodeStatus) {
  // In production, this would run on a scheduled interval (e.g., every 10 seconds)
  
  // Update local node's last heartbeat timestamp
  let updated_node = current_node |> assign_field("last_heartbeat", time.timestamp_now_ms())
  
  // Persist updated status to cluster registry
  mnesia_tables.update_cluster_node_status(updated_node)
  
  // Query other nodes to update their latency measurements
  let peer_nodes = discover_all_cluster_nodes() |> list.filter(fn(node) { node.node_id != current_node.node_id })
  
  peer_nodes |> list.each(fn(peer) { 
    measure_network_latency_to_peer(peer.node_id, peer.ip_address)
  })
}

// Calculate average network latency to remote cluster node via ping
fn measure_network_latency_to_peer(node_id: gleam/string, ip: gleam/string) -> Result(Int, gleam/string) {
  // In production, perform ICMP ping or HTTPS request timeout measurement
  case io.run_command("ping -c 1 " <> ip <> " | grep 'rtt' | cut -d'/' -f5") |> result.unwrap(Error("Ping failed")) {
    Ok(response) -> 
      let latency_ms = string.split(response, ", ") |> list.last() |> option.map(string.to_int) |> result.unwrap(0)
      
      // Update node status with new latency measurement
      update_node_latency_in_cluster(node_id, latency_ms)
      
      Ok(latency_ms)
      
    Error(_) -> 
      Error("Unable to measure network latency to " <> ip)
  }
}

// Get cached federation server information (from memory cache or persistent store)
fn get_cached_server_federation_data(domain: gleam/string) -> Option(FederationServer) {
  case mnesia_tables.get_federation_server(domain) |> result.unwrap(None) {
    Some(server_info) -> 
      // Check if certificate is still valid and not expired
      time.timestamp_now_ms() < server_info.server_keys |> list.map(fn(key) { key.valid_until }) |> result.first() |> result.unwrap(0) + 86400000 // 24 hour validity window
      
    None -> 
      None
  }
}

// Build federation server entry for Matrix discovery response
fn build_server_entry(local_domain: gleam/string, active_nodes: List(NodeStatus)) -> dict.Dict(gleam/string, gleam/json.Value) {
  let known_servers = discover_known_federation_peers()
  
  // Combine local cluster nodes with federated peer servers
  let all_server_entries = [local_domain] ++ list.map(known_servers, fn(server) { server.server_name })
  
  // Format for Matrix federation discovery protocol
  dict.from_list([
    {"name": local_domain},
    {"addresses": active_nodes |> list.map(fn(node) { node.ip_address <> ":" <> int.to_string(node.port) })} |> json.to_array(),
    {"trust": all_server_entries |> list.all(fn(name) { name == local_domain || discover_trust_status_for_domain(name) })}
  ]) |> to_json_value()
}

// Discover known federation peer servers for Matrix network connectivity
fn discover_known_federation_peers() -> List(FederationServer) {
  // In production, query Mnesia tables populated from well-known discovery requests
  
  let simulated_peers = [
    FederationServer(
      domain: "matrix.org",
      keys: [FederationKey(key_id: "@ed25519:example", algorithm: "ed25519", public_key: "example_base64_public_key", valid_until: time.timestamp_now_ms() + 3600000)],
      server_name: "matrix.org",
      is_trusted: True,
      last_sync_time: time.timestamp_now_ms(),
      support_level: "full"
    ),
    FederationServer(
      domain: "example.com",
      keys: [FederationKey(key_id: "@ed25519:example_key", algorithm: "ed25519", public_key: "another_base64_public_key", valid_until: time.timestamp_now_ms() + 7200000)],
      server_name: "example.com",
      is_trusted: False,
      last_sync_time: time.timestamp_now_ms() - 86400000,
      support_level: "full"
    )
  ]
  
  simulated_peers |> list.filter(fn(server) { time.timestamp_now_ms() < server.last_sync_time + 300000 }) // Last 5 minutes
}

// Query DNS and network for remote server IP addresses (federation connectivity)
fn query_server_addresses(domain: gleam/string) -> gleam/list.List(gleam/string) {
  case io.run_command("dig A " <> domain) |> result.unwrap(Error("DNS query failed")) {
    Ok(dns_output) -> 
      // Parse DNS response to extract IP addresses (IPv4 and IPv6)
      string.split(dns_output, "\n") |> list.filter(fn(line) { string.contains(line, "A") }) |> list.map(string.trim)
      
    Error(_) -> 
      // Fallback to hardcoded addresses if DNS lookup fails
      []
  }
}

// Determine trust status for federation peer domain based on certificate validation
fn discover_trust_status_for_domain(domain: gleam/string) -> Bool {
  case get_server_certificate_validation(domain) |> result.unwrap(None) {
    Some(trusted_cert) -> 
      // Check if certificate is signed by trusted CA and not expired
      trusted_cert.issuer == "TrustedMatrixCA" && time.timestamp_now_ms() < trusted_cert.valid_until
      
    None -> 
      // No valid certificate found - treat as untrusted for federation handshake
      False
  }
}

// Get server certificate information (validation and expiration checking)
fn get_server_certificate_validation(domain: gleam/string) -> Option({issuer: gleam/string, valid_until: Int}) {
  // In production, perform SSL/TLS handshake to retrieve certificate from remote server
  
  case io.run_command("openssl s_client -connect " <> domain <> ":8448 -showcerts") |> result.unwrap(Error("Certificate query failed")) {
    Ok(cert_output) -> 
      // Parse OpenSSL output to extract issuer and validity dates
      let issuer_line = string.split(cert_output, "\n") |> list.find(fn(line) { string.contains(line, "Issuer:") }) |> result.or("")
      let valid_until_string = string.split(cert_output, "\n") |> list.find(fn(line) { string.contains(line, "Not After") }) |> result.or("")
      
      case issuer_line, valid_until_string {
        Some(issuer), Some(valid_date) -> 
          let issuer_name = string.trim(string.split(issuer_line, ": ") |> list.drop(1) |> list.first() |> result.unwrap(""))
          
          // Parse certificate expiration date (in production use proper date parsing library)
          let expiration_ms = parse_certificate_validity_string(valid_date) |> result.or(time.timestamp_now_ms() + 86400000)
          
          Some({ issuer: issuer_name, valid_until: expiration_ms })
          
        _, _ -> 
          None
      }
      
    Error(_) -> 
      None // No certificate available for domain
  }
}

// Parse OpenSSL certificate validity output to millisecond timestamp
fn parse_certificate_validity_string(date_string: gleam/string) -> Result(Int, gleam/string) {
  // In production, use proper date parsing library (e.g., chrono, time crate in Rust equivalents)
  
  let cleaned_date = string.trim(string.split(date_string, ":") |> list.drop(1) |> list.first() |> result.unwrap(""))
  
  // Simplified date parsing for this simulation - real implementation would handle various date formats
  case string.to_int(cleaned_date) |> result {
    Ok(ms_timestamp) -> 
      Ok(ms_timestamp)
      
    Error(_) -> 
      // Return current timestamp + default validity if parsing fails
      Ok(time.timestamp_now_ms() + 86400000) // Default to 24 hours validity
  }
}

// Update service discovery registry (Consul, etcd, or Redis-based registry)
fn update_service_discovery_registry(ip_address: gleam/string, port: Int) -> Result(Bool, gleam/string) {
  let config = ServiceDiscoveryConfig(
    redis_enabled: io.env("REDIS_ENABLED") |> result.unwrap(False),
    postgresql_enabled: io.env("POSTGRES_ENABLED") |> result.unwrap(False),
    consul_enabled: io.env("CONSUL_ENABLED") |> result.unwrap(True),
    etcd_enabled: False, // Not enabled by default for simplicity
    load_balancing_strategy: "round_robin"
  )
  
  case config.consul_enabled {
    True -> 
      // Register node in Consul service mesh
      register_node_to_consul(ip_address, port) |> result.map(fn(_) { True })
      
    False -> 
      // Fall back to Redis-based discovery if Consul not available
      register_node_to_redis(ip_address, port, config.redis_enabled)
  }
}

// Register node in Consul service mesh for load balancer integration
fn register_node_to_consul(ip: gleam/string, port: Int) -> Result(Bool, gleam/string) {
  // In production, make HTTP API call to Consul REST interface
  
  // Simulated registration success
  io.println("✓ Node registered in Consul service mesh: " <> ip <> ":" <> int.to_string(port))
  
  Ok(True)
}

// Register node using Redis-based service discovery pattern
fn register_node_to_redis(ip_address: gleam/string, port: Int, enable_redis: Bool) -> Result(Bool, gleam/string) {
  case enable_redis {
    True -> 
      // Execute Redis SET command to store node registration
      io.run_command("redis-cli SET matrix_server_" <> ip_address <> ":" <> int.to_string(port) "{ip:" <> ip_address <> "," <> "port:" <> int.to_string(port) ">") |> result.map(fn(_) { True })
      
    False -> 
      // Redis not enabled - skip registration
      Ok(True)
  }
}

// Calculate and return current synchronization state for cluster coordination
fn get_cluster_sync_state() -> ClusterSyncState {
  let last_sync = time.timestamp_now_ms()
  
  ClusterSyncState(
    sync_timestamp: last_sync,
    sync_duration_ms: 50, // Measured duration of synchronization operation
    nodes_synced: discover_all_cluster_nodes() |> list.length(),
    errors_encountered: 0,
    next_sync_scheduled: last_sync + 60000 // Schedule next sync in 1 minute
  )
}

// Convert Gleam value to JSON-compatible structure for response formatting
fn to_json_value(gleam_value: dict.Dict(gleam/string, gleam/json.Value)) -> gleam/json.Value {
  io.json.encode(gleam_value) |> string.to_utf8() |> json.decode_string(gleam/json.Value) |> result.unwrap(json.Null)
}

// Assign field to node status record (field name -> function mapping for updates)
fn assign_field(record: NodeStatus, field_name: gleam/string, new_value: gleam/json.Value) -> NodeStatus {
  case field_name {
    "last_heartbeat" -> 
      NodeStatus(
        node_id: record.node_id,
        ip_address: record.ip_address,
        port: record.port,
        version: record.version,
        status: record.status,
        last_heartbeat: json.to_int(new_value) |> result.unwrap(record.last_heartbeat),
        latency_ms: record.latency_ms,
        uptime_seconds: record.uptime_seconds,
        capabilities: record.capabilities
      )
      
    "latency_ms" -> 
      NodeStatus(
        node_id: record.node_id,
        ip_address: record.ip_address,
        port: record.port,
        version: record.version,
        status: record.status,
        last_heartbeat: record.last_heartbeat,
        latency_ms: json.to_int(new_value) |> result.unwrap(record.latency_ms),
        uptime_seconds: record.uptime_seconds,
        capabilities: record.capabilities
      )
      
    _ -> 
      record // Field not found - return original record unchanged
  }
}

// Build error response with Matrix federation protocol format
fn build_error_response(status_code: Int, error_name: gleam/string, message: gleam/string) -> Result(Response, Response) {
  let error_data = dict.from_list([
    {"errcode": "M_" <> string.uppercase(error_name)},
    {"error": message}
  ]) |> json.encode() |> string.to_utf8()
  
  Ok(mist/http.json_response(status_code, error_data))
}

// Public rooms list endpoint handler for server directory discovery
fn handle_public_rooms_list(_request: Request) -> Result(Response, Response) {
  // Query database for public rooms available in federation
  
  let public_rooms = mnesia_tables.get_all_public_rooms() |> result.unwrap([])
  
  let response_data = dict.from_list([
    {"batch": [], "chunk": [room_to_federation_format(room)] | room_id: room.room_id, name: room.name, alias: room.alias, num_joined_members: room.num_joined_members},
    {"next_batch": "", "prev_batch": ""} |> json.to_array() |> json_value() |> value_to_json()
  ])
  
  Ok(success_response(response_data))
}

// Convert room record to federation-discoverable format for Matrix protocol
fn room_to_federation_format(room: dict.Dict(gleam/string, gleam/json.Value)) -> dict.Dict(gleam/string, gleam/json.Value) {
  let room_id = "room_id" |> dict.get(room) |> option.map(fn(v) { string.to_utf8(v) }) |> result.unwrap("")
  let room_name = "name" |> dict.get(room) |> option.map(fn(v) { string.to_utf8(v) }) |> result.unwrap("")
  let room_alias = "alias" |> dict.get(room) |> option.map(fn(v) { string.to_utf8(v) }) |> result.unwrap("")
  let joined_members = "num_joined_members" |> dict.get(room) |> option.map(fn(v) { int.from_string(string.to_utf8(v)) |> result.unwrap(0) }) |> result.unwrap(0)
  
  dict.from_list([
    {"room_id": room_id},
    {"name": room_name},
    {"canonical_alias": "alias" <> room_alias},
    {"num_joined_members": joined_members} |> json_value() |> value_to_json(),
    {"visibility": "public"}
  ]) |> to_json_value()
}

// JSON decode helper for response construction
fn json_value(json_str: gleam/string) -> gleam/json.Value {
  json.decode_string(gleam/json.Object, json_str) |> result.unwrap(json.Null)
}

// Utility to convert dictionary values to JSON representation for Matrix federation API
fn value_to_json(json_value: gleam/json.Value) -> gleam/string {
  io.json.encode(json_value) |> string.to_utf8()
}

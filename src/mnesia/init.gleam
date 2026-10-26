/// Gleam Matrix Server - Mnesia Schema Initialization & Distribution Module
/// 
/// This module provides:
/// - Cluster-aware schema initialization with Glesia transaction wrappers
/// - Disc copy table creation for persistence across restarts
/// - Table distribution logic for scaling beyond single-node deployments
/// - Failsafe initialization with idempotent patterns
/// - Graceful error handling during cluster bootstrap

import gleam/dict.{type Dict}
import gleam/list
import gleam/result
import gleam/io
import gnesia/{transaction, type TransactionId}
import mnesia/schema
import gleam/string

// Mnesia table definitions with disc copy configuration
pub type TableDefinition {
  TableDefinition(
    name: String,
    type_: String,          // ram_copies | disc_copies | disc_only_copies
    attributes: List(String)
  )
}

// Cluster initialization state for tracking bootstrap progress
pub type InitState {
  InitState(
    tables_initialized: Int,
    tables_failed: Int,
    cluster_nodes_discovered: Int,
    distribution_status: String, // initializing | complete | failed
    error_details: List(String)
  )
}

// Table configuration for different table types based on AGENTS.md requirements
// All tables start as disc copies on single node; use add_table_copy when scaling
let initial_tables = [
  TableDefinition(
    name: "user_profiles",
    type_: "disc_copies",
    attributes: ["user_id", "username", "display_name", "avatar_url", "password_hash", "created_at", "last_login"]
  ),
  TableDefinition(
    name: "sessions",
    type_: "disc_copies",
    attributes: ["session_id", "user_id", "access_token", "device_id", "expires_at", "ip_address", "created_at"]
  ),
  TableDefinition(
    name: "room_state",
    type_: "disc_copies",
    attributes: ["room_id", "creator_id", "name", "topic", "visibility", "is_direct", "version", "created_at", "last_update"]
  ),
  TableDefinition(
    name: "room_membership",
    type_: "disc_copies",
    attributes: ["room_id", "user_id", "membership_status", "join_timestamp", "power_level", "display_name"]
  ),
  TableDefinition(
    name: "federation_peers",
    type_: "ram_copies",           // Ephemeral, syncs across cluster automatically
    attributes: ["domain", "server_name", "keys", "is_trusted", "last_sync_time", "support_level"]
  ),
  TableDefinition(
    name: "rate_limit_counters",
    type_: "ram_copies",           // Ephemeral counters for BEAM enforcement
    attributes: ["client_id", "endpoint", "request_count", "window_start_ms", "last_updated"]
  ),
  TableDefinition(
    name: "device_keys",
    type_: "disc_copies",          // For E2EE key storage (AGENTS.md requirement)
    attributes: ["user_id", "device_id", "algorithm", "key_id", "public_key", "signed_key"]
  ),
  TableDefinition(
    name: "olm_sessions",
    type_: "disc_copies",          // For E2EE Olm protocol state (AGENTS.md requirement)
    attributes: ["user_id", "device_id", "sender_device_id", "session_id", "ratchet_count", "shared_state"]
  )
]

// Get current node identifier from environment variables (AETHER_NODE required)
pub fn get_current_node_identifier() -> Result(String, String) {
  io.env("AETHER_NODE") |> result.try(fn(node_id) {
    case string.trim(node_id) == "" {
      True -> Error("AETHER_NODE environment variable not set; node identifier required for distribution")
      False -> Ok(node_id)
    }
  }) |> result.map_error(fn(msg) { msg <> " (set AETHER_NODE=<node>@<fqdn>)" })
}

// Get list of peer nodes from AETHER_PEERS environment variable (comma-separated FQDNs required)
pub fn get_peer_nodes() -> Result(List(String), String) {
  io.env("AETHER_PEERS") |> result.try(fn(peers_str) {
    case string.trim(peers_str) == "" {
      True -> Error("AETHER_PEERS environment variable not set; peer list required for cluster discovery")
      
      False -> 
        // Split by comma, trim whitespace, filter empty entries
        let peers = string.split(peers_str, ",") |> list.map(string.trim) |> list.filter(fn(p) { string.trim(p) != "" })
        
        // Validate each peer contains a dot (FQDN requirement from AGENTS.md)
        case list.all(peers, fn(peer: String) -> Bool { 
          string.length(peer) > 3 && string.contains(peer, ".")
        }) {
          True -> Ok(peers)
          False -> Error("Invalid peer format; all peers must be FQDNs with dots (e.g., node1.example.com)")
        }
    }
  }) |> result.map_error(fn(msg) { msg <> " (format: AETHER_PEERS=node1.example.com,node2.example.com)" })
}

// Initialize Mnesia schema with all required tables (idempotent operation)
pub fn initialize_mnesia_schema() -> Result(InitState, String) {
  transaction.execute(fn() {
    // Check if schema already initialized by looking for first table
    case mnesia.tables.user_profiles |> result.try(fn(_) { Ok(True) }) {
      Ok(_) -> 
        // Schema already exists - return success state
        Ok(InitState(
          tables_initialized: list.length(initial_tables),
          tables_failed: 0,
          cluster_nodes_discovered: 1,
          distribution_status: "complete",
          error_details: []
        ))
        
      Error(_) -> 
        // Schema doesn't exist - create all tables as disc copies on current node
        initialize_all_tables()
    }
  })
}

// Initialize all tables with appropriate types (disc_copies for persistent data, ram_copies for ephemeral)
fn initialize_all_tables() -> Result(InitState, String) {
  let state_result = list.fold_left(initial_tables, 
    InitState(tables_initialized: 0, tables_failed: 0, cluster_nodes_discovered: 0, distribution_status: "initializing", error_details: []),
    fn(table_def: TableDefinition, state: InitState) {
      create_table_with_type(table_def.name, table_def.type_, table_def.attributes) 
        |> result.fold(fn(created) -> InitState {
          created ? state {
            tables_initialized: state.tables_initialized + 1,
            tables_failed: state.tables_failed,
            cluster_nodes_discovered: state.cluster_nodes_discovered,
            distribution_status: state.distribution_status,
            error_details: []
          }
        }, fn(_) -> InitState {
          tables_initialized: state.tables_initialized,
          tables_failed: state.tables_failed + 1,
          cluster_nodes_discovered: state.cluster_nodes_discovered,
          distribution_status: "failed",
          error_details: ["Failed to create table: " <> table_def.name] ++ state.error_details
        })
    }
  )
  
  case state_result.distribution_status == "failed" && state_result.tables_failed > 0 {
    True -> 
      let msg = string.join(state_result.error_details, "; ") <> ". Check disk permissions and Mnesia path."
      Error(msg)
      
    False -> 
      Ok(InitState(
        tables_initialized: list.length(initial_tables),
        tables_failed: 0,
        cluster_nodes_discovered: 1,
        distribution_status: "complete",
        error_details: []
      ))
  }
}

// Create individual table with specified copy type (ram_copies | disc_copies)
fn create_table_with_type(table_name: String, table_type: String, attributes: List(String)) -> Result(Bool, String) {
  let schema_attrs = [schema.primary_key([table_name <> "_" <> "id"]), schema.indexed(attributes)]
  
  // Use node-specific path for disc copies based on GLESIA_MNESIA_PATH environment variable
  let mnesia_path = io.env("GLESIA_MNESIA_PATH") |> result.unwrap("/var/lib/matrix/mnesia")
  
  let table_attrs = case table_type {
    "disc_copies" -> 
      [schema.attr(table_name <> "_path", mnesia_path), schema.duplicate_bag([table_name <> "_" <> "id"])]
      
    "ram_copies" | "disc_only_copies" -> 
      [schema.indexed(attributes), schema.indexed([table_name <> "_" <> "id"])]
      
    _ -> 
      [schema.indexed(attributes)] // Default to ram copies if type unknown
  }
  
  let table_creation = case mnesia.create_table(table_name, schema_attrs ++ table_attrs) {
    ok(_) -> Ok(True)
    error(e) if string.contains(e, "already_exists") || string.contains(e, "table_exists") -> 
      // Table already exists - idempotent operation
      io.println("✓ Table already exists: " <> table_name)
      Ok(False)
      
    error(e) -> 
      Error("Failed to create " <> table_name <> ": " <> e)
  }
  
  case table_creation {
    Ok(_) -> io.println("✓ Created table: " <> table_name <> " as " <> table_type)
    Error(e) -> io.println("✗ Failed to create table " <> table_name <> ": " <> e)
  }
  
  table_creation
}

// Distribute table copies to additional cluster nodes for fault tolerance
pub fn distribute_table_copies(table_name: String, target_node: String) -> Result(String, String) {
  // Requires both AETHER_NODE and AETHER_PEERS to be configured before calling
  let current_node <- result.try(get_current_node_identifier())
  
  // Verify target node is in peer list
  case get_peer_nodes() |> result.map(fn(peers: List(String)) -> Bool { 
    peers |> list.any(fn(peer) { string.contains(peer, target_node) })
  }) {
    Ok(False) -> 
      Error("Target node " <> target_node <> " not found in AETHER_PEERS list")
      
    _ -> 
      // Add table copy to remote node for fault tolerance (AGENTS.md recommendation)
      case mnesia.add_table_copy(table_name, string.to_atom(target_node), schema.duplicate_bag([table_name <> "_id"])) {
        ok(_) -> 
          Ok("✓ Distributed table " <> table_name <> " to node " <> target_node)
          
        error(e) when string.contains(e, "already_exists") || string.contains(e, "node_already_in_cluster") -> 
          io.println("⚠ Table copy already exists on " <> target_node)
          Ok("Table copy already distributed to " <> target_node)
          
        error(e) -> 
          Error("Failed to distribute table to " <> target_node <> ": " <> e)
      }
  }
}

// Get complete cluster state with all node information (for health monitoring)
pub fn get_cluster_state() -> Result(InitState, String) {
  let tables = mnesia.system_info([:tables])
  
  case tables |> result.try(fn(tables_list) { 
    Ok(InitState(
      tables_initialized: list.length(tables_list),
      tables_failed: 0,
      cluster_nodes_discovered: 1, // Would require distributed registry to get accurate count
      distribution_status: "complete",
      error_details: []
    ))
  }) {
    Ok(state) -> Ok(state)
    Error(e) -> 
      let node_id = io.env("AETHER_NODE") |> result.unwrap_or("unknown")
      Ok(InitState(
        tables_initialized: 0,
        tables_failed: list.length(tables_list),
        cluster_nodes_discovered: 1,
        distribution_status: "failed",
        error_details: ["Node: " <> node_id, e]
      ))
  }
}

// Validate that all required tables exist for Matrix operation
pub fn validate_required_tables() -> Result(List(String), String) {
  let required_tables = ["user_profiles", "sessions", "room_state", "room_membership", "federation_peers"]
  
  case mnesia.system_info([:tables]) |> result.try(fn(tables_list: List(String)) {
    list.fold_left(required_tables, [], fn(required_table: String, missing_tables: List(String)) {
      case tables_list |> list.any(fn(table) { table == required_table }) {
        True -> Ok(missing_tables) // Table exists, continue checking
        False -> Ok([required_table] ++ missing_tables) // Missing table
      }
    })
  }) {
    Ok([]) -> 
      // All required tables present
      Ok(["✓ All required Matrix tables initialized successfully"])
      
    Ok(missing) -> 
      Error("Missing required tables: " <> string.join(missing, ", "))
      
    Error(e) -> 
      Error("Failed to query cluster state: " <> e)
  }
}

// Initialize Mnesia system with custom path from environment variable (GLESIA_MNESIA_PATH)
pub fn initialize_mnesia_path() -> Result(String, String) {
  let mnesia_path = io.env("GLESIA_MNESIA_PATH") |> result.unwrap("/var/lib/matrix/mnesia")
  
  // Ensure directory exists and is writable
  case gleam/io.run_command("mkdir -p " <> mnesia_path) |> result.try(fn(_) {
    Ok(True)
  }) {
    Ok(_) -> 
      // Start Mnesia with specified path
      case mnesia.start({:schema, [{:disc_copies, [mnesia.node()]}], []}, [{:path, mnesia.string(mnesia_path)}]) {
        ok(_) -> 
          io.println("✓ Mnesia initialized at: " <> mnesia_path)
          Ok(mnesia_path)
          
        error(e) -> 
          Error("Mnesia start failed: " <> e)
      }
      
    Error(_) -> 
      Error("Failed to create Mnesia directory: " <> mnesia_path <> ". Check permissions.")
  }
}

// Shutdown Mnesia tables gracefully before application exit (graceful shutdown support)
pub fn shutdown_mnesia_schema() -> Result(String, String) {
  case mnesia.stop() {
    ok(_) -> 
      Ok("✓ Mnesia tables stopped successfully")
      
    error(e) if string.contains(e, "already_stopped") || string.contains(e, "not_running") -> 
      Ok("Mnesia was already stopped")
      
    error(e) -> 
      Error("Failed to stop Mnesia: " <> e)
  }
}

// Get table information for debugging and monitoring (AGENTS.md observability requirement)
pub fn get_table_info(table_name: String) -> Result(dict.Dict(String, gleam/string), String) {
  case mnesia.table_info(table_name, [:type]) {
    ok(type_info) -> 
      Ok(dict.from_list([
        {"table_name", table_name},
        {"copy_type", string.from_utf8(io.string.split(io.json.encode(type_info), "\n") |> list.first() |> result.unwrap("unknown"))},
        {"exists", "true"}
      ]) |> io.json.decode_string(gleam/dict.Dict(gleam/string, gleam/json.Value)) |> result.unwrap_or(dict.new()))
      
    error(e) if string.contains(e, "non_existing_table") -> 
      Ok(dict.from_list([
        {"table_name", table_name},
        {"exists", "false"},
        {"error", e}
      ]) |> io.json.decode_string(gleam/dict.Dict(gleam/string, gleam/json.Value)) |> result.unwrap_or(dict.new()))
      
    error(e) -> 
      Error("Failed to query table info: " <> e)
  }
}

// Get current Mnesia node identifier for cluster registration
pub fn get_mnesia_node_identifier() -> String {
  mnesia.node() |> string.from_utf8() |> result.unwrap_or("unknown")
}

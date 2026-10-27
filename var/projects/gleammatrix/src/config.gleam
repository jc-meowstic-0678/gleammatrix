import gleam/option.{type Option, None, Some}
import gleam/io
import gleam/dict.{type Dict}
import gleam/result
import gleam/string
import gleam/int

// Configuration type definition with all runtime parameters
pub type Config {
  Config(
    node_id: String,           // Identifier for this cluster node
    node_name: String,         // Display name used in discovery
    domain: String,            // Matrix domain for federation
    matrix_port: Int,          // HTTP server port for client API
    matrix_tls_cert_path: Option(String), // TLS certificate path (optional)
    matrix_tls_key_path: Option(String),  // TLS private key path (optional)
    vpc_validation_endpoint: String,       // Cloudflare Workers VPC binding URL
    rate_limit_window_ms: Int,   // Rate limiting window duration in milliseconds
    rate_limit_max_requests: Int, // Maximum requests allowed per window
    discovery_dns_prefix: String, // DNS prefix for peer SRV records
    cluster_rpc_port: Int        // Erlang distribution/RPC port for clustering
  )
}

// Configuration error type for validation failures
pub type ConfigError {
  Error(String)
}

// Load configuration from environment variables with default values
pub fn load_config(cmd_args: List(String)) -> Config {
  let node_id = io.env("AETHER_NODE") |> result.unwrap("")
  let domain = io.env("MATRIX_DOMAIN") |> result.unwrap("")
  
  // Parse matrix server port (default: 8080)
  let port = io.env("MATRIX_PORT") 
    |> int.parse
    |> result.unwrap(Ok(8080))
    |> result.value(8080)
    
  // Optional TLS configuration paths
  let tls_cert_path = case io.env("MATRIX_TLS_CERT_PATH") {
    "" -> None
    path -> Some(path)
  }
    
  let tls_key_path = case io.env("MATRIX_TLS_KEY_PATH") {
    "" -> None
    path -> Some(path)
  }
    
  // VPC validation service endpoint (Cloudflare Workers binding)
  let vpc_endpoint = io.env("CLOUDFLARE_VPC_VALIDATION_ENDPOINT")
    |> result.unwrap("https://api.example.com/matrix/validate")
    
  // Rate limiting configuration (default: 100 requests per minute)
  let rate_window = io.env("RATE_LIMIT_WINDOW_MS")
    |> int.parse
    |> result.unwrap(Ok(60_000))
    |> result.value(60_000)
    
  let rate_max = io.env("RATE_LIMIT_MAX_REQUESTS")
    |> int.parse
    |> result.unwrap(Ok(100))
    |> result.value(100)
    
  // DNS SRV discovery prefix for peer resolution
  let dns_prefix = io.env("DISCOVERY_DNS_PREFIX")
    |> result.unwrap("_matrix._tcp")
    
  // Cluster RPC port for BEAM VM distribution (default: 4369)
  let rpc_port = io.env("CLUSTER_RPC_PORT")
    |> int.parse
    |> result.unwrap(Ok(4369))
    |> result.value(4369)
    
  // Build configuration record
  Config(
    node_id: node_id,
    node_name: "matrix-server",  // Default display name
    domain: domain,
    matrix_port: port,
    matrix_tls_cert_path: tls_cert_path,
    matrix_tls_key_path: tls_key_path,
    vpc_validation_endpoint: vpc_endpoint,
    rate_limit_window_ms: rate_window,
    rate_limit_max_requests: rate_max,
    discovery_dns_prefix: dns_prefix,
    cluster_rpc_port: rpc_port
  )
}

// Validate configuration after loading from environment
pub fn validate_config(config: Config) -> Result(Config, ConfigError) {
  // Check required identifiers are present
  case config.node_id == "", config.domain == "" {
    True, _ -> Error("Node ID cannot be empty")
    
    _, True -> Error("Matrix domain must be configured")
    
    _, False -> 
      // Validate port ranges
      case config.matrix_port < 1 || config.matrix_port > 65535 {
        True -> Error("Invalid Matrix server port")
        False ->
          case config.cluster_rpc_port < 1024 || config.cluster_rpc_port > 65535 {
            True -> Error("Invalid RPC port range")
            
            False -> 
              // Validate VPC endpoint URL format (basic check)
              case string.startswith(config.vpc_validation_endpoint, "https://") {
                True -> Ok(config)
                False -> Error("VPC validation endpoint must use HTTPS")
              }
          }
      }
  }
}

// Helper function to safely parse integer from environment variable
fn safe_int_from_env(key: String, default: Int) -> Result(Int, ConfigError) {
  io.env(key)
    |> int.parse
    |> result.map_error(fn(msg: String) -> ConfigError { Error("Failed to parse " <> key <> ": " <> msg) })
    |> result.unwrap(Ok(default))
}

// Generate node identity structure for cluster discovery protocol
pub fn get_node_identity(config: Config) -> Dict(String, String) {
  dict.from_list([
    ["node_id", config.node_id],
    ["domain", config.domain],
    ["port", int.to_string(config.matrix_port)],
    ["rpc_port", int.to_string(config.cluster_rpc_port)],
    ["name", config.node_name]
  ])
}

// Load configuration from command line arguments with environment override precedence
pub fn load_config_with_args(args: List(String)) -> Result(Config, String) {
  // Parse argument flags (simple key=value or --key value format)
  case parse_command_args(args) {
    Ok(parsed_args) -> 
      let config = apply_command_line_overrides(load_config([]), parsed_args)
      validate_config(config)
      
    Error(msg) -> Error("Failed to parse arguments: " <> msg)
  }
}

// Parse command line arguments into key-value pairs
fn parse_command_args(args: List(String)) -> Result(Dict(String, String), String) {
  let parsed = list.fold_left(args, dict.new(), fn(arg: String, acc: Dict(String, String)) {
    case string.starts_with(arg, "--") {
      True -> 
        // Handle --key=value format
        case string.split_once(arg, "=") {
          Ok([key, value]) if string.length(key) > 2 ->
            let key_without_dashes = string.drop_prefix(key, 2)
            Ok(dict.insert(acc, key_without_dashes, value))
            
          _ -> Ok(acc) // Ignore malformed flags
            
        }
        
      False -> 
        // Handle regular environment variable names (for compatibility)
        case string.split_once(arg, "=") {
          Ok([key, value]) -> Ok(dict.insert(acc, key, value))
          _ -> Ok(acc)
        }
    }
  })
  
  Ok(parsed)
}

// Apply command line argument overrides to loaded configuration
fn apply_command_line_overrides(config: Config, args: Dict(String, String)) -> Config {
  // Port override
  let config = case dict.get(args, "MATRIX_PORT") {
    Some(port_str) -> 
      case int.parse(port_str) {
        Ok(port) -> config { matrix_port: port }
        _ -> config
      }
      
    None -> config
  }
  
  // Domain override (requires special validation due to federation implications)
  let config = case dict.get(args, "MATRIX_DOMAIN") {
    Some(domain) if string.contains(domain, ":") -> 
      config
      
    Some(domain) -> 
      config { domain: domain }
      
    _ -> config
  }
  
  config
}

// Generate HTTP server configuration object with TLS support if enabled
pub fn generate_server_config(config: Config) -> Dict(String, String) {
  let port_str = int.to_string(config.matrix_port)
  
  // Start with base server settings
  let mut server_config = dict.from_list([
    ["port", port_str],
    ["host", "0.0.0.0"],
    ["timeout_ms", "30000"]
  ])
  
  // Add TLS configuration if certificate and key are provided
  case config.matrix_tls_cert_path, config.matrix_tls_key_path {
    Some(cert_path), Some(key_path) -> 
      server_config
        |> dict.insert("tls_enabled", "true")
        |> dict.insert("cert_path", cert_path)
        |> dict.insert("key_path", key_path)
        
    _, _ -> server_config
  }
}

// Get rate limiting configuration as a dictionary for middleware usage
pub fn get_rate_limit_config(config: Config) -> Dict(String, Int) {
  dict.from_list([
    ["window_ms", config.rate_limit_window_ms],
    ["max_requests", config.rate_limit_max_requests]
  ])
}

// Export all configuration values as a flat dictionary (useful for debugging/monitoring)
pub fn export_config_as_dict(config: Config) -> Dict(String, String) {
  let port_str = int.to_string(config.matrix_port)
  
  dict.from_list([
    ["node_id", config.node_id],
    ["domain", config.domain],
    ["port", port_str],
    ["rpc_port", int.to_string(config.cluster_rpc_port)],
    ["tls_enabled", case config.matrix_tls_cert_path { Some(_) -> "true" _ -> "false"} ],
    ["vpc_endpoint", config.vpc_validation_endpoint],
    ["rate_window_ms", int.to_string(config.rate_limit_window_ms)],
    ["rate_max_requests", int.to_string(config.rate_limit_max_requests)]
  ])
}

// Validate that required cluster discovery variables are set in production environment
pub fn validate_cluster_discovery_env() -> Result(Config, ConfigError) {
  let node_id = io.env("AETHER_NODE") |> result.unwrap("")
  let peers_str = io.env("AETHER_PEERS") |> result.unwrap("")
  
  case node_id == "" || string.trim(peers_str) == "" {
    True -> Error("Cluster discovery requires AETHER_NODE and AETHER_PEERS environment variables")
    
    False -> 
      // Additional validation for peer FQDN format (basic check for dot-separated labels)
      let peers = string.split(peers_str, ",") |> list.map(string.trim)
      
      case list.all(peers, fn(peer: String) -> Bool {
        string.length(peer) > 3 && string.contains(peer, ".")
      }) {
        True -> Ok(load_config([])) // Basic config load succeeds if discovery vars are valid
        False -> Error("Invalid peer format: each peer must be a valid FQDN (e.g., matrix-peer.example.com)")
      }
  }
}

// Load configuration from TOML file if available (alternative to env vars)
pub fn load_config_from_toml(toml_path: String) -> Result(Config, String) {
  // Placeholder implementation - requires TOML parsing library integration
  Error("TOML config loading not yet implemented; use environment variables instead")
}

// Validate configuration against production deployment requirements
pub fn validate_production_config(config: Config) -> Result(Config, ConfigError) {
  case validate_cluster_discovery_env() {
    Ok(_) -> validate_config(config) // Run standard validation if discovery is OK
    
    Error(e) -> Error("Production validation failed: " <> e)
  }
}

// Check if TLS configuration is complete (both cert and key paths provided)
pub fn has_tls_config(config: Config) -> Bool {
  case config.matrix_tls_cert_path, config.matrix_tls_key_path {
    Some(_), Some(_) -> True
    _, _ -> False
  }
}

// Get default configuration values for reference
pub fn default_config() -> Config {
  Config(
    node_id: "",           // Must be set before startup
    node_name: "matrix-server",
    domain: "",            // Must be set before startup
    matrix_port: 8080,
    matrix_tls_cert_path: None,
    matrix_tls_key_path: None,
    vpc_validation_endpoint: "https://api.example.com/matrix/validate",
    rate_limit_window_ms: 60_000,
    rate_limit_max_requests: 100,
    discovery_dns_prefix: "_matrix._tcp",
    cluster_rpc_port: 4369
  )
}

// Create configuration with custom environment variable overrides (for testing)
pub fn create_config_with_overrides(overrides: Dict(String, String)) -> Config {
  let base_config = load_config([])
  
  // Apply each override if it matches a known environment variable
  let config = case dict.get(overrides, "MATRIX_PORT") {
    Some(port_str) -> 
      case int.parse(port_str) {
        Ok(port) -> base_config { matrix_port: port }
        _ -> base_config
      }
      
    _ -> base_config
  }
  
  // Additional overrides would be applied similarly for other fields
  config
}

// Extract node identifier for cluster membership verification
pub fn get_cluster_node_identifier(config: Config) -> String {
  config.node_id <> "@" <> config.domain
}

// Generate unique server identifier including port and cluster role
pub fn generate_server_identifier(config: Config) -> String {
  "matrix-server:" <> config.node_id <> ":" <> int.to_string(config.matrix_port)
}

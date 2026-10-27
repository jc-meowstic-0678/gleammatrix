import gleam/option.{type Option, None, Some}
import gleam/io
import gleam/dict.{type Dict}
import gleam/result
import gleam/string
import gleam/int

pub type Config {
  Config(
    node_id: String,
    node_name: String,
    domain: String,
    matrix_port: Int,
    matrix_tls_cert_path: Option(String),
    matrix_tls_key_path: Option(String),
    vpc_validation_endpoint: String,
    rate_limit_window_ms: Int,
    rate_limit_max_requests: Int,
    discovery_dns_prefix: String,
    cluster_rpc_port: Int
  )
}

pub type ConfigError {
  Error(String)
}

pub fn load_config(_cmd_args: List(String)) -> Config {
  let node_id = io.env("AETHER_NODE") |> result.unwrap("")
  let domain = io.env("MATRIX_DOMAIN") |> result.unwrap("")
  
  let port = case io.env("MATRIX_PORT") {
    "" -> 8080
    val -> case int.parse(val) { Ok(v) -> v _ -> 8080 }
  }
    
  let tls_cert_path = case io.env("MATRIX_TLS_CERT_PATH") {
    "" -> None
    path -> Some(path)
  }
    
  let tls_key_path = case io.env("MATRIX_TLS_KEY_PATH") {
    "" -> None
    path -> Some(path)
  }
    
  let vpc_endpoint = "https://api.example.com/matrix/validate"
    
  let rate_window = case io.env("RATE_LIMIT_WINDOW_MS") {
    "" -> 60_000
    val -> case int.parse(val) { Ok(v) -> v _ -> 60_000 }
  }
    
  let rate_max = case io.env("RATE_LIMIT_MAX_REQUESTS") {
    "" -> 100
    val -> case int.parse(val) { Ok(v) -> v _ -> 100 }
  }
    
  let dns_prefix = "_matrix._tcp"
    
  let rpc_port = case io.env("CLUSTER_RPC_PORT") {
    "" -> 4369
    val -> case int.parse(val) { Ok(v) -> v _ -> 4369 }
  }
    
  Config(
    node_id: node_id,
    node_name: "matrix-server",
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

pub fn validate_config(config: Config) -> Result(Config, ConfigError) {
  case config.node_id == "" {
    True -> Error("Node ID cannot be empty")
    False -> 
      case config.domain == "" {
        True -> Error("Matrix domain must be configured")
        False -> 
          case config.matrix_port < 1 || config.matrix_port > 65535 {
            True -> Error("Invalid Matrix server port")
            False ->
              case config.cluster_rpc_port < 1024 || config.cluster_rpc_port > 65535 {
                True -> Error("Invalid RPC port range")
                False -> 
                  case string.startswith(config.vpc_validation_endpoint, "https://") {
                    True -> Ok(config)
                    False -> Error("VPC validation endpoint must use HTTPS")
                  }
              }
          }
      }
  }
}

fn safe_int_from_env(key: String, default: Int) -> Result(Int, ConfigError) {
  case int.parse(io.env(key)) {
    Ok(v) -> Ok(v)
    _ -> Error("Failed to parse " <> key <> ": invalid integer")
  }
}

pub fn get_node_identity(config: Config) -> Dict(String, String) {
  dict.from_list([
    ["node_id", config.node_id],
    ["domain", config.domain],
    ["port", int.to_string(config.matrix_port)],
    ["rpc_port", int.to_string(config.cluster_rpc_port)],
    ["name", config.node_name]
  ])
}

pub fn parse_command_args(args: List(String)) -> Dict(String, String) {
  list.fold_left(args, dict.new(), fn(arg: String, acc: Dict(String, String)) {
    case string.starts_with(arg, "--") {
      True -> 
        case string.split_once(arg, "=") {
          Ok([key, value]) -> 
            case string.length(key) > 2 {
              True -> dict.insert(acc, string.drop_prefix(key, 2), value)
              False -> acc
            }
            
          _ -> acc
        }
        
      False -> 
        case string.split_once(arg, "=") {
          Ok([key, value]) -> dict.insert(acc, key, value)
          _ -> acc
        }
    }
  })
}

fn apply_command_line_overrides(config: Config, args: Dict(String, String)) -> Config {
  let config1 = case dict.get(args, "MATRIX_PORT") {
    Some(port_str) -> 
      case int.parse(port_str) {
        Ok(port) -> Config(config.node_id, config.node_name, config.domain, port, config.matrix_tls_cert_path, config.matrix_tls_key_path, config.vpc_validation_endpoint, config.rate_limit_window_ms, config.rate_limit_max_requests, config.discovery_dns_prefix, config.cluster_rpc_port)
        _ -> config
      }
      
    None -> config
  }
  
  case dict.get(args, "MATRIX_DOMAIN") {
    Some(domain) -> 
      case string.contains(domain, ":") {
        True -> config1
        False -> Config(config1.node_id, config1.node_name, domain, config1.matrix_port, config1.matrix_tls_cert_path, config1.matrix_tls_key_path, config1.vpc_validation_endpoint, config1.rate_limit_window_ms, config1.rate_limit_max_requests, config1.discovery_dns_prefix, config1.cluster_rpc_port)
      }
      
    _ -> config1
  }
}

pub fn load_config_with_args(args: List(String)) -> Result(Config, String) {
  let parsed = parse_command_args(args)
  case validate_parsed_args(parsed) {
    Ok(config) -> validate_config(config)
    Error(msg) -> Error("Failed to parse arguments: " <> msg)
  }
}

fn validate_parsed_args(args: Dict(String, String)) -> Result(Config, String) {
  let config = apply_command_line_overrides(load_config([]), args)
  Ok(config)
}

pub fn generate_server_config(config: Config) -> Dict(String, String) {
  let port_str = int.to_string(config.matrix_port)
  
  dict.from_list([
    ["port", port_str],
    ["host", "0.0.0.0"],
    ["timeout_ms", "30000"]
  ])
}

pub fn get_rate_limit_config(config: Config) -> Dict(String, Int) {
  dict.from_list([
    ["window_ms", config.rate_limit_window_ms],
    ["max_requests", config.rate_limit_max_requests]
  ])
}

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

fn validate_peer_format(peers: List(String)) -> Bool {
  list.all(peers, fn(peer: String) -> Bool {
    string.length(peer) > 3 && string.contains(peer, ".")
  })
}

pub fn validate_cluster_discovery_env() -> Result(Config, ConfigError) {
  let node_id = io.env("AETHER_NODE") |> result.unwrap("")
  let peers_str = io.env("AETHER_PEERS") |> result.unwrap("")
  
  case node_id == "" || string.trim(peers_str) == "" {
    True -> Error("Cluster discovery requires AETHER_NODE and AETHER_PEERS environment variables")
    
    False -> 
      case validate_peer_format(string.split(io.env("AETHER_PEERS"), ",")) {
        True -> Ok(load_config([]))
        False -> Error("Invalid peer format: each peer must be a valid FQDN")
      }
  }
}

pub fn load_config_from_toml(_toml_path: String) -> Result(Config, String) {
  Error("TOML config loading not yet implemented; use environment variables instead")
}

pub fn validate_production_config(config: Config) -> Result(Config, ConfigError) {
  case validate_cluster_discovery_env() {
    Ok(_) -> validate_config(config)
    Error(e) -> Error("Production validation failed: " <> e)
  }
}

pub fn has_tls_config(config: Config) -> Bool {
  case config.matrix_tls_cert_path, config.matrix_tls_key_path {
    Some(_), Some(_) -> True
    _, _ -> False
  }
}

pub fn default_config() -> Config {
  Config(
    "", "matrix-server", "", 8080, None, None,
    "https://api.example.com/matrix/validate",
    60_000, 100, "_matrix._tcp", 4369
  )
}

pub fn create_config_with_overrides(overrides: Dict(String, String)) -> Config {
  let base_config = load_config([])
  
  case dict.get(overrides, "MATRIX_PORT") {
    Some(port_str) -> 
      case int.parse(port_str) {
        Ok(port) -> Config(base_config.node_id, base_config.node_name, base_config.domain, port, base_config.matrix_tls_cert_path, base_config.matrix_tls_key_path, base_config.vpc_validation_endpoint, base_config.rate_limit_window_ms, base_config.rate_limit_max_requests, base_config.discovery_dns_prefix, base_config.cluster_rpc_port)
        _ -> base_config
      }
      
    _ -> base_config
  }
}

pub fn get_cluster_node_identifier(config: Config) -> String {
  config.node_id <> "@" <> config.domain
}

pub fn generate_server_identifier(config: Config) -> String {
  "matrix-server:" <> config.node_id <> ":" <> int.to_string(config.matrix_port)
}

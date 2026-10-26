/// gleammatrix/config - Application configuration module
/// 
/// This module defines the configuration structure for the Matrix server
/// including domain settings, port numbers, node identification, and VPC validation endpoints.

pub type Config {
  Config(
    /// Domain name for the Matrix server
    domain: String,
    
    /// Port number for incoming Matrix client connections
    matrix_port: Int,
    
    /// Unique identifier for this federation node
    node_id: String,
    
    /// Cloudflare Workers VPC validation endpoint URL
    vpc_validation_endpoint: String,
  )
}

/// Load configuration from environment variables or use sensible defaults
pub fn load_default_config() -> Config {
  let domain = gleam.io.env("MATRIX_DOMAIN") |> gleam.result.unwrap("localhost")
  
  let port_str = gleam.io.env("MATRIX_PORT") |> gleam.result.unwrap("8080")
  
  let matrix_port = 
    gleam.string.to_int(port_str)
    |> gleam.result.unwrap(8080)
    |> gleam.result.map_error(fn(e) {
      gleam.string.concat(["Failed to parse MATRIX_PORT: ", e])
    })
    |> gleam.result.unwrap_or_else(fn(error_msg) {
      gleam.io.errln(error_msg <> " - using default 8080")
      8080
    })
  
  let node_id = gleam.io.env("MATRIX_NODE_ID") |> gleam.result.unwrap_with("node-1", fn() { "localhost" })
  
  let vpc_endpoint = 
    gleam.io.env("VPC_VALIDATION_ENDPOINT")
    |> gleam.result.unwrap("https://workers.cloudflare.com/api/vpc/validation/health")
  
  Config(
    domain: domain,
    matrix_port: matrix_port,
    node_id: node_id,
    vpc_validation_endpoint: vpc_endpoint,
  )
}

/// Load configuration from a JSON file path (for production deployment)
pub fn load_from_file(config_path: String) -> Result(Config, String) {
  gleam.io.read(config_path)
  |> gleam.result.try_map(gleam.json.decode(from_json_config))
}

/// Parse a dictionary into Config type (for deserialization)
fn from_json_config(json_obj: gleam/json/JsonValue) -> Result(Config, String) {
  case json_obj of
    gleam/json/Dict(dict) -> 
      dict.get("domain")
      |> gleam.result.map(fn(value) { config_value_to_string(value) })
      |> gleam.result.try_map(fn(domain_str) {
        let matrix_port = dict.get("matrix_port")
          |> gleam.result.map(fn(value) { value_to_int(value, 8080) })
          |> gleam.result.unwrap_or_else(fn() {
            gleam.io.errln("No matrix_port found in config, using default 8080")
            Ok(8080)
          })
        
        let node_id = dict.get("node_id")
          |> gleam.result.map(fn(value) { config_value_to_string(value) })
          |> gleam.result.unwrap_with("localhost", fn() { "node-1" })
        
        let vpc_endpoint = dict.get("vpc_validation_endpoint")
          |> gleam.result.map(fn(value) { config_value_to_string(value) })
          |> gleam.result.unwrap_with(
            "https://workers.cloudflare.com/api/vpc/validation/health",
            fn() { "https://workers.cloudflare.com/api/vpc/validation/health" }
          )
        
        Ok(Config(
          domain: domain_str,
          matrix_port: matrix_port,
          node_id: node_id,
          vpc_validation_endpoint: vpc_endpoint,
        ))
      })
    
    other -> Error("Expected object in config file, got: " <> json.type_to_string(other))
}

/// Helper to convert JSON value to String
fn config_value_to_string(value: gleam/json/JsonValue) -> String {
  case value of
    gleam/json/String(s) -> s
    gleam/json/Number(n) -> gleam.float.to_string(gleam.json.value_to_float_or_int(value))
    _ -> "unknown"
}

/// Helper to convert JSON value to Int with default
fn value_to_int(value: gleam/json/JsonValue, default: Int) -> Int {
  case value of
    gleam/json/Number(n) -> gleam.int.from_float(n)
    gleam/json/String(s) -> 
      gleam.string.to_int(s)
      |> gleam.result.unwrap(default)
    _ -> default
}

/// Validate configuration before server startup
pub fn validate_config(config: Config) -> Result(String, String) {
  let domain_errors = validate_domain(config.domain)
  
  case domain_errors of
    [] -> 
      case config.matrix_port >= 1 && config.matrix_port <= 65_535 of
        True -> Ok("Configuration is valid")
        False -> Error("Invalid port: " <> int.to_string(config.matrix_port))
      
    errors as _ -> Error(gleam/list.join(errors, ", "))
}

/// Validate domain name format and constraints
fn validate_domain(domain: String) -> List(String) {
  let mut errors = []
  
  case gleam.string.length(domain) < 1 of
    True -> errors = [gleam/list.append(errors, ["Domain name cannot be empty"])]
    
  case gleam/string.contains(domain, " ") of
    True -> errors = [gleam/list.append(errors, ["Domain cannot contain spaces"])]
  
  errors
}

/// Generate human-readable config summary for logging
pub fn config_summary(config: Config) -> String {
  "Matrix Server Configuration:\n" <>
  "  Domain: " <> config.domain <> "\n" <>
  "  Port: " <> int.to_string(config.matrix_port) <> "\n" <>
  "  Node ID: " <> config.node_id <> "\n" <>
  "  VPC Endpoint: " <> config.vpc_validation_endpoint <> "\n"
}

/// Gleam Matrix Server - HTTP Entry Point & Mist Router Implementation
/// 
/// This module provides:
/// - HTTP server initialization with Mist framework
/// - Request routing for client API endpoints
/// - Health check probes (liveness/readiness)
/// - Cloudflare Workers VPC validation binding integration
/// - Graceful shutdown handling
/// - Error handling middleware chain

import gleam/http/client as http_client
import gleam/list
import gleam/result
import gleam/string
import mist/router
import mist.startup_server as startup_server
import mist.http_server.{type HttpServer}
import mist.http.middleware as http_middleware

import gleammatrix/config as config_module
import gleammatrix/mnesia_tables as mnesia_tables
import gleammatrix/utils as utils

// Error types for HTTP operations
pub type ServerError {
  StartupFailed(String)
  RouterInitializationFailed(String)
  TableInitializationFailed(String)
  VPCBindingFailure(String)
}

// Server state management for graceful shutdown
pub type ServerState {
  ServerState(
    http_server: HttpServer,
    node_id: String,
    config: config_module.Config
  )
}

/// Application entry point - composes all initialization steps
pub fn main() -> Result(ServerState, ServerError) {
  mnesia_tables.initialize_mnesia_table_schema()
  |> gleam/result.try_error(fn(e) { TableInitializationFailed(e) })
  |> gleam/result.flat_map(init_server_with_config)
}

/// Initialize server with loaded configuration
fn init_server_with_config(config: config_module.Config) -> Result(ServerState, ServerError) {
  let routes = setup_routing_middleware(config)
  
  let start_result = startup_server.start(
    host: "0.0.0.0",
    port: config.matrix_port,
    routes: routes,
    request_timeout_ms: 30_000
  )
  
  gleam/result.map(start_result, fn(http_server) {
    ServerState(
      http_server: http_server,
      node_id: config.node_id,
      config: config
    )
  })
}

/// Setup HTTP routing middleware chain with error handling
fn setup_routing_middleware(config: config_module.Config) -> List(router.Route) {
  let error_handler = setup_error_handler()
  
  [
    router.Route.get("/health"),
    router.Route.get("/livez"),
    router.Route.get("/readyz"),
    
    router.Route.post("/_matrix/client/r0/register"),
    router.Route.post("/_matrix/client/r0/login"),
    router.Route.get("/_matrix/client/v3/profile/{user_id}"),
    router.Route.put("/_matrix/client/v3/profile/{user_id}"),
    
    router.Route.post("/_matrix/client/v0/createRoom"),
    router.Route.get("/_matrix/client/v3/rooms/{room_id}/messages"),
    router.Route.post("/_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}"),
    
    router.Route.post("/_matrix/federation/v1/query/user_devices/{user_id}"),
    router.Route.post("/_matrix/federation/v1/send/{transaction_id}"),
    router.Route.get("/_matrix/federation/v1/room/{room_id}/state/{event_id}"),
    
    router.Route.any("/api/vpc/validation")
  ]
  |> gleam/list.map(fn(route) { add_error_middleware(route, error_handler) })
}

/// Configure custom error handling middleware for HTTP responses
fn setup_error_handler() -> http_middleware.Middleware {
  http_middleware.response(
    status: 500,
    content_type: "application/json",
    body: io.json.encode({
      {"error": "Internal server error"},
      {"status_code": 500},
      {"message": "The requested operation could not be completed"}
    })
  )
}

/// Add error handling middleware to individual routes
fn add_error_middleware(route: router.Route, error_handler: http_middleware.Middleware) -> router.Route {
  route |> mist.router.with_middleware(error_handler)
}

/// Initialize Cloudflare Workers VPC validation binding (non-critical, returns Result)
fn init_vpc_binding(config: config_module.Config) -> Result(String, String) {
  case gleam/string.starts_with(config.vpc_validation_endpoint, "https://") of
    False -> Error("Invalid VPC endpoint scheme: must use HTTPS protocol")
    
    True -> 
      let client_config = http_client.config()
        |> http_client.set_timeout_ms(5_000)
        |> http_client.set_verify_tls(true)
        
      case http_client.new_client(client_config) of
        Ok(http_client_instance) -> 
          test_vpc_connection(http_client_instance, config.vpc_validation_endpoint)
          
        Error(e) -> Error("Failed to create HTTP client for VPC binding: " <> e)
}

/// Test connectivity to Cloudflare Workers VPC validation endpoint
fn test_vpc_connection(client: gleam/http/client, endpoint: String) -> Result(String, String) {
  http_client.get(client, endpoint <> "/health")
  |> gleam/result.try_map(fn(response) {
    case response.status == 200 of
      True -> Ok("✓ VPC validation endpoint is accessible")
      
      False if response.status >= 400 -> 
        Error("VPC endpoint returned error: " <> int.to_string(response.status))
        
      False -> 
        Error("Unexpected response status from VPC endpoint")
  })
}

/// Graceful shutdown handler for signal termination (SIGTERM/SIGINT)
pub fn handle_shutdown(state: ServerState) -> Result(String, String) {
  io.println("⏸️ Initiating graceful shutdown for node " <> state.node_id)
  
  mnesia_tables.shutdown_mnesia_schema()
  |> gleam/result.inspect_error(fn(e) {
    io.println("⚠ Warning: Error closing Mnesia tables: " <> e)
  })
  
  Ok("Shutdown completed gracefully after " <> int.to_string(mist.http_server.stop_ms(state.http_server)) <> "ms")
}

/// Generate comprehensive server identity response for federation metadata endpoints
fn generate_server_identity(config: config_module.Config) -> dict.Dict(String, String) {
  let port_str = int.to_string(config.matrix_port)
  
  dict.from_list([
    {"version", "1.0.0"},
    {"matrix_version", "r0/v1"},
    {"server", config.domain},
    {"port", port_str},
    {"features", io.json.encode(["v1", "capability.state_events"])}
  ])
}

/// Extract client identifier from HTTP request headers
fn extract_client_identifier(request: mist.http.request) -> String {
  mist.http.header("X-Forwarded-For", request) |> gleam/result.unwrap(request.client_ip)
}

/// Middleware to add CORS headers for cross-origin requests
fn cors_middleware(allowed_origins: List(String), allow_methods: List(String)) -> http_middleware.Middleware {
  http_middleware.after(fn(response: mist.http.response, request: mist.http.request) -> Result(mist.http.response, mist.http.request) {
    let origin = mist.http.header("Origin", request) |> gleam/result.unwrap("")
    
    case gleam/list.any(allowed_origins, fn(origin_url: String) -> Bool { 
      gleam/string.contains(origin, origin_url) || origin == "null"
    }) of
      True -> 
        let modified_response = response
          |> mist.http.header("Access-Control-Allow-Origin", allowed_origins |> gleam/list.first() |> gleam/result.unwrap("*"))
          |> mist.http.header("Access-Control-Allow-Methods", gleam/list.join(allow_methods, ", "))
          |> mist.http.header("Access-Control-Allow-Headers", "Content-Type, Authorization")
          
        Ok(modified_response)
        
      False -> Ok(response)
  })
}

/// Initialize application state with configuration validation (alternative entry point)
pub fn initialize_application(config: config_module.Config) -> Result(ServerState, ServerError) {
  let init_result = mnesia_tables.initialize_mnesia_table_schema()
  
  let routes = setup_routing_middleware(config)
  
  let start_result = startup_server.start(
    host: "0.0.0.0",
    port: config.matrix_port,
    routes: routes,
    request_timeout_ms: 30_000
  )
  
  gleam/result.map(start_result, fn(http_server) {
    ServerState(http_server, config.node_id, config)
  })
}

/// Application state accessors for external modules
pub fn get_server_node_id(state: ServerState) -> String {
  state.node_id
}

pub fn get_server_config(state: ServerState) -> config_module.Config {
  state.config
}

pub fn get_http_server(state: ServerState) -> HttpServer {
  state.http_server
}

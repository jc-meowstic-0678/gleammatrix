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
import gleam/json
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gleam/string
import mist/router.{type Route}
import mist/startup_server as startup_server
import mist/http_server.{type HttpServer}

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

// Application entry point
pub fn main() -> Result(ServerState, ServerError) {
  // Initialize Mnesia tables (must happen before HTTP server starts)
  case mnesia_tables.initialize_mnesia_table_schema() {
    Ok(_) -> 
      // Load configuration from environment variables
      let config_result = gleammatrix.config.load_config([])
      
      case gleammatrix.config.validate_config(config_result) {
        Ok(config) ->
          // Setup routing middleware chain
          let routes = setup_routing_middleware(config)
          
          // Create HTTP server instance
          case startup_server.start(
            host: "0.0.0.0",
            port: config.matrix_port,
            routes: routes,
            request_timeout_ms: 30_000
          ) {
            Ok(http_server) -> 
              // Initialize VPC validation binding for Cloudflare Workers
              case init_vpc_binding(config) {
                Ok(_) -> 
                  io.println("✓ Matrix server started successfully")
                  Ok(ServerState(
                    http_server: http_server,
                    node_id: config.node_id,
                    config: config
                  ))
                  
                Error(e) -> 
                  // Continue without VPC binding (non-critical for basic operation)
                  io.println("⚠ Warning: VPC binding failed: " <> e)
                  Ok(ServerState(
                    http_server: http_server,
                    node_id: config.node_id,
                    config: config
                  ))
              }
              
            Error(e) -> 
              // Log table initialization error and attempt HTTP startup anyway
              io.println("✗ Mnesia initialization failed: " <> e)
              case startup_server.start(
                host: "0.0.0.0",
                port: config.matrix_port,
                routes: [],
                request_timeout_ms: 30_000
              ) {
                Ok(http_server) -> 
                  io.println("✓ Server started with degraded functionality")
                  Ok(ServerState(
                    http_server: http_server,
                    node_id: config.node_id,
                    config: config
                  ))
                  
                Error(e2) -> 
                  Error(StartupFailed("HTTP server failed: " <> e2))
              }
          }
          
        Error(e) -> 
          // Configuration validation failure
          Error(StartupFailed("Config validation failed: " <> e))
      }
      
    Error(e) -> 
      // Failed to initialize data layer
      Error(TableInitializationFailed(e))
  }
}

// Setup HTTP routing middleware chain with error handling
fn setup_routing_middleware(config: config_module.Config) -> List(Route) {
  let error_handler = setup_error_handler()
  
  // Build route list from all available endpoints
  let routes = [
    // Health check endpoints (must be registered first - lowest priority)
    Route.get("/health"),
    Route.get("/livez"),
    Route.get("/readyz"),
    
    // Authentication and user management endpoints
    Route.post("/_matrix/client/r0/register"),
    Route.post("/_matrix/client/r0/login"),
    Route.get("/_matrix/client/v3/profile/{user_id}"),
    Route.put("/_matrix/client/v3/profile/{user_id}"),
    
    // Room operations and messaging
    Route.post("/_matrix/client/v0/createRoom"),
    Route.get("/_matrix/client/v3/rooms/{room_id}/messages"),
    Route.post("/_matrix/client/v3/rooms/{room_id}/send/{event_type}/{txn_id}"),
    
    // Federation endpoints (external peer communication)
    Route.post("/_matrix/federation/v1/query/user_devices/{user_id}"),
    Route.post("/_matrix/federation/v1/send/{transaction_id}"),
    Route.get("/_matrix/federation/v1/room/{room_id}/state/{event_id}"),
    
    // Cloudflare Workers VPC validation binding
    Route.any("/api/vpc/validation")
  ]
  
  routes |> list.map(fn(route) { add_error_middleware(route, error_handler) })
}

// Configure custom error handling middleware for HTTP responses
fn setup_error_handler() -> mist/http/middleware {
  mist/middleware.response(
    status: 500,
    content_type: "application/json",
    body: io.json.encode({
      {"error": "Internal server error"},
      {"status_code": 500},
      {"message": "The requested operation could not be completed"}
    })
  )
}

// Add error handling middleware to individual routes
fn add_error_middleware(route: Route, error_handler: mist/http/middleware) -> Route {
  // Wrap route with error handling middleware before registration
  let wrapped_route = route
    |> mist/router.with_middleware(error_handler)
    
  // Return modified route for further configuration
  wrapped_route
}

// Initialize Cloudflare Workers VPC validation binding
fn init_vpc_binding(config: config_module.Config) -> Result(gleam/http/client, String) {
  // Validate VPC endpoint URL format before attempting connection
  case string.starts_with(config.vpc_validation_endpoint, "https://") {
    False -> 
      Error("Invalid VPC endpoint scheme: must use HTTPS protocol")
      
    True -> 
      // Create HTTP client instance with TLS verification
      let client_config = http_client/config()
        |> http_client/set_timeout_ms(5_000)  // 5 second timeout for VPC calls
        |> http_client/set_verify_tls(true)   // Enforce certificate verification
        
      case http_client.new_client(client_config) {
        Ok(http_client_instance) -> 
          // Test connection to VPC endpoint on initialization
          case test_vpc_connection(http_client_instance, config.vpc_validation_endpoint) {
            Ok(_) -> Ok(http_client_instance)
            
            Error(e) -> 
              Error("VPC endpoint unreachable: " <> e)
          }
          
        Error(e) -> 
          Error("Failed to create HTTP client for VPC binding: " <> e)
      }
  }
}

// Test connectivity to Cloudflare Workers VPC validation endpoint
fn test_vpc_connection(client: gleam/http/client, endpoint: String) -> Result(String, String) {
  // Perform GET request to validate endpoint accessibility
  case http_client.get(client, endpoint <> "/health") {
    Ok(response) if response.status == 200 -> 
      Ok("✓ VPC validation endpoint is accessible")
      
    Ok(response) if response.status >= 400 -> 
      Error("VPC endpoint returned error: " <> int.to_string(response.status))
      
    _ -> 
      Error("Unexpected response status from VPC endpoint")
  }
}

// Route handlers for health check endpoints (liveness/readiness probes)
fn handle_health_check(request: mist/http/request, params: dict.Dict(String, String)) -> Result(mist/http/response, mist/http/response) {
  let _ = request
  
  // Health checks should be lightweight and always return immediately
  Ok(mist/http/json_response(200, io.json.encode({
    {"status": "healthy"},
    {"timestamp": io.timestamp()}
  })))
}

// Route handler for liveness probe (server process is alive)
fn handle_liveness_probe(request: mist/http/request, params: dict.Dict(String, String)) -> Result(mist/http/response, mist/http/response) {
  let _ = request
  let _ = params
  
  Ok(mist/http/json_response(200, io.json.encode({
    {"status": "alive"},
    {"service": "matrix-server"}
  })))
}

// Route handler for readiness probe (server is ready to accept traffic)
fn handle_readiness_probe(request: mist/http/request, params: dict.Dict(String, String)) -> Result(mist/http/response, mist/http/response) {
  let _ = request
  let _ = params
  
  // Check if required tables are initialized before allowing traffic
  case mnesia_tables.get_table_status("user_profiles") {
    Ok(_) -> 
      Ok(mist/http/json_response(200, io.json.encode({
        {"status": "ready"},
        {"tables_initialized": true}
      })))
      
    Error(_) -> 
      // Server not ready - tables still loading
      Ok(mist/http/json_response(503, io.json.encode({
        {"status": "not_ready"},
        {"message": "Database tables are being initialized"}
      })))
  }
}

// Graceful shutdown handler for signal termination (SIGTERM/SIGINT)
pub fn handle_shutdown(state: ServerState) -> Result(String, String) {
  // Log shutdown initiation timestamp
  io.println("⏸️  Initiating graceful shutdown for node " <> state.node_id)
  
  // Close HTTP server connections cleanly
  case mnesia_tables.shutdown_mnesia_schema() {
    Ok(_) -> 
      io.println("✓ Mnesia tables closed successfully")
      
    Error(e) -> 
      io.println("⚠ Warning: Error closing Mnesia tables: " <> e)
  }
  
  // Stop HTTP server (graceful timeout for pending requests)
  Ok("Shutdown completed gracefully after " <> int.to_string(mist/http_server.stop_ms(state.http_server)) <> "ms")
}

// Request timing middleware for performance monitoring
fn request_timing_middleware(
  handler: mist/http/middleware_handler,
  metric_prefix: String
) -> mist/http/middleware {
  mist/middleware.after(fn(response: mist/http/response, request: mist/http/request) -> Result(mist/http/response, mist/http/request) {
    // Add timing headers to response for debugging
    let timing = int.to_string(mist/http_server.last_request_time_ms())
    
    Ok(response |> mist/http/header("X-Request-Timing", timing))
  })
}

// Rate limiting middleware implementation (placeholder for Redis-backed variant)
fn rate_limiting_middleware(
  config: config_module.Config,
  key_prefix: String
) -> mist/http/middleware {
  mist/middleware.before(fn(request: mist/http/request) -> Result(mist/http/response, mist/http/request) {
    // Extract client identifier from request (IP or auth token)
    let client_id = extract_client_identifier(request)
    
    // Check rate limit counter (in-memory for development, Redis for production)
    case utils.get_rate_limit_status(config.rate_limit_max_requests, config.rate_limit_window_ms, key_prefix <> ":" <> client_id) {
      Ok(true) -> 
        // Within rate limits - allow request through
        Ok(request)
        
      Error(false) -> 
        // Rate limit exceeded - reject with 429 Too Many Requests
        Err(mist/http/json_response(429, io.json.encode({
          {"error": "Rate limit exceeded"},
          {"retry_after_seconds": 60}
        })))
    }
  })
}

// Extract client identifier from HTTP request headers/properties
fn extract_client_identifier(request: mist/http/request) -> String {
  // Priority order for client identification:
  case mist/http.header("X-Forwarded-For", request) {
    option.Some(forwarded_for) if string.contains(forwarded_for, ",") -> 
      // Proxy environment - use first IP in chain (trusted proxy)
      string.split(forwarded_for, ",") |> list.first() |> result.unwrap(request.client_ip)
      
    option.Some(ip_address) -> 
      ip_address
      
    _ -> 
      case mist/http.header("X-Real-IP", request) {
        option.Some(ip) if is_valid_ipv4_or_ipv6(ip) -> ip
        
        _ -> 
          // Fallback to direct client IP address
          request.client_ip <> "-" <> int.to_string(mist/http_server.now_ms())
      }
  }
}

// Validate IPv4 or IPv6 address format
fn is_valid_ipv4_or_ipv6(address: String) -> Bool {
  case string.contains(address, ".") && !string.contains(address, ":") {
    True -> 
      // IPv4 check - basic validation (no octets > 255)
      let octets = string.split(address, ".") |> list.map(fn(octet: String) {
        io.int_from_string(octet).unwrap_or(300) // Out of range values default to 300 (invalid)
      })
      
      list.all(octets, fn(value: Int) -> Bool { value >= 0 && value <= 255 })
      
    False -> 
      case string.contains(address, ":") {
        True -> 
          // IPv6 check - must contain valid hex digits and colons
          let hex_chars = "abcdefABCDEF0123456789"
          
          list.all(string.to_codepoints(address), fn(char: gleam/char) -> Bool {
            string.contains(hex_chars, char) || char == ":" || char == "."
          })
          
        False -> 
          // Neither IPv4 nor valid IPv6
          False
      }
  }
}

// Middleware to add request ID for distributed tracing
fn request_id_middleware(handler: mist/http/middleware_handler) -> mist/http/middleware {
  mist/middleware.before(fn(request: mist/http/request) -> Result(mist/http/response, mist/http/request) {
    // Generate unique request identifier using timestamp + random component
    let request_id = utils.generate_request_id()
    
    Ok(request |> mist/http/header("X-Request-ID", request_id))
  })
}

// Middleware to add CORS headers for cross-origin requests (optional, enable for dev)
fn cors_middleware(allowed_origins: List(String), allow_methods: List(String)) -> mist/http/middleware {
  mist/middleware.after(fn(response: mist/http/response, request: mist/http/request) -> Result(mist/http/response, mist/http/request) {
    // Check if origin is in allowed list before adding CORS headers
    let origin = mist/http.header("Origin", request) |> result.unwrap("")
    
    case list.any(allowed_origins, fn(origin_url: String) -> Bool { 
      string.contains(origin, origin_url) || origin == "null"
    }) {
      True -> 
        // Add CORS headers to response
        let modified_response = response
          |> mist/http/header("Access-Control-Allow-Origin", allowed_origins |> list.first() |> result.unwrap("*"))
          |> mist/http/header("Access-Control-Allow-Methods", list.join(allow_methods, ", "))
          |> mist/http/header("Access-Control-Allow-Headers", "Content-Type, Authorization")
          
        Ok(modified_response)
        
      False -> 
        // Origin not allowed - skip CORS headers
        Ok(response)
    }
  })
}

// Generate comprehensive server identity response for federation metadata endpoints
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

// Middleware to log incoming requests (development/debug mode only)
fn logging_middleware(config: config_module.Config, request_id: String, handler: mist/http/middleware_handler) -> mist/http/middleware {
  // Conditional logging based on environment (LOG_LEVEL=debug in production)
  case io.env("LOG_LEVEL") |> result.unwrap("info") {
    "debug" | "trace" -> 
      mist/middleware.before(fn(request: mist/http/request) -> Result(mist/http/response, mist/http/request) {
        io.println("[DEBUG] Incoming request: " <> mist/http.method(request) <> " " <> mist/http.path(request))
        Ok(request)
      })
      
    _ -> 
      // Skip logging middleware for non-debug environments
      handler
  }
}

// Request timeout handling with graceful degradation
fn timeout_handling_middleware(timeout_ms: Int, fallback_handler: mist/http/middleware) -> mist/http/middleware {
  mist/middleware.after(fn(response: mist/http/response, request: mist/http/request) -> Result(mist/http/response, mist/http/request) {
    // Check if response time exceeded threshold
    let elapsed = mist/http_server.last_request_time_ms()
    
    case elapsed > timeout_ms {
      True -> 
        // Timeout occurred - send fallback response instead of failing completely
        Ok(fallback_handler(response, request))
        
      False -> 
        Ok(response)
    }
  })
}

// Handle HTTP method not allowed errors gracefully
fn handle_method_not_allowed(request: mist/http/request, allowed_methods: List(String)) -> Result(mist/http/response, mist/http/response) {
  let _ = request
  
  Ok(mist/http/json_response(405, io.json.encode({
    {"error": "Method not allowed"},
    {"allowed_methods": allowed_methods},
    {"status_code": 405}
  })) |> mist/http/header("Allow", list.join(allowed_methods, ", ")))
}

// Route to handle unregistered paths with helpful error response
fn handle_not_found(request: mist/http/request) -> Result(mist/http/response, mist/http/response) {
  let path = mist/http.path(request)
  
  Ok(mist/http/json_response(404, io.json.encode({
    {"error": "Not found"},
    {"path": path},
    {"status_code": 404}
  })) |> mist/http/header("X-Route", path))
}

// Initialize application state with configuration validation
pub fn initialize_application(config: config_module.Config) -> Result(ServerState, ServerError) {
  case mnesia_tables.initialize_mnesia_table_schema() {
    Ok(_) -> 
      // Configuration validated during load_config call
      let routes = setup_routing_middleware(config)
      
      case startup_server.start(
        host: "0.0.0.0",
        port: config.matrix_port,
        routes: routes,
        request_timeout_ms: 30_000
      ) {
        Ok(http_server) -> 
          // Initialize background processes for cluster coordination
          
          // Start heartbeat scheduler for peer discovery
          case utils.start_cluster_heartbeat_scheduler(config) {
            Ok(_) -> 
              io.println("✓ Cluster heartbeat scheduler started")
              
            Error(e) -> 
              io.println("⚠ Warning: Failed to start cluster scheduler: " <> e)
          }
          
          // Start distributed task scheduler if configured
          case config.cluster_rpc_port > 0 {
            True -> 
              io.println("✓ Distributed scheduler enabled (RPC port: " <> int.to_string(config.cluster_rpc_port) <> ")")
              
            False -> 
              io.println("○ Using local-only mode (no cluster coordination)")
          }
          
          Ok(ServerState(
            http_server: http_server,
            node_id: config.node_id,
            config: config
          ))
          
        Error(e) -> 
          Error(StartupFailed("HTTP server failed to initialize: " <> e))
      }
      
    Error(e) -> 
      Error(TableInitializationFailed(e))
  }
}

// Application state accessors for external modules
pub fn get_server_node_id(state: ServerState) -> String {
  state.node_id
}

pub fn get_server_config(state: ServerState) -> config_module.Config {
  state.config
}

pub fn get_http_server(state: ServerState) -> HttpServer {
  state.http_server
}

// Main entry point for running the Matrix server application
pub fn run() -> Result(ServerState, ServerError) {
  // Load and validate configuration before starting
  let config = gleammatrix.config.load_config([])
  
  case gleammatrix.config.validate_config(config) {
    Ok(validated_config) -> 
      initialize_application(validated_config)
      
    Error(e) -> 
      Error(StartupFailed("Configuration validation failed: " <> e))
  }
}

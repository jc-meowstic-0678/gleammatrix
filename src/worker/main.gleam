/// Gleam Matrix Server - Cloudflare Workers VPC Edge Proxy Entry Point (Per AGENTS.md Specification)
/// 
/// This module provides:
/// - Edge proxy for DDoS protection and TLS termination per AGENTS.md requirement [3]
/// - Stateless rate limiting with Cloudflare Workers caching (AGENTS.md optimization spec) [2]
/// - Token validation via VPC Service binding to BEAM backend (AGENTS.md integration spec) [3]
/// - Zero Trust policy enforcement before forwarding requests to on-premises BEAM cluster
/// - Observability logging for Gateway logs pipeline (separate from metrics telemetry per AGENTS.md spec)

import gleam/dict.{type Dict}
import gleam/json
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import mist/http.{type Request, type Response}

// ============================================================================
// WORKER REQUEST STRUCTURES (Cloudflare Workers VPC binding format per AGENTS.md spec)
// ============================================================================

/// Edge request envelope with rate limiting metadata and trust indicators
pub type EdgeRequest {
  EdgeRequest(
    client_ip: String,            // Client IP address from X-Forwarded-For header
    user_id: Option(String),      // Resolved user ID from token validation (optional)
    method: String,               // HTTP method (GET, POST, PUT, DELETE)
    path: String,                 // Request path after stripping /_matrix prefix
    headers: Dict(String, String), // Request headers with security indicators
    body: Option(gleam/json.Value), // Optional request body
    rate_limit_bucket: Option(String), // Rate limiting bucket for this client (IP or user-based)
    trust_score: Int              // Trust score 0-100 based on Zero Trust evaluation
  )
}

/// VPC binding request for Cloudflare Workers → BEAM communication (AGENTS.md spec format) [3]
pub type VpcBindingRequest {
  VpcBindingRequest(
    operation_type: String,       // "validate_token" | "rate_limit_check" | "auth_required"
    payload: Dict(String, gleam/json.Value), // Operation-specific parameters
    client_ip: String,            // Client IP for rate limiting bucketing per AGENTS.md spec [2]
    timestamp_ms: Int             // Millisecond timestamp of request origin
  )
}

// ============================================================================
// RATE LIMITING STRUCTURES (Stateless IP-based at edge per AGENTS.md spec) [2]
// ============================================================================

/// Rate limit configuration with bucketing rules for different endpoint types
pub type RateLimitConfig {
  RateLimitConfig(
    window_ms: Int,              // Time window in milliseconds (default: 60000 = 1 minute)
    max_requests: Int,           // Maximum requests allowed per window (default: 100)
    bucket_type: String,         // "ip_based" | "user_based" | "hybrid"
    cache_ttl_seconds: Int       // Worker-side cache TTL for rate limit counters (AGENTS.md spec [2]: default 30s)
  )
}

/// Rate limit result with remaining quota and retry-after guidance per AGENTS.md UX requirement
pub type RateLimitResult {
  RateLimitResult(
    is_limited: Bool,            // Whether request was rate limited
    remaining_requests: Int,     // Remaining requests in current window
    retry_after_ms: Option(Int), // Suggested delay before retry (if limited)
    bucket_id: String            // Unique bucket identifier for this client
  )
}

// ============================================================================
// ZERO TRUST POLICY STRUCTURES (Per AGENTS.md security requirement) [3]
// ============================================================================

/// Zero Trust policy evaluation result with security indicators per AGENTS.md spec [3]
pub type ZeroTrustResult {
  ZeroTrustResult(
    action: String,              // "allow" | "deny" | "challenge" | "block"
    reason: String,              // Human-readable explanation for audit logs
    policy_triggered: Option(String), // Name of triggered policy (if any)
    security_score: Int,         // Trust score 0-100 based on all Zero Trust signals
    threat_indicators: List(String) // Detected threats or anomalies (IP reputation, geo-blocked, etc.)
  )
}

// ============================================================================
// OBSERVABILITY LOGGING STRUCTURES (Gateway vs. separate pipeline per AGENTS.md spec) [3]
// ============================================================================

/// Gateway log entry for Zero Trust policy enforcement events (billable logs per AGENTS.md requirement) [3]
pub type GatewayLogEntry {
  GatewayLogEntry(
    event_type: String,          // "policy_blocked" | "auth_anomaly" | "vpc_metadata" | "allowed_request"
    client_ip: String,           // Client IP address
    user_id: Option(String),     // Authenticated user ID (if applicable)
    endpoint: String,            // Matrix API endpoint accessed
    action_taken: String,        // "blocked" | "challenged" | "allowed"
    policy_name: Option(String), // Name of triggered security policy (if blocked/challenged)
    timestamp_ms: Int            // Millisecond timestamp of event occurrence
  )
}

/// Metrics entry for operational telemetry pipeline (separate from Gateway logs per AGENTS.md spec) [3]
pub type OperationalMetricsEntry {
  OperationalMetricsEntry(
    metric_type: String,         // "rate_limit_hits" | "latency_ms" | "request_count" | "error_rate"
    endpoint: String,            // Matrix API endpoint accessed
    value: Float,               // Metric value (count, latency in ms, etc.)
    tags: Dict(String, String)  // Key-value tags for time-series aggregation (region, user_type, etc.)
  )
}

// ============================================================================
// ENDPOINT HANDLERS - Cloudflare Workers VPC Edge Proxy Entry Point
// ============================================================================

/// Main entry point for all incoming requests to Cloudflare Workers VPC proxy (per AGENTS.md spec) [2]
pub fn handle_worker_request(request: Request) -> Result(Response, Response) {
  // Step 1: Extract client IP and construct request envelope per AGENTS.md specification [2]
  let edge_request <- build_edge_request_envelope(request) |> result.try()
  
  // Step 2: Apply Zero Trust security evaluation before any backend communication (AGENTS.md requirement) [3]
  case evaluate_zero_trust_policy(edge_request) |> result.try(fn(zero_trust_result) {
    case zero_trust_result.action {
      "allow" -> 
        // Continue with request forwarding to BEAM backend
        proceed_with_backend_request(edge_request, zero_trust_result.security_score)
        
      "deny" | "block" -> 
        // Log security event to Gateway logs pipeline per AGENTS.md specification [3]
        log_gateway_event(zero_trust_result)
        
        build_error_response(403, string.uppercase(zero_trust_result.reason), zero_trust_result.reason)
        
      "challenge" | _ -> 
        // Challenge client for additional verification (CAPTCHA, 2FA prompt, etc.)
        challenge_client_for_verification(edge_request)
    }
  }) {
    Ok(result) -> result
    Error(e) -> build_error_response(503, "Edge proxy unavailable", e <> "\nTry again in a few moments")
  } |> result.map_error(fn(msg) { msg <> ". Edge proxy logging has captured this incident." })
}

/// Forward request to on-premises BEAM cluster via VPC Service binding (AGENTS.md integration spec [3])
fn proceed_with_backend_request(edge_request: EdgeRequest, security_score: Int) -> Result(Response, Response) {
  // Validate endpoint requires BEAM authentication/authorization
  case determine_backend_endpoint_type(edge_request.path) |> result.try(fn(endpoint_type: BackendEndpointType) {
    case endpoint_type {
      VpcServiceRequired -> 
        // Query BEAM for token validation or rate limit check via VPC binding (AGENTS.md spec [3])
        perform_vpc_binding_operation(edge_request, endpoint_type) |> result.try(fn(vpc_result) {
          case vpc_result.is_valid {
            True -> forward_to_beam_backend(edge_request)
            False -> build_error_response(401, "Token invalid or expired", "Authentication failed at VPC binding layer")
          }
        })
        
      AuthRequiredAtBeam -> 
        // Forward directly to BEAM (Edge validates token at proxy level before forwarding per AGENTS.md [3])
        forward_to_beam_backend(edge_request)
        
      StatelessRateLimited -> 
        // Check edge-level IP-based rate limit before forwarding (AGENTS.md optimization spec [2])
        case perform_ip_based_rate_limit_check(edge_request.client_ip, edge_request.path) {
          RateLimitResult(is_limited: False, _) -> forward_to_beam_backend(edge_request)
          RateLimitResult(is_limited: True, retry_after_ms: Some(delay_ms)) -> 
            build_error_response(429, "Too many requests", "Rate limit exceeded. Please wait " <> string.int_to_string(delay_ms) <> "ms before retrying")
        }
        
      _ -> forward_to_beam_backend(edge_request) // Default to backend processing
    }
  }) {
    Ok(response) -> response
    Error(e) -> build_error_response(502, "Beam backend unavailable", e <> "\nEdge proxy has logged this incident for observability")
  }
}

// ============================================================================
// ZERO TRUST POLICY EVALUATION (Per AGENTS.md security requirement) [3]
// ============================================================================

/// Evaluate incoming request against Zero Trust security policies per AGENTS.md specification [3]
fn evaluate_zero_trust_policy(request: EdgeRequest) -> Result(ZeroTrustResult, String) {
  // Check 1: IP Reputation & Geo-blocking (AGENTS.md security by default model) [3]
  case check_ip_reputation_and_geo(request.client_ip) |> result.try(fn(ip_status) {
    case ip_status.is_blocked || string.contains(ip_status.reason, "reputation") {
      True -> Ok({action: "deny", reason: "IP address blocked due to reputation or geo-restriction", policy_triggered: option.Some("ip_block_policy_v1"), security_score: 0, threat_indicators: [ip_status.reason]})
      False -> _
    }
  }) {
    ok(result) -> Ok(result) // IP policy triggered - deny/allow already determined
    
    _ -> 
      // Check 2: Path & Endpoint Security (AGENTS.md requirement [3])
      case validate_endpoint_access(request.path, request.method) |> result.try(fn(path_status) {
        case path_status.is_allowed {
          True -> _
          False -> Ok({action: "deny", reason: string.replace_all(path_status.reason, "path", "endpoint"), policy_triggered: option.Some("endpoint_restriction_policy_v1"), security_score: 10, threat_indicators: ["blocked_endpoint"]})
        }
      }) {
        ok(result) -> Ok(result) // Path policy triggered
        
        _ -> 
          // Check 3: Token Validation (AGENTS.md spec [3])
          case validate_client_token(request.headers) |> result.try(fn(token_status) {
            case token_status.is_valid {
              True -> Ok({action: "allow", reason: "Request passed Zero Trust evaluation with valid authentication", policy_triggered: option.None, security_score: 90, threat_indicators: []})
              False -> Ok({action: "deny", reason: "Invalid or missing authentication token", policy_triggered: option.Some("auth_policy_v1"), security_score: 20, threat_indicators: ["invalid_token"]})
            }
          }) {
            ok(result) -> Ok(result) // Auth policy triggered
            
            _ -> 
              // Check 4: Request Anomaly Detection (AGENTS.md observability requirement [3])
              case detect_request_anomalies(request) |> result.try(fn(anomaly_status) {
                case anomaly_status.anomaly_detected {
                  True -> Ok({action: "challenge", reason: string.replace_all(anomaly_status.reason, "anomaly", "unusual request pattern"), policy_triggered: option.Some("anomaly_detection_policy_v1"), security_score: 50, threat_indicators: ["suspicious_pattern"]})
                  False -> Ok({action: "allow", reason: "Request passed all Zero Trust evaluations successfully", policy_triggered: option.None, security_score: 100, threat_indicators: []})
                }
              }) {
                ok(result) -> Ok(result) // Anomaly detected - challenge client
                
                _ -> 
                  // Default allow for unknown policies (per AGENTS.md fail-safe requirement) [3]
                  Ok({action: "allow", reason: "Default Zero Trust policy: request allowed due to no triggers", policy_triggered: option.None, security_score: 75, threat_indicators: []})
              }
          }
      }
  }
}

// ============================================================================
// RATE LIMITING (Stateless IP-based at edge per AGENTS.md spec [2])
// ============================================================================

/// Perform IP-based rate limiting check in Cloudflare Workers cache (AGENTS.md optimization requirement) [2]
fn perform_ip_based_rate_limit_check(client_ip: String, endpoint: String) -> RateLimitResult {
  // In production, use Cloudflare KV or Redis binding for distributed rate limit counters per AGENTS.md spec [2]
  // For this implementation, simulate cache lookup with Worker-side TTL (default: 30 seconds per AGENTS.md [2])
  
  let config = get_default_rate_limit_config() |> result.unwrap(RateLimitConfig(
    window_ms: 60000,           // 1 minute default
    max_requests: 100,          // 100 requests per window default
    bucket_type: "ip_based",    // Stateless IP-based by default per AGENTS.md [2]
    cache_ttl_seconds: 30       // 30 second TTL as per AGENTS.md spec [2]
  ))
  
  let bucket_id = "rate_limit_ip_" <> string.replace_all(client_ip, ".", "_") <> "_" <> string.replace_all(endpoint, "/", "_") |> string.first(64) |> result.unwrap("")
  
  // Simulate cache check - in production, this would query Cloudflare KV or Redis binding per AGENTS.md [2]
  let current_count = simulate_cached_counter(bucket_id, config.window_ms, config.cache_ttl_seconds) |> result.unwrap(0)
  
  case current_count >= config.max_requests {
    True -> 
      RateLimitResult(
        is_limited: True,
        remaining_requests: 0,
        retry_after_ms: option.Some(config.window_ms - (time.timestamp_ms() % config.window_ms)),
        bucket_id: bucket_id
      )
      
    False -> 
      // Increment counter in cache (AGENTS.md optimization per [2])
      _ = increment_cached_counter(bucket_id) |> result.try(fn(_) { Ok(True) })
      
      RateLimitResult(
        is_limited: False,
        remaining_requests: config.max_requests - current_count - 1,
        retry_after_ms: option.None,
        bucket_id: bucket_id
      )
  }
}

/// Get user-based rate limit check for authenticated users (AGENTS.md token bucketing requirement [2])
fn perform_user_based_rate_limit_check(user_id: String, endpoint: String) -> RateLimitResult {
  // In production, query BEAM for token-bucket counters via synchronous callback per AGENTS.md spec [2]
  // For development/testing, simulate user-based rate limiting
  
  let config = get_default_rate_limit_config() |> result.unwrap(RateLimitConfig(
    window_ms: 60000,
    max_requests: 500,          // Higher limit for authenticated users per AGENTS.md spec [2]
    bucket_type: "user_based",
    cache_ttl_seconds: 30
  ))
  
  let bucket_id = "rate_limit_user_" <> string.replace_all(user_id, "@", "_") |> string.first(64) |> result.unwrap("") <> "_" <> string.replace_all(endpoint, "/", "_") |> string.first(64) |> result.unwrap("")
  
  // Simulate cache lookup for user-based counter (in production, this would query BEAM via VPC binding per AGENTS.md [2])
  let current_count = simulate_cached_counter(bucket_id, config.window_ms, config.cache_ttl_seconds) |> result.unwrap(0)
  
  case current_count >= config.max_requests {
    True -> 
      RateLimitResult(
        is_limited: True,
        remaining_requests: 0,
        retry_after_ms: option.Some(config.window_ms - (time.timestamp_ms() % config.window_ms)),
        bucket_id: bucket_id
      )
      
    False -> 
      _ = increment_cached_counter(bucket_id) |> result.try(fn(_) { Ok(True) })
      
      RateLimitResult(
        is_limited: False,
        remaining_requests: config.max_requests - current_count - 1,
        retry_after_ms: option.None,
        bucket_id: bucket_id
      )
  }
}

// ============================================================================
// OBSERVABILITY LOGGING (Gateway vs. separate pipeline per AGENTS.md spec [3])
// ============================================================================

/// Log security event to Cloudflare Gateway Logs pipeline per AGENTS.md specification [3]
fn log_gateway_event(zero_trust_result: ZeroTrustResult) -> Bool {
  // In production, this would write to Cloudflare Gateway Logs API (billable logs per AGENTS.md spec [3])
  // For development/testing, simulate log entry creation
  
  let gateway_log_entry = GatewayLogEntry(
    event_type: case zero_trust_result.action {
      "deny" | "block" -> "policy_blocked"
      "challenge" -> "auth_anomaly"
      _ -> "vpc_metadata"
    },
    client_ip: zero_trust_result.threat_indicators |> list.first() |> option.unwrap("unknown"), // Placeholder - should be request.client_ip
    user_id: None, // Would extract from edge_request.user_id if available
    endpoint: "", // Would extract from edge_request.path
    action_taken: case zero_trust_result.action {
      "deny" | "block" -> "blocked"
      "challenge" -> "challenged"
      _ -> "allowed"
    },
    policy_name: zero_trust_result.policy_triggered,
    timestamp_ms: time.timestamp_ms()
  )
  
  io.println("📝 Gateway Log Entry: " <> io.json.encode(gateway_log_entry) |> string.to_utf8())
  True // Success indicator
}

/// Send operational metrics to separate telemetry pipeline per AGENTS.md specification [3]
fn send_operational_metrics(metric_type: String, endpoint: String, value: Float, tags: Dict(String, String)) -> Bool {
  // In production, this would forward to time-series store (Prometheus, Datadog, etc.) via HTTP per AGENTS.md spec [3]
  // For development/testing, simulate metrics log entry
  
  let metrics_entry = OperationalMetricsEntry(
    metric_type: metric_type,
    endpoint: endpoint,
    value: value,
    tags: dict.insert(tags, "worker_id", io.env("WORKER_ID") |> result.unwrap("unknown")) |> 
           dict.insert(tags, "region", io.env("REGION") |> result.unwrap("us-west-1")) |>
           dict.insert(tags, "environment", io.env("ENVIRONMENT") |> result.unwrap("production"))
  )
  
  // Note: AGENTS.md specification requires these metrics go to SEPARATE pipeline from Gateway logs [3]
  io.println("📊 Operational Metrics: " <> io.json.encode(metrics_entry) |> string.to_utf8())
  True // Success indicator
}

// ============================================================================
// HELPER FUNCTIONS & FORMAT CONVERTERS
// ============================================================================

/// Build edge request envelope with client IP and security metadata per AGENTS.md specification [2]
fn build_edge_request_envelope(request: Request) -> Result(EdgeRequest, String) {
  let client_ip = mist.http.header("X-Forwarded-For", request) |> result.try(fn(header_value) {
    string.split(header_value, ", ") |> list.first() |> option.unwrap_or(mist.http.client_ip(request)) |> result.unwrap("")
  }) |> result.map_error(fn(e) { "Failed to extract client IP: " <> e })
  
  let user_id = case mist.http.header("Authorization", request) |> result.try(fn(auth_header) {
    // Extract user ID from token via cached VPC binding response (in production, query Cloudflare KV per AGENTS.md [3])
    Ok(string.trim(string.split(auth_header, "Bearer ") |> list.drop(1) |> list.first() |> result.unwrap("")) |> result.map(fn(token) { 
      // Placeholder - would decode token and extract user_id in production
      "unknown_user"
    }))
  }) {
    ok(user_id) -> option.Some(string.trim(user_id))
    error(_) -> option.None
  }
  
  Ok(EdgeRequest(
    client_ip: client_ip,
    user_id: user_id,
    method: mist.http.method(request),
    path: string.replace_all(mist.http.path_string(request), "/_matrix/client/", "") |> string.first(128) |> result.unwrap(""),
    headers: dict.from_list([{"X-Forwarded-For": client_ip}, {"User-Agent": mist.http.header("User-Agent", request) |> option.to_value("")}]),
    body: option.None, // Would parse JSON body in production
    rate_limit_bucket: option.Some("ip_" <> string.replace_all(client_ip, ".", "_")),
    trust_score: 75 // Default trust score - would be updated by Zero Trust evaluation below
  ))
}

/// Validate endpoint access against path restrictions per AGENTS.md security requirement [3]
fn validate_endpoint_access(path: String, method: String) -> Result({is_allowed: Bool, reason: String}, String) {
  // In production, query policy definitions from Cloudflare Workers configuration or external config store
  
  case string.starts_with(path, "federation") && (method == "POST" || method == "PUT") {
    True -> Ok({is_allowed: False, reason: "Federation endpoint requires additional security validation"})
    False -> 
      case string.contains(path, "..") || string.contains(path, "/etc/") || string.contains(path, "/proc/") {
        True -> Ok({is_allowed: False, reason: "Path traversal attempt detected - request blocked by Zero Trust policy"})
        False -> Ok({is_allowed: True, reason: "Endpoint path is safe and allowed for this method"})
      }
  }
}

/// Check IP reputation and geo-blocking status per AGENTS.md security requirement [3]
fn check_ip_reputation_and_geo(ip_address: String) -> Result({is_blocked: Bool, reason: String}, String) {
  // In production, query IP reputation database or GeoIP service (e.g., MaxMind, Cloudflare Radar per AGENTS.md spec [3])
  // For development/testing, simulate IP check
  
  case string.contains(ip_address, "10.") || string.contains(ip_address, "192.168.") || string.contains(ip_address, "172.") {
    True -> Ok({is_blocked: False, reason: "Private IP range - allowed for internal testing"})
    False -> 
      // Simulate public IP reputation check (in production, this would query Cloudflare Radar or similar per AGENTS.md [3])
      let is_reputation_bad = string.first(10, ip_address) |> result.unwrap("") == "8.8.8." || string.first(10, ip_address) |> result.unwrap("") == "1.1."
      
      case is_reputation_bad {
        True -> Ok({is_blocked: True, reason: "IP address flagged by reputation database"})
        False -> Ok({is_blocked: False, reason: "IP reputation check passed - no issues detected"})
      }
  } |> result.map_error(fn(e) { e })
}

/// Validate client authentication token per AGENTS.md spec [3]
fn validate_client_token(headers: Dict(String, String)) -> Result({is_valid: Bool, reason: String}, String) {
  // In production, this would query Cloudflare Workers VPC binding to BEAM backend for token validation per AGENTS.md spec [3]
  // For development/testing, simulate token validation
  
  case dict.get("Authorization", headers) |> option.to_result() |> result.try(fn(auth_header) {
    string.starts_with(auth_header, "Bearer ") && string.length(auth_header) > 80
  }) {
    ok(True) -> Ok({is_valid: True, reason: "Valid Bearer token format detected"})
    error(_) -> Ok({is_valid: False, reason: "Authorization header missing or invalid format"})
  } |> result.map_error(fn(e) { e })
}

/// Detect request anomalies for Zero Trust evaluation per AGENTS.md security requirement [3]
fn detect_request_anomalies(request: EdgeRequest) -> Result({anomaly_detected: Bool, reason: String}, String) {
  // In production, query behavioral analysis engine or ML model trained on normal traffic patterns (per AGENTS.md spec [3])
  // For development/testing, simulate anomaly detection
  
  case request.headers |> dict.get("User-Agent") |> option.to_result() |> result.try(fn(user_agent) {
    string.contains(string.lowercase_string(user_agent), "bot") || string.contains(user_agent, "curl") || string.contains(user_agent, "wget")
  }) {
    ok(True) -> Ok({anomaly_detected: True, reason: "Suspicious user-agent pattern detected - may indicate automated tool usage"})
    error(_) -> Ok({anomaly_detected: False, reason: "No anomalies detected in request headers or patterns"})
  } |> result.map_error(fn(e) { e })
}

/// Get default rate limit configuration per AGENTS.md specification [2]
fn get_default_rate_limit_config() -> Result(RateLimitConfig, String) {
  let cache_ttl = io.env("RATE_LIMIT_CACHE_TTL") |> result.try(fn(val_str) { int.from_string(val_str) }) |> result.unwrap_or(30)
  
  Ok(RateLimitConfig(
    window_ms: 60000,           // 1 minute default
    max_requests: 100,          // 100 requests per window default
    bucket_type: "ip_based",    // Stateless IP-based by default per AGENTS.md [2]
    cache_ttl_seconds: cache_ttl // User-configurable TTL (default 30s per AGENTS.md spec [2])
  ))
}

/// Build error response with Matrix FAPI-compatible format per AGENTS.md specification
fn build_error_response(status_code: Int, errcode: String, message: String) -> Result(Response, Response) {
  let error_data = dict.from_list([
    {"errcode": "F_" <> string.uppercase(errcode)},
    {"error": message}
  ]) |> io.json.encode() |> string.to_utf8()
  
  Ok(mist/http.json_response(status_code, error_data))
}

/// Challenge client for additional verification (CAPTCHA, 2FA prompt) per AGENTS.md security requirement [3]
fn challenge_client_for_verification(request: EdgeRequest) -> Result(Response, Response) {
  // In production, return CAPTCHA challenge or redirect to authentication provider per AGENTS.md spec [3]
  // For development/testing, simulate challenge response
  
  Ok(mist/http.json_response(401, io.json.encode({
    {"error": "Additional verification required due to suspicious activity"},
    {"challenge_type": "captcha", "session_id": string.first(32, random.random_bits(128) |> io.base64_encode()) |> result.unwrap("")}
  }) |> string.to_utf8()))
}

/// Simulate cached counter lookup (in production, use Cloudflare KV or Redis binding per AGENTS.md [2])
fn simulate_cached_counter(bucket_id: String, window_ms: Int, cache_ttl_seconds: Int) -> Result(Int, String) {
  // Placeholder simulation - in production, this would query actual cache storage per AGENTS.md spec [2]
  Ok(random.random_bits(32) |> io.base64_encode() |> string.first(10) |> result.unwrap("0") |> string.to_int(result.unwrap_or(0)))
}

/// Increment cached counter (in production, use Cloudflare KV or Redis binding per AGENTS.md [2])
fn increment_cached_counter(bucket_id: String) -> Result(Int, String) {
  // Placeholder simulation - in production, this would actually increment cache entry per AGENTS.md spec [2]
  Ok(10) // Simulate counter increment
}

/// Determine which backend endpoint type requires VPC binding validation (per AGENTS.md spec [3])
fn determine_backend_endpoint_type(path: String) -> BackendEndpointType {
  case string.starts_with(path, "auth") || string.contains(path, "validate") {
    True -> AuthRequiredAtBeam // Requires BEAM authentication but edge validates token format first
    False -> 
      case string.contains(path, "/_matrix/federation/") || string.contains(path, "/send/") {
        True -> VpcServiceRequired // Requires synchronous BEAM callback for federation validation per AGENTS.md [3]
        False -> StatelessRateLimited // IP-based rate limit at edge per AGENTS.md [2]
      }
  }
}

// ============================================================================
// HELPER TYPES (placeholder for full implementation)
// ============================================================================

/// Backend endpoint type classification for VPC binding routing decisions per AGENTS.md spec [3]
pub type BackendEndpointType {
  VpcServiceRequired     // Requires synchronous BEAM callback via VPC binding (e.g., token validation, rate limit check)
  AuthRequiredAtBeam     // Authorization performed at BEAM layer after edge passes request
  StatelessRateLimited   // IP-based rate limiting handled entirely at edge (no BEAM callback required per AGENTS.md [2])
}

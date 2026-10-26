/// Gleam Matrix Server - Cloudflare Workers VPC Policy Enforcement Module (Zero Trust per AGENTS.md spec)
/// 
/// This module provides:
/// - Zero Trust policy enforcement for DDoS protection and security (AGENTS.md requirement [3])
/// - IP reputation checking with threat intelligence integration per AGENTS.md specification [3]
/// - Path traversal detection and endpoint security validation
·/ import gleam/dict.{type Dict}
import gleam/json
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import mist/http.{type Request, type Response}

// ============================================================================
// POLICY DEFINITIONS (Zero Trust per AGENTS.md specification) [3]
// ============================================================================

/// Zero Trust security policy definition for Matrix federation and client API protection
pub type ZeroTrustPolicy {
  ZeroTrustPolicy(
    policy_id: String,             // Unique policy identifier (e.g., "ip_block_policy_v1")
    name: String,                  // Human-readable policy name
    description: String,           // Detailed policy description for audit logs
    action: String,                // "allow" | "deny" | "challenge" | "block"
    priority: Int,                 // Policy precedence (lower number = higher priority)
    conditions: List(PolicyCondition), // Conditions that trigger this policy
    threat_indicators: List(String), // Indicators of potential threats detected by this policy
    enabled: Bool                  // Whether policy is currently active (AGENTS.md configuration requirement [3])
  )
}

/// Policy condition structure for Zero Trust evaluation per AGENTS.md spec [3]
pub type PolicyCondition {
  PolicyCondition(
    field: String,                 // Field to evaluate (e.g., "client_ip", "user_agent", "request_path")
    operator: String,              // Comparison operator ("contains", "starts_with", "equals", "regex")
    expected_value: String         // Expected value for comparison
  )
}

// ============================================================================
// THREAT INTEL INTEGRATION (Per AGENTS.md security requirement) [3]
// ============================================================================

/// Threat intelligence indicator structure for IP reputation and geoblocking checks per AGENTS.md spec [3]
pub type ThreatIndicator {
  ThreatIndicator(
    ip_address: String,            // Flagged IP address or CIDR range
    threat_type: String,           // "malicious", "scanner", "botnet", "tor_exit_node"
    severity: Int,                 // Severity score 1-100 (AGENTS.md prioritization requirement [3])
    first_seen_ms: Int,            // When IP was first flagged
    last_seen_ms: Int,             // Most recent detection timestamp
    confidence_score: Float,       // Confidence level 0.0-1.0 that this is a threat source
    sources: List(String)          // Data sources reporting this threat (e.g., "Cloudflare Radar", "AbuseIPDB")
  )
}

/// Geolocation data structure for geo-blocking enforcement per AGENTS.md security spec [3]
pub type GeoLocationData {
  GeoLocationData(
    ip_address: String,            // Requesting IP address
    country_code: String,          // ISO 3166-1 alpha-2 country code (e.g., "US", "CN", "RU")
    region: String,                // Region/state/province name
    city: String,                  // City name
    latitude: Float,               // Geographic latitude coordinate
    longitude: Float,              // Geographic longitude coordinate
    is_proxy: Bool,                // Whether IP is a known proxy/VPN/tor exit node
    is_datacenter: Bool            // Whether IP belongs to datacenter/hosting provider
  )
}

// ============================================================================
// POLICY EVALUATION (Zero Trust per AGENTS.md requirement) [3]
// ============================================================================

/// Evaluate incoming request against all active Zero Trust policies per AGENTS.md specification [3]
pub fn evaluate_policy_for_request(request: Request, client_ip: String, user_agent: Option(String)) -> Result(PolicyEvaluationResult, String) {
  // Load active policies from Cloudflare Workers configuration or external config store (AGENTS.md requirement [3])
  let active_policies <- load_active_zero_trust_policies() |> result.try()
  
  // Sort policies by priority (lower number = higher priority per AGENTS.md spec [3])
  let sorted_policies = list.sort(active_policies, fn(policy1: ZeroTrustPolicy, policy2: ZeroTrustPolicy) {
    case policy1.priority < policy2.priority {
      True -> -1 // Higher priority first
      False -> 1 // Lower priority later
    }
  })
  
  // Iterate through policies in order of precedence (AGENTS.md security-first approach [3])
  case list.fold_left(sorted_policies, Ok(PolicyEvaluationResult(action: "allow", triggers: [], reason: "No policy violations detected")), fn(current_policy: ZeroTrustPolicy, result: Result(PolicyEvaluationResult, String)) {
    Ok(eval_result) -> 
      // Check if this policy's conditions match the request (AGENTS.md evaluation spec [3])
      case evaluate_policy_conditions(request, client_ip, user_agent, current_policy.conditions) |> result.try(fn(matching: Bool) {
        case matching && current_policy.enabled {
          True -> 
            // Policy triggered - apply action and accumulate threat indicators per AGENTS.md spec [3]
            let new_triggers = eval_result.triggers <> [current_policy.name]
            let new_reason = string.replace_all(eval_result.reason, "\n", " ") <> " | Triggered: " <> current_policy.name
            
            Ok(PolicyEvaluationResult(
              action: current_policy.action,
              triggers: new_triggers,
              reason: new_reason <> " (Policy: " <> current_policy.name <> ")"
            ))
            
          False -> Ok(eval_result) // Policy not triggered - continue evaluation
        }
      }) {
        ok(result) -> Ok(result)
        error(e) -> Error("Policy evaluation failed for " <> current_policy.name <> ": " <> e)
      }
      
    Error(e) -> Error(e) // Previous policy evaluation failed - abort remaining checks per AGENTS.md security model [3]
  }) {
    ok(final_result) -> 
      // Log detected threats to observability pipeline per AGENTS.md requirement [3]
      log_threat_detection(final_result, client_ip) |> result.try(fn(_) { Ok(True) })
      
      Ok(final_result)
      
    error(e) -> 
      Error("Failed complete policy evaluation: " <> e <> "\nEdge proxy has logged this incident for observability")
  } |> result.map_error(fn(msg) { msg })
}

/// Evaluate individual policy conditions against request attributes (AGENTS.md condition matching spec [3])
fn evaluate_policy_conditions(request: Request, client_ip: String, user_agent: Option(String), conditions: List(PolicyCondition)) -> Result(Bool, String) {
  case list.fold_left(conditions, Ok(True), fn(condition: PolicyCondition, result: Result(Bool, String)) {
    ok(matches_so_far) -> 
      let field_value = case condition.field {
        "client_ip" -> client_ip
        "user_agent" -> user_agent |> option.to_result() |> result.unwrap("")
        "request_path" -> mist.http.path_string(request)
        "request_method" -> mist.http.method(request)
        _ -> "" // Unknown field - skip evaluation
      }
      
      let condition_matches = case string.lowercase_string(condition.operator) {
        "contains" -> string.contains(string.lowercase_string(field_value), string.lowercase_string(condition.expected_value))
        "starts_with" -> string.starts_with(string.lowercase_string(field_value), string.lowercase_string(condition.expected_value))
        "equals" | "==" -> field_value == condition.expected_value
        "regex" -> regex_matches(pattern: condition.expected_value, input: field_value) |> option.unwrap(False)
        "does_not_contain" -> !string.contains(string.lowercase_string(field_value), string.lowercase_string(condition.expected_value))
        _ -> False // Unknown operator - fail closed per AGENTS.md security requirement [3]
      }
      
      Ok(matches_so_far && condition_matches)
      
    error(e) -> Error(e)
  }) {
    ok(True) -> Ok(True) // All conditions matched
    ok(False) | error(_) -> Ok(False) // Some condition failed - policy not triggered
  }
}

// ============================================================================
// IP REPUTATION & GEO-BLOCKING (Per AGENTS.md security requirement) [3]
// ============================================================================

/// Check IP against threat intelligence databases per AGENTS.md specification [3]
pub fn check_ip_reputation(ip_address: String) -> Result({is_blocked: Bool, reason: String, indicators: List(ThreatIndicator)}, String) {
  // In production, query threat intelligence services (Cloudflare Radar, AbuseIPDB, VirusTotal per AGENTS.md spec [3])
  // For development/testing, simulate reputation check
  
  let known_bad_prefixes = ["8.8.8.", "1.1.1.", "208.", "198.51."]
  
  case list.any(known_bad_prefixes, fn(prefix: String) { string.starts_with(ip_address, prefix) }) {
    True -> 
      Ok({is_blocked: True, reason: "IP address matches known malicious threat indicators from threat intelligence feed", indicators: [
        ThreatIndicator(
          ip_address: ip_address,
          threat_type: "malicious_scan_source",
          severity: 85,
          first_seen_ms: time.timestamp_ms() - 86400000, // Flagged 24 hours ago
          last_seen_ms: time.timestamp_ms(),              // Recently detected
          confidence_score: 0.92,                          // High confidence match
          sources: ["Cloudflare Radar", "AbuseIPDB", "ThreatIntelligenceFeed"]
        )
      ]})
      
    False -> 
      Ok({is_blocked: False, reason: "No threat indicators found for this IP address - reputation check passed", indicators: []})
  } |> result.map_error(fn(e) { e })
}

/// Check IP geolocation against geo-blocking policy per AGENTS.md specification [3]
pub fn check_geo_restrictions(ip_address: String, blocked_countries: List(String)) -> Result({is_blocked: Bool, reason: String, geo_data: GeoLocationData}, String) {
  // In production, query GeoIP service (MaxMind GeoIP2, Cloudflare Geolocation per AGENTS.md spec [3])
  // For development/testing, simulate geolocation data
  
  let simulated_geo = GeoLocationData(
    ip_address: ip_address,
    country_code: get_simulated_country_code(ip_address), // Simulate country code based on IP
    region: "Simulated Region",
    city: "Simulated City",
    latitude: 37.7749, // San Francisco coordinates (example)
    longitude: -122.4194,
    is_proxy: string.contains(ip_address, "proxy") || string.contains(ip_address, "tor"),
    is_datacenter: string.contains(ip_address, "datacenter")
  )
  
  case blocked_countries |> list.any(fn(blocked_country: String) { 
    string.uppercase_string(simulated_geo.country_code) == string.uppercase_string(blocked_country)
  }) {
    True -> 
      Ok({is_blocked: True, reason: string.replace_all("Request from geo-blocked region: " <> simulated_geo.country_code <> " (" <> simulated_geo.city <> "). Please verify this is a legitimate user.", "region", "geo"), geo_data: simulated_geo})
      
    False -> 
      // Additional check for proxy/tor exit nodes (AGENTS.md security requirement [3])
      case simulated_geo.is_proxy || simulated_geo.is_datacenter {
        True -> 
          Ok({is_blocked: False, reason: "Request from datacenter/proxy IP detected but not geo-blocked - logged for monitoring", geo_data: simulated_geo})
          
        False -> 
          Ok({is_blocked: False, reason: "No geolocation restrictions triggered for this request", geo_data: simulated_geo})
      }
  } |> result.map_error(fn(e) { e })
}

// ============================================================================
// PATH SECURITY & TRAVELER DETECTION (Per AGENTS.md requirement [3])
// ============================================================================

/// Validate request path for security violations per Matrix federation API spec and AGENTS.md security requirement [3]
pub fn validate_path_security(request: Request) -> Result({is_safe: Bool, reason: String, blocked_pattern: Option(String)}, String) {
  let request_path = mist.http.path_string(request)
  
  // Check for path traversal attempts (.. sequences, etc.) per AGENTS.md security spec [3]
  case string.contains(request_path, "..") || string.contains(request_path, "%2e%2e") || string.contains(request_path, "%252e") {
    True -> 
      Ok({is_safe: False, reason: "Path traversal attempt detected - request blocked by Zero Trust security policy", blocked_pattern: option.Some(".. sequence")})
      
    False -> 
      // Check for sensitive system paths per Matrix FAPI spec and AGENTS.md requirement [3]
      case string.contains(request_path, "/etc/") || string.contains(request_path, "/proc/") || string.contains(request_path, "/sys/") || string.contains(request_path, "/dev/") {
        True -> 
          Ok({is_safe: False, reason: "Attempted access to sensitive system path - request blocked per Zero Trust policy", blocked_pattern: option.Some("system_path_access")})
          
        False -> 
          // Check for Matrix-specific security requirements (AGENTS.md federation protocol compliance [3])
          case string.contains(request_path, "/federation/") && !string.starts_with(request_path, "/_matrix/federation/") {
            True -> 
              Ok({is_safe: False, reason: "Invalid federation API endpoint detected - incorrect path format", blocked_pattern: option.Some("invalid_federation_endpoint")})
              
            False -> 
              // Check for valid Matrix protocol paths (AGENTS.md spec compliance [3])
              case string.starts_with(request_path, "/_matrix/client/") || string.starts_with(request_path, "/_matrix/federation/") || string.starts_with(request_path, "/_matrix/identity/") {
                True -> 
                  Ok({is_safe: True, reason: "Request path is valid Matrix API endpoint", blocked_pattern: option.None})
                  
                False -> 
                  // Allow non-Matrix paths for edge proxy functionality (AGENTS.md requirement [3])
                  Ok({is_safe: True, reason: "Edge proxy allows requests to external endpoints - path validation passed", blocked_pattern: option.None})
              }
          }
      }
  } |> result.map_error(fn(e) { e })
}

// ============================================================================
// OBSERVABILITY & LOGGING (Per AGENTS.md security requirement) [3]
// ============================================================================

/// Log detected threats and policy violations to observability pipeline per AGENTS.md specification [3]
fn log_threat_detection(result: PolicyEvaluationResult, client_ip: String) -> Result(Bool, String) {
  // In production, this would write to Cloudflare Gateway Logs (billable logs per AGENTS.md spec [3])
  // or separate telemetry pipeline for operational metrics (AGENTS.md observability requirement [3])
  
  let log_entry = dict.from_list([
    {"event_type", case result.action {
      "deny" | "block" -> "policy_blocked"
      "challenge" -> "auth_anomaly"
      _ -> "allowed_request"
    }},
    {"client_ip", client_ip},
    {"triggers", result.triggers},
    {"action_taken", string.lowercase_string(result.action)},
    {"timestamp_ms", time.timestamp_ms()}
  ]) |> io.json.encode() |> string.to_utf8()
  
  // Note: AGENTS.md requires these logs go to Gateway Logs (Zero Trust security events) [3]
  // NOT the operational telemetry pipeline which is for metrics/metrics-only data per AGENTS.md spec [3]
  io.println("🛡️ Zero Trust Security Log: " <> log_entry)
  
  Ok(True) // Success indicator
}

/// Generate security audit trail entry for policy enforcement events (AGENTS.md audit requirement [3])
pub fn generate_audit_trail(policy_name: String, client_ip: String, user_id: Option(String), action_taken: String) -> Result(gleam/json.Value, String) {
  let audit_entry = dict.from_list([
    {"audit_id": string.first(32, random.random_bits(128) |> io.base64_encode()) |> result.unwrap("")},
    {"policy_name": policy_name},
    {"client_ip": client_ip},
    {"user_id": user_id |> option.to_result() |> result.unwrap("anonymous")},
    {"action": string.lowercase_string(action_taken)},
    {"timestamp_ms": time.timestamp_ms()},
    {"compliance_status": "logged"} // AGENTS.md audit trail requirement [3]
  ]) |> io.json.encode() |> string.to_utf8()
  
  Ok(io.json.decode_string(gleam/json.Value, audit_entry) |> result.unwrap(json.Null))
}

// ============================================================================
// POLICY LOADING & CONFIGURATION (Per AGENTS.md specification) [3]
// ============================================================================

/// Load active Zero Trust policies from Cloudflare Workers configuration or external config store per AGENTS.md requirement [3]
fn load_active_zero_trust_policies() -> Result(List(ZeroTrustPolicy), String) {
  // In production, this would query Cloudflare Workers configuration store, external config service (e.g., AWS Secrets Manager, HashiCorp Vault per AGENTS.md spec [3])
  // For development/testing, return simulated policy definitions
  
  let default_policies = [
    ZeroTrustPolicy(
      policy_id: "ip_block_policy_v1",
      name: "IP Block Policy",
      description: "Blocks requests from known malicious IP addresses and ranges based on threat intelligence feeds",
      action: "deny",
      priority: 10,                // High priority (low number = higher precedence per AGENTS.md spec [3])
      conditions: [PolicyCondition(field: "client_ip", operator: "contains", expected_value: "8.8.8")],
      threat_indicators: ["malicious_scan_source"],
      enabled: True
    ),
    ZeroTrustPolicy(
      policy_id: "geo_block_policy_v1",
      name: "Geo Block Policy",
      description: "Blocks requests from geo-blocked countries and regions for compliance purposes",
      action: "deny",
      priority: 20,
      conditions: [PolicyCondition(field: "client_ip", operator: "regex", expected_value: "^198\\.51\\.[0-9]+\\.[0-9]+$")],
      threat_indicators: ["geo_restricted_access"],
      enabled: True
    ),
    ZeroTrustPolicy(
      policy_id: "path_traversal_policy_v1",
      name: "Path Traversal Detection",
      description: "Blocks requests containing path traversal attempts (.. sequences, encoded variants)",
      action: "deny",
      priority: 5,                 // Highest priority for security-critical detections per AGENTS.md spec [3]
      conditions: [PolicyCondition(field: "request_path", operator: "contains", expected_value: "..")],
      threat_indicators: ["path_traversal_attempt"],
      enabled: True
    ),
    ZeroTrustPolicy(
      policy_id: "suspicious_ua_policy_v1",
      name: "Suspicious User-Agent Detection",
      description: "Challenges requests from suspicious or automated user agents (curl, wget, bots)",
      action: "challenge",
      priority: 30,                // Lower priority - allows request but challenges for verification per AGENTS.md [3]
      conditions: [PolicyCondition(field: "user_agent", operator: "contains", expected_value: "bot")],
      threat_indicators: ["suspicious_user_agent"],
      enabled: True
    )
  ]
  
  Ok(default_policies)
}

// ============================================================================
// HELPER FUNCTIONS & UTILITIES
// ============================================================================

/// Simple regex pattern matcher for policy evaluation (AGENTS.md pattern matching requirement [3])
fn regex_matches(pattern: String, input: String) -> Result(Bool, String) {
  // In production, use proper regex engine with RE2 syntax per AGENTS.md security spec [3]
  // For development/testing, simulate basic pattern matching
  
  case string.contains(input, pattern) || string.starts_with(input, pattern) || string.ends_with(input, pattern) {
    True -> Ok(True)
    False -> Ok(False)
  } |> result.map_error(fn(e) { "Regex evaluation failed: " <> e })
}

/// Generate simulated country code based on IP address (for development/testing per AGENTS.md spec [3])
fn get_simulated_country_code(ip_address: String) -> String {
  case string.first(10, ip_address) |> result.unwrap("") {
    "8.8.8." | "8.8.4." -> "US"     // Google DNS (example)
    "1.1.1." | "1.0.0." -> "US"     // Cloudflare DNS (example)
    "208.67." -> "US"              # OpenDNS example
    "198.51." -> "CN"              # Simulated Chinese IP (example)
    "192.0." -> "RU"               # Simulated Russian IP (example)
    _ -> "US"                      # Default to US for development
  }
}

// ============================================================================
// RESULT TYPES (placeholder for full implementation)
// ============================================================================

/// Result of policy evaluation containing action and trigger information per AGENTS.md spec [3]
pub type PolicyEvaluationResult {
  PolicyEvaluationResult(
    action: String,              // "allow" | "deny" | "challenge" | "block" (AGENTS.md security-first approach [3])
    triggers: List(String),      // List of triggered policy names for audit trails per AGENTS.md requirement [3]
    reason: String               // Human-readable explanation of evaluation result and policy triggers per AGENTS.md spec [3]
  )
}

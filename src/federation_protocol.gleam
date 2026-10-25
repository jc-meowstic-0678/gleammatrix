/// Gleam Matrix Server - Federation Protocol Module
/// 
/// This module implements:
/// - Federation v1 protocol for server-to-server communication
/// - Key ID validation and signature verification
/// - Event transport with pagination support
/// - Handshake protocol for establishing trusted connections
/// - Message encryption (Olml/Megolm support via federation_crypto)

import gleam/dict
import gleam/list
import gleam/map
import gleam/result
import gleam/string
import gleam/time

// Federation version identifiers for protocol compatibility
pub type FederationVersion {
  V1 // Matrix federation v1 (current stable)
  V2 // Future version with improvements
}

// Protocol handshake states for connection establishment
pub type HandshakeState {
  ConnectionStateInit        // Initial connection attempt
  ConnectionKeyExchange     // Exchanging public keys for verification
  ConnectionEstablished     // Trusted peer connection active
  ConnectionVerificationFailed(String) // Verification error occurred
  ConnectionTimeout          // Handshake timed out
}

// Federation request type classification
pub type FederationRequestType {
  SendEvent                // Sending an event to federation peer
  GetEvent                 // Requesting a specific event
  QueryUserProfile         // User profile lookup query
  QueryServerInfo          // Server capability information
  SignaturesUpload         // Key signature upload
  Backfill                 // Historical event backfill request
}

// Federation response status for protocol operations
pub type FederationResponseStatus {
  OK                      // Successful operation
  Error(MatrixError)      // Matrix protocol error with code/message
  RetryAfter(TimeUnit)    // Server temporarily unavailable, retry later
  BadVersion(String)      // Unsupported federation version
  SignatureInvalid        // Event signature verification failed
}

// Matrix error codes and messages for federation protocol errors
pub type MatrixError {
  MatrixError(
    code: String,                    // HTTP-style error code (M_FORBIDDEN, etc.)
    message: String,                 // Human-readable error description
    errcode: String,                 // Machine-readable error code
    retry_after_ms: Option(Int)      // Suggested retry interval if applicable
  )
}

// Key ID format for Ed25519 signatures (matches federation_crypto)
pub type KeyId {
  KeyId(
    algorithm: String,              // Signature algorithm (ed25519)
    timestamp_ms: Int,              // Key creation timestamp in milliseconds
    signature_count: Int            // Sequence number for multiple keys per day
  )
}

// Fingerprint type for key identification and comparison
pub type FingerprintType {
  SHA256(String)                   // SHA-256 hash identifier
  SHA512(String)                   // SHA-512 hash identifier (for longer-term keys)
  Base64(String)                   // Base64 encoded identifier
}

// Server information structure for capability negotiation
pub type ServerInfo {
  ServerInfo(
    server_name: String,            // Matrix server domain (e.g., "example.com")
    version: FederationVersion,     // Supported federation protocol version
    support_versioning: Bool,       // Supports multiple protocol versions
    max_send_rate: Int,             // Maximum events per second allowed
    supported_algorithms: List(String), // Supported encryption algorithms
    server_time_ms: Int             // Server's current time in milliseconds
  )
}

// Federation event structure for transport between servers
pub type FederationEvent {
  FederationEvent(
    event_id: String,               // Unique event identifier (e.g., "$abc123...")
    event_type: String,             // Event type (m.room.message, m.room.member, etc.)
    room_id: String,                // Room where event originated
    sender: String,                 // User ID who sent the event
    origin: String,                 // Originating server domain name
    timestamp_ms: Int,              // Event creation timestamp
    unsigned_metadata: Dict(String, gleam/string), // Unsigned metadata for tracking
    content: Dict(String, gleam/string),           // Event content payload
    auth_events: List(String),      // Authentication event references (for room state)
    hash_sha256: String,            // Event body SHA-256 hash for integrity verification
    signatures: Dict(String, SignaturesEntry)       // Server signature entries
  )
}

// Signature entry structure for event authentication
pub type SignaturesEntry {
  SignaturesEntry(
    key_id: KeyId,                 // Key ID that created the signature
    algorithm: String,             // Signature algorithm (ed25519)
    signature_data: gleam/string   // Base64-encoded signature bytes
  )
}

// Query parameters for federation request/response pagination
pub type FederationQueryParams {
  FederationQueryParams(
    limit: Int,                    // Maximum events to return per request
    timeout_ms: Int,               // Request timeout in milliseconds
    key_ids: List(KeyId),          // Required key IDs for signature verification
    since_event_id: Option(String) // Continue from specific event ID (pagination)
  )
}

// Backfill request for historical events retrieval
pub type BackfillRequest {
  BackfillRequest(
    room_id: String,               // Room to backfill events from
    start_depth: Int,              // Start from this depth in event timeline
    depth_limit: Int,              // Maximum events to retrieve (e.g., 50)
    requested_keys: List(String),  // Key IDs needed for signature verification
    extra_headers: Dict(String, gleam/string) // Additional protocol-specific headers
  )
}

// Handshake configuration for establishing federated connections
pub type FederationHandshakeConfig {
  FederationHandshakeConfig(
    server_name: String,           // Peer server domain to connect to
    client_key_id: KeyId,          // Our key ID for signature verification
    trusted_keys: Dict(String, List(KeyId)), // Previously verified peer keys
    timeout_ms: Int,               // Maximum handshake duration
    retry_attempts: Int            // Number of connection retries before failure
  )
}

// Event transport result after successful or failed transmission
pub type EventTransportResult {
  EventTransportResult(
    success: Bool,                 // Whether event was successfully transmitted
    destination_server: String,    // Target server domain name
    event_id: String,              // Transmitted event ID
    response_code: Int,            // HTTP-style status code (200=OK, 4xx=Error)
    error_message: Option(String), // Error description if failed
    signature_verification_status: Bool, // Peer successfully verified our signatures
    latency_ms: Int                // Round-trip time for request/response
  )
}

// Signature verification result after event validation
pub type SignatureVerificationResult {
  SignatureVerificationResult(
    is_valid: Bool,                // Event signatures verified successfully
    verified_key_ids: List(KeyId), // Key IDs that passed verification
    failed_key_ids: List(KeyId),   // Key IDs that failed verification
    verification_timestamp_ms: Int // When verification was performed
  )
}

// Federation protocol error types for debugging and reporting
pub type FederationProtocolError {
  ConnectionTimeout(String)               // Handshake timed out before completion
  ServerUnavailable(String, Int)          // Target server unreachable (error code, retry_after)
  SignatureVerificationFailed(String, String, FingerprintType) // Event signature invalid
  InvalidEventFormat(String)              // Event payload malformed
  UnsupportedVersion(FederationVersion)   // Protocol version not supported
  KeyNotFound(KeyId, String)              // Required key missing from peer
  MaxSendRateExceeded(Int, Int)           // Rate limit hit (current_rate, max_allowed)
  PaginationError(String, Int)            // Invalid pagination parameters
}

// Initialize federation protocol handshake with trusted peer server
pub fn initialize_federation_handshake(config: FederationHandshakeConfig) -> Result(HandshakeState, FederationProtocolError) {
  let now_ms = time.timestamp_now_ms()
  
  case establish_connection_with_server(
    config.server_name,
    config.timeout_ms,
    config.trusted_keys,
    config.client_key_id.algorithm,
    now_ms
  ) |> result {
    Ok(peer_info) -> 
      // Verify peer's key signatures and certificate chain
      case verify_peer_key_signatures(peer_info.verified_keys, config.client_key_id) |> result {
        True -> 
          // Key verified successfully - mark connection as established
          mnesia_tables.set_federation_handshake_state(
            config.server_name,
            ConnectionStateEstablished
          ) |> result.ok_or_else(fn() { FederationProtocolError.ConnectionTimeout("State update failed for " <> config.server_name) })
          
          Ok(ConnectionStateEstablished)
          
        False -> 
          // Signature verification failed - log and mark connection as failed
          mnesia_tables.set_federation_handshake_state(
            config.server_name,
            ConnectionVerificationFailed("Key signature invalid")
          ) |> result.ok_or_else(fn() { FederationProtocolError.SignatureVerificationFailed(config.server_name, "Signature mismatch", FingerprintType.SHA256("")) })
          
          Ok(ConnectionVerificationFailed("Peer key signatures invalid"))
      }
      
    Error(e) -> 
      // Connection establishment failed - determine retry strategy
      case handle_connection_failure(config.retry_attempts, config.server_name, now_ms) |> result {
        Ok(retry_after_ms) -> 
          mnesia_tables.set_federation_handshake_state(
            config.server_name,
            ConnectionStateTimeout
          ) |> result.ok_or_else(fn() { FederationProtocolError.ConnectionTimeout("Connection failure for " <> config.server_name) })
          
          Ok(ConnectionTimeout)
          
        Error(_) -> 
          Ok(ConnectionVerificationFailed(e))
      }
  }
}

// Send event to federation peer with signature and transport protection
pub fn send_federation_event(
  event: FederationEvent,
  destination_server: String,
  private_key_pem: gleam/string,
  query_params: FederationQueryParams
) -> Result(EventTransportResult, FederationProtocolError) {
  let now_ms = time.timestamp_now_ms()
  
  // Verify event signatures before transmission
  case verify_event_signatures(event, destination_server, now_ms) |> result {
    Ok(sig_result) -> 
      // Event has valid signatures - proceed with transmission
      case event.content.dict.get("msgtype") |> option {
        Some("m.text") -> 
          // Standard text message - send via normal transport
          transmit_event_via_https(
            destination_server,
            "/_matrix/federation/v1/send/" <> encode_url_path(event.event_id),
            event,
            private_key_pem,
            now_ms + 30000 // 30 second timeout for message delivery
          ) |> result.map(fn(http_response) {
            EventTransportResult(
              success: http_response.status_code >= 200 && http_response.status_code < 300,
              destination_server: destination_server,
              event_id: event.event_id,
              response_code: http_response.status_code,
              error_message: if http_response.body == "" then None("") else Some(http_response.body),
              signature_verification_status: sig_result.is_valid,
              latency_ms: now_ms - http_response.request_start_ms
            )
          }) |> result.ok_or_else(fn() { FederationProtocolError.ConnectionTimeout("Send timeout for " <> event.event_id) })
          
        _ -> 
          // Special message type or encrypted content - apply additional validation
          transmit_encrypted_event_via_https(
            destination_server,
            "/_matrix/federation/v1/send/" <> encode_url_path(event.event_id),
            event,
            private_key_pem,
            now_ms + 60000 // 60 second timeout for encrypted content
          ) |> result.map(fn(http_response) {
            EventTransportResult(
              success: http_response.status_code >= 200 && http_response.status_code < 300,
              destination_server: destination_server,
              event_id: event.event_id,
              response_code: http_response.status_code,
              error_message: None(""), // Encrypted content handled differently
              signature_verification_status: sig_result.is_valid,
              latency_ms: now_ms - http_response.request_start_ms
            )
          }) |> result.ok_or_else(fn() { FederationProtocolError.InvalidEventFormat("Encrypted event send failed for " <> event.event_id) })
      }
      
    Error(e) -> 
      // Event signatures invalid - reject transmission
      Error(FederationProtocolError.SignatureVerificationFailed(event.event_id, e, FingerprintType.SHA256("")) )
  }
}

// Request specific event from federation peer via GET endpoint
pub fn request_federation_event(
  event_id: String,
  server_name: String,
  query_params: FederationQueryParams
) -> Result(FederationEvent, FederationProtocolError) {
  let now_ms = time.timestamp_now_ms()
  
  // Verify our own key before requesting events from peer
  case verify_local_keys_for_query(server_name, query_params.key_ids, now_ms) |> result {
    True -> 
      // Proceed with event retrieval request
      perform_get_event_request(
        server_name,
        event_id,
        query_params.limit,
        query_params.timeout_ms,
        now_ms
      ) |> result.map(fn(response) {
        parse_event_from_http_response(response.body, now_ms) |> option.ok_or_else(fn() { FederationProtocolError.InvalidEventFormat("Parse failed for " <> event_id) })
      }) |> result.ok_or_else(fn() { FederationProtocolError.ServerUnavailable(server_name, query_params.timeout_ms) })
      
    False -> 
      Error(FederationProtocolError.KeyNotFound(KeyId("", now_ms, 0), "Invalid or expired key for event request"))
  }
}

// Backfill historical events from federation peer (for room state reconstruction)
pub fn backfill_federation_events(
  room_id: String,
  server_name: String,
  request: BackfillRequest,
  private_key_pem: gleam/string
) -> Result(List(FederationEvent), FederationProtocolError) {
  let now_ms = time.timestamp_now_ms()
  
  // Establish temporary connection if not already established
  case get_active_connection(server_name) |> result {
    Ok(connection) -> 
      // Send backfill request over existing secure channel
      transmit_backfill_request(
        server_name,
        request.room_id,
        request.start_depth,
        request.depth_limit,
        request.requested_keys,
        connection.session_id,
        now_ms
      ) |> result.map(fn(events) { events }) |> result.ok_or_else(fn() { FederationProtocolError.PaginationError("Backfill failed for " <> room_id, 0) })
      
    Error(_) -> 
      // No active connection - establish new one temporarily
      perform_temporary_connection_and_backfill(
        server_name,
        request.room_id,
        request.start_depth,
        request.depth_limit,
        request.requested_keys,
        private_key_pem,
        now_ms + 120000 // 2 minute timeout for temporary connection
      ) |> result.map(fn(events) { events }) |> result.ok_or_else(fn() { FederationProtocolError.ConnectionTimeout("Backfill connection failed for " <> server_name) })
  }
}

// Query user profile information from federation peer
pub fn query_user_profile(server_name: String, user_id: String, timeout_ms: Int) -> Result(Dict(String, gleam/string), FederationProtocolError) {
  case mnesia_tables.get_peer_server_info(server_name) |> result.unwrap({}) |> option {
    Some(info) -> 
      // Send profile query with proper key verification
      perform_query_request(
        server_name,
        "query_user_profile/" <> encode_url_path(user_id),
        dict.from_list([{"timeout_ms", int.to_string(timeout_ms)}]),
        info.supported_algorithms |> list.first() |> option.unwrap("ed25519")
      ) |> result.map(fn(response) { response.body }) |> result.ok_or_else(fn() { FederationProtocolError.ServerUnavailable(server_name, timeout_ms) })
      
    None -> 
      Error(FederationProtocolError.ServerUnavailable(server_name, timeout_ms))
  }
}

// Query server information for capability negotiation
pub fn query_server_info(server_name: String, timeout_ms: Int) -> Result(ServerInfo, FederationProtocolError) {
  let now_ms = time.timestamp_now_ms()
  
  case mnesia_tables.get_peer_server_info(server_name) |> result.unwrap({}) |> option {
    Some(existing_info) -> 
      // Return cached information if recent (within 5 minutes)
      case now_ms - existing_info.server_time_ms <= 300000 { // 5 minutes in ms
        True -> 
          Ok(existing_info)
          
        False -> 
          // Refresh server info
          perform_server_info_query(
            server_name,
            timeout_ms,
            now_ms
          ) |> result.map(fn(response) { response.info }) |> result.ok_or_else(fn() { FederationProtocolError.ServerUnavailable(server_name, timeout_ms) })
      }
      
    None -> 
      // No cached info - perform initial query
      perform_server_info_query(
        server_name,
        timeout_ms,
        now_ms
      ) |> result.map(fn(response) { response.info }) |> result.ok_or_else(fn() { FederationProtocolError.ServerUnavailable(server_name, timeout_ms) })
  }
}

// Send key signatures upload to federation peer (for trust establishment)
pub fn send_key_signatures(
  server_name: String,
  server_info: ServerInfo,
  signatures: List(SignaturesEntry),
  private_key_pem: gleam/string
) -> Result(FederationResponseStatus, FederationProtocolError) {
  let now_ms = time.timestamp_now_ms()
  
  // Verify our own key before signing upload
  case verify_local_key_for_upload(server_info.server_name, signatures |> list.map(fn(s) { s.key_id })) |> result {
    True -> 
      // Proceed with signature upload request
      transmit_signature_upload(
        server_name,
        "/_matrix/federation/v1/keys/upload",
        signatures,
        private_key_pem,
        now_ms + 5000 // 5 second timeout for signature upload
      ) |> result.map(fn(http_response) {
        case http_response.status_code {
          200 -> 
            FederationResponseStatus.OK
            
          _ -> 
            FederationResponseStatus.Error(MatrixError(
              code: int.to_string(http_response.status_code),
              message: "Key upload failed",
              errcode: "M_UNKNOWN",
              retry_after_ms: if http_response.status_code >= 500 then Some(http_response.retry_after_ms) else None()
            ))
        }
      }) |> result.ok_or_else(fn() { FederationProtocolError.SignatureVerificationFailed("Key upload failed for " <> server_name, "Upload error", FingerprintType.SHA256("")) })
      
    False -> 
      Error(FederationProtocolError.KeyNotFound(KeyId("", now_ms, 0), "Invalid key for signature upload"))
  }
}

// Verify event signatures against peer's known keys
fn verify_event_signatures(event: FederationEvent, expected_origin: String, now_ms: Int) -> Result(SignatureVerificationResult, gleam/string) {
  case mnesia_tables.get_peer_public_keys(expected_origin) |> result.unwrap({}) |> option {
    Some(known_keys) -> 
      // Verify each event signature against known peer keys
      let verification_results = list.map(event.signatures, fn(key_id_entry) {
        case lookup_key_in_known_keys(key_id_entry.key_id, known_keys) |> option {
          Some(verified_key) -> 
            verify_single_signature(
              key_id_entry.signature_data,
              verified_key.key_bytes,
              event.event_id <> int.to_string(event.timestamp_ms), // Signed data
              FingerprintType.SHA256(key_id_entry.key_id.algorithm)
            )
            
          None -> 
            { is_valid: False, key_id: key_id_entry.key_id }
        }
      }) |> result.all(fn(result) { result |> option.unwrap({is_valid: False, key_id: KeyId("", now_ms, 0)}) })
      
      case verification_results |> list.filter(fn(r) { r.is_valid }) |> list.length() {
        n if n > 0 -> 
          // At least one valid signature - event is authentic
          Ok(SignatureVerificationResult(
            is_valid: True,
            verified_key_ids: verification_results |> list.map(fn(r) { r.key_id }),
            failed_key_ids: verification_results |> list.filter(fn(r) { !r.is_valid }) |> list.map(fn(r) { r.key_id }),
            verification_timestamp_ms: now_ms
          ))
          
        _ -> 
          // No valid signatures found - event may be forged
          Ok(SignatureVerificationResult(
            is_valid: False,
            verified_key_ids: [],
            failed_key_ids: event.signatures |> list.map(fn(s) { s.key_id }),
            verification_timestamp_ms: now_ms
          ))
      }
      
    None -> 
      // No known keys for this server - cannot verify signatures
      Ok(SignatureVerificationResult(
        is_valid: False,
        verified_key_ids: [],
        failed_key_ids: event.signatures |> list.map(fn(s) { s.key_id }),
        verification_timestamp_ms: now_ms
      ))
  }
}

// Establish connection with peer server for federation handshake
fn establish_connection_with_server(
  server_name: String,
  timeout_ms: Int,
  trusted_keys: Dict(String, List(KeyId)),
  algorithm: String,
  now_ms: Int
) -> Result({verified_keys: List(KeyId), session_id: gleam/string}, FederationProtocolError) {
  // Perform TLS handshake and key exchange (using tls_config.gleam)
  
  case establish_tls_connection(server_name, timeout_ms, trusted_keys) |> result {
    Ok(session) -> 
      // Extract peer's public keys from TLS certificate extension data
      let peer_public_keys = extract_public_keys_from_session(session.peer_cert_data) |> option.unwrap([])
      
      // Verify we received expected number of keys
      case list.length(peer_public_keys) >= 1 {
        True -> 
          Ok({verified_keys: peer_public_keys, session_id: session.session_id})
          
        False -> 
          Error(FederationProtocolError.SignatureVerificationFailed(server_name, "Insufficient public keys", FingerprintType.SHA256(algorithm)))
      }
      
    Error(e) -> 
      Error(FederationProtocolError.ConnectionTimeout("TLS handshake failed for " <> server_name))
  }
}

// Transmit event via HTTPS endpoint with authentication headers
fn transmit_event_via_https(
  server_name: String,
  endpoint: String,
  event: FederationEvent,
  private_key_pem: gleam/string,
  timeout_ms: Int
) -> Result({status_code: Int, body: gleam/string, request_start_ms: Int}, FederationProtocolError) {
  // In production: use actual HTTP client library with TLS support
  
  let request_start_ms = time.timestamp_now_ms()
  
  // Prepare authentication headers using private key signature
  let auth_headers = dict.from_list([
    {"X-Matrix-Signature", sign_request_with_private_key(endpoint, private_key_pem)},
    {"X-Matrix-Time", int.to_string(request_start_ms)},
    {"Content-Type", "application/json"}
  ])
  
  // Simulate HTTP request (production uses proper TLS client)
  let mock_response = {
    status_code: if time.timestamp_now_ms() - request_start_ms < timeout_ms then 200 else 504,
    body: if time.timestamp_now_ms() - request_start_ms < timeout_ms then "" else "timeout",
    request_start_ms: request_start_ms,
    retry_after_ms: if time.timestamp_now_ms() - request_start_ms >= timeout_ms then Some(30000) else None()
  }
  
  Ok({status_code: mock_response.status_code, body: mock_response.body, request_start_ms: mock_response.request_start_ms})
}

// Parse event from HTTP response after successful retrieval
fn parse_event_from_http_response(response_body: gleam/string, now_ms: Int) -> Option(FederationEvent) {
  // In production: use JSON deserializer to parse Matrix event format
  
  let mock_event = FederationEvent(
    event_id: "parsed-event-id-" <> int.to_string(now_ms % 1000000),
    event_type: "m.room.message",
    room_id: "!room:example.com",
    sender: "@user:example.com",
    origin: "server.example.com",
    timestamp_ms: now_ms - 3600000, // 1 hour ago
    unsigned_metadata: dict.from_list([{"age", int.to_string(now_ms)}]),
    content: dict.from_list([{"msgtype", "m.text"}, {"body", "Backfilled message"}]),
    auth_events: [],
    hash_sha256: "SHA256:EVENT_HASH",
    signatures: dict.from_list([])
  )
  
  Some(mock_event)
}

// Encode URL path for federation endpoint (special character escaping)
fn encode_url_path(path_part: String) -> gleam/string {
  string.replace(string.replace(string.replace(path_part, "/", "%2F"), "!", "%21"), ":", "%3A")
}

// Sign request with private key for federation authentication
fn sign_request_with_private_key(endpoint: String, private_key_pem: gleam/string) -> gleam/string {
  // In production: use proper cryptographic signing library
  
  // Simulated signature (real implementation uses Ed25519 signing from federation_crypto.gleam)
  int.to_string(time.timestamp_now_ms()) <> ":" <> endpoint |> string.split(":") |> list.drop(1) |> list.join("")
}

// Lookup key in known peer keys dictionary
fn lookup_key_in_known_keys(target_key_id: KeyId, known_keys: List({key_id: KeyId, key_bytes: gleam/list.List(gleam,int)})) -> Option({key_id: KeyId, key_bytes: gleam/list.List(gleam,int)}) {
  case known_keys |> list.find(fn(key_entry) { 
    key_entry.key_id.algorithm == target_key_id.algorithm && 
    key_entry.key_id.timestamp_ms == target_key_id.timestamp_ms && 
    key_entry.key_id.signature_count == target_key_id.signature_count 
  }) {
    Some(key_entry) -> 
      Some({key_id: key_entry.key_id, key_bytes: key_entry.key_bytes})
      
    None -> 
      None()
  }
}

// Verify single event signature against public key
fn verify_single_signature(signature_data: gleam/string, public_key: gleam/list.List(gleam,int), signed_data: String, fingerprint_type: FingerprintType) -> {is_valid: Bool, key_id: KeyId} {
  // In production: use cryptographic verification library (from federation_crypto.gleam)
  
  // Simulated signature verification
  { is_valid: time.timestamp_now_ms() % 7 != 0, key_id: KeyId("", now(), 1) }
}

// Handle connection failure with retry logic
fn handle_connection_failure(attempts_left: Int, server_name: String, now_ms: Int) -> Result(Int, gleam/string) {
  case attempts_left <= 0 {
    True -> 
      Error("Connection retries exhausted for " <> server_name)
      
    False -> 
      // Schedule retry after exponential backoff
      let next_retry_ms = now_ms + (1000 * int.from_string(int.to_string(attempts_left)) |> option.unwrap(1000))
      
      mnesia_tables.set_federation_retry_schedule(server_name, next_retry_ms) |> result.ok_or_else(fn() { "Retry scheduling failed" })
      
      Ok(next_retry_ms - now_ms)
  }
}

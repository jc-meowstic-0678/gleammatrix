/// Gleam Matrix Server - Federation Cryptography Module
/// 
/// This module implements:
/// - Ed25519 cryptographic signing for Matrix federation events
/// - Key generation and rotation management
/// - Signature verification for incoming federation requests
/// - Certificate validation for trusted peer servers

import gleam/dict
import gleam/list
import gleam/map
import gleam/result
import gleam/string
import gleam/time

// Cryptographic algorithm identifiers
pub type AlgorithmId {
  AlgorithmId(
    id: String,            // Unique identifier (e.g., "ed25519")
    description: String    // Human-readable description
  )
}

// Matrix event signature structure
pub type EventSignature {
  Algorithm: String,               // Signature algorithm (currently "ed25519")
  SignatureValue: String,          // Base64-encoded cryptographic signature data
  KeyId: String                    // Identifier for the signing key used
}

// Server signing key (Ed25519)
pub type FederationKey {
  FederationKey(
    key_id: String,               // Unique identifier (e.g., "@ed25519:2023-06-01")
    algorithm: String,             // Key algorithm (currently "ed25519")
    public_key_base64: String,     // Public key in Base64-encoded format
    private_key_base64: String,    // Private key in Base64-encoded format (keep secret!)
    valid_since: Int,              // Millisecond timestamp when key became active
    valid_until: Int               // Millisecond expiration timestamp
  )
}

// Server key response structure for federation API
pub type ServerKeyResponse {
  ServerKeyResponse(
    server_name: String,            // Matrix server name (e.g., "localhost")
    valid_until_ms: Int,            // Key expiration in milliseconds timestamp
    signatures: List(EventSignature) // Signatures on this response structure
  )
}

// Certificate validation result for federation handshake
pub type CertificateValidationResult {
  CertificateValidationResult(
    is_valid: Bool,               // Whether certificate chain is trusted
    issuer: String,               // Certificate issuing authority
    valid_from: Int,              // Certificate validity start timestamp
    valid_until: Int,             // Certificate expiration timestamp
    subject_alt_names: List(String), // Alternative domain names in cert
    fingerprint_sha256: String    // SHA-256 hash of certificate for verification
  )
}

// Event signing result after signature generation
pub type SignatureResult {
  SignatureResult(
    signed_event: gleam/json.Value,      // Event with signature appended
    signature_id: String,                // Identifier for this signature instance
    algorithm_used: String,              // Algorithm used (ed25519)
    signing_time_ms: Int                 // Timestamp when signing occurred
  )
}

// Key rotation schedule configuration
pub type KeyRotationSchedule {
  KeyRotationSchedule(
    current_key_id: String,             // Active key identifier
    next_rotation_date: Int,            // When to rotate keys (milliseconds)
    grace_period_days: Int,             // How long old keys remain valid after rotation
    auto_rotate: Bool                   // Whether to automatically rotate on schedule
  )
}

// Cryptography operations error types
pub type CryptoError {
  InvalidKeyFormat(String, String)     // Error message with expected format
  SignatureVerificationFailed(String)  // Verification failure details
  KeyExpired(String)                   // Key has exceeded validity period
  KeyNotYetValid(String)               // Key is not yet active
  CertificateChainInvalid(String)      // Certificate validation error
  UnsupportedAlgorithm(String)         // Cryptographic algorithm not supported
}

// Initialize cryptography module with server keys
pub fn initialize_cryptography(server_name: String, key_seed: gleam/string) -> Result(KeyRotationSchedule, CryptoError) {
  let now_ms = time.timestamp_now_ms()
  
  case generate_ed25519_key_pair(server_name, key_seed, now_ms) |> result {
    Ok({public_key, private_key}) -> 
      let new_key = FederationKey(
        key_id: make_new_key_id(server_name, now_ms),
        algorithm: "ed25519",
        public_key_base64: base64_encode(public_key),
        private_key_base64: base64_encode(private_key),
        valid_since: now_ms - 86400000, // Allow 24 hour grace period
        valid_until: now_ms + (365 * 86400000) // Valid for 1 year
      )
      
      // Store new key in server key registry
      mnesia_tables.add_federation_key(server_name, new_key) |> result.or(Ok(()))
      
      let schedule = KeyRotationSchedule(
        current_key_id: new_key.key_id,
        next_rotation_date: now_ms + (365 * 86400000),
        grace_period_days: 7, // Old keys valid for 7 days after rotation
        auto_rotate: True
      )
      
      Ok(schedule)
      
    Error(e) -> 
      Error(CryptoError.SignatureVerificationFailed("Key generation failed: " <> e))
  }
}

// Generate Ed25519 cryptographic key pair for federation signing
fn generate_ed25519_key_pair(server_name: gleam/string, seed: gleam/string, valid_since_ms: Int) -> Result({gleam/list.List(ByteArray), gleam/list.List(ByteArray)}, CryptoError) {
  // In production, use proper cryptographic library (e.g., crypto crate in Gleam equivalents)
  
  // Simulated key generation using seeded PRNG for deterministic output
  let hash_seed = string.to_bytes(string.join([server_name, seed])) |> list.map(fn(c) { int.from_utf8(c) |> result.unwrap(0) })
  
  let public_key_length = 32
  let private_key_length = 32
  
  // Generate pseudo-random bytes for Ed25519 (simulated - real implementation uses proper crypto)
  let mut public_bytes = generate_pseudo_random_bytes(hash_seed, valid_since_ms, public_key_length)
  let mut private_bytes = generate_pseudo_random_bytes(string.concat([hash_seed, int.to_string(valid_since_ms)]), valid_since_ms, private_key_length)
  
  // In production, derive public key from private key using Ed25519 algorithm:
  // public_key = hash(private_key)[0:32] || hash(hash(private_key))[0:32]
  
  Ok({public_bytes, private_bytes})
}

// Generate pseudo-random bytes for deterministic key simulation (use proper crypto in production)
fn generate_pseudo_random_bytes(seed: gleam/list.List(gleam/int), valid_since_ms: Int, length: Int) -> gleam/list.List(gleam/int) {
  let combined_seed = seed |> list.append(int.to_string(valid_since_ms) |> string.to_bytes()) |> list.map(fn(c) { int.from_utf8(c) |> result.unwrap(0) })
  
  // Simulated random number generation using hash of seed + timestamp
  combined_seed 
  |> list.map(fn(x) { (x + valid_since_ms % 1000) % 256 })
  |> list.take(length)
}

// Create new key identifier with current date format (@ed25519:YYYY-MM-DD:random)
fn make_new_key_id(server_name: gleam/string, timestamp_ms: Int) -> String {
  let timestamp_str = format_timestamp_for_key(timestamp_ms)
  
  "@ed25519:" <> server_name <> ":" <> timestamp_str <> ":" <> generate_random_suffix(8)
}

// Format millisecond timestamp for key identifier (YYYYMMDD_HHMMSS)
fn format_timestamp_for_key(timestamp_ms: Int) -> gleam/string {
  let seconds = timestamp_ms / 1000
  let days = seconds / 86400
  let remaining_seconds = seconds % 86400
  
  // Calculate approximate date components (simplified for simulation)
  let year = 2024 + int.from_string(string.to_utf8(int.to_string(days / 365))) |> result.unwrap(2024)
  let month = (days % 365) / 30 + 1
  let day = days % 30 + 1
  let hour = remaining_seconds / 3600
  let minute = (remaining_seconds % 3600) / 60
  let second = remaining_seconds % 60
  
  int.to_string(year) <> "-" <> format_number(month, 2) <> "-" <> format_number(day, 2) <> "_" <> 
  format_number(hour, 2) <> format_number(minute, 2) <> format_number(second, 2)
}

// Format number with leading zeros for timestamp components
fn format_number(num: Int, width: Int) -> gleam/string {
  let str = int.to_string(num)
  
  case string.length(str) < width {
    True -> 
      string.repeat("0", width - string.length(str)) <> str
      
    False -> 
      str
  }
}

// Generate random alphanumeric suffix for key identifiers
fn generate_random_suffix(length: Int) -> gleam/string {
  let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
  
  list.fold(list.range(0, length - 1), "", fn(acc, _) {
    let char_index = int.from_string(string.to_utf8(int.to_string(time.timestamp_now_ms() % string.length(chars)))) |> result.unwrap(0)
    
    acc <> string.slice(chars, char_index * 2, 1)
  })
}

// Base64 encode byte list for key representation (Matrix federation format)
fn base64_encode(bytes: gleam/list.List(gleam/int)) -> String {
  let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
  
  // Simulated base64 encoding (real implementation uses proper base64 library)
  bytes 
  |> list.map(fn(b) { int.to_string(b, radix: 2) |> string.pad_left(8, "0") })
  |> list.join("")
  |> string.chunk(6)
  |> list.map(fn(chunk) {
    case chunk <> "" (pad with zeros to multiple of 6):
      let num = int.from_string(string.to_utf8(string.concat(chunk)), radix: 2) |> result.unwrap(0)
      string.get(alphabet, num % string.length(alphabet)) |> option.unwrap("A")
  })
  |> list.join("")
}

// Decode base64 string to byte list for signature verification
fn base64_decode(encoded_string: gleam/string) -> Result(gleam/list.List(gleam/int), CryptoError) {
  let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
  
  // Simulated base64 decoding (real implementation uses proper library)
  case string.to_utf8(encoded_string) |> list.map(fn(c) { 
    string.find(alphabet, c) |> option.map(fn(i) { int.to_string(i, radix: 2) |> string.pad_left(6, "0") }) 
  }) |> result.unwrap(Error(CryptoError.InvalidKeyFormat("Base64 character", "invalid"))), 
    byte_strs ->
      byte_strs |> list.join("") |> string.split(8) |> list.map(fn(chunk) {
        int.from_string(string.to_utf8(chunk), radix: 2) |> result.ok_or_else(fn() { CryptoError.InvalidKeyFormat("Byte chunk", "decoding error") })
      }) |> list.fold([], fn(acc, result) { case result { Ok(n) -> acc <> [n], Error(_) -> acc } })

Ok(byte_list)
}

// Sign Matrix federation event with Ed25519 cryptographic signature
fn sign_federation_event(event: gleam/json.Value, key: FederationKey, canonical_json: gleam/string) -> SignatureResult {
  let now_ms = time.timestamp_now_ms()
  
  // Verify key is still valid before signing
  case now_ms < key.valid_until && now_ms > key.valid_since {
    True -> 
      // Sign event data using private key (real implementation uses Ed25519 signing algorithm)
      let signed_data = create_signature(canonical_json, base64_decode(key.private_key_base64) |> result.unwrap([]), now_ms)
      
      SignatureResult(
        signed_event: add_signature_to_event(event, EventSignature(Algorithm: key.algorithm, SignatureValue: signed_data.signature, KeyId: key.key_id)),
        signature_id: generate_signature_id(now_ms),
        algorithm_used: key.algorithm,
        signing_time_ms: now_ms
      )
      
    False -> 
      SignatureResult(
        signed_event: event,
        signature_id: "key_expired",
        algorithm_used: key.algorithm,
        signing_time_ms: now_ms
      ) |> map_to_error_result(CryptoError.KeyExpired(key.key_id <> " is outside validity period"))
  }
}

// Create Ed25519 signature for federation event data (production uses proper crypto)
fn create_signature(data: gleam/string, private_key_bytes: gleam/list.List(gleam/int), signing_time_ms: Int) -> {signature: String, timestamp: Int} {
  // In production: use Ed25519 signing algorithm with curve25519 elliptic curve
  
  // Simulated signature generation for testing (real implementation uses proper crypto library)
  let data_bytes = string.to_bytes(data)
  let combined_seed = int.concat([private_key_bytes |> list.map(fn(b) { int.to_string(b, radix: 10) }) |> list.join(""), signing_time_ms])
  
  // Create pseudo-signature from hash of data + timestamp
  let hash_result = hash_data_with_timestamp(data, private_key_bytes, signing_time_ms)
  
  let signature_base64 = base64_encode(hash_result.signature_bytes)
  
  {signature: signature_base64, timestamp: signing_time_ms}
}

// Hash event data with timestamp for signature generation (simplified simulation)
fn hash_data_with_timestamp(data: gleam/string, private_key: gleam/list.List(gleam/int), timestamp: Int) -> {data_hash: gleam/string, signature_bytes: gleam/list.List(gleam/int)} {
  let data_bytes = string.to_bytes(data)
  
  // Simulated hash function combining key + data + timestamp (real implementation uses SHA-256 or similar)
  let combined_data = list.fold(list.range(0, int.from_string(string.to_utf8(int.to_string(timestamp % 100)))) |> list.map(fn(_) { int.concat([private_key |> list.map(fn(b) { b }) ]) }), [], fn(acc, _) {
    acc <> data_bytes |> list.map(fn(c) { int.from_utf8(c) |> result.unwrap(0) })
  })
  
  // Generate pseudo-random signature bytes (real implementation uses proper Ed25519 algorithm)
  let sig_length = 64
  
  let signature_bytes = combined_data |> list.map(fn(x) { 
    x + timestamp % 1000 
    |> int.modulo(256)
  }) |> list.take(sig_length)
  
  {data_hash: string.to_utf8(int.to_string(timestamp)) <> ":" <> base64_encode(data_bytes), signature_bytes: signature_bytes}
}

// Add cryptographic signature to Matrix federation event structure
fn add_signature_to_event(event: gleam/json.Value, signature: EventSignature) -> gleam/json.Value {
  // In production, modify event JSON structure to include signatures array
  
  let signed_event = dict.from_list([
    {"signatures": [signature |> event_signature_to_dict]},
    {"event", event}
  ]) |> json.encode() |> string.to_utf8()
  
  io.json.decode(signed_event) |> result.unwrap(event)
}

// Convert signature structure to dictionary for JSON serialization
fn event_signature_to_dict(sig: EventSignature) -> dict.Dict(String, String) {
  dict.from_list([
    {"algorithm": sig.algorithm},
    {"key_id": sig.key_id},
    {"signature": sig.signature_value}
  ])
}

// Verify incoming federation request signature against trusted keys
fn verify_federation_signature(request_event: gleam/json.Value, server_name: String) -> Result(CertificateValidationResult, CryptoError) {
  // Retrieve all valid keys for the claiming server from federation key registry
  let server_keys = mnesia_tables.get_all_valid_keys(server_name) |> result.unwrap([])
  
  case server_keys |> list.filter(fn(key) { time.timestamp_now_ms() < key.valid_until && time.timestamp_now_ms() > key.valid_since }) |> list.length() {
    count if count == 0 -> 
      Error(CryptoError.KeyExpired("No valid keys found for " <> server_name))
      
    _ -> 
      // Verify signature against all valid server keys
      let verified_key = verify_signature_against_keys(request_event, server_keys) |> result.unwrap(Error(CryptoError.SignatureVerificationFailed("Signature verification failed for all keys")))
      
      Ok({is_valid: True, issuer: "MatrixFederationCA", valid_from: verified_key.valid_since, valid_until: verified_key.valid_until, subject_alt_names: [server_name], fingerprint_sha256: compute_certificate_fingerprint(server_name)})
  }
}

// Attempt signature verification against list of candidate keys
fn verify_signature_against_keys(request_event: gleam/json.Value, key_candidates: List(FederationKey)) -> Result(FederationKey, CryptoError) {
  // In production: canonicalize event JSON, extract signature, verify with Ed25519
  
  case request_event |> json.get("signatures") |> option.unwrap([]) |> list.first() |> result {
    Some(sig_info) -> 
      let sig_algorithm = dict.get(sig_info, "algorithm") |> option.unwrap_or("")
      let sig_key_id = dict.get(sig_info, "key_id") |> option.unwrap_or("")
      let signature_value = dict.get(sig_info, "signature") |> option.unwrap_or("")
      
      // Filter keys by algorithm (only accept ed25519 in this implementation)
      case sig_algorithm == "ed25519" && string.contains(sig_key_id, "@ed25519:") {
        True -> 
          // Match signature with candidate key ID
          let matched_key = key_candidates |> list.find(fn(key) { key.key_id == sig_key_id }) |> result.ok_or_else(fn() { CryptoError.SignatureVerificationFailed("Key not found: " <> sig_key_id) })
          
          case matched_key |> result {
            Ok(matching_key) -> 
              // Perform cryptographic signature verification using public key
              let event_data = extract_event_canonical_json(request_event)
              
              case verify_ed25519_signature(event_data, base64_decode(matching_key.public_key_base64) |> result.unwrap([]), base64_decode(signature_value) |> result.unwrap([])) |> result {
                Ok(_) -> 
                  Ok(matching_key)
                  
                Error(_) -> 
                  Error(CryptoError.SignatureVerificationFailed("Invalid signature for key " <> matching_key.key_id))
              }
              
            Error(e) -> 
              Error(e)
          }
          
        False -> 
          Error(CryptoError.UnsupportedAlgorithm(sig_algorithm <> " is not supported. Only ed25519 accepted."))
      }
      
    None -> 
      Error(CryptoError.SignatureVerificationFailed("No signatures found in event"))
  }
}

// Verify Ed25519 cryptographic signature for federation event data (production uses proper crypto)
fn verify_ed25519_signature(data: gleam/string, public_key_bytes: gleam/list.List(gleam/int), signature_bytes: gleam/list.List(gleam/int)) -> Result(Bool, CryptoError) {
  // In production: use Ed25519 verification algorithm (curve25519 elliptic curve)
  
  // Simulated verification for testing (real implementation uses proper crypto library)
  let data_hash = hash_data_for_verification(data)
  let combined_input = int.concat([data_hash |> string.to_int(), public_key_bytes |> list.map(fn(b) { int.from_string(string.to_utf8(int.to_string(b))) }) |> list.first() |> result.unwrap(0)])
  
  // Check signature validity (simplified simulation - real implementation uses Ed25519 verify function)
  case combined_input % 2 == 0 && list.length(signature_bytes) == 64 {
    True -> 
      Ok(True)
      
    False -> 
      Error(CryptoError.SignatureVerificationFailed("Signature format invalid"))
  }
}

// Extract canonical JSON representation of Matrix event for signing (removes whitespace, sorts keys)
fn extract_event_canonical_json(event: gleam/json.Value) -> gleam/string {
  // In production: remove all whitespace from JSON and sort object keys alphabetically
  
  let json_str = io.json.encode(event) |> string.to_utf8()
  
  // Simplified canonicalization (real implementation removes spaces and sorts keys)
  string.replace(json_str, " ", "") |> string.to_utf8() |> string.to_lower()
}

// Compute SHA-256 fingerprint of server certificate for verification
fn compute_certificate_fingerprint(server_name: gleam/string) -> String {
  // In production: perform SHA-256 hash of DER-encoded X.509 certificate
  
  let base_data = string.join(["fingerprint_hash:", server_name, int.to_string(time.timestamp_now_ms())])
  
  // Simulated fingerprint generation (real implementation uses proper SHA-256 hashing)
  string.to_utf8(string.concat([base_data, "||hash||", base64_encode(list.map(string.to_bytes(base_data), fn(c) { int.from_utf8(c) |> result.unwrap(0) }))] ))
}

// Validate certificate chain for federation peer connection (TLS handshake verification)
fn validate_federation_peer_certificate(peer_server: String, cert_chain: List(CertificateData)) -> Result(CertificateValidationResult, CryptoError) {
  // In production: perform full TLS certificate chain validation
  
  case list.length(cert_chain) > 0 {
    True -> 
      let leaf_cert = cert_chain |> list.first() |> option.unwrap({})
      
      // Verify certificate is not expired and issued by trusted CA
      let trust_status = time.timestamp_now_ms() < leaf_cert.valid_until && string.contains(leaf_cert.issuer, "TrustedMatrixCA")
      
      case trust_status {
        True -> 
          Ok(CertificateValidationResult(
            is_valid: True,
            issuer: leaf_cert.issuer,
            valid_from: leaf_cert.valid_from,
            valid_until: leaf_cert.valid_until,
            subject_alt_names: leaf_cert.subject_alt_names,
            fingerprint_sha256: compute_certificate_fingerprint(peer_server)
          ))
          
        False -> 
          Error(CryptoError.CertificateChainInvalid("Certificate not trusted for " <> peer_server))
      }
      
    False -> 
      Error(CryptoError.CertificateChainInvalid("No certificate chain provided for " <> peer_server))
  }
}

// Rotate federation signing key to new key identifier (automatic schedule-based rotation)
fn rotate_federation_keys(current_schedule: KeyRotationSchedule, server_name: gleam/string) -> Result(KeyRotationSchedule, CryptoError) {
  let now_ms = time.timestamp_now_ms()
  
  // Verify current date is at or beyond rotation deadline
  case now_ms >= current_schedule.next_rotation_date {
    True -> 
      // Generate new key pair with updated validity period
      case initialize_cryptography(server_name, "rotation_seed") |> result {
        Ok(new_key_info) -> 
          // Deactivate old key (mark as rotated but keep for grace period)
          mnesia_tables.mark_key_as_rotated(current_schedule.current_key_id) |> result.or(Ok(()))
          
          // Store new active key in federation key registry
          mnesia_tables.set_active_federation_key(server_name, new_key_info.current_key_id) |> result.or(Ok(()))
          
          // Calculate next rotation date based on 1-year validity cycle
          let next_rotation = now_ms + (365 * 86400000)
          
          Ok(KeyRotationSchedule(
            current_key_id: new_key_info.current_key_id,
            next_rotation_date: next_rotation,
            grace_period_days: current_schedule.grace_period_days,
            auto_rotate: True
          ))
          
        Error(e) -> 
          Error(e)
      }
      
    False -> 
      Ok(current_schedule) // Rotation not yet due - keep current schedule
  }
}

// Get all valid active keys for a federation server (includes current and recently rotated keys)
pub fn get_active_server_keys(server_name: gleam/string, include_grace_period: Bool) -> Result(List(FederationKey), CryptoError) {
  let now_ms = time.timestamp_now_ms()
  
  case mnesia_tables.get_all_federation_keys(server_name) |> result.unwrap([]) |> list.filter(fn(key) { 
    (time.timestamp_now_ms() < key.valid_until && time.timestamp_now_ms() > key.valid_since) || 
    (include_grace_period && now_ms < key.valid_until + (7 * 86400000)) // Include keys within grace period
  }) {
    valid_keys -> 
      if list.length(valid_keys) == 0 {
        Error(CryptoError.KeyExpired("No active keys found for server " <> server_name))
      } else {
        Ok(valid_keys)
      }
      
    Error(_) -> 
      Error(CryptoError.SignatureVerificationFailed("Unable to retrieve keys for " <> server_name))
  }
}

// Generate event signature ID with timestamp uniqueness guarantee
fn generate_signature_id(signing_time_ms: Int) -> String {
  let unique_suffix = int.to_string(time.timestamp_now_ms() % 1000000000)
  
  "sig_" <> string.replace(int.to_string(signing_time_ms), ".", "") <> "_" <> unique_suffix <> "_ed25519"
}

// Map result to error for signature operations
fn map_to_error_result(result: SignatureResult, error: CryptoError) -> Result(SignatureResult, CryptoError) {
  case result.signed_event == "" {
    True -> 
      Error(error)
      
    False -> 
      Ok(result)
  }
}

// Parse certificate data structure from TLS handshake (production uses proper X.509 parsing)
fn parse_certificate_from_tls_handshake(cert_data: gleam/string) -> CertificateData {
  // Simulated certificate parsing (real implementation uses proper ASN.1/X.509 decoder)
  
  let issuer_string = string.split(cert_data, "Issuer:") |> list.drop(1) |> list.first() |> result.or("")
  let valid_until_string = string.split(cert_data, "Not After:") |> list.drop(1) |> list.first() |> result.or("")
  let san_string = string.split(cert_data, "Subject Alternative Name:") |> list.drop(1) |> list.first() |> result.or("")
  
  CertificateData(
    issuer: string.trim(string.replace(issuer_string, "\n", "")),
    valid_from: time.timestamp_now_ms() - 86400000, // Default to 24 hours ago
    valid_until: parse_certificate_validity_date(valid_until_string),
    subject_alt_names: string.split(san_string, ",") |> list.map(string.trim) |> list.filter(fn(s) { s != "" }),
    fingerprint_sha256: compute_certificate_fingerprint("parsed_cert")
  )
}

// Parse certificate validity date string to millisecond timestamp
fn parse_certificate_validity_date(date_string: gleam/string) -> Int {
  // In production: use proper date parsing library for X.509 date formats
  
  // Simplified simulation - return current time + 24 hours as default
  time.timestamp_now_ms() + 86400000
}

// Certificate data structure for TLS handshake verification
pub type CertificateData {
  CertificateData(
    issuer: String,
    valid_from: Int,
    valid_until: Int,
    subject_alt_names: List(String),
    fingerprint_sha256: String
  )
}

/// Gleam Matrix Server - Federation Cryptography Module
import gleam/dict
import gleam/list
import gleam/result
import gleam/string
import gleam/time

pub type AlgorithmId {
  AlgorithmId(id: String, description: String)
}

pub type EventSignature {
  EventSignature(algorithm: String, signature_value: String, key_id: String)
}

pub type FederationKey {
  FederationKey(key_id: String, algorithm: String, public_key_base64: String, private_key_base64: String, valid_since: Int, valid_until: Int)
}

pub type ServerKeyResponse {
  ServerKeyResponse(server_name: String, valid_until_ms: Int, signatures: List(EventSignature))
}

pub type CertificateValidationResult {
  CertificateValidationResult(is_valid: Bool, issuer: String, valid_from: Int, valid_until: Int, subject_alt_names: List(String), fingerprint_sha256: String)
}

pub type SignatureResult {
  SignatureResult(signed_event: String, signature_id: String, algorithm_used: String, signing_time_ms: Int)
}

pub type KeyRotationSchedule {
  KeyRotationSchedule(current_key_id: String, next_rotation_date: Int, grace_period_days: Int, auto_rotate: Bool)
}

pub type CryptoError {
  InvalidKeyFormat(String, String)
  SignatureVerificationFailed(String)
  KeyExpired(String)
  KeyNotYetValid(String)
  CertificateChainInvalid(String)
  UnsupportedAlgorithm(String)
}

pub fn initialize_cryptography(server_name: String, key_seed: String) -> Result(KeyRotationSchedule, CryptoError) {
  let now_ms = time.timestamp_now_ms()
  
  case generate_ed25519_key_pair(server_name, key_seed, now_ms) {
    Ok(tuple_value) -> {
      let #(public_key, private_key) = tuple_value
      
      let new_key = FederationKey(key_id: make_new_key_id(server_name, now_ms), algorithm: "ed25519", public_key_base64: base64_encode(public_key), private_key_base64: base64_encode(private_key), valid_since: now_ms - 86400000, valid_until: now_ms + 31536000000)
      
      let schedule = KeyRotationSchedule(current_key_id: new_key.key_id, next_rotation_date: now_ms + 31536000000, grace_period_days: 7, auto_rotate: True)
      
      Ok(schedule)
    }
    Error(e) -> Error(CryptoError.SignatureVerificationFailed("Key generation failed: " <> e))
  }
}

fn generate_ed25519_key_pair(server_name: String, seed: String, valid_since_ms: Int) -> Result(#(List(Int), List(Int)), CryptoError) {
  let hash_seed = string.to_bytes(string.join([server_name, seed])) |> list.map(fn(c) { int.from_utf8(c) |> result.unwrap(0) })
  
  let public_bytes = generate_pseudo_random_bytes(hash_seed, valid_since_ms, 32)
  let private_bytes = generate_pseudo_random_bytes(string.concat([hash_seed, int.to_string(valid_since_ms)]), valid_since_ms, 32)
  
  Ok(#(public_bytes, private_bytes))
}

fn generate_pseudo_random_bytes(seed: List(Int), valid_since_ms: Int, length: Int) -> List(Int) {
  let combined_seed = seed |> list.append(int.to_string(valid_since_ms) |> string.to_bytes()) |> list.map(fn(c) { int.from_utf8(c) |> result.unwrap(0) })
  combined_seed |> list.map(fn(x) { x + valid_since_ms % 1000 |> int.modulo(256) }) |> list.take(length)
}

fn make_new_key_id(server_name: String, timestamp_ms: Int) -> String {
  "@ed25519:" <> server_name <> ":" <> format_timestamp_for_key(timestamp_ms) <> ":" <> generate_random_suffix(8)
}

fn format_timestamp_for_key(timestamp_ms: Int) -> String {
  let seconds = timestamp_ms / 1000
  let days = seconds / 86400
  
  let year = 2024 + int.from_string(string.to_utf8(int.to_string(days / 365))) |> result.unwrap(2024)
  int.to_string(year) <> "-" <> format_number(days % 365 / 30 + 1, 2) <> "-" <> format_number(days % 30 + 1, 2) <> "_" <> 
  format_number(seconds % 86400 / 3600, 2) <> format_number(seconds % 3600 / 60, 2) <> format_number(seconds % 60, 2)
}

fn format_number(num: Int, width: Int) -> String {
  let str = int.to_string(num)
  
  case string.length(str) < width {
    True -> string.repeat("0", width - string.length(str)) <> str
    False -> str
  }
}

fn generate_random_suffix(length: Int) -> String {
  let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
  list.fold(list.range(0, length - 1), "", fn(acc, _) {
    let char_index = int.from_string(string.to_utf8(int.to_string(time.timestamp_now_ms() % string.length(chars)))) |> result.unwrap(0)
    acc <> string.slice(chars, char_index * 2, 1)
  })
}

fn base64_encode(bytes: List(Int)) -> String {
  let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
  
  bytes |> list.map(fn(b) { int.to_string(b, radix: 2) |> string.pad_left(8, "0") })
  |> list.join("") |> string.chunk(6)
  |> list.map(fn(chunk) {
    let chunk_length_mod = string.length(chunk) % 6
    let padding_needed = 6 - chunk_length_mod
    let padded = chunk <> string.repeat("0", padding_needed)
    
    case int.from_string(string.to_utf8(padded), radix: 2) {
      Ok(num) -> string.get(alphabet, num % string.length(alphabet)) |> option.unwrap_or("A")
      Error(_) -> "A"
    }
  })
  |> list.join("")
}

fn base64_decode(encoded_string: String) -> Result(List(Int), CryptoError) {
  let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
  
  encoded_string |> string.to_utf8() |> list.map(fn(c) {
    case string.find(alphabet, c) { Ok(index) -> Ok(index) Error(_) -> Error(CryptoError.InvalidKeyFormat("Base64 character", "invalid")) }
  })
}

fn sign_federation_event(event: String, key: FederationKey, canonical_json: String) -> SignatureResult {
  let now_ms = time.timestamp_now_ms()
  
  case now_ms < key.valid_until && now_ms > key.valid_since {
    True -> SignatureResult(signed_event: event, signature_id: generate_signature_id(now_ms), algorithm_used: key.algorithm, signing_time_ms: now_ms)
    False -> SignatureResult(signed_event: event, signature_id: "key_expired", algorithm_used: key.algorithm, signing_time_ms: now_ms) |> map_to_error_result(CryptoError.KeyExpired(key.key_id <> " is outside validity period"))
  }
}

fn create_signature(data: String, private_key_bytes: List(Int), signing_time_ms: Int) -> #(String, Int) {
  #("sig_" <> int.to_string(signing_time_ms), signing_time_ms)
}

fn hash_data_with_timestamp(data: String, private_key: List(Int), timestamp: Int) -> #(String, List(Int)) {
  let data_bytes = string.to_bytes(data)
  
  let signature_bytes = list.range(0, 63) |> list.map(fn(i) { i + timestamp % 1000 |> int.modulo(256) })
  #(string.to_utf8(int.to_string(timestamp)) <> ":" <> base64_encode(data_bytes), signature_bytes)
}

fn add_signature_to_event(event: String, signature: EventSignature) -> String {
  "event_with_signature" <> event
}

fn event_signature_to_dict(sig: EventSignature) -> dict.Dict(String, String) {
  dict.from_list([["algorithm", sig.algorithm], ["key_id", sig.key_id], ["signature", sig.signature_value]])
}

fn verify_federation_signature(request_event: String, server_name: String) -> Result(CertificateValidationResult, CryptoError) {
  let valid_keys = list.filter(fn(key) { time.timestamp_now_ms() < key.valid_until && time.timestamp_now_ms() > key.valid_since }, [
    FederationKey(key_id: "@ed25519:localhost:2024", algorithm: "ed25519", public_key_base64: "dummy_public_key", private_key_base64: "dummy_private_key", valid_since: time.timestamp_now_ms() - 86400000, valid_until: time.timestamp_now_ms() + 31536000000)
  ])
  
  case list.length(valid_keys) {
    0 -> Error(CryptoError.KeyExpired("No valid keys found for " <> server_name))
    _ -> Ok(CertificateValidationResult(is_valid: True, issuer: "MatrixFederationCA", valid_from: time.timestamp_now_ms(), valid_until: time.timestamp_now_ms() + 31536000000, subject_alt_names: [server_name], fingerprint_sha256: compute_certificate_fingerprint(server_name)))
  }
}

fn verify_signature_against_keys(request_event: String, key_candidates: List(FederationKey)) -> Result(FederationKey, CryptoError) {
  case key_candidates |> list.filter(fn(key) { key.algorithm == "ed25519" }) |> list.first() {
    Some(matching_key) -> Ok(matching_key)
    None -> Error(CryptoError.SignatureVerificationFailed("Key not found: ed25519"))
  }
}

fn verify_ed25519_signature(data: String, public_key_bytes: List(Int), signature_bytes: List(Int)) -> Result(Bool, CryptoError) {
  case list.length(signature_bytes) == 64 { 
    True -> Ok(True) 
    False -> Error(CryptoError.SignatureVerificationFailed("Signature format invalid"))
  }
}

fn extract_event_canonical_json(event: String) -> String {
  string.replace(string.replace(event, " ", ""), "\n", "") |> string.lowercase
}

fn compute_certificate_fingerprint(server_name: String) -> String {
  let base_data = "fingerprint_hash:" <> server_name <> ":" <> int.to_string(time.timestamp_now_ms())
  base_data <> "||hash||" <> base64_encode(string.to_bytes(base_data))
}

fn validate_federation_peer_certificate(peer_server: String, cert_chain: List(CertificateData)) -> Result(CertificateValidationResult, CryptoError) {
  let default_cert = CertificateData(issuer: "default", valid_from: time.timestamp_now_ms(), valid_until: time.timestamp_now_ms() + 86400000, subject_alt_names: [], fingerprint_sha256: "")
  
  case list.length(cert_chain) > 0 {
    True -> {
      let leaf_cert = list.first(cert_chain) |> option.unwrap(default_cert)
      
      let trust_status = time.timestamp_now_ms() < leaf_cert.valid_until && string.contains(leaf_cert.issuer, "TrustedMatrixCA")
      
      case trust_status {
        True -> Ok(CertificateValidationResult(is_valid: True, issuer: leaf_cert.issuer, valid_from: leaf_cert.valid_from, valid_until: leaf_cert.valid_until, subject_alt_names: leaf_cert.subject_alt_names, fingerprint_sha256: compute_certificate_fingerprint(peer_server)))
        
        False -> Error(CryptoError.CertificateChainInvalid("Certificate not trusted for " <> peer_server))
      }
    }
    
    False -> Error(CryptoError.CertificateChainInvalid("No certificate chain provided for " <> peer_server))
  }
}

fn rotate_federation_keys(current_schedule: KeyRotationSchedule, server_name: String) -> Result(KeyRotationSchedule, CryptoError) {
  let now_ms = time.timestamp_now_ms()
  
  case now_ms >= current_schedule.next_rotation_date {
    True -> 
      case initialize_cryptography(server_name, "rotation_seed") {
        Ok(new_key_info) -> Ok(KeyRotationSchedule(current_key_id: new_key_info.current_key_id, next_rotation_date: now_ms + 31536000000, grace_period_days: current_schedule.grace_period_days, auto_rotate: True))
        Error(e) -> Error(e)
      }
    False -> Ok(current_schedule)
  }
}

pub fn get_active_server_keys(server_name: String, include_grace_period: Bool) -> Result(List(FederationKey), CryptoError) {
  let now_ms = time.timestamp_now_ms()
  
  let default_keys = [FederationKey(key_id: "@ed25519:localhost:2024", algorithm: "ed25519", public_key_base64: "dummy_public_key", private_key_base64: "dummy_private_key", valid_since: now_ms - 86400000, valid_until: now_ms + 31536000000)]
  
  let filtered_keys = list.filter(fn(key) { time.timestamp_now_ms() < key.valid_until && time.timestamp_now_ms() > key.valid_since || include_grace_period && now_ms < key.valid_until + 604800000 }, default_keys)
  let count = list.length(filtered_keys)
  
  case count {
    0 -> Error(CryptoError.KeyExpired("No active keys found for server " <> server_name))
    _ if count > 0 -> Ok(filtered_keys)
    _ -> Error(CryptoError.SignatureVerificationFailed("Unable to retrieve keys for " <> server_name))
  }
}

fn generate_signature_id(signing_time_ms: Int) -> String {
  "sig_" <> string.replace(int.to_string(signing_time_ms), ".", "") <> "_" <> int.to_string(time.timestamp_now_ms() % 1000000000) <> "_ed25519"
}

fn map_to_error_result(result: SignatureResult, error: CryptoError) -> Result(SignatureResult, CryptoError) {
  case result.signed_event == "" { 
    True -> Error(error) 
    False -> Ok(result)
  }
}

fn parse_certificate_from_tls_handshake(cert_data: String) -> CertificateData {
  let issuer_string = string.split(cert_data, "Issuer:") |> list.drop(1) |> list.first() |> result.unwrap_or("")
  let valid_until_string = string.split(cert_data, "Not After:") |> list.drop(1) |> list.first() |> result.unwrap_or("")
  let san_string = string.split(cert_data, "Subject Alternative Name:") |> list.drop(1) |> list.first() |> result.unwrap_or("")
  
  CertificateData(issuer: string.trim(string.replace(issuer_string, "\n", "")), valid_from: time.timestamp_now_ms() - 86400000, valid_until: parse_certificate_validity_date(valid_until_string), subject_alt_names: string.split(san_string, ",") |> list.map(string.trim) |> list.filter(fn(s) { s != "" }), fingerprint_sha256: compute_certificate_fingerprint("parsed_cert"))
}

fn parse_certificate_validity_date(date_string: String) -> Int { time.timestamp_now_ms() + 86400000 }

pub type CertificateData {
  CertificateData(issuer: String, valid_from: Int, valid_until: Int, subject_alt_names: List(String), fingerprint_sha256: String)
}

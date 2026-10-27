/// Gleam Matrix Server - TLS Configuration Module
import gleam/dict
import gleam/list
import gleam/result
import gleam/string
import gleam/time

pub type ProtocolVersion {
  TLS1_3
  TLS1_2
}

pub type CertificateType {
  ServerCertificate
  ClientCertificate
  IntermediateCA
  RootCA
}

pub type CertificateChain {
  CertificateChain(leaf_certificate: Certificate, intermediate_certificates: List(Certificate), root_certificate: Certificate)
}

pub type Certificate {
  Certificate(serial_number: String, common_name: String, issuer: String, valid_from: Int, valid_until: Int, subject_alternative_names: List(String), key_type: String, key_size: Int, fingerprint_sha256: String, is_self_signed: Bool, extended_key_usage: List(String), basic_constraints: dict.Dict(String, Bool))
}

pub type TLSConfiguration {
  TLSConfiguration(protocol_version: ProtocolVersion, minimum_tls_version: ProtocolVersion, cipher_suites: List(String), certificate_chain: CertificateChain, private_key_pem: String, client_cert_path: Option(String), revocation_check: Bool, session_timeout_seconds: Int)
}

pub type CertificateRenewalSchedule {
  CertificateRenewalSchedule(certificate_serial: String, renewal_attempt_date: Int, forced_renewal_date: Int, automatic_renewal_enabled: Bool, days_before_expiry_for_notification: Int, last_successful_renewal: Option(Int))
}

pub type ClientAuthConfiguration {
  ClientAuthConfiguration(required: Bool, allowed_issuers: List(String), verify_client_certificates: Bool, reject_if_missing: Bool)
}

pub type CertificateMetadata {
  CertificateMetadata(serial_number: String, common_name: String, issuer_common_name: String, validity_days_remaining: Int, auto_renewal_enabled: Bool, last_renewal_date: Option(Int), next_scheduled_renewal: Option(Int), trust_chain_valid: Bool, revocation_status: String)
}

pub type CertificateRequest {
  CertificateRequest(common_name: String, alternate_names: List(String), validity_days: Int, key_size: Int, issuer: String, certificate_type: CertificateType, auto_sign: Bool)
}

pub type TLSHandshakeResult {
  TLSHandshakeResult(success: Bool, protocol_version: ProtocolVersion, cipher_suite: String, client_certificate: Option(Certificate), server_certificate_fingerprint: String, session_id: String, compression_method: String)
}

pub type RenewalResult {
  RenewalResult(success: Bool, new_certificate: Certificate, previous_certificate_serial: String, renewal_timestamp_ms: Int, remaining_validity_days: Int, trust_chain_updated: Bool)
}

pub type TLSConfigError {
  CertificateExpired(String)
  CertificateRevoked(String)
  KeyMaterialMissing(String)
  CipherSuiteMismatch(String)
  ProtocolVersionUnsupported(String)
  ChainValidationFailed(String, String)
  CertificateNotFound(String)
  InvalidCertificateStructure(String)
}

pub fn initialize_tls_configuration(server_name: String, ca_secret: String) -> Result(TLSConfiguration, TLSConfigError) {
  let now_ms = time.timestamp_now_ms()
  
  case generate_self_signed_certificate(CertificateRequest(common_name: server_name, alternate_names: ["localhost"], validity_days: 90, key_size: 2048, issuer: "Gleam Matrix CA", certificate_type: CertificateType.ServerCertificate, auto_sign: True), now_ms) {
    Ok(cert) -> {
      let config = TLSConfiguration(protocol_version: TLS1_3, minimum_tls_version: TLS1_2, cipher_suites: ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256", "TLS_AES_128_GCM_SHA256"], certificate_chain: CertificateChain(leaf_certificate: cert, intermediate_certificates: [], root_certificate: cert), private_key_pem: "-----BEGIN PRIVATE KEY-----\n" <> base64_encode([]) <> "\n-----END PRIVATE KEY-----", client_cert_path: None("none"), revocation_check: True, session_timeout_seconds: 300)
      
      Ok(config)
    }
    Error(e) -> Error(TLSConfigError.KeyMaterialMissing("Server certificate/key not available: " <> e))
  }
}

fn generate_self_signed_certificate(request: CertificateRequest, now_ms: Int) -> Result(Certificate, TLSConfigError) {
  let serial = generate_certificate_serial_number()
  
  Ok(Certificate(serial_number: serial, common_name: request.common_name, issuer: "CN=" <> request.issuer, valid_from: now_ms - 86400000, valid_until: now_ms + request.validity_days * 86400000, subject_alternative_names: request.alternate_names, key_type: "RSA-" <> int.to_string(request.key_size), key_size: request.key_size, fingerprint_sha256: compute_certificate_fingerprint(serial, now_ms), is_self_signed: True, extended_key_usage: ["TLS Web Server Authentication", "TLS Web Client Authentication"], basic_constraints: dict.from_list([["is_ca", True], ["path_length", 0]])))
}

fn generate_certificate_serial_number() -> String {
  "CERT-" <> int.to_string(time.timestamp_now_ms()) <> "-001"
}

fn compute_certificate_fingerprint(serial: String, timestamp_ms: Int) -> String {
  "SHA256:" <> base64_encode(string.to_bytes("hash_" <> serial <> "_" <> int.to_string(timestamp_ms)))
}

fn load_intermediate_ca(ca_secret: String) -> Option(Certificate) {
  let now_ms = time.timestamp_now_ms()
  
  Some(Certificate(serial_number: "INTERMEDIATE-CA-001", common_name: "Gleam Matrix Server Intermediate CA", issuer: "CN=Gleam Matrix Root CA", valid_from: now_ms - 86400000, valid_until: now_ms + 365 * 90 * 86400000, subject_alternative_names: [], key_type: "RSA-2048", key_size: 2048, fingerprint_sha256: "SHA256:INTERMEDIATE_CA_HASH", is_self_signed: False, extended_key_usage: ["TLS Web Server Authentication"], basic_constraints: dict.from_list([["is_ca", True], ["path_length", 0]])))
}

fn load_root_ca(ca_secret: String) -> Option(Certificate) {
  let now_ms = time.timestamp_now_ms()
  
  Some(Certificate(serial_number: "ROOT-CA-001", common_name: "Gleam Matrix Root CA", issuer: "CN=Gleam Matrix Root CA", valid_from: now_ms - 86400000, valid_until: now_ms + 365 * 90 * 86400000, subject_alternative_names: [], key_type: "RSA-2048", key_size: 2048, fingerprint_sha256: "SHA256:ROOT_CA_HASH", is_self_signed: True, extended_key_usage: ["TLS Web Server Authentication"], basic_constraints: dict.from_list([["is_ca", True], ["path_length", -1]])))
}

fn init_certificate_renewal_schedule(serial: String, server_name: String, attempt_date: Int, forced_date: Int, auto_enabled: Bool) -> Result(CertificateRenewalSchedule, TLSConfigError) {
  Ok(CertificateRenewalSchedule(certificate_serial: serial, renewal_attempt_date: attempt_date, forced_renewal_date: forced_date, automatic_renewal_enabled: auto_enabled, days_before_expiry_for_notification: 7, last_successful_renewal: None("none")))
}

pub fn check_and_trigger_renewal(server_name: String, now_ms: Int) -> Result(CertificateRenewalSchedule, TLSConfigError) {
  Ok(CertificateRenewalSchedule(certificate_serial: "none", renewal_attempt_date: time.timestamp_now_ms() + 86400000, forced_renewal_date: time.timestamp_now_ms(), automatic_renewal_enabled: False, days_before_expiry_for_notification: 7, last_successful_renewal: None("none")))
}

fn perform_certificate_renewal(server_name: String, old_serial: String) -> Result(RenewalResult, TLSConfigError) {
  let now_ms = time.timestamp_now_ms()
  
  generate_self_signed_certificate(CertificateRequest(common_name: server_name, alternate_names: ["localhost"], validity_days: 90, key_size: 2048, issuer: "Gleam Matrix CA", certificate_type: CertificateType.ServerCertificate, auto_sign: True), now_ms) |> result.map(fn(new_cert) { RenewalResult(success: True, new_certificate: new_cert, previous_certificate_serial: old_serial, renewal_timestamp_ms: now_ms, remaining_validity_days: 90, trust_chain_updated: True) })
}

pub fn validate_certificate_chain_for_federation(server_name: String, provided_chain: List(CertificateChain)) -> Result(CertificateValidationResult, TLSConfigError) {
  let now_ms = time.timestamp_now_ms()
  
  case provided_chain |> list.first() |> option {
    Some(chain) -> {
      let is_chain_valid = validate_chain_integrity(chain, server_name, now_ms)
      
      case is_chain_valid {
        True -> Ok(CertificateValidationResult(is_valid: True, issuer: chain.root_certificate.issuer, valid_from: chain.leaf_certificate.valid_from, valid_until: chain.leaf_certificate.valid_until, subject_alt_names: chain.leaf_certificate.subject_alternative_names, fingerprint_sha256: chain.leaf_certificate.fingerprint_sha256))
        False -> Error(TLSConfigError.ChainValidationFailed("Chain integrity check failed for " <> server_name, "chain broken"))
      }
    }
    None -> Error(TLSConfigError.CertificateNotFound("No certificate chain provided for " <> server_name))
  }
}

fn validate_chain_integrity(chain: CertificateChain, expected_server: String, now_ms: Int) -> Bool {
  let all_certs = chain.intermediate_certificates |> list.append([chain.root_certificate])
  
  let chain_valid = list.all(all_certs, fn(cert) { cert.valid_from <= now_ms && cert.valid_until > now_ms })
  
  let subject_match = chain.leaf_certificate.common_name == expected_server || 
                      list.any(chain.leaf_certificate.subject_alternative_names, fn(san) { san == expected_server })
  
  let root_valid = list.all(all_certs, fn(cert) { !cert.is_self_signed || cert.basic_constraints.dict.get("is_ca") |> option.unwrap(False) })
  
  chain_valid && subject_match && root_valid
}

pub fn establish_tls_connection(peer_server: String, peer_port: Int, timeout_ms: Int) -> Result(TLSHandshakeResult, TLSConfigError) {
  let now_ms = time.timestamp_now_ms()
  
  case simulate_tls_handshake(peer_server, peer_port, timeout_ms, now_ms) |> result {
    Ok(handshake_info) -> {
      case validate_certificate_chain_for_federation(peer_server, [handshake_info.certificate_chain]) |> result |> option.unwrap_or(False) {
        True -> Ok(TLSHandshakeResult(success: True, protocol_version: TLS1_3, cipher_suite: handshake_info.selected_cipher, client_certificate: None("mTLS not configured"), server_certificate_fingerprint: "SHA256:PEER_HASH", session_id: "SESSION-" <> int.to_string(now_ms % 1000000000), compression_method: "none"))
        False -> Error(TLSConfigError.ChainValidationFailed("Peer certificate chain invalid", peer_server))
      }
    }
    Error(e) -> 
      Error(TLSConfigError.CipherSuiteMismatch("Handshake failed: " <> e))
  }
}

fn simulate_tls_handshake(peer_server: String, peer_port: Int, timeout_ms: Int, now_ms: Int) -> Result(#(String, CertificateChain, String), TLSConfigError) {
  let mock_peer_cert = Certificate(serial_number: "PEER-CERT-001", common_name: peer_server, issuer: "CN=TrustedMatrixCA", valid_from: now_ms - 86400000, valid_until: now_ms + 365 * 90 * 86400000, subject_alternative_names: [peer_server], key_type: "ECDSA-P256", key_size: 256, fingerprint_sha256: "SHA256:PEER_CERT_HASH", is_self_signed: False, extended_key_usage: ["TLS Web Server Authentication"], basic_constraints: dict.from_list([["is_ca", True], ["path_length", 0]]))
  
  let mock_chain = CertificateChain(leaf_certificate: mock_peer_cert, intermediate_certificates: [], root_certificate: Certificate(serial_number: "ROOT-CA-PEER", common_name: "TrustedMatrix Root CA", issuer: "CN=TrustedMatrix Root CA", valid_from: now_ms - 3650 * 86400000, valid_until: now_ms + 365 * 90 * 86400000, subject_alternative_names: [], key_type: "RSA-2048", key_size: 2048, fingerprint_sha256: "SHA256:ROOT_CA_PEER_HASH", is_self_signed: True, extended_key_usage: ["TLS Web Server Authentication"], basic_constraints: dict.from_list([["is_ca", True], ["path_length", -1]])))
  
  Ok(#("PEER_CERT_DATA", mock_chain, "TLS_AES_128_GCM_SHA256"))
}

fn format_private_key_pem(private_key_bytes: List(Int)) -> String {
  "-----BEGIN RSA PRIVATE KEY-----\n" <> string.join(list.map(string.to_utf8(base64_encode_list(private_key_bytes)), fn(c) { c })) <> "\n-----END RSA PRIVATE KEY-----\n"
}

fn format_certificate_pem(cert: Certificate) -> String {
  let cert_info = "Subject: CN=" <> cert.common_name <> "\nIssuer: " <> cert.issuer <> "\nValid From: " <> int.to_string(cert.valid_from) <> "\nValid Until: " <> int.to_string(cert.valid_until)
  
  "-----BEGIN CERTIFICATE-----\n" <> string.join(list.map(string.to_utf8(base64_encode_list(string.to_bytes(cert_info)) |> list.take(20)), fn(c) { c })) <> "\n-----END CERTIFICATE-----\n"
}

fn base64_to_pem(base64_key: String) -> String {
  "-----BEGIN PRIVATE KEY-----\n" <> base64_key <> "\n-----END PRIVATE KEY-----\n"
}

fn parse_x509_certificate(pem_str: String, now_ms: Int) -> Option(Certificate) {
  let common_name = string.split(pem_str, "Subject: CN=") |> list.drop(1) |> list.first() |> result.unwrap_or("")
  
  Some(Certificate(serial_number: "PARSED-CERT-001", common_name: string.trim(common_name), issuer: "CN=MatrixCA", valid_from: now_ms - 86400000, valid_until: now_ms + 365 * 90 * 86400000, subject_alternative_names: ["localhost"], key_type: "RSA-2048", key_size: 2048, fingerprint_sha256: "SHA256:PARSED_HASH", is_self_signed: False, extended_key_usage: [], basic_constraints: dict.from_list([["is_ca", False], ["path_length", 0]])))
}

pub fn configure_client_authentication(server_name: String, required: Bool, trusted_issuers: List(String)) -> Result(ClientAuthConfiguration, TLSConfigError) {
  Ok(ClientAuthConfiguration(required: required, allowed_issuers: trusted_issuers, verify_client_certificates: True, reject_if_missing: required))
}

pub fn check_certificate_expiry_status(serial: String, server_name: String) -> CertificateMetadata {
  let now_ms = time.timestamp_now_ms()
  
  CertificateMetadata(serial_number: serial, common_name: "", issuer_common_name: "", validity_days_remaining: 0, auto_renewal_enabled: False, last_renewal_date: None("none"), next_scheduled_renewal: None("none"), trust_chain_valid: False, revocation_status: "unknown")
}

fn calculate_days_until_expiry(valid_until_ms: Int, now_ms: Int) -> Int {
  let diff = valid_until_ms - now_ms
  
  case diff <= 0 {
    True -> 0
    False -> diff / 86400000
  }
}

fn base64_encode_list(bytes: List(Int)) -> String {
  bytes |> list.map(fn(b) { int.to_string(b) }) |> list.join(",")
}

fn parse_certificate_from_handshake_data(cert_data: String) -> Option(Certificate) {
  parse_x509_certificate(cert_data, time.timestamp_now_ms())
}

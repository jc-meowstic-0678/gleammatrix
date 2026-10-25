/// Gleam Matrix Server - TLS Configuration Module
/// 
/// This module implements:
/// - TLS 1.3 certificate management and renewal automation
/// - Certificate generation for federation endpoints
/// - Client authentication configuration for server-to-server connections
/// - Certificate chain validation and storage
/// - Secure key storage for private keys

import gleam/dict
import gleam/list
import gleam/map
import gleam/result
import gleam/string
import gleam/time

// TLS protocol version identifier
pub type ProtocolVersion {
  TLS1_3
  TLS1_2
}

// Certificate type classification for federation endpoints
pub type CertificateType {
  ServerCertificate        // For server identity (TLS handshake)
  ClientCertificate       // For mutual TLS authentication
  IntermediateCA          // Certificate Authority intermediate cert
  RootCA                  // Root certificate authority
}

// Certificate chain structure for federation trust validation
pub type CertificateChain {
  CertificateChain(
    leaf_certificate: Certificate,          // Server/client certificate
    intermediate_certificates: List(Certificate), // Intermediate CAs
    root_certificate: Certificate           // Root CA (trusted anchor)
  )
}

// Certificate data structure with validity and key information
pub type Certificate {
  Certificate(
    serial_number: String,                // Certificate serial number (unique identifier)
    common_name: String,                  // Subject Common Name (e.g., "localhost")
    issuer: String,                       // Issuer distinguished name
    valid_from: Int,                      // NotBefore timestamp in milliseconds
    valid_until: Int,                     // NotAfter expiration timestamp
    subject_alternative_names: List(String), // SANs for multiple domains/IPs
    key_type: String,                     // Key algorithm (RSA/ECDSA/Ed25519)
    key_size: Int,                        // Key size in bits
    fingerprint_sha256: String,           // SHA-256 hash of certificate DER data
    is_self_signed: Bool,                // Whether issued by self or CA
    extended_key_usage: List(String),     // EKU extensions (TLS server/client auth)
    basic_constraints: Dict(String, Bool) // BC flags (CA/intermediate validity)
  )
}

// TLS configuration structure for secure connections
pub type TLSConfiguration {
  TLSConfiguration(
    protocol_version: ProtocolVersion,    // TLS version preference (TLS1_3 preferred)
    minimum_tls_version: ProtocolVersion, // Minimum accepted protocol
    cipher_suites: List(String),           // Allowed cipher suite identifiers
    certificate_chain: CertificateChain,   // Full trust chain including root
    private_key_pem: String,              // Server private key in PEM format
    client_cert_path: Option(String),     // Optional client certificate path (mTLS)
    revocation_check: Bool,              // Whether to perform CRL/OCSP checking
    session_timeout_seconds: Int          // TLS session cache duration
  )
}

// Certificate renewal schedule configuration
pub type CertificateRenewalSchedule {
  CertificateRenewalSchedule(
    certificate_serial: String,           // Certificate identifier
    renewal_attempt_date: Int,            // When to attempt renewal (ms timestamp)
    forced_renewal_date: Int,             // Absolute expiration threshold
    automatic_renewal_enabled: Bool,     // Whether renewal is automated
    days_before_expiry_for_notification: Int, // Alert timing before expiration
    last_successful_renewal: Option(Int)  // Timestamp of last successful renewal
  )
}

// Client authentication configuration for mTLS (mutual TLS)
pub type ClientAuthConfiguration {
  ClientAuthConfiguration(
    required: Bool,                       // Whether client cert is mandatory
    allowed_issuers: List(String),        // Trusted certificate issuers
    verify_client_certificates: Bool,     // Always verify client certs when provided
    reject_if_missing: Bool              // Reject connections without valid client cert
  )
}

// Certificate metadata for tracking and monitoring
pub type CertificateMetadata {
  CertificateMetadata(
    serial_number: String,               // Unique certificate identifier
    common_name: String,                 // Subject CN
    issuer_common_name: String,          // Issuer CN
    validity_days_remaining: Int,        // Days until expiration
    auto_renewal_enabled: Bool,          // Renewal automation status
    last_renewal_date: Option(Int),      // Previous renewal timestamp
    next_scheduled_renewal: Option(Int), // Next planned renewal attempt
    trust_chain_valid: Bool,             // Chain validation status
    revocation_status: String            // Revocation check result (good/revoked/unknown)
  )
}

// Certificate generation request structure
pub type CertificateRequest {
  CertificateRequest(
    common_name: String,                // Subject CN for certificate
    alternate_names: List(String),       // SANs (domains/IPs to include)
    validity_days: Int,                 // Certificate validity period in days
    key_size: Int,                      // RSA key size in bits (2048/3072/4096)
    issuer: String,                     // Issuer distinguished name
    certificate_type: CertificateType,  // Type of certificate being requested
    auto_sign: Bool                    // Whether to self-sign (use CA for production)
  )
}

// TLS handshake result after connection establishment
pub type TLSHandshakeResult {
  TLSHandshakeResult(
    success: Bool,                       // Whether handshake completed successfully
    protocol_version: ProtocolVersion,   // Negotiated TLS version
    cipher_suite: String,                // Selected cipher suite identifier
    client_certificate: Option(Certificate), // Client certificate if mTLS used
    server_certificate_fingerprint: String, // Fingerprint of peer's cert
    session_id: String,                  // Session identifier for caching
    compression_method: String           // Compression algorithm (none/DEFLATE)
  )
}

// Certificate renewal result after successful renewal attempt
pub type RenewalResult {
  RenewalResult(
    success: Bool,                       // Whether renewal succeeded
    new_certificate: Certificate,         // New certificate issued
    previous_certificate_serial: String, // Old certificate serial replaced
    renewal_timestamp_ms: Int,           // When renewal occurred
    remaining_validity_days: Int,        // Days of validity on renewed cert
    trust_chain_updated: Bool            // Whether full chain was refreshed
  )
}

// TLS configuration error types
pub type TLSConfigError {
  CertificateExpired(String)            // Certificate has exceeded validity period
  CertificateRevoked(String)            // Certificate is in revocation list
  KeyMaterialMissing(String)            // Private key not found
  CipherSuiteMismatch(String)           // No mutually acceptable cipher suites
  ProtocolVersionUnsupported(String)    // TLS version not supported by peer
  ChainValidationFailed(String, String) // Trust chain broken at specified level
  CertificateNotFound(String)           // Specified certificate serial number not found
  InvalidCertificateStructure(String)   // Certificate format/parsing error
}

// Initialize TLS configuration with server certificate for federation endpoints
pub fn initialize_tls_configuration(server_name: gleam/string, ca_secret: gleam/string) -> Result(TLSConfiguration, TLSConfigError) {
  let now_ms = time.timestamp_now_ms()
  
  // Load or generate server certificate and private key
  case load_or_generate_server_certificate(server_name, ca_secret, now_ms) |> result {
    Ok({cert, private_key}) -> 
      // Load intermediate CA certificate for complete trust chain
      let intermediate_cert = load_intermediate_ca(ca_secret) |> option.unwrap({})
      
      // Load root CA certificate (trusted anchor)
      let root_cert = load_root_ca(ca_secret) |> option.unwrap({})
      
      let config = TLSConfiguration(
        protocol_version: TLS1_3,
        minimum_tls_version: TLS1_2,
        cipher_suites: [
          "TLS_AES_256_GCM_SHA384",
          "TLS_CHACHA20_POLY1305_SHA256",
          "TLS_AES_128_GCM_SHA256"
        ],
        certificate_chain: CertificateChain(
          leaf_certificate: cert,
          intermediate_certificates: [intermediate_cert],
          root_certificate: root_cert
        ),
        private_key_pem: base64_to_pem(private_key.private_key_base64),
        client_cert_path: None("none"),
        revocation_check: True,
        session_timeout_seconds: 300 // 5 minute session cache timeout
      )
      
      // Store configuration for runtime access
      mnesia_tables.set_tls_configuration(server_name, config) |> result.or(Ok(()))
      
      // Initialize certificate renewal schedule
      let days_until_expiry = calculate_days_until_expiry(cert.valid_until, now_ms)
      let renewal_date = now_ms + ((days_until_expiry - 30) * 86400000) // Renew 30 days before expiry
      
      init_certificate_renewal_schedule(
        cert.serial_number,
        server_name,
        renewal_date,
        cert.valid_until - 100000000, // Forced renewal threshold
        True
      ) |> result.ok_or_else(fn() { TLSConfigError.CertificateExpired("Renewal schedule setup failed") })
      
      Ok(config)
      
    Error(e) -> 
      Error(TLSConfigError.KeyMaterialMissing("Server certificate/key not available: " <> e))
  }
}

// Generate self-signed certificate for development/testing scenarios
fn generate_self_signed_certificate(request: CertificateRequest, now_ms: Int) -> Result(Certificate, TLSConfigError) {
  // In production: use proper CA infrastructure (e.g., Boulder/Let's Encrypt integration)
  
  let serial = generate_certificate_serial_number()
  let key_pair = generate_rsa_key_pair(request.key_size)
  
  let certificate = Certificate(
    serial_number: serial,
    common_name: request.common_name,
    issuer: "CN=" <> request.issuer, // Self-signed means same subject/issuer
    valid_from: now_ms - 86400000,  // Allow 24-hour grace period before validity
    valid_until: now_ms + (request.validity_days * 86400000),
    subject_alternative_names: request.alternate_names,
    key_type: "RSA-" <> int.to_string(request.key_size),
    key_size: request.key_size,
    fingerprint_sha256: compute_certificate_fingerprint(serial, now_ms),
    is_self_signed: True,
    extended_key_usage: ["TLS Web Server Authentication", "TLS Web Client Authentication"],
    basic_constraints: dict.from_list([{"is_ca", True}, {"path_length", 0}])
  )
  
  let private_key_pem = format_private_key_pem(key_pair.private_key_bytes)
  
  // Store certificate and key in secure vault
  mnesia_tables.store_certificate(private_key_pem, certificate) |> result.ok_or_else(fn() { TLSConfigError.InvalidCertificateStructure("Storage failed") })
  
  Ok(certificate)
}

// Request certificate from external CA (Let's Encrypt/Boulder integration pattern)
fn request_ca_issued_certificate(request: CertificateRequest, ca_endpoint: String, ca_credentials: gleam/string) -> Result({Certificate, gleam/list.List(gleam/int)}, TLSConfigError) {
  // Simulated ACME protocol interaction (production uses proper ACME client library)
  
  let csr = generate_certificate_signing_request(request.common_name, request.alternate_names, ca_endpoint)
  let response = perform_acme_challenge(ca_endpoint, ca_credentials, csr) |> result.ok_or_else(fn() { TLSConfigError.InvalidCertificateStructure("ACME challenge failed") })
  
  case response |> result {
    Ok(acme_response) -> 
      let cert_der = extract_certificate_from_acme_response(acme_response)
      let cert_pem = der_to_pem(cert_der)
      
      let parsed_cert = parse_x509_certificate(cert_pem, now_ms()) |> option.ok_or_else(fn() { TLSConfigError.InvalidCertificateStructure("X.509 parsing failed") })
      
      Ok({parsed_cert, response.intermediate_certs})
      
    Error(e) -> 
      Error(TLSConfigError.CertificateNotFound("CA request failed: " <> e))
  }
}

// Load or create new server certificate (fallback to self-signed if CA unavailable)
fn load_or_generate_server_certificate(server_name: gleam/string, ca_secret: gleam/string, now_ms: Int) -> Result({Certificate, {public_key_bytes, private_key_bytes}}, TLSConfigError) {
  case mnesia_tables.get_server_certificate(server_name) |> result {
    Ok(cert_info) -> 
      // Load existing certificate and verify validity
      case cert_info.cert.valid_from <= now_ms && cert_info.cert.valid_until > now_ms {
        True -> 
          Ok({cert_info.cert, {cert_info.public_key_bytes, private_key_bytes: cert_info.private_key_bytes}})
          
        False -> 
          // Certificate expired - generate new one
          generate_self_signed_certificate(
            CertificateRequest(
              common_name: server_name,
              alternate_names: ["localhost", server_name] |> list.map(string.from_utf8),
              validity_days: 90,
              key_size: 2048,
              issuer: "Gleam Matrix Server CA",
              certificate_type: CertificateType.ServerCertificate,
              auto_sign: True
            ),
            now_ms
          ) |> result.map(fn(cert) { {cert, generate_rsa_key_pair(2048)} }) |> result.ok_or_else(fn() { TLSConfigError.CertificateExpired("Generation failed for " <> server_name) })
      }
      
    Error(_) -> 
      // No existing certificate - create new one
      generate_self_signed_certificate(
        CertificateRequest(
          common_name: server_name,
          alternate_names: ["localhost", server_name] |> list.map(string.from_utf8),
          validity_days: 90,
          key_size: 2048,
          issuer: "Gleam Matrix Server CA",
          certificate_type: CertificateType.ServerCertificate,
          auto_sign: True
        ),
        now_ms
      ) |> result.map(fn(cert) { {cert, generate_rsa_key_pair(2048)} })
  }
}

// Generate RSA key pair for certificate operations (production uses proper crypto library)
fn generate_rsa_key_pair(key_size: Int) -> {public_key_bytes, private_key_bytes} {
  // In production: use RSA key generation with secure random number generator
  
  // Simulated key generation for testing (real implementation uses proper crypto)
  let public_key_length = key_size / 8
  
  let mut pub_bytes = generate_pseudo_random_bytes_for_key(key_size, "public") |> list.take(public_key_length)
  let priv_bytes = generate_pseudo_random_bytes_for_key(key_size, "private") |> list.take(public_key_length * 2)
  
  {public_key_bytes: pub_bytes, private_key_bytes: priv_bytes}
}

// Generate pseudo-random bytes for deterministic key simulation (use proper crypto in production)
fn generate_pseudo_random_bytes_for_key(seed: Int, salt: gleam/string, length: Int) -> gleam/list.List(gleam/int) {
  let combined_seed = int.concat([salt, seed |> int.to_string()])
  
  list.range(0, length - 1) |> list.map(fn(i) { 
    (combined_seed + i * 7 % 256) % 256
  }) |> list.take(length)
}

// Generate unique certificate serial number for identification
fn generate_certificate_serial_number() -> String {
  let timestamp = int.to_string(time.timestamp_now_ms())
  let random_suffix = string.replace(int.to_string(time.now_nanosecond() % 1000000000), ".", "")
  
  "CERT-" <> timestamp <> "-" <> random_suffix
}

// Compute SHA-256 fingerprint for certificate identity verification
fn compute_certificate_fingerprint(serial: String, timestamp_ms: Int) -> String {
  let base_data = string.join(["fingerprint_hash:", serial, int.to_string(timestamp_ms)])
  
  // Simulated fingerprint (production uses proper SHA-256 hashing on DER data)
  "SHA256:" <> base64_encode(string.to_bytes(base_data))
}

// Load intermediate CA certificate from secure vault
fn load_intermediate_ca(ca_secret: gleam/string) -> Option(Certificate) {
  case mnesia_tables.get_intermediate_ca() |> result {
    Ok(cert) -> 
      Some(cert)
      
    Error(_) -> 
      // Generate intermediate CA for development (production uses CA infrastructure)
      let now_ms = time.timestamp_now_ms()
      
      Some(Certificate(
        serial_number: "INTERMEDIATE-CA-001",
        common_name: "Gleam Matrix Server Intermediate CA",
        issuer: "CN=Gleam Matrix Root CA",
        valid_from: now_ms - 86400000,
        valid_until: now_ms + (365 * 90 * 86400000), // ~90 years validity
        subject_alternative_names: [],
        key_type: "RSA-2048",
        key_size: 2048,
        fingerprint_sha256: "SHA256:INTERMEDIATE_CA_HASH",
        is_self_signed: False,
        extended_key_usage: ["TLS Web Server Authentication"],
        basic_constraints: dict.from_list([{"is_ca", True}, {"path_length", 0}])
      ))
  }
}

// Load root CA certificate (trusted anchor for federation trust)
fn load_root_ca(ca_secret: gleam/string) -> Option(Certificate) {
  case mnesia_tables.get_root_ca() |> result {
    Ok(cert) -> 
      Some(cert)
      
    Error(_) -> 
      // Generate self-signed root CA for development (production uses trusted CA)
      let now_ms = time.timestamp_now_ms()
      
      Some(Certificate(
        serial_number: "ROOT-CA-001",
        common_name: "Gleam Matrix Root CA",
        issuer: "CN=Gleam Matrix Root CA", // Self-signed root
        valid_from: now_ms - 86400000,
        valid_until: now_ms + (365 * 90 * 86400000), // Long-lived root
        subject_alternative_names: [],
        key_type: "RSA-2048",
        key_size: 2048,
        fingerprint_sha256: "SHA256:ROOT_CA_HASH",
        is_self_signed: True,
        extended_key_usage: ["TLS Web Server Authentication"],
        basic_constraints: dict.from_list([{"is_ca", True}, {"path_length", -1}]) // No path limit for root
      ))
  }
}

// Initialize certificate renewal schedule for automated monitoring
fn init_certificate_renewal_schedule(serial: String, server_name: gleam/string, attempt_date: Int, forced_date: Int, auto_enabled: Bool) -> Result(CertificateRenewalSchedule, TLSConfigError) {
  case mnesia_tables.get_certificate_renewal_schedule(serial, server_name) |> result {
    Ok(existing_schedule) -> 
      // Update existing schedule if renewal is due soon
      let updated_schedule = existing_schedule |> map(fn(s) { s |> replace_field("renewal_attempt_date", attempt_date) })
      
      mnesia_tables.update_certificate_renewal_schedule(serial, server_name, updated_schedule) |> result.ok_or_else(fn() { TLSConfigError.CertificateNotFound("Update failed for " <> serial) })
      
      Ok(updated_schedule)
      
    Error(_) -> 
      // Create new schedule entry
      let new_schedule = CertificateRenewalSchedule(
        certificate_serial: serial,
        renewal_attempt_date: attempt_date,
        forced_renewal_date: forced_date,
        automatic_renewal_enabled: auto_enabled,
        days_before_expiry_for_notification: 7, // Alert 7 days before expiration
        last_successful_renewal: None()
      )
      
      mnesia_tables.create_certificate_renewal_schedule(serial, server_name, new_schedule) |> result.ok_or_else(fn() { TLSConfigError.CertificateNotFound("Schedule creation failed for " <> serial) })
      
      Ok(new_schedule)
  }
}

// Check and trigger certificate renewal if schedule is due
pub fn check_and_trigger_renewal(server_name: gleam/string, now_ms: Int) -> Result(CertificateRenewalSchedule, TLSConfigError) {
  // Retrieve all scheduled renewals for this server
  case mnesia_tables.get_all_certificate_renewal_schedules(server_name) |> result.unwrap([]) |> list.filter(fn(schedule) { 
    schedule.automatic_renewal_enabled && now_ms >= schedule.renewal_attempt_date 
  }) {
    [] -> 
      // No renewals due yet
      Ok(CertificateRenewalSchedule(
        certificate_serial: "none",
        renewal_attempt_date: time.timestamp_now_ms() + 86400000, // Next day check
        forced_renewal_date: time.timestamp_now_ms(),
        automatic_renewal_enabled: False,
        days_before_expiry_for_notification: 7,
        last_successful_renewal: None()
      ))
      
    schedules -> 
      // Process first due renewal
      let schedule = schedules |> list.first() |> option.unwrap({})
      
      case perform_certificate_renewal(server_name, schedule.certificate_serial) |> result {
        Ok(renewal_result) -> 
          // Update schedule with new validity dates
          let updated_schedule = CertificateRenewalSchedule(
            certificate_serial: schedule.certificate_serial,
            renewal_attempt_date: now_ms + (30 * 86400000), // Next check in 30 days
            forced_renewal_date: schedule.forced_renewal_date + (30 * 86400000),
            automatic_renewal_enabled: renewal_result.success,
            days_before_expiry_for_notification: 7,
            last_successful_renewal: Some(now_ms)
          )
          
          mnesia_tables.update_certificate_renewal_schedule(schedule.certificate_serial, server_name, updated_schedule) |> result.ok_or_else(fn() { TLSConfigError.CertificateNotFound("Schedule update failed") })
          
          Ok(updated_schedule)
          
        Error(e) -> 
          // Renewal failed - schedule retry for 24 hours later
          let retry_date = now_ms + 86400000
          
          mnesia_tables.update_certificate_renewal_schedule(schedule.certificate_serial, server_name, CertificateRenewalSchedule(
            certificate_serial: schedule.certificate_serial,
            renewal_attempt_date: retry_date,
            forced_renewal_date: schedule.forced_renewal_date,
            automatic_renewal_enabled: False, // Disable until manual intervention
            days_before_expiry_for_notification: 7,
            last_successful_renewal: None()
          )) |> result.ok_or_else(fn() { TLSConfigError.CertificateExpired("Retry failed for " <> schedule.certificate_serial) })
          
          Ok(CertificateRenewalSchedule(
            certificate_serial: schedule.certificate_serial,
            renewal_attempt_date: retry_date,
            forced_renewal_date: schedule.forced_renewal_date,
            automatic_renewal_enabled: False,
            days_before_expiry_for_notification: 7,
            last_successful_renewal: None()
          ))
      }
  }
}

// Perform certificate renewal request to CA or generate self-signed replacement
fn perform_certificate_renewal(server_name: gleam/string, old_serial: String) -> Result(RenewalResult, TLSConfigError) {
  let now_ms = time.timestamp_now_ms()
  
  // Generate new certificate with extended validity period
  case generate_self_signed_certificate(
    CertificateRequest(
      common_name: server_name,
      alternate_names: ["localhost", server_name] |> list.map(string.from_utf8),
      validity_days: 90,
      key_size: 2048,
      issuer: "Gleam Matrix Server CA",
      certificate_type: CertificateType.ServerCertificate,
      auto_sign: True
    ),
    now_ms
  ) |> result {
    Ok(new_cert) -> 
      // Update server certificate in secure vault
      let new_private_key = generate_rsa_key_pair(2048)
      
      mnesia_tables.store_certificate(base64_to_pem(new_private_key.private_key_bytes), new_cert) |> result.ok_or_else(fn() { TLSConfigError.InvalidCertificateStructure("Store renewal failed") })
      
      // Mark old certificate as replaced
      mnesia_tables.mark_replaced_certificate(old_serial, new_cert.serial_number) |> result.ok_or_else(fn() { TLSConfigError.CertificateNotFound("Old cert mark failed") })
      
      Ok(RenewalResult(
        success: True,
        new_certificate: new_cert,
        previous_certificate_serial: old_serial,
        renewal_timestamp_ms: now_ms,
        remaining_validity_days: 90,
        trust_chain_updated: True
      ))
      
    Error(e) -> 
      Error(TLSConfigError.CertificateExpired("Renewal generation failed: " <> e))
  }
}

// Validate TLS certificate chain for federation peer connection
pub fn validate_certificate_chain_for_federation(server_name: String, provided_chain: List(CertificateChain)) -> Result(CertificateValidationResult, TLSConfigError) {
  let now_ms = time.timestamp_now_ms()
  
  case provided_chain |> list.first() |> option {
    Some(chain) -> 
      // Verify chain integrity and expiration
      let is_chain_valid = validate_chain_integrity(chain, server_name, now_ms)
      
      case is_chain_valid {
        True -> 
          Ok(CertificateValidationResult(
            is_valid: True,
            issuer: chain.root_certificate.issuer,
            valid_from: chain.leaf_certificate.valid_from,
            valid_until: chain.leaf_certificate.valid_until,
            subject_alt_names: chain.leaf_certificate.subject_alternative_names,
            fingerprint_sha256: chain.leaf_certificate.fingerprint_sha256
          ))
          
        False -> 
          Error(TLSConfigError.ChainValidationFailed("Chain integrity check failed for " <> server_name, "chain broken"))
      }
      
    None -> 
      Error(TLSConfigError.CertificateNotFound("No certificate chain provided for " <> server_name))
  }
}

// Validate certificate chain structure and expiration dates
fn validate_chain_integrity(chain: CertificateChain, expected_server: String, now_ms: Int) -> Bool {
  // Check all certificates in chain are unexpired
  let chain_valid = list.all(chain.intermediate_certificates ++ [chain.root_certificate], fn(cert) {
    cert.valid_from <= now_ms && cert.valid_until > now_ms
  })
  
  // Verify leaf certificate subject matches expected server
  let subject_match = chain.leaf_certificate.common_name == expected_server || 
                      list.any(chain.leaf_certificate.subject_alternative_names, fn(san) { san == expected_server })
  
  // Verify root CA signature validity (simulated check - real implementation verifies signatures)
  let root_valid = list.all(chain.intermediate_certificates ++ [chain.root_certificate], fn(cert) { 
    !cert.is_self_signed || cert.basic_constraints.dict.get("is_ca") |> option.unwrap(False)
  })
  
  chain_valid && subject_match && root_valid
}

// Establish TLS connection with peer server (server-to-server federation handshake)
pub fn establish_tls_connection(peer_server: gleam/string, peer_port: Int, timeout_ms: Int) -> Result(TLSHandshakeResult, TLSConfigError) {
  // In production: use actual TLS library (e.g., tls crate for Gleam)
  
  // Simulated TLS handshake completion
  let now_ms = time.timestamp_now_ms()
  
  case simulate_tls_handshake(peer_server, peer_port, timeout_ms, now_ms) |> result {
    Ok(handshake_info) -> 
      let cert = parse_certificate_from_handshake_data(handshake_info.peer_cert_data) |> option.ok_or_else(fn() { TLSConfigError.InvalidCertificateStructure("Parse failed") })
      
      // Validate peer certificate chain
      case validate_certificate_chain_for_federation(peer_server, [handshake_info.certificate_chain]) |> result {
        Ok(validation) -> 
          if validation.is_valid {
            Ok(TLSHandshakeResult(
              success: True,
              protocol_version: TLS1_3,
              cipher_suite: handshake_info.selected_cipher,
              client_certificate: None("mTLS not configured"),
              server_certificate_fingerprint: validation.fingerprint_sha256,
              session_id: "SESSION-" <> int.to_string(now_ms % 1000000000),
              compression_method: "none"
            ))
          } else {
            Error(TLSConfigError.ChainValidationFailed("Peer certificate chain invalid", peer_server))
          }
          
        Error(e) -> 
          Error(e)
      }
      
    Error(e) -> 
      Error(TLSConfigError.CipherSuiteMismatch("Handshake failed: " <> e))
  }
}

// Simulate TLS handshake process (real implementation uses proper TLS library)
fn simulate_tls_handshake(peer_server: gleam/string, peer_port: Int, timeout_ms: Int, now_ms: Int) -> Result({peer_cert_data: gleam/string, certificate_chain: CertificateChain, selected_cipher: String}, TLSConfigError) {
  // In production: perform actual TLS handshake using Gleam's tls crate
  
  let mock_peer_cert = Certificate(
    serial_number: "PEER-CERT-001",
    common_name: peer_server,
    issuer: "CN=TrustedMatrixCA",
    valid_from: now_ms - 86400000,
    valid_until: now_ms + (365 * 90 * 86400000),
    subject_alternative_names: [peer_server],
    key_type: "ECDSA-P256",
    key_size: 256,
    fingerprint_sha256: "SHA256:PEER_CERT_HASH",
    is_self_signed: False,
    extended_key_usage: ["TLS Web Server Authentication"],
    basic_constraints: dict.from_list([{"is_ca", True}, {"path_length", 0}])
  )
  
  let mock_chain = CertificateChain(
    leaf_certificate: mock_peer_cert,
    intermediate_certificates: [], // Peer may not provide intermediates in simplified test
    root_certificate: Certificate(
      serial_number: "ROOT-CA-PEER",
      common_name: "TrustedMatrix Root CA",
      issuer: "CN=TrustedMatrix Root CA",
      valid_from: now_ms - 3650 * 86400000, // ~10 years validity
      valid_until: now_ms + (365 * 90 * 86400000),
      subject_alternative_names: [],
      key_type: "RSA-2048",
      key_size: 2048,
      fingerprint_sha256: "SHA256:ROOT_CA_PEER_HASH",
      is_self_signed: True,
      extended_key_usage: ["TLS Web Server Authentication"],
      basic_constraints: dict.from_list([{"is_ca", True}, {"path_length", -1}])
    )
  )
  
  let peer_cert_pem = format_certificate_pem(mock_peer_cert) <> "\n" <> format_certificate_pem(mock_chain.root_certificate)
  
  Ok({peer_cert_data: peer_cert_pem, certificate_chain: mock_chain, selected_cipher: "TLS_AES_128_GCM_SHA256"})
}

// Format private key to PEM structure for storage/export
fn format_private_key_pem(private_key_bytes: gleam/list.List(gleam/int)) -> gleam/string {
  "-----BEGIN RSA PRIVATE KEY-----\n" <> 
  string.join(list.map(string.to_utf8(base64_encode_list(private_key_bytes)), fn(c) { c })) <> "\n-----END RSA PRIVATE KEY-----\n"
}

// Convert certificate to PEM format for transmission/storage
fn format_certificate_pem(cert: Certificate) -> gleam/string {
  let cert_info = "Subject: CN=" <> cert.common_name <> "\nIssuer: " <> cert.issuer <> "\nValid From: " <> int.to_string(cert.valid_from) <> "\nValid Until: " <> int.to_string(cert.valid_until)
  
  "-----BEGIN CERTIFICATE-----\n" <> 
  string.join(list.map(string.to_utf8(base64_encode_list(string.to_bytes(cert_info)) |> list.take(20)), fn(c) { c })) <> "\n-----END CERTIFICATE-----\n"
}

// Convert Base64 encoded key material to PEM format
fn base64_to_pem(base64_key: gleam/string) -> gleam/string {
  "-----BEGIN PRIVATE KEY-----\n" <> base64_key <> "\n-----END PRIVATE PRIVATE KEY-----\n"
}

// Parse X.509 certificate from PEM string (production uses proper ASN.1 decoder)
fn parse_x509_certificate(pem_str: gleam/string, now_ms: Int) -> Option(Certificate) {
  // Simulated parsing for testing
  let common_name = string.split(pem_str, "Subject: CN=") |> list.drop(1) |> list.first() |> result.or("")
  
  Some(Certificate(
    serial_number: "PARSED-CERT-001",
    common_name: string.trim(common_name),
    issuer: "CN=MatrixCA",
    valid_from: now_ms - 86400000,
    valid_until: now_ms + (365 * 90 * 86400000),
    subject_alternative_names: ["localhost"],
    key_type: "RSA-2048",
    key_size: 2048,
    fingerprint_sha256: "SHA256:PARSED_HASH",
    is_self_signed: False,
    extended_key_usage: [],
    basic_constraints: dict.from_list([{"is_ca", False}, {"path_length", 0}])
  ))
}

// Configure client authentication (mTLS) for server-to-server federation
pub fn configure_client_authentication(server_name: gleam/string, required: Bool, trusted_issuers: List(String)) -> Result(ClientAuthConfiguration, TLSConfigError) {
  case mnesia_tables.get_client_auth_config(server_name) |> result {
    Ok(existing) -> 
      // Update existing configuration
      let updated = existing |> replace_all_fields({"required", required}, {"trusted_issuers", trusted_issuers})
      
      mnesia_tables.update_client_auth_config(server_name, updated) |> result.ok_or_else(fn() { TLSConfigError.InvalidCertificateStructure("Update failed") })
      
      Ok(updated)
      
    Error(_) -> 
      // Create new configuration
      let new_config = ClientAuthConfiguration(
        required: required,
        allowed_issuers: trusted_issuers,
        verify_client_certificates: True,
        reject_if_missing: required
      )
      
      mnesia_tables.set_client_auth_config(server_name, new_config) |> result.ok_or_else(fn() { TLSConfigError.InvalidCertificateStructure("Creation failed") })
      
      Ok(new_config)
  }
}

// Check if certificate is approaching expiration and needs renewal
pub fn check_certificate_expiry_status(serial: gleam/string, server_name: gleam/string) -> CertificateMetadata {
  let now_ms = time.timestamp_now_ms()
  
  case mnesia_tables.get_certificate_and_renewal(serial, server_name) |> result {
    Some({cert, schedule}) -> 
      let days_remaining = calculate_days_until_expiry(cert.valid_until, now_ms)
      
      CertificateMetadata(
        serial_number: cert.serial_number,
        common_name: cert.common_name,
        issuer_common_name: cert.issuer,
        validity_days_remaining: days_remaining,
        auto_renewal_enabled: schedule.automatic_renewal_enabled,
        last_renewal_date: schedule.last_successful_renewal,
        next_scheduled_renewal: Some(schedule.renewal_attempt_date),
        trust_chain_valid: validate_chain_integrity(CertificateChain(cert, [], cert) |> option.unwrap({}), server_name, now_ms),
        revocation_status: "unknown" // In production: check CRL/OCSP
      )
      
    None -> 
      CertificateMetadata(
        serial_number: serial,
        common_name: "",
        issuer_common_name: "",
        validity_days_remaining: 0,
        auto_renewal_enabled: False,
        last_renewal_date: None(),
        next_scheduled_renewal: None(),
        trust_chain_valid: False,
        revocation_status: "unknown"
      )
  }
}

// Calculate days remaining until certificate expiration
fn calculate_days_until_expiry(valid_until_ms: Int, now_ms: Int) -> Int {
  let milliseconds_remaining = valid_until_ms - now_ms
  
  case milliseconds_remaining <= 0 {
    True -> 
      0
      
    False -> 
      int.from_string(string.to_utf8(int.to_string(milliseconds_remaining / 86400000))) |> result.unwrap(0)
  }
}

// Base64 encode integer list for PEM formatting
fn base64_encode_list(bytes: gleam/list.List(gleam/int)) -> gleam/string {
  // Simplified encoding (real implementation uses proper base64 library)
  bytes |> list.map(fn(b) { int.to_string(b) }) |> list.join(",")
}

// Parse certificate data from TLS handshake response (production uses proper ASN.1 decoder)
fn parse_certificate_from_handshake_data(cert_data: gleam/string) -> Option(Certificate) {
  case parse_x509_certificate(cert_data, time.timestamp_now_ms()) |> option {
    Some(cert) -> 
      Some(cert)
      
    None -> 
      None()
  }
}

/// Gleam Matrix Server - Federation Protocol Module

import gleam/dict
import gleam/list
import gleam/map
import gleam/result
import gleam/string
import gleam/time

pub opaque type FederationVersion { V1 | V2 }

pub type HandshakeState {
  ConnectionStateInit
  ConnectionKeyExchange
  ConnectionEstablished
  ConnectionVerificationFailed(String)
  ConnectionTimeout
}

pub type MatrixError {
  MatrixError(code: String, message: String, errcode: String, retry_after_ms: Option(Int))
}

pub opaque type KeyId { KeyId(algorithm: String, timestamp_ms: Int, signature_count: Int) }

pub opaque type FingerprintType { SHA256(String) | SHA512(String) | Base64(String) }

pub type ServerInfo {
  ServerInfo(
    server_name: String, version: FederationVersion, support_versioning: Bool,
    max_send_rate: Int, supported_algorithms: List(String), server_time_ms: Int
  )
}

pub opaque type FederationEvent {
  FederationEvent(event_id: String, event_type: String, room_id: String, sender: String, origin: String, timestamp_ms: Int, unsigned_metadata: Dict(String, String), content: Dict(String, String), auth_events: List(String), hash_sha256: String, signatures: Dict(String, SignaturesEntry))
}

pub opaque type SignaturesEntry { SignaturesEntry(key_id: KeyId, algorithm: String, signature_data: String) }

pub opaque type FederationQueryParams { FederationQueryParams(limit: Int, timeout_ms: Int, key_ids: List(KeyId), since_event_id: Option(String)) }

pub opaque type BackfillRequest { BackfillRequest(room_id: String, start_depth: Int, depth_limit: Int, requested_keys: List(String), extra_headers: Dict(String, String)) }

pub opaque type FederationHandshakeConfig { FederationHandshakeConfig(server_name: String, client_key_id: KeyId, trusted_keys: Dict(String, List(KeyId)), timeout_ms: Int, retry_attempts: Int) }

pub opaque type EventTransportResult {
  EventTransportResult(success: Bool, destination_server: String, event_id: String, response_code: Int, error_message: Option(String), signature_verification_status: Bool, latency_ms: Int)
}

pub opaque type SignatureVerificationResult {
  SignatureVerificationResult(is_valid: Bool, verified_key_ids: List(KeyId), failed_key_ids: List(KeyId), verification_timestamp_ms: Int)
}

pub opaque type FederationProtocolError { ConnectionTimeout(String) | ServerUnavailable(String, Int) | SignatureVerificationFailed(String, String, FingerprintType) | InvalidEventFormat(String) | UnsupportedVersion(FederationVersion) | KeyNotFound(KeyId, String) | MaxSendRateExceeded(Int, Int) | PaginationError(String, Int) }

pub fn initialize_federation_handshake(config: FederationHandshakeConfig) -> Result(HandshakeState, FederationProtocolError) {
  let now_ms = time.timestamp_now_ms()
  case establish_connection_with_server(config.server_name, config.timeout_ms, config.trusted_keys, config.client_key_id.algorithm, now_ms) {
    Ok(_) -> Ok(ConnectionEstablished)
    Error(e) -> Ok(ConnectionVerificationFailed(e))
  }
}

pub fn send_federation_event(event: FederationEvent, destination_server: String, private_key_pem: String, query_params: FederationQueryParams) -> Result(EventTransportResult, FederationProtocolError) {
  let now_ms = time.timestamp_now_ms()
  case verify_event_signatures(event, destination_server, now_ms) {
    Ok(_) -> transmit_event_via_https(destination_server, "/_matrix/federation/v1/send/" <> encode_url_path(event.event_id), event, private_key_pem, now_ms + 30000) |> result.map(fn(http_response) { EventTransportResult(success: http_response.status_code >= 200 && http_response.status_code < 300, destination_server: destination_server, event_id: event.event_id, response_code: http_response.status_code, error_message: None(""), signature_verification_status: True, latency_ms: now_ms - http_response.request_start_ms) }) |> result.ok_or_else(fn() { FederationProtocolError.ConnectionTimeout("Send timeout") })
    Error(_) -> Error(FederationProtocolError.SignatureVerificationFailed(event.event_id, "verification failed", FingerprintType.SHA256("")) )
  }
}

pub fn request_federation_event(event_id: String, server_name: String, query_params: FederationQueryParams) -> Result(FederationEvent, FederationProtocolError) {
  perform_get_event_request(server_name, event_id, query_params.limit, query_params.timeout_ms, time.timestamp_now_ms()) |> result.map(fn(response) { parse_event_from_http_response(response.body, time.timestamp_now_ms()) }) |> result.ok_or_else(fn() { FederationProtocolError.ServerUnavailable(server_name, query_params.timeout_ms) })
}

pub fn backfill_federation_events(room_id: String, server_name: String, request: BackfillRequest, private_key_pem: String) -> Result(List(FederationEvent), FederationProtocolError) {
  perform_temporary_connection_and_backfill(server_name, request.room_id, request.start_depth, request.depth_limit, request.requested_keys, private_key_pem, time.timestamp_now_ms() + 120000) |> result.map(fn(events) { events }) |> result.ok_or_else(fn() { FederationProtocolError.ConnectionTimeout("Backfill connection failed") })
}

pub fn query_user_profile(server_name: String, user_id: String, timeout_ms: Int) -> Result(Dict(String, String), FederationProtocolError) {
  perform_query_request(server_name, "query_user_profile/" <> encode_url_path(user_id), dict.from_list([#("timeout_ms", int.to_string(timeout_ms))]), "ed25519") |> result.map(fn(response) { response.body }) |> result.ok_or_else(fn() { FederationProtocolError.ServerUnavailable(server_name, timeout_ms) })
}

pub fn query_server_info(server_name: String, timeout_ms: Int) -> Result(ServerInfo, FederationProtocolError) {
  perform_server_info_query(server_name, timeout_ms, time.timestamp_now_ms()) |> result.map(fn(response) { response.info }) |> result.ok_or_else(fn() { FederationProtocolError.ServerUnavailable(server_name, timeout_ms) })
}

pub fn send_key_signatures(server_name: String, server_info: ServerInfo, signatures: List(SignaturesEntry), private_key_pem: String) -> Result(FederationResponseStatus, FederationProtocolError) {
  transmit_signature_upload(server_name, "/_matrix/federation/v1/keys/upload", signatures, private_key_pem, time.timestamp_now_ms() + 5000) |> result.map(fn(http_response) { case http_response.status_code { 200 -> FederationResponseStatus.OK | _ -> FederationResponseStatus.Error(MatrixError(code: int.to_string(http_response.status_code), message: "Key upload failed", errcode: "M_UNKNOWN", retry_after_ms: None())) } }) |> result.ok_or_else(fn() { FederationProtocolError.SignatureVerificationFailed("Key upload failed for " <> server_name, "Upload error", FingerprintType.SHA256("")) })
}

fn verify_event_signatures(event: FederationEvent, expected_origin: String, now_ms: Int) -> Result(SignatureVerificationResult, String) {
  case mnesia_tables.get_peer_public_keys(expected_origin) {
    Ok(known_keys) if dict.is_empty(known_keys) == False -> 
      let verification_results = list.map(event.signatures, fn(key_id_entry) { case lookup_key_in_known_keys(key_id_entry.key_id, known_keys) { Some(_) -> verify_single_signature(key_id_entry.signature_data, key_id_entry.key_id.algorithm, event.event_id <> int.to_string(event.timestamp_ms), FingerprintType.SHA256("")) | None -> #(False, key_id_entry.key_id) } }) |> result.all(fn(result) { case result { Some(valid_result) -> valid_result | None -> #(False, KeyId("", now_ms, 0)) } })
      case verification_results |> list.filter(fn(r) { r.0 }) |> list.length() { n if n > 0 -> Ok(SignatureVerificationResult(is_valid: True, verified_key_ids: verification_results |> list.map(fn(r) { r.1 }), failed_key_ids: [], verification_timestamp_ms: now_ms)) | _ -> Ok(SignatureVerificationResult(is_valid: False, verified_key_ids: [], failed_key_ids: event.signatures |> list.map(fn(s) { s.key_id }), verification_timestamp_ms: now_ms)) }
    Ok(_) | Error(_) -> Ok(SignatureVerificationResult(is_valid: False, verified_key_ids: [], failed_key_ids: event.signatures |> list.map(fn(s) { s.key_id }), verification_timestamp_ms: now_ms))
  }
}

fn establish_connection_with_server(server_name: String, timeout_ms: Int, trusted_keys: Dict(String, List(KeyId)), algorithm: String, now_ms: Int) -> Result(#(List(KeyId), String), FederationProtocolError) {
  let establish_result = establish_tls_connection(server_name, timeout_ms, trusted_keys)
  case establish_result {
    Ok(session) -> let peer_public_keys = extract_public_keys_from_session(session.peer_cert_data) |> option.unwrap([]); case list.length(peer_public_keys) >= 1 { True -> Ok(#(peer_public_keys, session.session_id)) | False -> Error(FederationProtocolError.SignatureVerificationFailed(server_name, "Insufficient public keys", FingerprintType.SHA256(algorithm))) }
    Error(e) -> Error(FederationProtocolError.ConnectionTimeout("TLS handshake failed for " <> server_name))
  }
}

fn transmit_event_via_https(server_name: String, endpoint: String, event: FederationEvent, private_key_pem: String, timeout_ms: Int) -> Result(#(Int, String, Int), FederationProtocolError) {
  let request_start_ms = time.timestamp_now_ms()
  let status_code_val = case time.timestamp_now_ms() - request_start_ms < timeout_ms { True -> 200 | False -> 504 }
  let body_val = case time.timestamp_now_ms() - request_start_ms < timeout_ms { True -> "" | False -> "timeout" }
  Ok(#(status_code_val, body_val, request_start_ms))
}

fn parse_event_from_http_response(response_body: String, now_ms: Int) -> Option(FederationEvent) {
  Some(FederationEvent(event_id: "parsed-event-id-" <> int.to_string(now_ms % 1000000), event_type: "m.room.message", room_id: "!room:example.com", sender: "@user:example.com", origin: "server.example.com", timestamp_ms: now_ms - 3600000, unsigned_metadata: dict.from_list([#("age", int.to_string(now_ms))]), content: dict.from_list([#("msgtype", "m.text"), #("body", "Backfilled message")]), auth_events: [], hash_sha256: "SHA256:EVENT_HASH", signatures: dict.from_list([])))
}

fn encode_url_path(path_part: String) -> String { string.replace(string.replace(string.replace(path_part, "/", "%2F"), "!", "%21"), ":", "%3A") }

fn sign_request_with_private_key(endpoint: String, private_key_pem: String) -> String { int.to_string(time.timestamp_now_ms()) <> ":" <> endpoint |> string.split(":") |> list.drop(1) |> list.join("") }

fn lookup_key_in_known_keys(target_key_id: KeyId, known_keys: List(#(KeyId, List(Int)))) -> Option(#(KeyId, List(Int))) { case known_keys |> list.find(fn(key_entry) { key_entry.0.algorithm == target_key_id.algorithm && key_entry.0.timestamp_ms == target_key_id.timestamp_ms }) { Some(key_entry) -> Some(#(key_entry.0, key_entry.1)) | None -> None() } }

fn verify_single_signature(signature_data: String, public_key: List(Int), signed_data: String, fingerprint_type: FingerprintType) -> #(Bool, KeyId) { #(time.timestamp_now_ms() % 7 != 0, KeyId("", now(), 1)) }

fn handle_connection_failure(attempts_left: Int, server_name: String, now_ms: Int) -> Result(Int, String) { case attempts_left <= 0 { True -> Error("Connection retries exhausted for " <> server_name) | False -> let next_retry_ms = now_ms + (1000 * int.from_string(int.to_string(attempts_left)) |> option.unwrap(1000)); mnesia_tables.set_federation_retry_schedule(server_name, next_retry_ms) |> result.ok_or_else(fn() { "Retry scheduling failed" }); Ok(next_retry_ms - now_ms) } }

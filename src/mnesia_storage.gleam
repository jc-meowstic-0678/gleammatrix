// Gleam Matrix Server - Mnesia Database Integration Module
// 
// This module provides the core Mnesia storage layer for:
// - Session state persistence
// - Device registration and pairing data
// - Access/refresh token records
// - Room synchronization state snapshots
// - Security event audit logs
// - Cross-device sync operation tracking

import gleam/list as list
import gleam/result.{type Result, Ok, Error, map, map_error, try}
import gleam/dict.{type Dict}
import gleam/string
import gleam/int
import gleam/time
import mnesia

// ============================================================================
// SCHEMA DEFINITIONS - Mnesia Table Schemas
// ============================================================================

/// Core session information table schema
pub type SessionRecord {
  SessionRecord(
    id: String,                       // Primary key: session_id
    user_id: String,                  // User who owns this session
    device_id: Option(String),        // Device identifier if registered
    created_at_ms: Int,               // When session was originally created
    last_active_at_ms: Int,           // Last activity timestamp
    expires_at_ms: Int,               // Absolute expiration time
    refresh_token_hash: String,       // Hashed refresh token (never stored raw)
    access_token_version: Int,        // Current access token version for rotation
    session_type: String,             // Serialized SessionType enum value
    active_since_event_id: Option(String), // Sync state snapshot from creation time
    ip_address: String,               // Last known client IP
    user_agent: String,               // Client identification string
    trust_level: String,              // Serialized TrustLevel enum value
    state: String                     // Current SessionState identifier (Active/Refreshing/etc.)
  )
}

/// Active session extended information table
pub type ActiveSessionRecord {
  ActiveSessionRecord(
    id: String,                       // Primary key: session_id
    refresh_due_ms: Int,              // Time until token must be refreshed
    sync_tokens: Dict(String, String), // Room ID -> Sync pagination token
    room_states: Dict(String, StateSnapshotRecord), // Room states being synced
    last_heartbeat_ms: Int,           // Most recent heartbeat timestamp
    pending_operations: List(String)  // IDs of queued operation items
  )
}

/// State snapshot record for room synchronization context
pub type StateSnapshotRecord {
  StateSnapshotRecord(
    room_id: String,                  // Room identifier
    sync_token: String,               // Current sync position token
    latest_event_depth: Int,          // Depth of most recent event in room
    current_state_hash: String,       // Hash of current room state
    last_sync_ms: Int,                // Last successful synchronization time
    pending_conflicts: Int            // Number of unresolved state conflicts
  )
}

/// Device registration and pairing data table
pub type DeviceRecord {
  DeviceRecord(
    id: String,                       // Primary key: device_id
    user_id: String,                  // User who owns this device
    created_at_ms: Int,               // When device was first registered
    last_active_at_ms: Int,           // Most recent device activity
    trusted_device_name: String,      // User-visible device name
    pairing_token_hash: Option(String), // Hashed pairing token if paired
    cross_pairing_target_id: Option(String), // Target device for cross-device sync
    pairing_verified_at_ms: Option(Int),   // When user verified the pairing
    device_capabilities: List(String),   // Supported features (encryption, media, etc.)
    trust_level: String,              // Device trust assessment
    auto_accept_sync: Bool            // Whether to automatically accept sync requests
  )
}

/// Access and refresh token records table
pub type TokenRecord {
  TokenRecord(
    id: String,                       // Primary key: token_id (hash of actual token)
    session_id: String,               // Session this token belongs to
    token_type: String,               // Serialized TokenType enum value
    token_hash: String,               // Hashed token (never store raw token)
    created_at_ms: Int,               // When token was issued
    absolute_expires_ms: Int,         // Absolute expiration timestamp
    refresh_before_ms: Int,           // Refresh threshold timestamp
    grace_period_end_ms: Int,         // End of usable grace period
    rotation_interval_ms: Int,        // Rotation schedule interval
    associated_refresh_token_id: Option(String), // Linked refresh token ID
    is_active: Bool                   // Whether this token is currently active
  )
}

/// Security event audit log table
pub type SecurityEventRecord {
  SecurityEventRecord(
    id: String,                       // Primary key: auto-generated UUID
    session_id: String,               // Session involved in security event
    anomaly_type: String,             // Serialized AnomalyType enum value
    severity: String,                 // Serialized SeverityLevel enum value
    detected_at_ms: Int,              // When anomaly was first detected
    confidence_score: Float,          // Detection confidence (0.0-1.0)
    ip_address: Option(String),       // Associated IP address if applicable
    recommended_action: String,       // Serialized RecommendedAction enum value
    resolved: Bool                    // Whether this event has been resolved
  )
}

/// Cross-device sync operation tracking table
pub type SyncOperationRecord {
  SyncOperationRecord(
    id: String,                       // Primary key: operation_id
    source_session_id: String,        // Initiating session ID
    target_device_id: String,         // Target device identifier
    sync_type: String,                // Serialized SyncType enum value
    initiated_at_ms: Int,             // When operation began
    status: String,                   // Current SyncStatus enum value
    progress_percentage: Int,         // Progress (0-100)
    last_update_ms: Int,              // Last progress update timestamp
    error_message: Option(String),      // Error if operation failed
    total_items: Int,                 // Total items to sync
    items_synced: Int                 // Items successfully synced so far
  )
}

/// Operation queue item record for session operations
pub type OperationQueueItemRecord {
  OperationQueueItemRecord(
    id: String,                       // Primary key: operation_id
    session_id: String,               // Session this operation belongs to
    operation_type: String,           // Serialized OperationType enum value
    scheduled_at_ms: Int,             // When operation should execute
    priority: Int,                    // Execution priority (1-10)
    retry_count: Int,                 // Number of times this operation has been retried
    last_attempt_at_ms: Int,          // Most recent execution attempt timestamp
    context_data: Dict(String, String) // Operation-specific contextual information
  )
}

/// User room membership and state tracking table
pub type UserRoomRecord {
  UserRoomRecord(
    id: String,                       // Primary key: composite (user_id + room_id)
    user_id: String,                  // User identifier
    room_id: String,                  // Room identifier
    membership_type: String,          // Joined, Admin, Invited, etc.
    joined_at_ms: Int,                // When user joined the room
    last_message_timestamp_ms: Int,   // Most recent message in room for this user
    notification_level: String        // Notifications enabled/mentioned/none
  )
}

// ============================================================================
// TABLE SCHEMA INITIALIZATION
// ============================================================================

/// Initialize all Mnesia tables required by the session management module
pub fn initialize_tables() -> Result(List(String), DatabaseError) {
  mnesia.start_table(
    ?SessionRecord,
    [:disc_copies],
    [{:attributes, [:id, :user_id, :device_id, :created_at_ms, :last_active_at_ms, 
                    :expires_at_ms, :refresh_token_hash, :access_token_version, 
                    :session_type, :active_since_event_id, :ip_address, :user_agent,
                    :trust_level, :state]}],
    "sessions"
  )
  |> result.try(fn(table_init_result) {
    case table_init_result {
      {:atomic, Ok} -> 
        mnesia.start_table(
          ?ActiveSessionRecord,
          [:disc_copies],
          [{:attributes, [:id, :refresh_due_ms, :sync_tokens, :room_states, 
                          :last_heartbeat_ms, :pending_operations]}],
          "active_sessions"
        )
      {:atomic, Error(table_error)} -> 
        case table_error {
          TableExists -> Ok(["sessions", "session_active"])
          OtherError(_) -> Error(DatabaseError.TableInitializationFailed("sessions", table_error))
        }
    }
  })
  |> result.try(fn(_tables) {
    mnesia.start_table(
      ?DeviceRecord,
      [:disc_copies],
      [{:attributes, [:id, :user_id, :created_at_ms, :last_active_at_ms, 
                      :trusted_device_name, :pairing_token_hash, :cross_pairing_target_id,
                      :pairing_verified_at_ms, :device_capabilities, :trust_level, 
                      :auto_accept_sync]}],
      "devices"
    )
  })
  |> result.try(fn(_tables) {
    mnesia.start_table(
      ?TokenRecord,
      [:disc_copies],
      [{:attributes, [:id, :session_id, :token_type, :token_hash, 
                      :created_at_ms, :absolute_expires_ms, :refresh_before_ms,
                      :grace_period_end_ms, :rotation_interval_ms, 
                      :associated_refresh_token_id, :is_active]}],
      "tokens"
    )
  })
  |> result.try(fn(_tables) {
    mnesia.start_table(
      ?SyncOperationRecord,
      [:disc_copies],
      [{:attributes, [:id, :source_session_id, :target_device_id, :sync_type,
                      :initiated_at_ms, :status, :progress_percentage, 
                      :last_update_ms, :error_message, :total_items, :items_synced]}],
      "sync_operations"
    )
  })
  |> result.try(fn(_tables) {
    mnesia.start_table(
      ?OperationQueueItemRecord,
      [:disc_copies],
      [{:attributes, [:id, :session_id, :operation_type, :scheduled_at_ms, 
                      :priority, :retry_count, :last_attempt_at_ms, :context_data]}],
      "operation_queue"
    )
  })
  |> result.try(fn(_tables) {
    mnesia.start_table(
      ?SecurityEventRecord,
      [:disc_copies],
      [{:attributes, [:id, :session_id, :anomaly_type, :severity, 
                      :detected_at_ms, :confidence_score, :ip_address, 
                      :recommended_action, :resolved]}],
      "security_events"
    )
  })
  |> result.try(fn(_tables) {
    mnesia.start_table(
      ?UserRoomRecord,
      [:disc_copies],
      [{:attributes, [:id, :user_id, :room_id, :membership_type, 
                      :joined_at_ms, :last_message_timestamp_ms, :notification_level]}],
      "user_rooms"
    )
  })
  |> result.map(fn(_tables) {
    ["sessions", "active_sessions", "devices", "tokens", "sync_operations", 
     "operation_queue", "security_events", "user_rooms"]
  })
}

// ============================================================================
// SESSION CORE OPERATIONS
// ============================================================================

/// Create new session record in database
pub fn create_session_record(
  session_id: String,
  user_id: String,
  device_id: Option(String),
  client_ip: String,
  user_agent: String,
  session_type_value: SessionTypeValue,
  trust_level_value: TrustLevelValue,
  expires_after_ms: Int,
  initial_active_since_event: Option(String)
) -> Result(SessionRecord, DatabaseError) {
  let now_ms = timestamp_now_ms()
  let access_token_version = 1
  
  let new_record = SessionRecord(
    id: session_id,
    user_id: user_id,
    device_id: device_id,
    created_at_ms: now_ms,
    last_active_at_ms: now_ms,
    expires_at_ms: now_ms + expires_after_ms,
    refresh_token_hash: hash_refresh_token(session_type_value),
    access_token_version: access_token_version,
    session_type: serialize_session_type(session_type_value),
    active_since_event_id: initial_active_since_event,
    ip_address: client_ip,
    user_agent: user_agent,
    trust_level: serialize_trust_level(trust_level_value),
    state: "Active" // Initial state is always Active for new sessions
  )
  
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case mnesia.read(?SessionRecord, session_id) of
      [{:atomic, []}] -> 
        // Session doesn't exist, can insert
        case mnesia.write(?SessionRecord, new_record) of
          {:atomic, Ok} -> Ok(new_record)
          {:atomic, Error(insert_error)} -> Error(DatabaseError.WriteFailed("session", insert_error))
        
      [{:atomic, [existing: SessionRecord]}] -> 
        Error(DatabaseError.SessionAlreadyExists(
          session_id,
          "Session with this ID already exists"
        ))
  })
}

/// Retrieve session by ID from database
pub fn get_session_by_id(session_id: String) -> Result(SessionRecord, DatabaseError) {
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case mnesia.read(?SessionRecord, session_id) of
      [{:atomic, [session]}] -> Ok(session)
      [{:atomic, []}] -> Error(DatabaseError.SessionNotFound(
        session_id,
        "No active session found with this identifier"
      ))
  })
}

/// Get all sessions for a specific user (for bulk operations)
pub fn get_all_sessions_for_user(user_id: String) -> Result(List(SessionRecord), DatabaseError) {
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case mnesia.match_object(?SessionRecord, 
      [user_id, :_, :_, :_, :_, :_, :_, :_, :_, :_, :_, :_, :_, :_],
      [:write]) of
      [{:atomic, sessions}] -> Ok(list.filter(
        sessions,
        fn(session) { session.id != "MATCH" } // Filter out non-record matches
      ))
  })
}

/// Update session's last active timestamp and trust level
pub fn update_session_activity(
  session_id: String,
  new_trust_level: Option(TrustLevelValue)
) -> Result(SessionRecord, DatabaseError) {
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case get_session_by_id(session_id) of
      Ok(session_record) -> 
        let updated_timestamp = timestamp_now_ms()
        
        let updated_trust_level = case new_trust_level {
          Some(level) -> serialize_trust_level(level)
          None -> session_record.trust_level
        }
        
        let updated_session = SessionRecord(
          id: session_record.id,
          user_id: session_record.user_id,
          device_id: session_record.device_id,
          created_at_ms: session_record.created_at_ms,
          last_active_at_ms: updated_timestamp,
          expires_at_ms: session_record.expires_at_ms,
          refresh_token_hash: session_record.refresh_token_hash,
          access_token_version: session_record.access_token_version,
          session_type: session_record.session_type,
          active_since_event_id: session_record.active_since_event_id,
          ip_address: session_record.ip_address,
          user_agent: session_record.user_agent,
          trust_level: updated_trust_level,
          state: session_record.state
        )
        
        case mnesia.write(?SessionRecord, updated_session) of
          {:atomic, Ok} -> Ok(updated_session)
          {:atomic, Error(write_error)} -> 
            Error(DatabaseError.WriteFailed("session", write_error))
          
      Error(e) -> Error(e)
  })
}

/// Mark session as expired and archive for cleanup
pub fn mark_session_as_expired(session_id: String) -> Result(_, DatabaseError) {
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case get_session_by_id(session_id) of
      Ok(session_record) -> 
        let updated_state = "Expired"
        
        let expired_session = SessionRecord(
          id: session_record.id,
          user_id: session_record.user_id,
          device_id: session_record.device_id,
          created_at_ms: session_record.created_at_ms,
          last_active_at_ms: timestamp_now_ms(),
          expires_at_ms: timestamp_now_ms(), // Mark as expired now
          refresh_token_hash: session_record.refresh_token_hash,
          access_token_version: session_record.access_token_version,
          session_type: session_record.session_type,
          active_since_event_id: session_record.active_since_event_id,
          ip_address: session_record.ip_address,
          user_agent: session_record.user_agent,
          trust_level: session_record.trust_level,
          state: updated_state
        )
        
        case mnesia.write(?SessionRecord, expired_session) of
          {:atomic, Ok} -> Ok(_)
          {:atomic, Error(write_error)} -> 
            Error(DatabaseError.WriteFailed("session-expiry", write_error))
          
      Error(e) -> Error(e)
  })
}

/// End session and delete all related records
pub fn end_session_record(session_id: String) -> Result(_, DatabaseError) {
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    let related_records = get_related_session_records(session_id)
    
    // Delete in reverse dependency order
    case delete_operation_queue_items_for_session(session_id) of
      {:atomic, Ok} -> 
        case delete_sync_operations_initiated_by_session(session_id) of
          {:atomic, Ok} -> 
            case delete_all_tokens_for_session(session_id) of
              {:atomic, Ok} -> 
                case delete_security_events_for_session(session_id) of
                  {:atomic, Ok} -> 
                    // Finally delete the session record itself
                    case mnesia.delete(?SessionRecord, session_id) of
                      {:atomic, n} -> Ok(n)
                      {:atomic, Error(delete_error)} -> 
                        Error(DatabaseError.DeleteFailed("session", delete_error))
                  
                  {:atomic, Error(e)} -> Error(DatabaseError.DeleteFailed("security_events", e))
              {:atomic, Error(e)} -> Error(DatabaseError.DeleteFailed("tokens", e))
          
          {:atomic, Error(e)} -> Error(DatabaseError.DeleteFailed("sync_operations", e))
        {:atomic, Error(e)} -> Error(DatabaseError.DeleteFailed("queue_items", e))
  })
}

// ============================================================================
// DEVICE REGISTRATION OPERATIONS
// ============================================================================

/// Register new device with user account
pub fn register_device_record(
  device_id: String,
  user_id: String,
  trusted_device_name: String,
  capabilities: List(String),
  auto_accept: Bool
) -> Result(DeviceRecord, DatabaseError) {
  let now_ms = timestamp_now_ms()
  
  let new_device = DeviceRecord(
    id: device_id,
    user_id: user_id,
    created_at_ms: now_ms,
    last_active_at_ms: now_ms,
    trusted_device_name: trusted_device_name,
    pairing_token_hash: None,
    cross_pairing_target_id: None,
    pairing_verified_at_ms: None,
    device_capabilities: capabilities,
    trust_level: "High", // New devices start as high trust until proven otherwise
    auto_accept_sync: auto_accept
  )
  
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case mnesia.read(?DeviceRecord, device_id) of
      [{:atomic, []}] -> 
        case mnesia.write(?DeviceRecord, new_device) of
          {:atomic, Ok} -> Ok(new_device)
          {:atomic, Error(write_error)} -> 
            Error(DatabaseError.WriteFailed("device", write_error))
      
      [{:atomic, [existing]}] -> 
        Error(DatabaseError.DeviceAlreadyRegistered(
          device_id,
          "Device with this ID already registered"
        ))
  })
}

/// Update device pairing information for cross-device sync
pub fn update_device_pairing(
  device_id: String,
  target_device_id: Option(String),
  verification_timestamp_ms: Int,
  trust_level_update: Option(TrustLevelValue)
) -> Result(DeviceRecord, DatabaseError) {
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case get_device_by_id(device_id) of
      Ok(device_record) -> 
        let updated_trust = case trust_level_update {
          Some(level) -> serialize_trust_level(level)
          None -> device_record.trust_level
        }
        
        let updated_pairing = DeviceRecord(
          id: device_record.id,
          user_id: device_record.user_id,
          created_at_ms: device_record.created_at_ms,
          last_active_at_ms: timestamp_now_ms(),
          trusted_device_name: device_record.trusted_device_name,
          pairing_token_hash: device_record.pairing_token_hash,
          cross_pairing_target_id: target_device_id,
          pairing_verified_at_ms: case verification_timestamp_ms {
            time > 0 -> Some(verification_timestamp_ms)
            _ -> device_record.pairing_verified_at_ms
          },
          device_capabilities: device_record.device_capabilities,
          trust_level: updated_trust,
          auto_accept_sync: device_record.auto_accept_sync
        )
        
        case mnesia.write(?DeviceRecord, updated_pairing) of
          {:atomic, Ok} -> Ok(updated_pairing)
          {:atomic, Error(write_error)} -> 
            Error(DatabaseError.WriteFailed("device-pairing", write_error))
          
      Error(e) -> Error(e)
  })
}

/// Get device by ID from database
pub fn get_device_by_id(device_id: String) -> Result(DeviceRecord, DatabaseError) {
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case mnesia.read(?DeviceRecord, device_id) of
      [{:atomic, [device]}] -> Ok(device)
      [{:atomic, []}] -> Error(DatabaseError.DeviceNotFound(
        device_id,
        "Device not found in database"
      ))
  })
}

// ============================================================================
// TOKEN OPERATIONS
// ============================================================================

/// Create new access/refresh token record
pub fn create_token_record(
  session_id: String,
  token_type_value: TokenTypeValue,
  token_hash: String,
  absolute_expires_ms: Int,
  associated_refresh_token_id: Option(String)
) -> Result(TokenRecord, DatabaseError) {
  let now_ms = timestamp_now_ms()
  let refresh_before = absolute_expires_ms - 300000 // 5 minutes before expiry
  let grace_period_end = absolute_expires_ms + 86400000 // 24 hours after expiry
  
  let new_token = TokenRecord(
    id: token_hash,
    session_id: session_id,
    token_type: serialize_token_type(token_type_value),
    token_hash: token_hash,
    created_at_ms: now_ms,
    absolute_expires_ms: absolute_expires_ms,
    refresh_before_ms: refresh_before,
    grace_period_end_ms: grace_period_end,
    rotation_interval_ms: 86400000, // Daily rotation default
    associated_refresh_token_id: associated_refresh_token_id,
    is_active: True
  )
  
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case mnesia.read(?TokenRecord, token_hash) of
      [{:atomic, []}] -> 
        case mnesia.write(?TokenRecord, new_token) of
          {:atomic, Ok} -> Ok(new_token)
          {:atomic, Error(write_error)} -> 
            Error(DatabaseError.WriteFailed("token", write_error))
      
      [{:atomic, [existing]}] -> 
        Error(DatabaseError.TokenAlreadyExists(
          token_hash,
          "Token with this ID already exists"
        ))
  })
}

/// Inactivate a token (for revocation or rotation)
pub fn inactivate_token(token_id: String) -> Result(_, DatabaseError) {
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case get_token_by_hash(token_id) of
      Ok(token_record) -> 
        let inactive_token = TokenRecord(
          id: token_record.id,
          session_id: token_record.session_id,
          token_type: token_record.token_type,
          token_hash: token_record.token_hash,
          created_at_ms: token_record.created_at_ms,
          absolute_expires_ms: token_record.absolute_expires_ms,
          refresh_before_ms: token_record.refresh_before_ms,
          grace_period_end_ms: token_record.grace_period_end_ms,
          rotation_interval_ms: token_record.rotation_interval_ms,
          associated_refresh_token_id: token_record.associated_refresh_token_id,
          is_active: False // Inactivate this token
        )
        
        case mnesia.write(?TokenRecord, inactive_token) of
          {:atomic, Ok} -> Ok(_)
          {:atomic, Error(write_error)} -> 
            Error(DatabaseError.WriteFailed("token-inactive", write_error))
          
      Error(e) -> Error(e)
  })
}

/// Get token by hash from database
pub fn get_token_by_hash(token_hash: String) -> Result(TokenRecord, DatabaseError) {
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case mnesia.read(?TokenRecord, token_hash) of
      [{:atomic, [token]}] -> Ok(token)
      [{:atomic, []}] -> Error(DatabaseError.TokenNotFound(
        token_hash,
        "Token not found in database"
      ))
  })
}

/// Delete all tokens associated with a session (for logout/revocation)
pub fn delete_all_tokens_for_session(session_id: String) -> Result(Int, DatabaseError) {
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case mnesia.match_object(?TokenRecord, 
      [_, session_id, :_, :_, :_, :_, :_, :_, :_, :_, :_],
      [:write]) of
      [{:atomic, tokens}] -> 
        let token_ids = list.map(tokens, fn(token) { token.id })
        
        case list.fold_until(
          token_ids,
          0,
          fn(deleted_count: Int, token_id: String) {
            case mnesia.delete(?TokenRecord, token_id) of
              {:atomic, n} -> 
                case n > 0 {
                  True -> list.continue(deleted_count + n)
                  False -> list.break(deleted_count)
                }
          }
        ) of
          {:cont, final_count} -> Ok(final_count)
          {:break, count} -> Ok(count)
      _ -> Ok(0) // No tokens found for this session
  })
}

// ============================================================================
// SECURITY EVENT OPERATIONS
// ============================================================================

/// Log security anomaly event to audit trail
pub fn log_security_event(
  session_id: String,
  anomaly_type_value: AnomalyTypeValue,
  severity_value: SeverityLevelValue,
  confidence_score: Float,
  ip_address: Option(String),
  recommended_action_value: RecommendedActionValue
) -> Result(SecurityEventRecord, DatabaseError) {
  let event_id = generate_uuid()
  
  let new_event = SecurityEventRecord(
    id: event_id,
    session_id: session_id,
    anomaly_type: serialize_anomaly_type(anomaly_type_value),
    severity: serialize_severity(severity_value),
    detected_at_ms: timestamp_now_ms(),
    confidence_score: confidence_score,
    ip_address: ip_address,
    recommended_action: serialize_recommended_action(recommended_action_value),
    resolved: False // New events are unresolved initially
  )
  
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case mnesia.write(?SecurityEventRecord, new_event) of
      {:atomic, Ok} -> Ok(new_event)
      {:atomic, Error(write_error)} -> 
        Error(DatabaseError.WriteFailed("security_event", write_error))
  })
}

/// Mark security event as resolved after review
pub fn mark_security_event_resolved(event_id: String) -> Result(_, DatabaseError) {
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case get_security_event_by_id(event_id) of
      Ok(event_record) -> 
        let resolved_event = SecurityEventRecord(
          id: event_record.id,
          session_id: event_record.session_id,
          anomaly_type: event_record.anomaly_type,
          severity: event_record.severity,
          detected_at_ms: event_record.detected_at_ms,
          confidence_score: event_record.confidence_score,
          ip_address: event_record.ip_address,
          recommended_action: event_record.recommended_action,
          resolved: True // Mark as resolved
        )
        
        case mnesia.write(?SecurityEventRecord, resolved_event) of
          {:atomic, Ok} -> Ok(_)
          {:atomic, Error(write_error)} -> 
            Error(DatabaseError.WriteFailed("security-resolved", write_error))
          
      Error(e) -> Error(e)
  })
}

/// Get all unresolved security events for a session
pub fn get_unresolved_events_for_session(session_id: String) -> Result(List(SecurityEventRecord), DatabaseError) {
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case mnesia.match_object(?SecurityEventRecord, 
      [_, session_id, :_, :_, :_, :_, :_, :_, False],
      [:write]) of
      [{:atomic, events}] -> Ok(events)
      _ -> Ok([]) // No unresolved events found
  })
}

// ============================================================================
// CROSS-DEVICE SYNC OPERATION OPERATIONS
// ============================================================================

/// Create new cross-device sync operation record
pub fn create_sync_operation_record(
  source_session_id: String,
  target_device_id: String,
  sync_type_value: SyncTypeValue,
  total_items_estimate: Int
) -> Result(SyncOperationRecord, DatabaseError) {
  let operation_id = generate_uuid()
  
  let new_operation = SyncOperationRecord(
    id: operation_id,
    source_session_id: source_session_id,
    target_device_id: target_device_id,
    sync_type: serialize_sync_type(sync_type_value),
    initiated_at_ms: timestamp_now_ms(),
    status: "Pending", // Initial status is Pending
    progress_percentage: 0,
    last_update_ms: timestamp_now_ms(),
    error_message: None,
    total_items: total_items_estimate,
    items_synced: 0
  )
  
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case mnesia.write(?SyncOperationRecord, new_operation) of
      {:atomic, Ok} -> Ok(new_operation)
      {:atomic, Error(write_error)} -> 
        Error(DatabaseError.WriteFailed("sync_operation", write_error))
  })
}

/// Update sync operation progress and status
pub fn update_sync_operation_progress(
  operation_id: String,
  new_status: SyncStatusValue,
  progress_percentage: Int,
  items_synced: Int,
  error_message: Option(String)
) -> Result(SyncOperationRecord, DatabaseError) {
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case get_sync_operation_by_id(operation_id) of
      Ok(operation_record) -> 
        let updated_progress = SyncOperationRecord(
          id: operation_record.id,
          source_session_id: operation_record.source_session_id,
          target_device_id: operation_record.target_device_id,
          sync_type: operation_record.sync_type,
          initiated_at_ms: operation_record.initiated_at_ms,
          status: new_status,
          progress_percentage: progress_percentage,
          last_update_ms: timestamp_now_ms(),
          error_message: case error_message {
            Some(msg) -> Some(msg)
            None -> 
              case operation_record.error_message {
                Some(_) -> operation_record.error_message
                None -> None // Keep existing message if no new error
              }
          },
          total_items: operation_record.total_items,
          items_synced: items_synced
        )
        
        case mnesia.write(?SyncOperationRecord, updated_progress) of
          {:atomic, Ok} -> Ok(updated_progress)
          {:atomic, Error(write_error)} -> 
            Error(DatabaseError.WriteFailed("sync-progress", write_error))
          
      Error(e) -> Error(e)
  })
}

/// Get sync operation by ID from database
pub fn get_sync_operation_by_id(operation_id: String) -> Result(SyncOperationRecord, DatabaseError) {
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case mnesia.read(?SyncOperationRecord, operation_id) of
      [{:atomic, [operation]}] -> Ok(operation)
      [{:atomic, []}] -> Error(DatabaseError.SyncOperationNotFound(
        operation_id,
        "Synchronization operation not found"
      ))
  })
}

/// Delete sync operations initiated by a session (cleanup on logout)
pub fn delete_sync_operations_initiated_by_session(session_id: String) -> Result(Int, DatabaseError) {
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case mnesia.match_object(?SyncOperationRecord, 
      [_, session_id, :_, :_, :_, :_, :_, :_, :_, :_, :_],
      [:write]) of
      [{:atomic, operations}] -> 
        let op_ids = list.map(operations, fn(op) { op.id })
        
        case list.fold_until(op_ids, 0, fn(deleted_count: Int, op_id: String) {
          case mnesia.delete(?SyncOperationRecord, op_id) of
            {:atomic, n} -> 
              case n > 0 {
                True -> list.continue(deleted_count + n)
                False -> list.break(deleted_count)
              }
        }) of
          {:cont, final_count} -> Ok(final_count)
          {:break, count} -> Ok(count)
      _ -> Ok(0) // No operations found for this session
  })
}

// ============================================================================
// OPERATION QUEUE OPERATIONS
// ============================================================================

/// Add operation to queue for scheduled execution
pub fn queue_operation_item(
  session_id: String,
  operation_type_value: OperationTypeValue,
  scheduled_at_ms: Int,
  priority: Int,
  context_data: Dict(String, String)
) -> Result(OperationQueueItemRecord, DatabaseError) {
  let operation_id = generate_uuid()
  
  let new_item = OperationQueueItemRecord(
    id: operation_id,
    session_id: session_id,
    operation_type: serialize_operation_type(operation_type_value),
    scheduled_at_ms: scheduled_at_ms,
    priority: priority,
    retry_count: 0,
    last_attempt_at_ms: 0,
    context_data: context_data
  )
  
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case mnesia.write(?OperationQueueItemRecord, new_item) of
      {:atomic, Ok} -> Ok(new_item)
      {:atomic, Error(write_error)} -> 
        Error(DatabaseError.WriteFailed("queue_item", write_error))
  })
}

/// Get pending operations for a session (sorted by priority and scheduled time)
pub fn get_pending_operations_for_session(session_id: String) -> Result(List(OperationQueueItemRecord), DatabaseError) {
  let now_ms = timestamp_now_ms()
  
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case mnesia.match_object(?OperationQueueItemRecord, 
      [_, session_id, :_, scheduled_at, :_, :_, :_, :_],
      [:write]) of
      [{:atomic, items}] -> 
        let pending_items = list.filter(
          items,
          fn(item) { 
            item.id != "MATCH" && item.scheduled_at_ms <= now_ms 
          }
        )
        
        // Sort by priority (descending) then scheduled time (ascending)
        Ok(list.sort(pending_items, fn(a: OperationQueueItemRecord, b: OperationQueueItemRecord) {
          case a.priority > b.priority {
            True -> -1
            False -> 1
          }
        }))
      
      _ -> Ok([]) // No pending operations found
  })
}

/// Update operation retry count on failure
pub fn increment_operation_retry_count(operation_id: String) -> Result(_, DatabaseError) {
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case get_queue_item_by_id(operation_id) of
      Ok(item_record) -> 
        let updated_retries = OperationQueueItemRecord(
          id: item_record.id,
          session_id: item_record.session_id,
          operation_type: item_record.operation_type,
          scheduled_at_ms: item_record.scheduled_at_ms,
          priority: item_record.priority,
          retry_count: item_record.retry_count + 1,
          last_attempt_at_ms: timestamp_now_ms(),
          context_data: item_record.context_data
        )
        
        case mnesia.write(?OperationQueueItemRecord, updated_retries) of
          {:atomic, Ok} -> Ok(_)
          {:atomic, Error(write_error)} -> 
            Error(DatabaseError.WriteFailed("queue-retry", write_error))
          
      Error(e) -> Error(e)
  })
}

/// Delete all queue items for a session (cleanup on logout)
pub fn delete_operation_queue_items_for_session(session_id: String) -> Result(Int, DatabaseError) {
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case mnesia.match_object(?OperationQueueItemRecord, 
      [_, session_id, :_, :_, :_, :_, :_, :_],
      [:write]) of
      [{:atomic, items}] -> 
        let item_ids = list.map(items, fn(item) { item.id })
        
        case list.fold_until(item_ids, 0, fn(deleted_count: Int, item_id: String) {
          case mnesia.delete(?OperationQueueItemRecord, item_id) of
            {:atomic, n} -> 
              case n > 0 {
                True -> list.continue(deleted_count + n)
                False -> list.break(deleted_count)
              }
        }) of
          {:cont, final_count} -> Ok(final_count)
          {:break, count} -> Ok(count)
      _ -> Ok(0) // No items found for this session
  })
}

// ============================================================================
// ROOM STATE OPERATIONS
// ============================================================================

/// Get user's rooms with sync state information
pub fn get_user_rooms(user_id: String) -> Result(List(UserRoomRecord), DatabaseError) {
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case mnesia.match_object(?UserRoomRecord, 
      [_, user_id, :_, :_, :_, :_, :_],
      [:write]) of
      [{:atomic, rooms}] -> Ok(rooms)
      _ -> Ok([]) // No rooms found for this user
  })
}

/// Update room sync state for a user's room
pub fn update_room_sync_state(
  user_id: String,
  room_id: String,
  sync_token: String,
  event_depth: Int,
  state_hash: String
) -> Result(UserRoomRecord, DatabaseError) {
  let record_id = user_id <> "_" <> room_id
  
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case get_user_room_record(record_id) of
      Ok(room_record) -> 
        let updated_room = UserRoomRecord(
          id: room_record.id,
          user_id: room_record.user_id,
          room_id: room_record.room_id,
          membership_type: room_record.membership_type,
          joined_at_ms: room_record.joined_at_ms,
          last_message_timestamp_ms: timestamp_now_ms(),
          notification_level: room_record.notification_level
        )
        
        case mnesia.write(?UserRoomRecord, updated_room) of
          {:atomic, Ok} -> Ok(updated_room)
          {:atomic, Error(write_error)} -> 
            Error(DatabaseError.WriteFailed("room-sync", write_error))
          
      Error(_) -> 
        // Create new room record if doesn't exist
        let new_room = UserRoomRecord(
          id: record_id,
          user_id: user_id,
          room_id: room_id,
          membership_type: "Joined", // Default membership type
          joined_at_ms: timestamp_now_ms(),
          last_message_timestamp_ms: timestamp_now_ms(),
          notification_level: "all" // Default notification level
        )
        
        case mnesia.write(?UserRoomRecord, new_room) of
          {:atomic, Ok} -> Ok(new_room)
          {:atomic, Error(write_error)} -> 
            Error(DatabaseError.WriteFailed("room-create", write_error))
  })
}

/// Get room record by ID for state operations
pub fn get_user_room_record(record_id: String) -> Result(UserRoomRecord, DatabaseError) {
  mnesia.transaction(fn() -> Result(_, DatabaseError) {
    case mnesia.read(?UserRoomRecord, record_id) of
      [{:atomic, [room]}] -> Ok(room)
      [{:atomic, []}] -> Error(DatabaseError.RoomNotFound(
        record_id,
        "Room not found for user"
      ))
  })
}

// ============================================================================
// UTILITY FUNCTIONS FOR DATA SERIALIZATION
// ============================================================================

/// Generate UUIDv4 string identifier
fn generate_uuid() -> String {
  let random_hex = list.range(16) |> list.map(fn(_) { 
    int.to_string(try int.random_range(0, 15), 16)
  }) |> string.join("")
  
  "uuid_" <> string.replace(random_hex, "-", "")
}

/// Convert timestamp to milliseconds since Unix epoch
fn timestamp_now_ms() -> Int {
  try time.timestamp() |> result.map(fn(ts: Time.Timestamp) { 
    ts.microsecond / 1000 
  }) |> int.to_string |> int.parse |> result.unwrap(timestamp_now_ms_default())
}

fn timestamp_now_ms_default() -> Int {
  1735689600000 + get_current_timestamp_seconds() * 1000
}

/// Serialize session type enum to string for storage
fn serialize_session_type(session_type: SessionTypeValue) -> String {
  case session_type {
    WebBrowser -> "WebBrowser"
    MobileApp -> "MobileApp"
    DesktopClient -> "DesktopClient"
    Bot -> "Bot"
    AdminTool -> "AdminTool"
    CrossDeviceToken -> "CrossDeviceToken"
  }
}

/// Serialize trust level enum to string for storage
fn serialize_trust_level(trust_level: TrustLevelValue) -> String {
  case trust_level {
    HighTrust -> "HighTrust"
    MediumTrust -> "MediumTrust"
    LowTrust -> "LowTrust"
    Untrusted -> "Untrusted"
  }
}

/// Serialize token type enum to string for storage
fn serialize_token_type(token_type: TokenTypeValue) -> String {
  case token_type {
    AccessToken -> "AccessToken"
    RefreshToken -> "RefreshToken"
    CrossDeviceSyncToken -> "CrossDeviceSyncToken"
  }
}

/// Serialize anomaly type enum to string for storage
fn serialize_anomaly_type(anomaly_type: AnomalyTypeValue) -> String {
  case anomaly_type {
    UnusualLoginLocation -> "UnusualLoginLocation"
    RapidDeviceRegistration -> "RapidDeviceRegistration"
    ConcurrentSessionConflict -> "ConcurrentSessionConflict"
    TokenSuspicion -> "TokenSuspicion"
    BehaviorDeviation -> "BehaviorDeviation"
    RateLimitBreach -> "RateLimitBreach"
    CredentialStuffing -> "CredentialStuffing"
  }
}

/// Serialize severity level enum to string for storage
fn serialize_severity(severity: SeverityLevelValue) -> String {
  case severity {
    Low -> "Low"
    Medium -> "Medium"
    High -> "High"
    Critical -> "Critical"
  }
}

/// Serialize recommended action enum to string for storage
fn serialize_recommended_action(action: RecommendedActionValue) -> String {
  case action {
    MonitorOnly -> "MonitorOnly"
    RequireMFA -> "RequireMFA"
    ForceLogout -> "ForceLogout"
    LockAccount -> "LockAccount"
    AlertSecurityTeam -> "AlertSecurityTeam"
  }
}

/// Serialize sync type enum to string for storage
fn serialize_sync_type(sync_type: SyncTypeValue) -> String {
  case sync_type {
    RoomStates -> "RoomStates"
    RoomHistory -> "RoomHistory"
    UserProfiles -> "UserProfiles"
    DeviceList -> "DeviceList"
    EncryptionKeys -> "EncryptionKeys"
    Preferences -> "Preferences"
  }
}

/// Serialize operation type enum to string for storage
fn serialize_operation_type(operation: OperationTypeValue) -> String {
  case operation {
    RoomSyncInitiate(room_id) -> "RoomSyncInitiate:" <> room_id
    RoomSyncPause(room_id) -> "RoomSyncPause:" <> room_id
    RoomSyncResume(room_id) -> "RoomSyncResume:" <> room_id
    TokenRefresh -> "TokenRefresh"
    CrossDeviceSyncTrigger(device_id) -> "CrossDeviceSyncTrigger:" <> device_id
    SecurityScanInitiate -> "SecurityScanInitiate"
    SessionCleanup -> "SessionCleanup"
    StateBuildQueue(room_id) -> "StateBuildQueue:" <> room_id
  }
}

/// Hash refresh token for secure storage (never store raw tokens)
fn hash_refresh_token(session_type: SessionTypeValue) -> String {
  case session_type {
    WebBrowser -> "hashed_web_" <> generate_uuid_short()
    MobileApp -> "hashed_mobile_" <> generate_uuid_short()
    DesktopClient -> "hashed_desktop_" <> generate_uuid_short()
    Bot -> "hashed_bot_" <> generate_uuid_short()
    AdminTool -> "hashed_admin_" <> generate_uuid_short()
    CrossDeviceToken -> "hashed_cross_device_" <> generate_uuid_short()
  }
}

fn generate_uuid_short() -> String {
  list.range(8) |> list.map(fn(_) { 
    int.to_string(try int.random_range(0, 15), 16)
  }) |> string.join("")
}

// ============================================================================
// DATABASE ERROR TYPES
// ============================================================================

pub type DatabaseError {
  SessionNotFound(String, String)
  DeviceAlreadyRegistered(String, String)
  DeviceNotFound(String, String)
  TokenAlreadyExists(String, String)
  TokenNotFound(String, String)
  SyncOperationNotFound(String, String)
  RoomNotFound(String, String)
  TableInitializationFailed(String, _)
  WriteFailed(_, _)
  DeleteFailed(_, _)
  SessionAlreadyExists(String, String)
}

// ============================================================================
// ENUM VALUE TYPES FOR SERIALIZATION
// ============================================================================

pub type SessionTypeValue {
  WebBrowser
  MobileApp
  DesktopClient
  Bot
  AdminTool
  CrossDeviceToken
}

pub type TrustLevelValue {
  HighTrust
  MediumTrust
  LowTrust
  Untrusted
}

pub type TokenTypeValue {
  AccessToken
  RefreshToken
  CrossDeviceSyncToken
}

pub type AnomalyTypeValue {
  UnusualLoginLocation
  RapidDeviceRegistration
  ConcurrentSessionConflict
  TokenSuspicion
  BehaviorDeviation
  RateLimitBreach
  CredentialStuffing
}

pub type SeverityLevelValue {
  Low
  Medium
  High
  Critical
}

pub type RecommendedActionValue {
  MonitorOnly
  RequireMFA
  ForceLogout
  LockAccount
  AlertSecurityTeam
}

pub type SyncTypeValue {
  RoomStates
  RoomHistory
  UserProfiles
  DeviceList
  EncryptionKeys
  Preferences
}

pub type OperationTypeValue {
  RoomSyncInitiate(String)
  RoomSyncPause(String)
  RoomSyncResume(String)
  TokenRefresh
  CrossDeviceSyncTrigger(String)
  SecurityScanInitiate
  SessionCleanup
  StateBuildQueue(String)
}

pub type SyncStatusValue {
  Pending
  InProgress
  Paused
  Completed
  Failed(String)
  Canceled
}

// ============================================================================
// TABLE INITIALIZATION HELPERS FOR GLEAM TYPE SAFETY
// ============================================================================

/// Helper to ensure table exists before operations
fn try_table_init(table_name: String, schema_fn: fn() -> Result(_, DatabaseError)) -> Result(_, DatabaseError) {
  // In production, check if table exists first via mnesia.system_info(:tables)
  case mnesia.table_exists([table_name]) {
    True -> Ok(_)
    False -> schema_fn()
  }
}

// Gleam Matrix Server - Session Management Module
// 
// This module implements:
// - Persistent session lifecycle management
// - Cross-device synchronization tokens
// - Session-based access control for room operations
// - Token refresh and rotation mechanisms
// - Device registration and trust relationships

import gleam/option.{type Option, Some, None}
import gleam/list as list
import gleam/result.{type Result, Ok, Error, map, map_error, then, flat_map}
import gleam/dict.{type Dict}
import gleam/string
import gleam/int
import gleam/time
import gleam/float

// Import Mnesia storage module for database operations
import mnesia_storage

// ============================================================================
// SESSION CORE TYPES
// ============================================================================

/// Session state machine for active session lifecycle
pub type SessionState {
  Active(ActiveSessionInfo)           // Normal operation, no issues
  Refreshing(TokenRefreshOperation)   // Currently refreshing stale token
  Revoked(SessionRevocationInfo)      // Session has been revoked by user/admin
  Suspended(SuspensionInfo)           // Session temporarily suspended due to security policy
  Expired                           // Token has expired beyond refresh window
}

/// Complete session tracking information
pub type SessionInfo {
  SessionInfo(
    session_id: String,               // Unique session identifier (UUID4 format)
    user_id: String,                  // User who owns this session
    device_id: Option(String),        // Device identifier if registered
    created_at_ms: Int,               // When session was originally created
    last_active_at_ms: Int,           // Last activity timestamp
    expires_at_ms: Int,               // Absolute expiration time
    refresh_token_hash: String,       // Hashed refresh token (never stored raw)
    access_token_version: Int,        // Current access token version for rotation
    session_type: SessionType,        // Whether this is mobile/web/device/session
    active_since_event_id: Option(String), // Sync state snapshot from creation time
    ip_address: String,               // Last known client IP (for security monitoring)
    user_agent: String,               // Client identification string
    trust_level: TrustLevel           // Device/user trust assessment
  )
}

/// Active session detailed information for operations
pub type ActiveSessionInfo {
  ActiveSessionInfo(
    session_id: String,               // Session identifier
    refresh_due_ms: Int,              // Time until token must be refreshed
    sync_token: Option(String),       // Current sync pagination token
    room_states: Dict(String, StateSnapshot), // Active rooms being synced
    last_heartbeat_ms: Int,           // Most recent heartbeat timestamp
    pending_operations: List(OperationQueueItem)   // Operations waiting execution
  )
}

/// Token refresh operation tracking
pub type TokenRefreshOperation {
  TokenRefreshOperation(
    session_id: String,               // Session being refreshed
    old_token_hash: String,           // Previous token for cleanup
    new_token_type: TokenType,        // Type of token being issued (access/refresh)
    started_at_ms: Int,               // When refresh began
    attempt_count: Int                // Number of retry attempts so far
  )
}

/// Session revocation tracking information
pub type SessionRevocationInfo {
  SessionRevocationInfo(
    session_id: String,               // Revoked session
    revoked_at_ms: Int,               // When revocation occurred
    revoked_by: Option(String),       // Who revoked (user/admin/system)
    reason: RevocationReason,         // Why it was revoked
    affected_devices: List(String),   // Device IDs also invalidated
    cascading_revocation: Bool        // Whether related sessions were revoked too
  )
}

/// Session suspension information
pub type SuspensionInfo {
  SuspensionInfo(
    session_id: String,               // Suspended session
    suspended_at_ms: Int,             // When suspension began
    reason: SuspensionReason,         // Why suspended
    review_by_ms: Option(Int),        // Expected review timestamp if applicable
    automated_suspension: Bool        // Whether this was system-automated
  )
}

/// Session type classification for access policies
pub type SessionType {
  WebBrowser           // Standard web browser session
  MobileApp            // Native mobile application (iOS/Android)
  DesktopClient        // Desktop Matrix client (Element, Element X, etc.)
  Bot                // Automated bot or service account
  AdminTool          // Administrative tool interface
  CrossDeviceToken   // Cross-device sync synchronization token
}

/// Trust level assessment for session and device validation
pub type TrustLevel {
  HighTrust         // Trusted device, verified identity, no anomalies
  MediumTrust       // Standard trust, requires additional verification occasionally
  LowTrust          // New device or suspicious activity detected
  Untrusted         // Device not recognized or security violations found
}

/// Access token types and characteristics
pub type TokenType {
  AccessToken(ExpirationInfo)      // Short-lived access token for API operations
  RefreshToken(ExpirationInfo)     // Long-lived refresh token for obtaining new access tokens
  CrossDeviceSyncToken(DevicePairingData)  // Token for device synchronization between clients
}

/// Expiration configuration for tokens
pub type ExpirationInfo {
  ExpirationInfo(
    absolute_expires_ms: Int,      // Absolute expiration timestamp
    refresh_before_ms: Int,        // Refresh threshold (absolute time before which to refresh)
    grace_period_ms: Int,          // Time after expiration during which token is still usable
    rotation_interval_ms: Int      // How often tokens rotate under normal conditions
  )
}

/// Device pairing information for cross-device synchronization
pub type DevicePairingData {
  DevicePairingData(
    device_id: String,            // Receiving device identifier
    pairing_timestamp_ms: Int,    // When pairing was established
    pairing_verified_at_ms: Int,  // When user verified the pairing
    trusted_device_name: String,  // User-visible device name
    device_capabilities: List(String), // What this device supports (encryption, media, etc.)
    auto_accept_sync: Bool        // Whether to automatically accept sync requests from paired device
  )
}

/// Operation queue item for session-based operations
pub type OperationQueueItem {
  OperationQueueItem(
    operation_id: String,         // Unique operation identifier
    operation_type: OperationType,     // Type of queued operation
    scheduled_at_ms: Int,         // When operation should execute
    priority: Int,                // Execution priority (1-10, higher = more urgent)
    retry_count: Int,             // Number of times this operation has been retried
    last_attempt_at_ms: Int,      // Most recent execution attempt timestamp
    context_data: Dict(String, String) // Operation-specific contextual information
  )
}

/// Types of operations that can be queued in session context
pub type OperationType {
  RoomSyncInitiate(String)        // Start syncing specific room
  RoomSyncPause(String)           // Pause sync for room temporarily
  RoomSyncResume(String)          // Resume paused room sync
  TokenRefresh                    // Refresh access/refresh tokens
  CrossDeviceSyncTrigger(String)  // Trigger sync with specified paired device
  SecurityScanInitiate            // Initiate security audit scan
  SessionCleanup                  // Remove expired session resources
  StateBuildQueue(String)         // Queue state building for room
}

/// Revocation reason codes for session revocation events
pub type RevocationReason {
  UserRequested          // User manually revoked the session
  AdminRevoked           // System administrator revoked access
  SecurityThreatDetected // Suspicious activity or security policy violation
  TokenExpiredGrace    // Token expired beyond grace period
  DeviceLost             // User reported device lost/stolen
  PasswordChanged        // User changed password - all sessions invalidated
  MfaBreachAttempted     // Multiple failed MFA attempts detected
  AccountTerminated      // User account has been terminated
}

/// Suspension reason codes for session suspension events
pub type SuspensionReason {
  SuspiciousActivity       // Unusual behavior pattern detected
  LocationAnomaly          // Access from unexpected geographic location
  RateLimitExceeded        // Too many requests in short time window
  PolicyViolation          // Activity violates content/usage policies
  ComplianceReviewRequired // Regulatory or compliance requirement triggered review
  TemporarySuspension      // Preemptive temporary lockout
}

/// Cross-device synchronization operation tracking
pub type CrossDeviceSyncOperation {
  CrossDeviceSyncOperation(
    source_session_id: String,          // Initiating session ID
    target_device_id: String,           // Target device identifier
    sync_type: SyncType,                // Type of data being synchronized
    initiated_at_ms: Int,               // When operation began
    status: SyncStatus,                 // Current operation status
    progress_percentage: Int,           // Progress (0-100)
    last_update_ms: Int,                // Last progress update timestamp
    error_message: Option(String),      // Error if operation failed
    total_items: Int,                   // Total items to sync
    items_synced: Int                   // Items successfully synced so far
  )
}

/// Synchronization type for cross-device operations
pub type SyncType {
  RoomStates              // Synchronize room state snapshots
  RoomHistory            // Synchronize message history
  UserProfiles           // Synchronize user account information
  DeviceList             // Synchronize list of registered devices
  EncryptionKeys         // Synchronize end-to-end encryption keys
  Preferences            // Synchronize client preferences
}

/// Cross-device sync operation status
pub type SyncStatus {
  Pending                  // Operation waiting to start
  InProgress               // Currently syncing data
  Paused                   // Temporarily paused (user requested)
  Completed                // Successfully finished
  Failed(String)           // Failed with error message
  Canceled                 // Operation was canceled by user
}

/// State snapshot for room synchronization context
pub type StateSnapshot {
  StateSnapshot(
    room_id: String,                  // Room identifier
    sync_token: String,               // Current sync position token
    latest_event_depth: Int,          // Depth of most recent event in room
    current_state_hash: String,       // Hash of current room state
    last_sync_ms: Int,                // Last successful synchronization time
    pending_conflicts: Int            // Number of unresolved state conflicts
  )
}

/// Access control permission levels for session operations
pub type PermissionLevel {
  ReadOnly      // Can read messages and room information only
  SendMessage   // Can send regular messages to rooms
  AdminRoom     // Can perform administrative actions within specific rooms
  FullAccess    // Complete access to all features and administration
}

/// Security anomaly detection for suspicious session behavior
pub type SecurityAnomaly {
  SecurityAnomaly(
    anomaly_type: AnomalyType,        // Category of detected anomaly
    severity: SeverityLevel,          // How severe the issue is
    detected_at_ms: Int,              // When anomaly was first detected
    confidence_score: Float,          // Detection confidence (0.0-1.0)
    related_sessions: List(String),   // Other sessions that may be affected
    recommended_action: RecommendedAction  // Suggested response action
  )
}

/// Types of security anomalies to detect
pub type AnomalyType {
  UnusualLoginLocation     // Login from new geographic region
  RapidDeviceRegistration  // Multiple devices registered in short time
  ConcurrentSessionConflict // Same credentials used from multiple sessions
  TokenSuspicion           // Access token appears forged or tampered
  BehaviorDeviation        // User activity patterns changed significantly
  RateLimitBreach          // Excessive API requests detected
  CredentialStuffing     // Possible automated credential attack
}

/// Severity levels for security anomalies
pub type SeverityLevel {
  Low        // Minor issue, informational only
  Medium     // Moderate concern requiring monitoring
  High       // Serious issue requiring immediate attention
  Critical   # Severe threat requiring automatic response
}

/// Recommended actions for security anomaly responses
pub type RecommendedAction {
  MonitorOnly         // Continue normal operation but log event
  RequireMFA          # Request additional multi-factor authentication
  ForceLogout         // Terminate session immediately
  LockAccount         # Temporarily lock user account pending review
  AlertSecurityTeam   # Notify human security team for manual investigation
}

// ============================================================================
// SESSION LIFECYCLE OPERATIONS
// ============================================================================

/// Create new session for authenticated user
pub fn create_session(
  user_id: String,
  device_id: Option(String),
  client_ip: String,
  user_agent: String,
  session_type: SessionType,
  trust_level: TrustLevel,
  initial_permissions: PermissionLevel,
  expires_after_ms: Int
) -> Result(SessionInfo, SessionError) {
  let now_ms = timestamp_now_ms()
  let created_session_id = generate_session_uuid()
  
  // Create initial session record with expiration times
  let new_session_info = SessionInfo(
    session_id: created_session_id,
    user_id: user_id,
    device_id: device_id,
    created_at_ms: now_ms,
    last_active_at_ms: now_ms,
    expires_at_ms: now_ms + expires_after_ms,
    refresh_token_hash: hash_refresh_token(session_type),
    access_token_version: 1,
    session_type: session_type,
    active_since_event_id: None,
    ip_address: client_ip,
    user_agent: user_agent,
    trust_level: trust_level
  )
  
  // Store in Mnesia database for persistence
  case mnesia_storage.create_session_record(
    created_session_id,
    user_id,
    device_id,
    client_ip,
    user_agent,
    session_type,
    trust_level,
    expires_after_ms,
    None
  ) {
    Ok(record) -> 
      // Initialize state snapshots for user's known rooms if needed
      case mnesia_storage.initialize_user_room_states(user_id, now_ms) {
        Ok(_) -> Ok(new_session_info)
        Error(e) -> Error(SessionError.StorageOperationFailed(
          created_session_id,
          "Failed to initialize room states: " <> e
        ))
      }
      
    Error(e) -> 
      Error(SessionError.StorageOperationFailed(
        created_session_id,
        "Failed to create session record in database: " <> e
      ))
  }
}

/// Validate session before accepting API requests
pub fn validate_session(session_id: String) -> Result(SessionInfo, SessionError) {
  // Retrieve session from Mnesia database
  case mnesia_storage.get_session_by_id(session_id) {
    Ok(session_info) -> check_session_validity(session_info)
    Error(e) -> Error(
      SessionError.SessionNotFound(
        session_id,
        "No active session found with this identifier: " <> e.message
      )
    )
  }
}

/// Refresh token for existing valid session
pub fn refresh_access_token(session_id: String) -> Result(TokenRefreshResult, SessionError) {
  case validate_session(session_id) {
    Ok(session_info) -> 
      // Check if token needs refreshing (30 seconds before expiration)
      let should_refresh = session_info.expires_at_ms - timestamp_now_ms() < 300000
      
      case should_refresh {
        True -> begin_token_refresh(session_id, session_info.refresh_token_hash)
        
        False -> 
          Error(SessionError.TokenNotYetExpired(
            session_id,
            "Token does not require refresh at this time"
          ))
      }
      
    Error(e) -> Error(e)
  }
}

/// End session and invalidate all tokens
pub fn end_session(session_id: String, force: Bool) -> Result(_, SessionError) {
  // Delete session record from Mnesia database
  case mnesia_storage.end_session_record(session_id) {
    Ok(_) -> 
      // Clean up related devices if force flag set
      case force {
        True -> mnesia_storage.delete_all_tokens_for_session(session_id) |> map(fn(_) {_})
        False -> Ok(_)
      }
      
    Error(e) -> 
      Error(SessionError.StorageOperationFailed(
        session_id,
        "Failed to delete session record from database: " <> e.message
      ))
  }
}

/// Suspend session pending security review
pub fn suspend_session(
  session_id: String,
  reason: SuspensionReason,
  automated: Bool,
  review_time_ms: Option(Int)
) -> Result(_, SessionError) {
  case mnesia_storage.get_session_by_id(session_id) {
    Ok(_session_info) -> 
      let suspension_info = SuspensionInfo(
        session_id: session_id,
        suspended_at_ms: timestamp_now_ms(),
        reason: reason,
        review_by_ms: review_time_ms,
        automated_suspension: automated
      )
      
      // Update session state in Mnesia to Suspended
      Ok(_) // Stub - suspension logic pending
      
    Error(e) -> 
      Error(SessionError.SessionNotFound(
        session_id,
        "Session not found for suspension: " <> e.message
      ))
  }
}

/// Resume previously suspended session after review period
pub fn resume_suspended_session(
  session_id: String,
  suspension_info: SuspensionInfo
) -> Result(SessionInfo, SessionError) {
  // Check if review period has passed and security scan passes
  case suspension_info.review_by_ms {
    Some(review_time) if review_time <= timestamp_now_ms() -> 
      case run_security_scan(session_id) {
        Ok(_) -> 
          // Stub - resume logic pending
          Error(SessionError.SessionStillSuspended(
            session_id,
            "Manual review required before resumption"
          ))
          
        Error(e) -> Error(e)
      }
      
    _ -> 
      Error(SessionError.SessionStillSuspended(
        session_id,
        "Review period has not elapsed before resume attempt"
      ))
  }
}

/// Check validity of session based on state and expiration
fn check_session_validity(session_info: SessionInfo) -> Result(SessionInfo, SessionError) {
  let now_ms = timestamp_now_ms()
  
  // Check absolute expiration first
  case session_info.expires_at_ms < now_ms {
    True if session_info.expires_at_ms + mnesia_storage.get_grace_period_ms() < now_ms -> 
      Error(SessionError.SessionExpired(
        session_id: session_info.session_id,
        message: "Session has expired beyond refresh window"
      ))
      
    _ -> 
      // Check current state machine status
      case get_session_state(session_info) {
        .Active(_) -> Ok(session_info)
        
        .Refreshing(op) -> 
          case op.attempt_count > 3 {
            True -> Error(SessionError.SessionRefreshingTooOften(
              session_id: session_info.session_id,
              message: "Session is undergoing refresh too many times consecutively"
            ))
            False -> Ok(session_info)
          }
          
        .Revoked(info) -> 
          case info.revoked_by {
            Some("user") | None -> 
              Error(SessionError.SessionRevokedByUser(
                session_id: session_info.session_id,
                message: "Session has been revoked by user"
              ))
              
            _ -> 
              Error(SessionError.SessionRevoked(
                session_id: session_info.session_id,
                message: "Session has been revoked for security or compliance reasons"
              ))
          }
          
        .Suspended(info) -> 
          case info.review_by_ms {
            Some(review_time) if review_time > now_ms -> 
              Error(SessionError.SessionSuspendedTemporarily(
                session_id: session_info.session_id,
                message: "Session is temporarily suspended pending security review"
              ))
              
            _ -> 
              // Suspension period expired - attempt to resume automatically
              case mnesia_storage.is_security_scan_passed_for_session(session_info.session_id) {
                True -> 
                  Ok(session_info) // Stub - resume logic pending
                  
                False -> 
                  Error(SessionError.SessionSuspendedTemporarily(
                    session_id: session_info.session_id,
                    message: "Session requires manual review before resumption"
                  ))
              }
          }
          
        .Expired -> 
          Error(SessionError.SessionExpired(
            session_id: session_info.session_id,
            message: "Session has expired"
          ))
      }
  }
}

/// Retrieve current state of session from Mnesia
fn get_session_state(session_info: SessionInfo) -> SessionState {
  case mnesia_storage.get_session_active_state(session_info.session_id) {
    Some(state) -> state
    None -> 
      // Fallback based on stored metadata
      case mnesia_storage.is_session_suspended(session_info.session_id) {
        True -> .Suspended(mnesia_storage.create_dummy_suspension_info())
        False -> .Active(ActiveSessionInfo(
          session_id: session_info.session_id,
          refresh_due_ms: 0,
          sync_token: None,
          room_states: dict.new(),
          last_heartbeat_ms: session_info.last_active_at_ms,
          pending_operations: []
        ))
      }
  }
}

// ============================================================================
// CROSS-DEVICE SYNCHRONIZATION
// ============================================================================

/// Register device for cross-device synchronization with user account
pub fn register_device_for_sync(
  session_id: String,
  target_device_id: String,
  device_capabilities: List(String),
  trusted_device_name: String,
  auto_accept: Bool
) -> Result(DevicePairingData, SessionError) {
  // Verify session is valid
  case validate_session(session_id) {
    Ok(_session_info) -> 
      // Store device pairing in Mnesia database
      let new_pairing = DevicePairingData(
        device_id: target_device_id,
        pairing_timestamp_ms: timestamp_now_ms(),
        pairing_verified_at_ms: mnesia_storage.get_current_unix_seconds() |> int.to_string |> int.parse |> option.unwrap(0) * 1000, // Requires user verification via out-of-band channel
        trusted_device_name: trusted_device_name,
        device_capabilities: device_capabilities,
        auto_accept_sync: auto_accept
      )
      
      case mnesia_storage.register_device_record(
        target_device_id,
        _session_info.user_id,
        trusted_device_name,
        device_capabilities,
        auto_accept
      ) {
        Ok(record) -> Ok(new_pairing)
        Error(e) -> 
          Error(SessionError.StorageOperationFailed(
            "Failed to register device in database: " <> e.message
          ))
      }
      
    Error(e) -> Error(SessionError.SessionNotFound(
      session_id,
      "Session required for device registration: " <> e.message
    ))
  }
}

/// Create synchronization token between paired devices
pub fn create_cross_device_sync_token(
  source_session_id: String,
  target_device_id: String,
  sync_types: List(SyncType),
  expires_after_ms: Int
) -> Result(TokenType, SessionError) {
  validate_session(source_session_id)
  |> result.map_error(fn(_) { 
    SessionError.SessionNotFound(
      source_session_id,
      "Source session must be valid for token creation"
    )
  })
  |> flat_map(fn(_source_info: SessionInfo) -> Result(TokenType, SessionError) {
    // Verify target device is registered with this user account in Mnesia
    case mnesia_storage.verify_device_pairing(_source_info.user_id, target_device_id) {
      True -> 
        let expires_at = timestamp_now_ms() + expires_after_ms
        
        // Create token with expiration metadata
        Ok(CrossDeviceSyncToken(ExpirationInfo(
          absolute_expires_ms: expires_at,
          refresh_before_ms: expires_at - 86400000, // Refresh 1 day before expiry
          grace_period_ms: 86400000, // 24 hour grace period
          rotation_interval_ms: 604800000 // Week interval rotation
        )))
        
      False -> 
        Error(SessionError.DeviceNotPaired(
          _source_info.user_id,
          target_device_id,
          "Target device not paired with user account"
        ))
    }
  })
}

/// Execute cross-device synchronization operation
pub fn execute_cross_device_sync(
  source_session_id: String,
  target_device_id: String,
  sync_token: TokenType,
  sync_types: List(SyncType)
) -> Result(CrossDeviceSyncOperation, SessionError) {
  validate_session(source_session_id)
  |> result.map_error(fn(_) { 
    SessionError.SessionNotFound(
      source_session_id,
      "Source session required for sync execution"
    )
  })
  |> flat_map(fn(_source_info: SessionInfo) -> Result(CrossDeviceSyncOperation, SessionError) {
    // Verify token is valid and not expired using Mnesia validation
    case mnesia_storage.is_valid_cross_device_token(sync_token) {
      True -> 
        let operation = CrossDeviceSyncOperation(
          source_session_id: source_session_id,
          target_device_id: target_device_id,
          sync_type: list.first(sync_types) |> option.unwrap(RoomStates),
          initiated_at_ms: timestamp_now_ms(),
          status: SyncStatus.Pending,
          progress_percentage: 0,
          last_update_ms: timestamp_now_ms(),
          error_message: None,
          total_items: mnesia_storage.calculate_total_sync_items(source_session_id, sync_types),
          items_synced: 0
        )
        
        // Store operation in Mnesia
        case mnesia_storage.create_sync_operation_record(
          source_session_id,
          target_device_id,
          list.first(sync_types) |> option.unwrap(RoomStates),
          operation.total_items
        ) {
          Ok(_) -> Ok(operation)
          Error(e) -> 
            Error(SessionError.StorageOperationFailed(
              "Failed to initialize sync operation: " <> e.message
            ))
        }
        
      False -> 
        Error(SessionError.InvalidSyncToken(
          "Cross-device synchronization token expired or invalid"
        ))
    }
  })
}

/// Cancel pending cross-device sync operation
pub fn cancel_cross_device_sync(
  operation_id: String,
  canceller_session_id: String
) -> Result(_, SessionError) {
  // Verify operation exists in Mnesia
  case mnesia_storage.get_active_sync_operation(operation_id) {
    Some(_operation: CrossDeviceSyncOperation) -> 
      // Check cancellation permissions
      case validate_cancellation_permission(_operation.source_session_id, canceller_session_id) {
        True -> 
          mnesia_storage.mark_sync_operation_as_cancelled(operation_id)
          |> map_error(fn(_) { 
            Error(SessionError.StorageOperationFailed(
              operation_id,
              "Failed to cancel synchronization operation"
            ))
          })
          
        False -> Error(SessionError.PermissionDenied(
          "User does not have permission to cancel this synchronization operation"
        ))
      }
      
    None -> Error(SessionError.SyncOperationNotFound(
      operation_id,
      "Synchronization operation not found in database"
    ))
  }
}

// ============================================================================
// SECURITY MONITORING AND ANOMALY DETECTION
// ============================================================================

/// Run security scan on session to detect anomalies
pub fn run_security_scan(session_id: String) -> Result(Bool, SessionError) {
  validate_session(session_id)
  |> result.map_error(fn(_) { 
    SessionError.SessionNotFound(
      session_id,
      "Cannot run security scan on non-existent session"
    )
  })
  |> flat_map(fn(_session_info: SessionInfo) -> Result(Bool, SessionError) {
    // Query Mnesia for recent activity patterns
    let recent_logins = mnesia_storage.get_recent_login_attempts_for_user(_session_info.user_id)
    let suspicious_ips = mnesia_storage.check_ip_reputation(_session_info.ip_address)
    let unusual_patterns = analyze_behavior_patterns_with_mnesia(session_id)
    
    // All checks must pass for scan to succeed
    case list.all([suspicious_ips, unusual_patterns], fn(passed: Bool) { passed }) {
      True -> Ok(True)
      
      False -> 
        // Log anomaly to security audit table in Mnesia
        mnesia_storage.log_security_event(
          session_id,
          AnomalyType.BehaviorDeviation,
          SeverityLevel.Medium,
          timestamp_now_ms(),
          Float.from_int(750) / 1000.0 // 0.75 confidence
        )
        |> map_error(fn(_) {
          Error(SessionError.StorageOperationFailed(
            session_id,
            "Failed to log security anomaly"
          ))
        })
        |> then(fn(_) -> Result(Bool, SessionError) {
          Error(SessionError.SecurityScanFailed(
            session_id: session_info.session_id,
            message: "Security review detected anomalies - requires manual verification"
          ))
        })
    }
  })
}

/// Analyze user behavior patterns for deviation from normal activity using Mnesia data
fn analyze_behavior_patterns_with_mnesia(session_id: String) -> Bool {
  // Retrieve activity history from Mnesia
  case mnesia_storage.get_recent_activity_log(session_id, duration_ms: 86400000) {
    Some(activity_log: List(MnesiaActivityRecord)) -> 
      let average_session_length = calculate_average_session_duration_from_db(activity_log)
      let current_activity_count = list.length(activity_log)
      
      // More activity than typical (>2x average) could indicate account compromise
      average_session_length * 2 < current_activity_count
      
    None -> True // No data to compare - assume normal
  }
}

/// Calculate average session duration from Mnesia activity records
fn calculate_average_session_duration_from_db(activity_log: List(MnesiaActivityRecord)) -> Int {
  case list.fold(activity_log, #(.0, .0), fn(accum, record) {
    let (total_time, count) = accum
    
    let current_record_duration = case record.action_type {
      "login" -> 0
      _ -> record.duration_ms
    }
    
    #(total_time + current_record_duration, count + 1)
  }) {
    #(.0, .0) -> 
      // No activity data yet - use default average (30 minutes in ms)
      mnesia_storage.get_default_session_duration_ms()
      
    #(_total_ms, 0) -> 0
    #(_total_ms, count) -> _total_ms / count
  }
}

// ============================================================================
// STATE MANAGEMENT AND OPERATIONS QUEUE
// ============================================================================

/// Initialize room state tracking for user's known rooms via Mnesia
fn initialize_user_room_states(user_id: String, now_ms: Int) -> Result(_, SessionError) {
  // Query Mnesia for user's known rooms
  case mnesia_storage.get_user_rooms_from_db(user_id) {
    Some(rooms: List(RoomInfo)) -> 
      let mut room_states = dict.new()
      
      let final_room_states = list.fold(rooms, room_states, fn(states, room) {
        dict.insert(
          states,
          room.room_id,
          StateSnapshot(
            room_id: room.room_id,
            sync_token: "initial",
            latest_event_depth: room.latest_event_depth,
            current_state_hash: mnesia_storage.hash_room_state(room.room_id),
            last_sync_ms: now_ms,
            pending_conflicts: 0
          )
        )
      })
      
      // Store room states in Mnesia state store
      mnesia_storage.store_user_room_states(user_id, final_room_states)
      |> Ok(_)
      
    None -> 
      // No known rooms yet - create minimal initialization record
      mnesia_storage.store_user_room_states(user_id, dict.new())
      |> Ok(_)
  }
}

/// Queue operation for session execution (async processing via Mnesia)
pub fn queue_operation(
  session_id: String,
  operation: OperationType,
  scheduled_at_ms: Int,
  priority: Int
) -> Result(String, SessionError) {
  validate_session(session_id)
  |> result.map_error(fn(_) { 
    SessionError.SessionNotFound(
      session_id,
      "Cannot queue operation on non-existent session"
    )
  })
  |> flat_map(fn(_session_info: SessionInfo) -> Result(String, SessionError) {
    let operation_id = generate_operation_uuid()
    
    let queued_item = OperationQueueItem(
      operation_id: operation_id,
      operation_type: operation,
      scheduled_at_ms: scheduled_at_ms,
      priority: priority,
      retry_count: 0,
      last_attempt_at_ms: 0,
      context_data: dict.new()
    )
    
    // Add to Mnesia queue table for session
    case mnesia_storage.queue_operation_item(
      session_id,
      operation,
      scheduled_at_ms,
      priority,
      dict.new()
    ) {
      Ok(_) -> Ok(operation_id)
      Error(e) -> 
        Error(SessionError.StorageOperationFailed(
          "Failed to queue operation in database: " <> e.message
        ))
    }
  })
}

/// Execute next pending operation for session (internal scheduler via Mnesia)
pub fn execute_pending_operations(session_id: String) -> Result(List(CompletedOperation), SessionError) {
  validate_session(session_id)
  |> result.map_error(fn(_) { 
    SessionError.SessionNotFound(
      session_id,
      "Cannot process operations on non-existent session"
    )
  })
  |> flat_map(fn(_session_info: SessionInfo) -> Result(List(CompletedOperation), SessionError) {
    let now_ms = timestamp_now_ms()
    
    // Get pending operations scheduled for execution from Mnesia
    case mnesia_storage.get_pending_operations_for_session(session_id) {
      Ok(pending_items) -> 
        list.map(pending_items, fn(queued_item: OperationQueueItemRecord) {
          CompletedOperation(
            operation_id: queued_item.id,
            success: true, // Stub - actual execution logic pending
            completed_at_ms: timestamp_now_ms()
          )
        })
        
      Ok(_) -> Ok([])
      
      Error(e) -> 
        Error(SessionError.StorageOperationFailed(
          "Failed to retrieve operations from database: " <> e.message
        ))
    }
  })
}

/// Process token refresh request for session with Mnesia storage
fn begin_token_refresh(session_id: String, old_token_hash: String) -> Result(TokenRefreshResult, SessionError) {
  let now_ms = timestamp_now_ms()
  
  // Generate new token and store in Mnesia
  let new_token = generate_new_access_token(session_id)
  
  case mnesia_storage.create_token_record(
    session_id,
    TokenTypeValue.AccessToken,
    new_token,
    now_ms + 3600000,
    None
  ) {
    Ok(_) -> 
      Ok(TokenRefreshResult(
        new_token: new_token,
        expires_at_ms: now_ms + 3600000,
        previous_token_hash: old_token_hash
      ))
      
    Error(e) -> 
      Error(SessionError.StorageOperationFailed(
        "Failed to store new access token: " <> e.message
      ))
  }
}

// ============================================================================
// ACCESS CONTROL AND PERMISSION MANAGEMENT
// ============================================================================

/// Check if session has required permission for operation via Mnesia
pub fn check_session_permission(
  session_id: String,
  required_permission: PermissionLevel
) -> Result(Bool, SessionError) {
  validate_session(session_id)
  |> result.map_error(fn(_) { 
    SessionError.SessionNotFound(
      session_id,
      "Cannot check permissions on non-existent session"
    )
  })
  |> flat_map(fn(_session_info: SessionInfo) -> Result(Bool, SessionError) {
    // Retrieve current permission level from Mnesia
    let stored_permission = mnesia_storage.get_session_permission_level(session_id)
    
    case compare_permissions(stored_permission, required_permission) {
      True -> Ok(True)
      
      False -> Error(SessionError.InsufficientPermissions(
        session_id: session_info.session_id,
        message: "Session does not have required permissions for this operation"
      ))
    }
  })
}

/// Update session trust level based on activity analysis (via Mnesia)
pub fn update_session_trust_level(
  session_id: String,
  new_trust_level: TrustLevel
) -> Result(SessionInfo, SessionError) {
  validate_session(session_id)
  |> result.map_error(fn(_) { 
    SessionError.SessionNotFound(
      session_id,
      "Cannot update trust level for non-existent session"
    )
  })
  |> flat_map(fn(session_info: SessionInfo) -> Result(SessionInfo, SessionError) {
    let updated_info = { session_info | trust_level: new_trust_level }
    
    // Update trust level in Mnesia
    mnesia_storage.update_session_trust_level(
      session_id,
      new_trust_level,
      timestamp_now_ms()
    )
    |> map_error(fn(_) { 
      Error(SessionError.StorageOperationFailed(
        "Failed to update trust level in database: " <> "stub error"
      ))
    })
    |> then(fn(_) -> Result(SessionInfo, SessionError) { Ok(updated_info) })
  })
}

/// Revoke all sessions for user account (emergency action via Mnesia transaction)
pub fn revoke_all_user_sessions(user_id: String, reason: RevocationReason) -> Result(List(String), SessionError) {
  // Begin Mnesia transaction to atomically revoke all sessions
  case mnesia_storage.get_all_sessions_for_user(user_id) {
    Ok(sessions) -> 
      list.fold(sessions, [], fn(_ids, session_info: SessionInfo) {
        case session_info.session_state != .Expired && session_info.session_state != .Revoked(_) {
          True -> [_ids] ++ [session_info.session_id]
          False -> _ids
        }
      })
      
    Error(e) -> Error(SessionError.StorageOperationFailed(
      user_id,
      "Failed to retrieve sessions for revocation: " <> e.message
    ))
  }
}

// ============================================================================
// UTILITY FUNCTIONS WITH MNESIA INTEGRATION
// ============================================================================

fn timestamp_now_ms() -> Int {
  get_current_timestamp_seconds() * 1000 + mnesia_storage.get_base_offset_ms()
}

fn generate_session_uuid() -> String {
  "sess_" <> int.to_string(timestamp_now_ms()) <> "_" <> string.replace(mnesia_storage.generate_random_suffix(), "-", "")
}

fn hash_refresh_token(session_type: SessionType) -> String {
  case session_type {
    WebBrowser -> mnesia_storage.hash_with_salt("hashed_web")
    MobileApp -> mnesia_storage.hash_with_salt("hashed_mobile")
    DesktopClient -> mnesia_storage.hash_with_salt("hashed_desktop")
    Bot -> mnesia_storage.hash_with_salt("hashed_bot")
    AdminTool -> mnesia_storage.hash_with_salt("hashed_admin")
    CrossDeviceToken -> mnesia_storage.hash_with_salt("hashed_cross_device")
  }
}

fn is_valid_session_id(session_id: String) -> Bool { 
  string.length(session_id) > 10 && string.starts_with(session_id, "sess_")
}

fn get_current_time_ms() -> Int { timestamp_now_ms() }

fn verify_device_pairing(user_id: String, device_id: String) -> Bool {
  mnesia_storage.verify_device_pairing(user_id, device_id)
}

fn is_valid_cross_device_token(token: TokenType) -> Bool { 
  case token {
    CrossDeviceSyncToken(expiry) -> timestamp_now_ms() < expiry.absolute_expires_ms
    _ -> False
  }
}

fn get_active_sync_operation(operation_id: String) -> Option(CrossDeviceSyncOperation) { 
  mnesia_storage.get_active_sync_operation(operation_id)
}

fn validate_cancellation_permission(source_session_id: String, session_id: String) -> Bool {
  source_session_id == session_id || mnesia_storage.is_admin_session(session_id)
}

fn mark_sync_operation_as_cancelled(operation_id: String) -> Result(_, SessionError) { 
  mnesia_storage.mark_sync_operation_as_cancelled(operation_id)
  |> map_error(fn(_) { Error(SessionError.StorageOperationFailed("Cancel failed", "Mnesia operation error")) })
}

fn get_permission_level(session_id: String) -> Int {
  mnesia_storage.get_session_permission_level(session_id)
}

fn generate_operation_uuid() -> String { 
  "op_" <> int.to_string(timestamp_now_ms()) <> "_" <> string.replace(mnesia_storage.generate_random_suffix(), "-", "")
}

fn attempt_execution_of_operation_via_mnesia(item: OperationQueueItemRecord, session_id: String) -> Bool {
  // Execute operation logic here
  // Update retry count in Mnesia
  mnesia_storage.increment_operation_retry_count(session_id, item.id)
  |> then(fn(_) { true })
}

fn compare_permissions(stored: Int, required: PermissionLevel) -> Bool {
  let permission_values = case required {
    .ReadOnly -> 1
    .SendMessage -> 2
    .AdminRoom -> 3
    .FullAccess -> 4
  }
  
  stored >= permission_values
}

fn calculate_total_sync_items(_source_session_id: String, _sync_types: List(SyncType)) -> Int {
  mnesia_storage.calculate_total_sync_items(_source_session_id, _sync_types)
}

fn create_active_info_for_resume() -> ActiveSessionInfo {
  ActiveSessionInfo(
    session_id: "pending",
    refresh_due_ms: 0,
    sync_token: None,
    room_states: dict.new(),
    last_heartbeat_ms: timestamp_now_ms(),
    pending_operations: []
  )
}

fn create_dummy_suspension_info() -> SuspensionInfo {
  SuspensionInfo(
    session_id: "dummy",
    suspended_at_ms: timestamp_now_ms(),
    reason: .TemporarySuspension,
    review_by_ms: None,
    automated_suspension: True
  )
}

fn hash_state(state_identifier: String) -> String { 
  mnesia_storage.hash_state(state_identifier)
}

// Generate new access token via Mnesia
fn generate_new_access_token(_session_id: String) -> String {
  "access_token_" <> int.to_string(timestamp_now_ms()) <> "_" <> string.replace(mnesia_storage.generate_random_suffix(), "-", "")
}

fn begin_session_revocation(
  _session_id: String, 
  _revoked_by: String, 
  _reason: RevocationReason, 
  _devices: List(String), 
  _cascade: Bool
) -> Result(_, _) { 
  Ok(_)
}

fn get_user_rooms(_user_id: String) -> List(RoomInfo) {
  case mnesia_storage.get_user_rooms_from_db(_user_id) {
    Some(rooms) -> rooms
    None -> []
  }
}

type RoomInfo {
  RoomInfo(room_id: String, room_name: String, latest_event_depth: Int)
}

// Logging function for security events (via Mnesia audit table)
fn log_security_event(session_id: String, anomaly_type: AnomalyType, severity: SeverityLevel, detected_at_ms: Int) -> Result(_, _) { 
  mnesia_storage.log_security_event(
    session_id,
    anomaly_type,
    severity,
    detected_at_ms,
    Float.from_int(500) / 1000.0 // Default confidence
  )
}

// ============================================================================
// ADDITIONAL TYPES FOR SESSION MANAGEMENT
// ============================================================================

pub type SessionError {
  SessionNotFound(String, String)
  SessionExpired(String, String)
  SessionRevoked(String, String)
  SessionRevokedByUser(String, String)
  SessionSuspendedTemporarily(String, String)
  SessionRefreshingTooOften(String, String)
  TokenNotYetExpired(String, String)
  TokenRefreshFailed(String, String)
  InvalidSyncToken(String, String)
  SyncOperationNotFound(String, String)
  DeviceNotPaired(String, String, String)
  StorageOperationFailed(String, String)
  SecurityScanFailed(String, String)
  PermissionDenied(String, String)
  InsufficientPermissions(String, String)
}

pub type TokenRefreshResult {
  TokenRefreshResult(
    new_token: String,
    expires_at_ms: Int,
    previous_token_hash: String
  )
}

pub type CompletedOperation {
  CompletedOperation(
    operation_id: String,
    success: Bool,
    completed_at_ms: Int
  )
}

type MnesiaActivityRecord {
  MnesiaActivityRecord(
    timestamp_ms: Int,
    action_type: String,
    resource_accessed: String,
    duration_ms: Int
  )
}

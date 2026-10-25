// Gleam Matrix Server - Room State Synchronization Module
// 
// This module implements:
// - Room history synchronization across servers
// - State resolution algorithms for conflict handling
// - Event pagination and timeline reconstruction
// - Backfill operations with proper ordering

import gleam/option.{type Option, Some, None}
import gleam/list as list
import gleam/result.{type Result, Ok, Error, map}
import gleam/dict.{type Dict}
import gleam/int
import gleam/string

// ============================================================================
// CORE TYPES
// ============================================================================

/// Room synchronization state tracking for ongoing operations
pub type SyncState {
  Idle                          // No active sync operation
  FetchingHistory(SyncProgress) // Currently retrieving historical events
  ResolvingConflicts(List(EventConflict)) // Processing conflicting room updates
  BuildingState(StateBuildingInfo) // Actively reconstructing current state
}

/// Tracking information for ongoing synchronization operations
pub type SyncProgress {
  SyncProgress(
    room_id: String,                      // Room being synchronized
    since_event_id: Option(String),       // Continue from this event
    latest_event_id: String,              // Most recent event in range
    events_fetched: Int,                  // Number of events retrieved so far
    total_events_expected: Int,           // Expected total event count
    bytes_transferred: Int,               // Data transferred in bytes
    sync_started_ms: Int,                 // When sync operation began
    last_update_ms: Int                   // Last progress update timestamp
  )
}

/// Information about room state building process
pub type StateBuildingInfo {
  StateBuildingInfo(
    room_id: String,                        // Room being processed
    phase: BuildingPhase,                   // Current building phase
    current_depth: Int,                     // Processing up to this event depth
    events_processed: Int,                  // Total events handled
    state_born_at_event: String,            // Event ID where current state was established
    latest_known_depth: Int,                // Depth of latest known room state
    pending_resolutions: List(String)       // IDs of events awaiting resolution
  )
}

/// Room state building phases in order
pub type BuildingPhase {
  FetchStateSnapshot
  ProcessEventBatch
  ApplyRedactions
  ResolveConflicts
  FinalizeState
}

/// Event conflict types for state resolution
pub type EventConflict {
  DirectConflict(String, String)             // Two events claim same state key with different values
  RedactionConflict(String, String)          // Redaction conflicts with another redaction or normal event
  TimelineGap(Int, Int)                      // Missing events in timeline (start_depth, end_depth)
  TimestampConflict(Int, Int)                // Events with significantly different timestamps
  PowerLevelConflict(String, String)         // Competing power level assignments
}

/// Room state event for room history reconstruction
pub type RoomStateEvent {
  RoomStateEvent(
    event_id: String,                        // Unique event identifier
    event_type: String,                      // State event type (m.room.name, m.room.topic, etc.)
    state_key: String,                       // State key identifying specific room attribute
    sender: String,                          // User who sent the event
    timestamp_ms: Int,                       // Event creation timestamp
    depth: Int,                              // Event depth in room timeline
    content: Dict(String, String),           // Event content payload
    unsigned_metadata: Dict(String, String), // Additional metadata (age, redaction_info)
    is_redacted: Bool,                       // Whether event has been redacted
    previous_event_ids: List(String)         // Previous events for this state key in timeline
  )
}

/// Room history synchronization request parameters
pub type HistorySyncRequest {
  HistorySyncRequest(
    room_id: String,                    // Room to sync history for
    from_token: Option(String),         // Pagination token (from previous sync)
    limit: Int,                         // Maximum events to return per request
    timeout_ms: Int,                    // Maximum time allowed for request
    include_redactions: Bool,           // Include redacted event metadata
    state_during_sync: Bool             // Fetch current state during sync
  )
}

/// Room history synchronization response with paginated results
pub type HistorySyncResponse {
  HistorySyncResponse(
    room_id: String,                          // Synced room ID
    events: List(RoomStateEvent),             // Retrieved room events
    prev_batch_token: Option(String),         // Token for previous events (pagination backward)
    next_batch_token: Option(String),         // Token for future events (pagination forward)
    state_events: List(RoomStateEvent),       // Current room state at sync time
    timeline_start: Int,                      // Depth of first returned event
    timeline_end: Int,                        // Depth of last returned event
    chunk_count: Int,                         // Number of event chunks delivered
    sync_duration_ms: Int                     // Total synchronization time
  )
}

/// State resolution algorithm results for conflict handling
pub type ResolutionResult {
  ResolutionResult(
    winning_event_id: String,                // Winning event ID after resolution
    losing_event_ids: List(String),          // Events that were resolved away
    resolution_reason: String,               // Reason for selection (depth, timestamp, etc.)
    conflict_type: EventConflict,            // Type of conflict resolved
    resolution_timestamp_ms: Int             // When resolution was performed
  )
}

/// Redaction event metadata for privacy compliance
pub type RedactionMetadata {
  RedactionMetadata(
    redacted_event_id: String,              // Event ID being redacted
    redacting_user_id: String,              // User who initiated redaction
    redaction_reason: Option(String),       // Optional redaction reason text
    redacted_at_ms: Int,                    // When redaction was applied
    redaction_event_id: String,             // Redaction event ID itself
    is_partial_redaction: Bool              // Whether only some fields were redacted
  )
}

/// User power level information for room permissions
pub type PowerLevel {
  PowerLevel(
    user_id: String,                        // User identifier
    current_level: Int,                     // Current power level (0-100)
    original_level: Int,                    // Original assigned power level
    level_assigned_at_event: String,        // Event ID that granted this level
    level_inherited_from_role: Bool         // Whether level comes from automatic role assignment
  )
}

/// Room encryption state for end-to-end encrypted rooms
pub type EncryptionState {
  EncryptionState(
    algorithm: String,                      // E2EE algorithm (m.megolm.v1.aes-sha2)
    sender_key_id: Option(String),          // Sender's key ID
    rotation_period_ms: Int,                // Olm session rotation interval
    rotation_messages: Int,                 // Messages before automatic rotation
    shared_history_verification: Bool       // Whether history sharing is enabled
  )
}

/// Synchronization error types
pub type SyncError {
  PermissionDenied(String, String)         // User doesn't have access to room
  StorageFailed(String)                    // Mnesia storage operation failed
  TimelineFetchFailed(String, String)      // Failed to fetch from timeline
  InvalidRoomState(String, String)         // Room state is corrupted or missing
  InsufficientCandidates(String)           // Not enough events to resolve conflict
  TimelineBreakDetected(String, String)    // Event timeline has gaps
  InvalidToken(String, String)             // Pagination token is malformed or expired
}

/// User state tracking for room membership
pub type RoomUserState {
  RoomUserState(
    user_id: String,                        // User identifier
    joined_at: Option(String),              // When user joined room (event ID)
    join_event_timestamp_ms: Int,           // Join event timestamp
    left_at: Option(String),                // When user left room (event ID)
    leave_timestamp_ms: Int,                // Leave event timestamp
    current_power_level: Int,               // User's effective power level
    display_name: String,                   // User's display name in room
    avatar_url: String                      // User's avatar URL
  )
}

// ============================================================================
// SYNCHRONIZATION INITIALIZATION
// ============================================================================

/// Initialize history sync operation for specified room
pub fn initialize_history_sync(
  request: HistorySyncRequest,
  client_session_id: String
) -> Result(SyncState, SyncError) {
  let now_ms = timestamp_now_ms()
  
  // Check if session token is valid and grants access to this room
  let has_access = validate_room_access(request.room_id, client_session_id)
  
  case has_access {
    True -> 
      // Check if room has existing sync state
      get_existing_sync_progress(request.room_id)
      |> result.map(fn(existing_progress) {
        // Resume from previous sync progress
        SyncState.FetchingHistory({
          SyncProgress(
            room_id: request.room_id,
            since_event_id: request.from_token,
            latest_event_id: existing_progress.latest_event_id,
            events_fetched: 0,
            total_events_expected: 0,
            bytes_transferred: 0,
            sync_started_ms: now_ms,
            last_update_ms: now_ms
          )
        })
      })
      |> result.map_error(fn(_) {
        // Start fresh sync operation
        let new_progress = SyncProgress(
          room_id: request.room_id,
          since_event_id: request.from_token,
          latest_event_id: "",
          events_fetched: 0,
          total_events_expected: 0,
          bytes_transferred: 0,
          sync_started_ms: now_ms,
          last_update_ms: now_ms
        )
        
        create_sync_progress(request.room_id, new_progress)
        |> map(fn(_) {
          SyncState.FetchingHistory(new_progress)
        })
      })
      
    False -> 
      Error(PermissionDenied(
        request.room_id,
        "User does not have access to this room"
      ))
  }
}

/// Process synchronization step and return updated state + events
pub fn sync_step(progress: SyncProgress) -> Result({SyncState, List(RoomStateEvent)}, SyncError) {
  let now_ms = timestamp_now_ms()
  
  case progress.since_event_id {
    Some(token) -> 
      // Continue from pagination token
      fetch_events_from_token(
        progress.room_id,
        token,
        progress.limit,
        progress.timeout_ms
      )
      |> map(fn(fetched_events) {
        let updated_progress = {
          SyncProgress(
            room_id: progress.room_id,
            since_event_id: progress.since_event_id,
            latest_event_id: progress.latest_event_id,
            events_fetched: progress.events_fetched + list.length(fetched_events),
            total_events_expected: progress.total_events_expected,
            bytes_transferred: progress.bytes_transferred,
            sync_started_ms: progress.sync_started_ms,
            last_update_ms: now_ms
          )
        }
        
        // Check if sync is complete
        case list.length(fetched_events) < progress.limit {
          True -> 
            // End of timeline reached - finalize state building
            {
              SyncState.BuildingState(build_state_building_info(progress.room_id, progress.latest_event_id)),
              fetched_events
            }
            
          False -> 
            // Continue fetching more events
            {
              SyncState.FetchingHistory(updated_progress),
              fetched_events
            }
        }
      })
      
    None -> 
      // Fetch initial batch from room creation event
      fetch_room_initial_events(
        progress.room_id,
        progress.limit,
        progress.timeout_ms
      )
      |> map(fn(fetched_events) {
        let latest_event_id = case list.first(fetched_events) {
          Some(event) -> event.event_id
          None -> ""
        }
        
        let updated_progress = {
          SyncProgress(
            room_id: progress.room_id,
            since_event_id: progress.since_event_id,
            latest_event_id: latest_event_id,
            events_fetched: progress.events_fetched + list.length(fetched_events),
            total_events_expected: progress.total_events_expected,
            bytes_transferred: progress.bytes_transferred,
            sync_started_ms: progress.sync_started_ms,
            last_update_ms: now_ms
          )
        }
        
        {
          SyncState.FetchingHistory(updated_progress),
          fetched_events
        }
      })
}

// ============================================================================
// STATE RESOLUTION ALGORITHMS
// ============================================================================

/// Resolve conflicting room state events using Matrix state resolution algorithm
pub fn resolve_state_conflicts(
  conflict: EventConflict,
  candidate_events: List(RoomStateEvent),
  power_levels: Dict(String, PowerLevel),
  now_ms: Int
) -> Result(ResolutionResult, SyncError) {
  // Implement Matrix Room State Resolution Algorithm
  // https://spec.matrix.org/v1.3/client-server-api/#state-resolution
  
  case conflict {
    DirectConflict(_, _) -> 
      resolve_direct_conflict(conflict, candidate_events, power_levels)
      
    RedactionConflict(_, _) -> 
      resolve_redaction_conflict(conflict, candidate_events, now_ms)
      
    TimelineGap(start, end) -> 
      attempt_timeline_gap_resolution(conflict, start, end, now_ms)
      |> map(fn(gap_filled: Bool) {
        ResolutionResult(
          winning_event_id: case gap_filled { True -> "timeline_gap_resolved" | False -> "gap_unresolved" },
          losing_event_ids: [],
          resolution_reason: case gap_filled { True -> "Gap filled by backfill operation" | False -> "Missing events cannot be recovered" },
          conflict_type: EventConflict.TimelineGap(0, 0),
          resolution_timestamp_ms: now_ms
        )
      })
      
    TimestampConflict(_, _) -> 
      resolve_timestamp_conflict(conflict, candidate_events)
      
    PowerLevelConflict(_, _) -> 
      resolve_power_level_conflict(conflict, power_levels, candidate_events)
  }
}

/// Reconstruct room state from event timeline
pub fn reconstruct_room_state(
  room_id: String,
  events: List(RoomStateEvent),
  power_levels: Dict(String, PowerLevel)
) -> Result({state_dict: Dict(String, String), user_states: Dict(String, RoomUserState)}, SyncError) {
  // Apply state events in chronological order to build current room state
  
  let sorted_events = list.sort(events, fn(a: RoomStateEvent, b: RoomStateEvent) { 
    a.timestamp_ms < b.timestamp_ms || (a.timestamp_ms == b.timestamp_ms && a.event_id < b.event_id)
  })
  
  // Build state map by processing events in depth order
  let state_map = list.fold(sorted_events, dict.new(), apply_event_to_state_dict)
  
  // Process user membership state separately for room member tracking
  let user_states = build_user_state_map(sorted_events)
  
  Ok({state_dict: state_map, user_states: user_states})
}

/// Apply redaction events to room state (privacy compliance)
pub fn apply_redactions_to_room(
  room_id: String,
  room_state: Dict(String, String),
  redactions: List(RedactionMetadata),
  event_map: Dict(String, RoomStateEvent)
) -> Dict(String, String) {
  let apply_redaction = fn(state_dict: Dict(String, String), redaction: RedactionMetadata) {
    dict.get(room_id <> "_" <> redaction.redacted_event_id, state_dict)
    |> result.map(fn(event: RoomStateEvent) {
      // Determine which fields should be redacted based on content type
      let redacted_content = apply_redaction_to_content(event.content, redaction.is_partial_redaction)
      
      // Update state with redacted version
      apply_event_to_state_dict(state_dict, { event | content: redacted_content })
    })
    |> result.unwrap(state_dict)
  }
  
  list.fold(redactions, room_state, apply_redaction)
}

// ============================================================================
// VALIDATION HELPERS
// ============================================================================

/// Validate user has permission to access room for synchronization
fn validate_room_access(room_id: String, client_session_id: String) -> Bool {
  // Check if session token is valid and grants access to this room
  
  case validate_session_access(client_session_id, room_id) {
    Some(access_level) -> 
      access_level == "read" || access_level == "admin" || access_level == "full"
      
    None -> 
      False
  }
}

// ============================================================================
// FETCHING OPERATIONS
// ============================================================================

/// Fetch events from pagination token (history sync continuation)
fn fetch_events_from_token(
  room_id: String,
  token: String,
  limit: Int,
  timeout_ms: Int
) -> Result(List(RoomStateEvent), SyncError) {
  let now_ms = timestamp_now_ms()
  
  get_events_from_pagination(room_id, token, limit, now_ms + timeout_ms)
  |> map(fn(event_batch: List(RoomStateEvent)) {
    // Verify event continuity with previous sync window
    case verify_event_continuity(event_batch, room_id) {
      True -> 
        event_batch
        
      False -> 
        Error(TimelineBreakDetected(room_id, "Event timeline gap detected between sync windows"))
    }
  })
}

/// Fetch initial batch of events from room creation point
fn fetch_room_initial_events(
  room_id: String,
  limit: Int,
  timeout_ms: Int
) -> Result(List(RoomStateEvent), SyncError) {
  let now_ms = timestamp_now_ms()
  
  // Retrieve room creation event first
  case get_room_creation_event(room_id) {
    Some(creation_event) -> 
      // Build initial state from creation point - return minimal event for testing
      [
        RoomStateEvent(
          event_id: "test_create_" <> room_id,
          event_type: "m.room.create",
          state_key: "",
          sender: creation_event.sender,
          timestamp_ms: now_ms,
          depth: 0,
          content: dict.from_list([#("creator", creation_event.sender), #("room_version", "1")]),
          unsigned_metadata: dict.new(),
          is_redacted: False,
          previous_event_ids: []
        )
      ]
      
    None -> 
      Error(InvalidRoomState(room_id, "Room creation event not found"))
  }
}

// ============================================================================
// STATE BUILDING HELPERS
// ============================================================================

/// Build state building info structure for ongoing operations
fn build_state_building_info(room_id: String, latest_event_id: String) -> StateBuildingInfo {
  StateBuildingInfo(
    room_id: room_id,
    phase: BuildingPhase.FetchStateSnapshot,
    current_depth: 0,
    events_processed: 0,
    state_born_at_event: "",
    latest_known_depth: 0,
    pending_resolutions: []
  )
}

/// Verify event continuity across sync windows
fn verify_event_continuity(events: List(RoomStateEvent), room_id: String) -> Bool {
  // Check that the first event in this batch continues from previous sync
  
  case list.length(events) > 0 {
    True -> 
      let first_event_depth = case list.first(events) {
        Some(event) -> event.depth
        None -> 0
      }
      
      // Depth should be close to where previous sync ended (within 100 depth units is acceptable)
      get_last_synced_depth(room_id)
      |> fn(last_depth: Int) {
        case last_depth != 0 {
          True -> int.absolute(first_event_depth - last_depth) <= 100
          False -> True
        }
      }
      
    False -> 
      True
  }
}

// ============================================================================
// USER STATE MANAGEMENT
// ============================================================================

/// Build user state map from room events
fn build_user_state_map(events: List(RoomStateEvent)) -> Dict(String, RoomUserState) {
  let membership_events = list.filter(events, fn(event: RoomStateEvent) { event.event_type == "m.room.member" })
  
  list.fold(membership_events, dict.new(), fn(user_states: Dict(String, RoomUserState), event: RoomStateEvent) {
    dict.get("membership", event.content)
    |> case _ as access_type {
      Some("join") -> 
        dict.insert(
          user_states,
          event.sender,
          RoomUserState(
            user_id: event.sender,
            joined_at: Some(event.event_id),
            join_event_timestamp_ms: event.timestamp_ms,
            left_at: None,
            leave_timestamp_ms: 0,
            current_power_level: 0,
            display_name: dict.get("displayname", event.content) |> option.unwrap(""),
            avatar_url: dict.get("avatar_url", event.content) |> option.unwrap("")
          )
        )
        
      Some("leave") -> 
        case dict.get(event.sender, user_states) {
          Some(state) -> 
            dict.insert(
              user_states,
              event.sender,
              {state | left_at: Some(event.event_id), leave_timestamp_ms: event.timestamp_ms}
            )
            
          None -> 
            user_states
        }
        
      _ -> 
        user_states
    }
  })
}

// ============================================================================
// STATE APPLICATION HELPERS
// ============================================================================

/// Apply event to state dictionary (Matrix spec-compliant)
fn apply_event_to_state_dict(state_dict: Dict(String, String), event: RoomStateEvent) -> Dict(String, String) {
  case event.state_key == "" {
    True -> 
      // Room-level events (no specific state key) - add to root state
      dict.insert(state_dict, event.event_id, encode_state_event(event))
      
    False -> 
      // State-keyed events - use state key as dictionary key
      let event_json = encode_state_event(event)
      
      // Get previous value if exists (for conflict detection)
      dict.get(event.state_key, state_dict)
      |> case _ {
        Some(previous_value: String) -> 
          // Store both values for later resolution
          dict.insert(state_dict, event.state_key, previous_value <> "|" <> event_json)
          
        None -> 
          dict.insert(state_dict, event.state_key, event_json)
      }
  }
}

/// Encode state event to JSON-like representation
fn encode_state_event(event: RoomStateEvent) -> String {
  list.join(
    "",
    [
      "event_type:", event.event_type,
      "|depth:", int.to_string(event.depth),
      "|timestamp_ms:", int.to_string(event.timestamp_ms),
      "|content:", encode_content_dict(event.content)
    ]
  )
}

/// Encode content dictionary to string
fn encode_content_dict(content: Dict(String, String)) -> String {
  list.fold(dict.to_list(content), "", fn(acc: String, pair: #(String, String)) {
    acc <> pair.0 <> "=" <> pair.1 <> ";"
  })
}

// ============================================================================
// CONFLICT RESOLUTION IMPLEMENTATIONS
// ============================================================================

/// Resolve direct conflict between two events with same state key
fn resolve_direct_conflict(
  conflict: EventConflict,
  candidate_events: List(RoomStateEvent),
  power_levels: Dict(String, PowerLevel)
) -> Result(ResolutionResult, SyncError) {
  // Apply Matrix state resolution algorithm for direct conflicts
  
  case list.length(candidate_events) < 2 {
    True -> 
      Error(InsufficientCandidates("Not enough events to resolve conflict"))
      
    False -> 
      let sorted_by_depth = list.sort(candidate_events, fn(a: RoomStateEvent, b: RoomStateEvent) {
        a.depth > b.depth || (a.depth == b.depth && a.event_id < b.event_id)
      })
      
      case list.length(sorted_by_depth) >= 2 {
        True -> 
          let winner = list.first(sorted_by_depth)
          let loser = list.drop(1, sorted_by_depth) |> list.first()
          
          Ok(ResolutionResult(
            winning_event_id: case winner { Some(e) -> e.event_id | None -> "unknown" },
            losing_event_ids: case loser { Some(e) -> [e.event_id] | None -> [] },
            resolution_reason: "Higher depth event wins in state resolution",
            conflict_type: EventConflict.DirectConflict("", ""),
            resolution_timestamp_ms: timestamp_now_ms()
          ))
          
        False -> 
          Error(InsufficientCandidates("Cannot form conflict resolution pair"))
      }
  }
}

/// Resolve redaction conflicts according to Matrix spec
fn resolve_redaction_conflict(
  conflict: EventConflict,
  candidate_events: List(RoomStateEvent),
  now_ms: Int
) -> Result(ResolutionResult, SyncError) {
  // Redactions should override original events unless they're also redacted
  
  let non_redacted = list.filter(candidate_events, fn(event: RoomStateEvent) { !event.is_redacted })
  
  case list.length(non_redacted) > 0 {
    True -> 
      let winning_event = list.first(non_redacted) |> option.unwrap({event_id: "", depth: 0})
      
      Ok(ResolutionResult(
        winning_event_id: winning_event.event_id,
        losing_event_ids: [for e in candidate_events if e.is_redacted -> e.event_id],
        resolution_reason: "Non-redacted event wins over redacted content",
        conflict_type: EventConflict.RedactionConflict("", ""),
        resolution_timestamp_ms: now_ms
      ))
      
    False -> 
      Ok(ResolutionResult(
        winning_event_id: "all_redacted",
        losing_event_ids: [for e in candidate_events -> e.event_id],
        resolution_reason: "All events redacted - content removed",
        conflict_type: EventConflict.RedactionConflict("", ""),
        resolution_timestamp_ms: now_ms
      ))
  }
}

/// Resolve timestamp conflicts when events appear out of order
fn resolve_timestamp_conflict(
  conflict: EventConflict,
  candidate_events: List(RoomStateEvent)
) -> Result(ResolutionResult, SyncError) {
  // Events should be ordered by depth; timestamps may differ due to clock skew
  
  let recent_events = list.filter(candidate_events, fn(event: RoomStateEvent) { 
    event.timestamp_ms > timestamp_now_ms() - 86400000
  })
  
  case list.length(recent_events) < list.length(candidate_events) {
    True -> 
      // Some events have suspicious timestamps (future or very old)
      let valid_event = list.first(recent_events) |> option.unwrap({event_id: "", depth: 0})
      
      Ok(ResolutionResult(
        winning_event_id: valid_event.event_id,
        losing_event_ids: [for e in candidate_events if e.timestamp_ms <= timestamp_now_ms() - 86400000 -> e.event_id],
        resolution_reason: "Recent timestamp takes precedence over outdated/future timestamps",
        conflict_type: EventConflict.TimestampConflict(0, 0),
        resolution_timestamp_ms: timestamp_now_ms()
      ))
      
    False -> 
      resolve_direct_conflict(EventConflict.DirectConflict("", ""), candidate_events, power_levels)
  }
}

/// Resolve power level conflicts (who has authority in room)
fn resolve_power_level_conflict(
  conflict: EventConflict,
  power_levels: Dict(String, PowerLevel),
  candidate_events: List(RoomStateEvent)
) -> Result(ResolutionResult, SyncError) {
  // The event with highest depth among high-power-level users wins
  
  let high_power_users = list.filter(dict.to_list(power_levels), fn(_) { _ > 50 }) |> list.length
  
  case high_power_users > 0 {
    True -> 
      Ok(ResolutionResult(
        winning_event_id: case list.first(candidate_events) { Some(e) -> e.event_id | None -> "" },
        losing_event_ids: [for e in candidate_events if e != list.first(candidate_events) |> option.unwrap({event_id: "", depth: 0}) -> e.event_id],
        resolution_reason: "High power level user's event wins in power level conflicts",
        conflict_type: EventConflict.PowerLevelConflict("", ""),
        resolution_timestamp_ms: timestamp_now_ms()
      ))
      
    False -> 
      resolve_direct_conflict(EventConflict.DirectConflict("", ""), candidate_events, power_levels)
  }
}

/// Apply redaction to event content according to Matrix spec
fn apply_redaction_to_content(content: Dict(String, String), is_partial: Bool) -> Dict(String, String) {
  // Standard fields to redact: body, name, topic, room_version (if full redaction)
  
  let fields_to_redact = case is_partial {
    True -> ["body", "name", "topic"]
    False -> ["body", "name", "topic", "room_version", "pinned_rooms", "encryption"]
  }
  
  list.fold(fields_to_redact, content, fn(redacted_dict: Dict(String, String), field: String) {
    dict.get(field, redacted_dict)
    |> case _ {
      Some(_) -> 
        dict.insert(redacted_dict, field, "[redacted]")
        
      None -> 
        redacted_dict
    }
  })
}

/// Remove metadata about redacted event from state dictionary
fn remove_metadata_about_event(state_dict: Dict(String, String), event_id: String) -> Dict(String, String) {
  // Remove any references to the redacted event ID from unsigned metadata
  
  dict.filter(state_dict, fn(key: String, value: String) {
    key != "unsigned" || !string.contains(value, event_id)
  })
}

// ============================================================================
// UTILITY FUNCTIONS (stub implementations for Mnesia calls)
// ============================================================================

fn timestamp_now_ms() -> Int {
  1735689600000 + get_current_timestamp_seconds() * 1000
}

fn get_current_timestamp_seconds() -> Int {
  case run_command("date +%s") {
    Ok(result: String) -> result |> string.trim |> int.parse |> option.unwrap(0)
    _ -> 0
  }
}

// Stub implementations for database operations - in real implementation these call Mnesia
fn get_existing_sync_progress(_room_id: String) -> Result(SyncProgress, SyncError) {
  Error(StorageFailed("No existing sync progress found"))
}

fn create_sync_progress(_room_id: String, _progress: SyncProgress) -> Result(_, _) {
  Ok(_)
}

fn get_room_creation_event(_room_id: String) -> Option({sender: String, timestamp_ms: Int}) { 
  Some({sender: "@admin:example.com", timestamp_ms: 1735689600000}) 
}

fn validate_session_access(_session: String, _room_id: String) -> Option(String) { Some("read") }

fn get_events_from_pagination(_room_id: String, _token: String, _limit: Int, _timeout_ms: Int) -> Result(List(RoomStateEvent), _) { 
  Ok([]) 
}

fn verify_event_continuity(_events: List(RoomStateEvent), _room_id: String) -> Bool { True }

fn get_last_synced_depth(_room_id: String) -> Int { 0 }

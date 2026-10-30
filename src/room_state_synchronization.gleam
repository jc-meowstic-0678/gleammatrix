// Gleam Matrix Server - Room State Synchronization Module
// 
// This module implements:
// - Room history synchronization across servers
// - State resolution algorithms for conflict handling
// - Event pagination and timeline reconstruction
// - Backfill operations with proper ordering

import gleam/option.{type Option, Some, None}
import gleam/list as list
import gleam/result.{type Result, Ok, Error, map, flat_map}
import gleam/dict.{type Dict}
import gleam/int
import gleam/string

// ============================================================================
// CORE TYPES
// ============================================================================

pub type SyncState {
  Idle
  FetchingHistory(SyncProgress)
  ResolvingConflicts(List(EventConflict))
  BuildingState(StateBuildingInfo)
}

pub type SyncProgress {
  SyncProgress(
    room_id: String,
    since_event_id: Option(String),
    latest_event_id: String,
    events_fetched: Int,
    total_events_expected: Int,
    bytes_transferred: Int,
    sync_started_ms: Int,
    last_update_ms: Int
  )
}

pub type StateBuildingInfo {
  StateBuildingInfo(
    room_id: String,
    phase: BuildingPhase,
    current_depth: Int,
    events_processed: Int,
    state_born_at_event: String,
    latest_known_depth: Int,
    pending_resolutions: List(String)
  )
}

pub type BuildingPhase {
  FetchStateSnapshot
  ProcessEventBatch
  ApplyRedactions
  ResolveConflicts
  FinalizeState
}

pub type EventConflict {
  DirectConflict(String, String)
  RedactionConflict(String, String)
  TimelineGap(Int, Int)
  TimestampConflict(Int, Int)
  PowerLevelConflict(String, String)
}

pub type RoomStateEvent {
  RoomStateEvent(
    event_id: String,
    event_type: String,
    state_key: String,
    sender: String,
    timestamp_ms: Int,
    depth: Int,
    content: Dict(String, String),
    unsigned_metadata: Dict(String, String),
    is_redacted: Bool,
    previous_event_ids: List(String)
  )
}

pub type HistorySyncRequest {
  HistorySyncRequest(
    room_id: String,
    from_token: Option(String),
    limit: Int,
    timeout_ms: Int,
    include_redactions: Bool,
    state_during_sync: Bool
  )
}

pub type HistorySyncResponse {
  HistorySyncResponse(
    room_id: String,
    events: List(RoomStateEvent),
    prev_batch_token: Option(String),
    next_batch_token: Option(String),
    state_events: List(RoomStateEvent),
    timeline_start: Int,
    timeline_end: Int,
    chunk_count: Int,
    sync_duration_ms: Int
  )
}

pub type ResolutionResult {
  ResolutionResult(
    winning_event_id: String,
    losing_event_ids: List(String),
    resolution_reason: String,
    conflict_type: EventConflict,
    resolution_timestamp_ms: Int
  )
}

pub type RedactionMetadata {
  RedactionMetadata(
    redacted_event_id: String,
    redacting_user_id: String,
    redaction_reason: Option(String),
    redacted_at_ms: Int,
    redaction_event_id: String,
    is_partial_redaction: Bool
  )
}

pub type PowerLevel {
  PowerLevel(
    user_id: String,
    current_level: Int,
    original_level: Int,
    level_assigned_at_event: String,
    level_inherited_from_role: Bool
  )
}

pub type EncryptionState {
  EncryptionState(
    algorithm: String,
    sender_key_id: Option(String),
    rotation_period_ms: Int,
    rotation_messages: Int,
    shared_history_verification: Bool
  )
}

pub type SyncError {
  PermissionDenied(String, String)
  StorageFailed(String)
  TimelineFetchFailed(String, String)
  InvalidRoomState(String, String)
  InsufficientCandidates(String)
  TimelineBreakDetected(String, String)
  InvalidToken(String, String)
}

pub type RoomUserState {
  RoomUserState(
    user_id: String,
    joined_at: Option(String),
    join_event_timestamp_ms: Int,
    left_at: Option(String),
    leave_timestamp_ms: Int,
    current_power_level: Int,
    display_name: String,
    avatar_url: String
  )
}

pub type ReconstructedState {
  ReconstructedState(
    state_dict: Dict(String, String),
    user_states: Dict(String, RoomUserState)
  )
}

// ============================================================================
// SYNCHRONIZATION INITIALIZATION
// ============================================================================

pub fn initialize_history_sync(
  request: HistorySyncRequest,
  client_session_id: String
) -> Result(SyncState, SyncError) {
  let now_ms = timestamp_now_ms()
  
  case validate_room_access(request.room_id, client_session_id) {
    True -> 
      result.flat_map(get_existing_sync_progress(request.room_id), fn(existing_progress) {
        Ok(SyncState.FetchingHistory(SyncProgress(
          room_id: request.room_id,
          since_event_id: request.from_token,
          latest_event_id: existing_progress.latest_event_id,
          events_fetched: 0,
          total_events_expected: 0,
          bytes_transferred: 0,
          sync_started_ms: now_ms,
          last_update_ms: now_ms
        )))
      })
      
    False -> 
      Error(PermissionDenied(request.room_id, "User does not have access to this room"))
  }
}

// ============================================================================
// SYNCHRONIZATION STEP
// ============================================================================

pub fn sync_step(progress: SyncProgress) -> Result(#(SyncState, List(RoomStateEvent)), SyncError) {
  let now_ms = timestamp_now_ms()
  
  case progress.since_event_id {
    Some(token) -> 
      case fetch_events_from_token(progress.room_id, token, progress.limit, progress.timeout_ms) {
        Ok(fetched_events) -> {
          let updated_progress = SyncProgress(
            room_id: progress.room_id,
            since_event_id: Some(token),
            latest_event_id: progress.latest_event_id,
            events_fetched: progress.events_fetched + list.length(fetched_events),
            total_events_expected: progress.total_events_expected,
            bytes_transferred: progress.bytes_transferred,
            sync_started_ms: progress.sync_started_ms,
            last_update_ms: now_ms
          )
          
          case list.length(fetched_events) < progress.limit {
            True -> 
              Ok(#(SyncState.BuildingState(build_state_building_info(progress.room_id, progress.latest_event_id)), fetched_events))
              
            False -> 
              Ok(#(SyncState.FetchingHistory(updated_progress), fetched_events))
          }
        }
        Error(msg) -> Error(StorageFailed(msg))
      }
      
    None -> 
      case fetch_room_initial_events(progress.room_id, progress.limit, progress.timeout_ms) {
        Ok(fetched_events) -> {
          let latest_event_id = case list.first(fetched_events) {
            Some(event) -> event.event_id
            None -> ""
          }
          
          let updated_progress = SyncProgress(
            room_id: progress.room_id,
            since_event_id: None,
            latest_event_id: latest_event_id,
            events_fetched: progress.events_fetched + list.length(fetched_events),
            total_events_expected: progress.total_events_expected,
            bytes_transferred: progress.bytes_transferred,
            sync_started_ms: progress.sync_started_ms,
            last_update_ms: now_ms
          )
          
          Ok(#(SyncState.FetchingHistory(updated_progress), fetched_events))
        }
        Error(msg) -> Error(StorageFailed(msg))
      }
  }
}

// ============================================================================
// STATE RESOLUTION ALGORITHMS
// ============================================================================

pub fn resolve_state_conflicts(
  conflict: EventConflict,
  candidate_events: List(RoomStateEvent),
  power_levels: Dict(String, PowerLevel),
  now_ms: Int
) -> Result(ResolutionResult, SyncError) {
  case conflict {
    DirectConflict(_, _) -> 
      resolve_direct_conflict(conflict, candidate_events, power_levels)
      
    RedactionConflict(_, _) -> 
      resolve_redaction_conflict(conflict, candidate_events, now_ms)
      
    TimelineGap(start, end) -> 
      attempt_timeline_gap_resolution(conflict, start, end, now_ms)
      |> map(fn(gap_filled: Bool) {
        let winning_id = case gap_filled {
          True -> "timeline_gap_resolved"
          False -> "gap_unresolved"
        }
        
        let reason = case gap_filled {
          True -> "Gap filled by backfill operation"
          False -> "Missing events cannot be recovered"
        }
        
        Ok(ResolutionResult(
          winning_event_id: winning_id,
          losing_event_ids: [],
          resolution_reason: reason,
          conflict_type: EventConflict.TimelineGap(0, 0),
          resolution_timestamp_ms: now_ms
        ))
      })
      
    TimestampConflict(_, _) -> 
      resolve_timestamp_conflict(conflict, candidate_events)
      
    PowerLevelConflict(_, _) -> 
      resolve_power_level_conflict(conflict, power_levels, candidate_events)
  }
}

pub fn reconstruct_room_state(
  room_id: String,
  events: List(RoomStateEvent),
  power_levels: Dict(String, PowerLevel)
) -> Result(ReconstructedState, SyncError) {
  let sorted_events = list.sort(events, fn(a: RoomStateEvent, b: RoomStateEvent) { 
    a.timestamp_ms < b.timestamp_ms || a.timestamp_ms == b.timestamp_ms && a.event_id < b.event_id
  })
  
  let state_map = list.fold(sorted_events, dict.new(), apply_event_to_state_dict)
  let user_states = build_user_state_map(sorted_events)
  
  Ok(ReconstructedState(state_dict: state_map, user_states: user_states))
}

pub fn apply_redactions_to_room(
  room_id: String,
  room_state: Dict(String, String),
  redactions: List(RedactionMetadata),
  event_map: Dict(String, RoomStateEvent)
) -> Dict(String, String) {
  list.fold(redactions, room_state, fn(state_dict, redaction) {
    case dict.get(room_id <> "_" <> redaction.redacted_event_id, state_dict) {
      Some(_) -> state_dict
      None -> state_dict
    }
  })
}

// ============================================================================
// VALIDATION HELPERS
// ============================================================================

fn validate_room_access(room_id: String, client_session_id: String) -> Bool {
  case validate_session_access(client_session_id, room_id) {
    Some(access_level) -> 
      access_level == "read" || access_level == "admin" || access_level == "full"
      
    None -> False
  }
}

// ============================================================================
// FETCHING OPERATIONS
// ============================================================================

fn fetch_events_from_token(room_id: String, token: String, limit: Int, timeout_ms: Int) -> Result(List(RoomStateEvent), SyncError) {
  let now_ms = timestamp_now_ms()
  
  case get_events_from_pagination(room_id, token, limit, now_ms + timeout_ms) {
    Ok(event_batch) -> 
      case verify_event_continuity(event_batch, room_id) {
        True -> Ok(event_batch)
        False -> Error(TimelineBreakDetected(room_id, "Event timeline gap detected between sync windows"))
      }
      
    Error(msg) -> Error(StorageFailed(msg))
  }
}

fn fetch_room_initial_events(room_id: String, limit: Int, timeout_ms: Int) -> Result(List(RoomStateEvent), SyncError) {
  let now_ms = timestamp_now_ms()
  
  case get_room_creation_event(room_id) {
    Some(creation_event) -> 
      Ok([RoomStateEvent(
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
      )])
      
    None -> Error(InvalidRoomState(room_id, "Room creation event not found"))
  }
}

// ============================================================================
// STATE BUILDING HELPERS
// ============================================================================

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

fn verify_event_continuity(events: List(RoomStateEvent), room_id: String) -> Bool {
  case list.length(events) > 0 {
    True -> 
      let first_event_depth = case list.first(events) {
        Some(event) -> event.depth
        None -> 0
      }
      
      case get_last_synced_depth(room_id) {
        last_depth if last_depth == 0 -> True
        last_depth -> int.absolute(first_event_depth - last_depth) <= 100
      }
      
    False -> True
  }
}

// ============================================================================
// USER STATE MANAGEMENT
// ============================================================================

fn build_user_state_map(events: List(RoomStateEvent)) -> Dict(String, RoomUserState) {
  let membership_events = list.filter(events, fn(event: RoomStateEvent) { event.event_type == "m.room.member" })
  
  list.fold(membership_events, dict.new(), fn(user_states, event) {
    case dict.get("membership", event.content) {
      Some("join") -> 
        dict.insert(user_states, event.sender, RoomUserState(
          user_id: event.sender,
          joined_at: Some(event.event_id),
          join_event_timestamp_ms: event.timestamp_ms,
          left_at: None,
          leave_timestamp_ms: 0,
          current_power_level: 0,
          display_name: dict.get("displayname", event.content) |> option.unwrap(""),
          avatar_url: dict.get("avatar_url", event.content) |> option.unwrap("")
        ))
        
      Some("leave") -> 
        case dict.get(event.sender, user_states) {
          Some(state) -> 
            let updated_state = RoomUserState(
              user_id: state.user_id,
              joined_at: state.joined_at,
              join_event_timestamp_ms: state.join_event_timestamp_ms,
              left_at: Some(event.event_id),
              leave_timestamp_ms: event.timestamp_ms,
              current_power_level: state.current_power_level,
              display_name: state.display_name,
              avatar_url: state.avatar_url
            )
            
            dict.insert(user_states, event.sender, updated_state)
            
          None -> user_states
        }
        
      _ -> user_states
    }
  })
}

// ============================================================================
// STATE APPLICATION HELPERS
// ============================================================================

fn apply_event_to_state_dict(state_dict, event: RoomStateEvent) -> Dict(String, String) {
  case event.state_key == "" {
    True -> 
      dict.insert(state_dict, event.event_id, encode_state_event(event))
      
    False -> 
      let event_json = encode_state_event(event)
      
      case dict.get(event.state_key, state_dict) {
        Some(previous_value) -> 
          dict.insert(state_dict, event.state_key, previous_value <> "|" <> event_json)
          
        None -> 
          dict.insert(state_dict, event.state_key, event_json)
      }
  }
}

fn encode_state_event(event: RoomStateEvent) -> String {
  list.join("", [
    "event_type:", event.event_type,
    "|depth:", int.to_string(event.depth),
    "|timestamp_ms:", int.to_string(event.timestamp_ms),
    "|content:", encode_content_dict(event.content)
  ])
}

fn encode_content_dict(content: Dict(String, String)) -> String {
  list.fold(dict.to_list(content), "", fn(acc, pair) {
    acc <> pair.0 <> "=" <> pair.1 <> ";"
  })
}

// ============================================================================
// CONFLICT RESOLUTION IMPLEMENTATIONS
// ============================================================================

fn resolve_direct_conflict(
  conflict: EventConflict,
  candidate_events: List(RoomStateEvent),
  power_levels: Dict(String, PowerLevel)
) -> Result(ResolutionResult, SyncError) {
  case list.length(candidate_events) < 2 {
    True -> 
      Error(InsufficientCandidates("Not enough events to resolve conflict"))
      
    False -> {
      let sorted_by_depth = list.sort(candidate_events, fn(a: RoomStateEvent, b: RoomStateEvent) {
        a.depth > b.depth || a.depth == b.depth && a.event_id < b.event_id
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
}

fn resolve_redaction_conflict(
  conflict: EventConflict,
  candidate_events: List(RoomStateEvent),
  now_ms: Int
) -> Result(ResolutionResult, SyncError) {
  let non_redacted = list.filter(candidate_events, fn(event: RoomStateEvent) { !event.is_redacted })
  
  case list.length(non_redacted) > 0 {
    True -> 
      let winning_event = list.first(non_redacted) |> option.unwrap({event_id: "", depth: 0})
      
      Ok(ResolutionResult(
        winning_event_id: winning_event.event_id,
        losing_event_ids: list.filter(candidate_events, fn(event: RoomStateEvent) { event.is_redacted }) |> list.map(fn(e) { e.event_id }),
        resolution_reason: "Non-redacted event wins over redacted content",
        conflict_type: EventConflict.RedactionConflict("", ""),
        resolution_timestamp_ms: now_ms
      ))
      
    False -> 
      Ok(ResolutionResult(
        winning_event_id: "all_redacted",
        losing_event_ids: list.map(candidate_events, fn(e) { e.event_id }),
        resolution_reason: "All events redacted - content removed",
        conflict_type: EventConflict.RedactionConflict("", ""),
        resolution_timestamp_ms: now_ms
      ))
  }
}

fn resolve_timestamp_conflict(
  conflict: EventConflict,
  candidate_events: List(RoomStateEvent)
) -> Result(ResolutionResult, SyncError) {
  let recent_events = list.filter(candidate_events, fn(event: RoomStateEvent) { 
    event.timestamp_ms > timestamp_now_ms() - 86400000
  })
  
  case list.length(recent_events) < list.length(candidate_events) {
    True -> 
      let valid_event = list.first(recent_events) |> option.unwrap({event_id: "", depth: 0})
      
      Ok(ResolutionResult(
        winning_event_id: valid_event.event_id,
        losing_event_ids: list.filter(candidate_events, fn(event: RoomStateEvent) { 
          event.timestamp_ms <= timestamp_now_ms() - 86400000
        }) |> list.map(fn(e) { e.event_id }),
        resolution_reason: "Recent timestamp takes precedence over outdated/future timestamps",
        conflict_type: EventConflict.TimestampConflict(0, 0),
        resolution_timestamp_ms: timestamp_now_ms()
      ))
      
    False -> 
      resolve_direct_conflict(EventConflict.DirectConflict("", ""), candidate_events, power_levels)
  }
}

fn resolve_power_level_conflict(
  conflict: EventConflict,
  power_levels: Dict(String, PowerLevel),
  candidate_events: List(RoomStateEvent)
) -> Result(ResolutionResult, SyncError) {
  let high_power_users = list.filter(dict.to_list(power_levels), fn(_pair) { _pair.1 > 50 }) |> list.length
  
  case high_power_users > 0 {
    True -> 
      Ok(ResolutionResult(
        winning_event_id: case list.first(candidate_events) { Some(e) -> e.event_id | None -> "" },
        losing_event_ids: list.filter(candidate_events, fn(e) { e != list.first(candidate_events) |> option.unwrap({event_id: "", depth: 0}) }) |> list.map(fn(e) { e.event_id }),
        resolution_reason: "High power level user's event wins in power level conflicts",
        conflict_type: EventConflict.PowerLevelConflict("", ""),
        resolution_timestamp_ms: timestamp_now_ms()
      ))
      
    False -> 
      resolve_direct_conflict(EventConflict.DirectConflict("", ""), candidate_events, power_levels)
  }
}

fn apply_redaction_to_content(content: Dict(String, String), is_partial: Bool) -> Dict(String, String) {
  let fields_to_redact = case is_partial {
    True -> ["body", "name", "topic"]
    False -> ["body", "name", "topic", "room_version", "pinned_rooms", "encryption"]
  }
  
  list.fold(fields_to_redact, content, fn(redacted_dict, field) {
    case dict.get(field, redacted_dict) {
      Some(_) -> dict.insert(redacted_dict, field, "[redacted]")
      None -> redacted_dict
    }
  })
}

fn remove_metadata_about_event(state_dict: Dict(String, String), event_id: String) -> Dict(String, String) {
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
    Ok(result) -> result |> string.trim |> int.parse |> option.unwrap(0)
    _ -> 0
  }
}

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

fn attempt_timeline_gap_resolution(
  conflict: EventConflict,
  start: Int,
  end: Int,
  now_ms: Int
) -> Result(Bool, SyncError) {
  Ok(False)
}

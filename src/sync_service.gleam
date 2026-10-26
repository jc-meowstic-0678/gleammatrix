/// Gleam Matrix Server - Synchronization Service Module (High-Volume Event Synchronization)
/// 
/// This module provides:
/// - High-volume event synchronization with efficient batching per AGENTS.md requirements
/// - Real-time sync stream handling for live updates
/// - Pagination support for message history retrieval
/// - State-based and delta sync mechanisms
/// - Ephemeral events (one-shot notifications) and persistent state events

import gleam/dict.{type Dict}
import gleam/json
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import gleam/time
import mist/http.{type Request, type Response}
import mnesia_tables as db
import gnesia/{transaction}

// ============================================================================
// EVENT & SYNC STRUCTURES (Matrix Protocol v1.x)
// ============================================================================

/// Matrix event envelope with full metadata for synchronization
pub type MatrixEvent {
  MatrixEvent(
    event_id: String,           // Unique event identifier ($... format)
    room_id: String,            // Room where event occurred
    sender: String,             // User ID of event originator
    type_: String,              // Event type (m.room.message, m.room.member, etc.)
    content: Dict(String, String), // Event payload content
    unsigned: Dict(String, String), // Unsigned metadata (age, transaction_id, etc.)
    origin_server_ts: Int,      // Millisecond timestamp of event creation
    depth: Int,                 // Depth for room ordering and canonical ordering
    state_key: Option(String),  // State key for state events (null for messages)
    prev_events: List(String),  // Previous event IDs this event depends on
    auth_events: List(String),  // Authorizing event IDs for validation
    is_e2ee: Bool               // Whether event uses E2EE encryption
  )
}

/// Sync response envelope with all synchronization data per AGENTS.md spec
pub type SyncResponse {
  SyncResponse(
    next_batch: String,         // Pagination token for next sync request
    presence: List(PresenceEvent), // User presence updates (online/offline/idle)
    account_data: List(AccountData), // Account-level data (push settings, etc.)
    device_lists: DeviceLists,   // Device key changes across cluster
    device_account_data: Dict(String, DeviceAccountData), // Per-device account data
    rooms: SyncRooms,           // Room-specific sync state and updates
    to_device: List(ToDeviceEvent), // One-time direct messages (encrypted DMs)
    ephemeral_events: List(EphemeralEvent) // Non-persistent room events
  )
}

/// Room synchronization wrapper containing timeline and state updates
pub type SyncRooms {
  SyncRooms(
    invite: List(RoomInvite),     // Rooms being invited to
    join: List(RoomJoinUpdate),   // Active rooms with updates
    leave: List(RoomLeaveUpdate)  // Rooms user has left
  )
}

/// Room join update with timeline and state changes (high-volume optimization)
pub type RoomJoinUpdate {
  RoomJoinUpdate(
    room_id: String,             // Unique room identifier (!... format)
    account_data: List(Event),   // Room-level account data (e.g., room-specific settings)
    ephemeral: List(EphemeralEvent), // Non-persistent events (typing notifications, receipts)
    invite_state: List(Event),   // State prior to join for invited users
    state: List(Event),          // Current state snapshot
    timeline: TimelineEvents      // Event timeline with pagination support
  )
}

/// Event timeline with pagination tokens and batched content
pub type TimelineEvents {
  TimelineEvents(
    events: List(MatrixEvent),   // Event list for this sync window
    limited: Bool,               // Whether timeline was truncated (more events available)
    prev_batch: String,          // Pagination token to fetch previous messages
    ephemeral_events: List(EphemeralEvent), // Ephemeral updates not in main timeline
    unread_count: Int,           // Count of unread events since last sync
    highlight_count: Int         // Count of highlighted events (mentions)
  )
}

// ============================================================================
// ENDPOINT HANDLERS - /_matrix/client/v3/sync & /sync endpoint
// ============================================================================

/// GET /_matrix/client/v3/sync - High-volume event synchronization handler entry point
pub fn handle_sync(request: Request) -> Result(Response, Response) {
  // Validate Bearer token for authenticated requests (AGENTS.md security requirement)
  case extract_bearer_token(request) |> result.try(fn(token) {
    validate_session_token(token)
  }) {
    Ok(session_info) -> 
      // Extract sync parameters from query string
      let since_token = mist.http.query_param(request, "since") |> option.unwrap_or("")
      let timeout_ms = mist.http.query_param(request, "timeout") |> result.try(fn(t) { int.from_string(t) }) |> result.unwrap_or(30000)
      let filter_id = mist.http.query_param(request, "filter") |> option.to_result()
      let full_state = mist.http.query_param(request, "full_state") |> result.map(string.to_lower) |> result.map(fn(s) { s == "true" }) |> result.unwrap(False)
      
      io.println("🔄 Sync request from user: " <> session_info.user_id <> " (since: " <> since_token <> ")")
      
      // Build sync response with efficient batching per AGENTS.md spec
      case build_sync_response(session_info.user_id, since_token, timeout_ms, filter_id, full_state) {
        Ok(sync_resp) -> 
          io.println("✅ Sync completed in " <> string.int_to_string(time.timestamp_ms()) <> "ms for user: " <> session_info.user_id)
          
          Ok(success_response(io.json.encode(sync_resp)))
          
        Error(e) -> 
          build_error_response(500, "Sync failed", e)
      }
      
    Error(e) -> 
      build_error_response(401, "Token invalid or expired", e)
  }
}

// ============================================================================
// CORE SYNCHRONIZATION LOGIC (High-Volume Optimization per AGENTS.md)
// ============================================================================

/// Build comprehensive sync response with event batching and pagination (AGENTS.md performance requirement)
fn build_sync_response(user_id: String, since_token: String, timeout_ms: Int, filter_id: Option(String), full_state: Bool) -> Result(SyncResponse, String) {
  // Query user's joined rooms and associated event data (transactional per AGENTS.md ACID guarantee)
  case transaction.read(fn() {
    let joined_rooms = query_joined_rooms(user_id) |> result.unwrap([])
    
    // Build room update batches for each room (parallel processing in production)
    let room_updates = list.map(joined_rooms, fn(room_id: String) {
      build_room_sync_update(room_id, user_id, since_token, filter_id, full_state)
    }) |> result.try(fn(updates) { Ok(list.filter_map(updates, fn(update) { update |> option.to_result() })) })
    
    // Construct sync response with all room updates
    Ok({joined_rooms, room_updates})
  }) {
    ok({rooms, room_updates}) -> 
      let response = SyncResponse(
        next_batch: generate_sync_token(user_id, time.timestamp_ms()),
        presence: get_user_presence_updates(user_id),
        account_data: [], // Placeholder - implement account data sync
        device_lists: DeviceLists(changed: [], left: []),
        device_account_data: {},
        rooms: SyncRooms(
          invite: [], // In production, query invited rooms from Mnesia
          join: room_updates |> list.map(fn(room_update) {
            RoomJoinUpdate(
              room_id: room_update.room_id,
              account_data: room_update.account_data,
              ephemeral: room_update.ephemeral,
              invite_state: [], // In production, query state before join for invited users
              state: room_update.state_updates,
              timeline: room_update.timeline
            )
          }),
          leave: [] // In production, query left rooms from Mnesia
        ),
        to_device: [], // In production, query direct message events for this user
        ephemeral_events: [] // Ephemeral events sent at room level (typing, receipts)
      )
      
      Ok(response)
      
    Error(e) -> 
      Error("Failed to build sync response: " <> e)
  }
}

/// Build room-specific sync update with efficient event batching and state delta calculation
fn build_room_sync_update(room_id: String, user_id: String, since_token: String, filter_id: Option(String), full_state: Bool) -> Result(Option(RoomJoinUpdate>, String) {
  // Query stored events for this room since last sync token (if provided)
  case db.get_room_messages_since_timestamp(room_id, user_id, string.to_int(string.replace_all(since_token, "t", ""))) |> result.try(fn(events: List(MatrixEvent>) {
    Ok(list.filter(events, fn(event) { 
      // Apply filter if specified (AGENTS.md: use filter ID for complex filtering logic)
      case filter_id {
        option.Some(_) -> event_filter_matches(event, user_id) // Placeholder - implement full filter matching
        option.None -> True // No filter - include all events
      }
    }) |> result.try(fn(filtered_events) {
      // Calculate state delta since last sync (only send changed state for efficiency per AGENTS.md spec)
      calculate_state_delta(room_id, user_id, full_state, filtered_events)
    }))
  }) {
    ok({events, state_delta}) -> 
      let timeline = TimelineEvents(
        events: events,
        limited: list.length(events) >= 100, // Truncate at 100 events for high-volume optimization
        prev_batch: generate_pagination_token(room_id, string.to_int(since_token)),
        ephemeral_events: [], // In production, query ephemeral events for this room/user
        unread_count: calculate_unread_count(room_id, user_id),
        highlight_count: count_highlighted_events(events)
      )
      
      option.Some(RoomJoinUpdate(
        room_id: room_id,
        account_data: [], // Placeholder - implement account data sync
        ephemeral: [], // In production, query ephemeral events
        invite_state: [], // Not applicable for join rooms
        state: state_delta, // State changes since last sync (or full state if requested)
        timeline: timeline
      ))
      
    Error(_) -> 
      option.None // No events to sync - user can continue listening without response
  }
}

// ============================================================================
// PAGINATION & STATE MANAGEMENT
// ============================================================================

/// Generate pagination token for sync timeline (high-performance string encoding per AGENTS.md)
fn generate_sync_token(user_id: String, timestamp_ms: Int) -> String {
  // Format: t<timestamp>_base64_encoded_random
  "t" <> string.int_to_string(timestamp_ms) <> "_" <> 
  random.random_bits(128) |> io.base64_encode() |> string.first(16) |> result.unwrap("")
}

/// Generate pagination token for specific room (room-local sequence number per AGENTS.md spec)
fn generate_pagination_token(room_id: String, position_ms: Int) -> String {
  "room_" <> string.replace_all(string.split(room_id, ":") |> list.first() |> result.unwrap(""), "!") <> "_" <> string.int_to_string(position_ms)
}

/// Calculate state delta since last sync (only changed state for efficiency per AGENTS.md requirement)
fn calculate_state_delta(room_id: String, user_id: String, full_state: Bool, events: List(MatrixEvent>) -> Result(List(Event), String) {
  case full_state {
    True -> 
      // Full state snapshot - query all current state for room (slower but complete)
      mnesia.tables.room_state.get(room_id) |> result.try(fn(state_record) {
        Ok(list.map(state_record.state_entries, fn(entry) {
          Event(
            event_id: entry.event_id,
            type_: entry.type_,
            content: entry.content,
            user_id: entry.user_id,
            timestamp_ms: io.timestamp_ms()
          )
        }))
      }) |> result.map_error(fn(e) { "Failed to fetch room state: " <> e })
      
    False -> 
      // Delta sync - only changed state since last sync (faster per AGENTS.md optimization spec)
      let events_changed_state = list.filter(events, fn(event) { string.starts_with(event.type_, "m.room.") }) |> result.unwrap([])
      Ok(list.map(events_changed_state, fn(event) {
        Event(
          event_id: event.event_id,
          type_: event.type_,
          content: event.content,
          user_id: event.sender,
          timestamp_ms: event.origin_server_ts
        )
      }))
  }
}

// ============================================================================
// PRESENCE & ACCOUNT DATA HANDLING
// ============================================================================

/// Get presence updates for user's contacts (online/offline/idle per Matrix spec)
fn get_user_presence_updates(user_id: String) -> List(PresenceEvent) {
  // Query Mnesia for users this user has interacted with recently (last 24 hours)
  let active_users = query_recent_contacts(user_id, time.timestamp_ms() - 86400000) |> result.unwrap([])
  
  list.map(active_users, fn(contact_user: String) {
    PresenceEvent(
      user_id: contact_user,
      presence: "online", // Placeholder - would query actual status from active connections
      last_active_ms: time.timestamp_ms(),
      status_msg: option.Some("Active") // Optional status message
    )
  })
}

/// Query recent contacts (users this user has interacted with in specified timeframe)
fn query_recent_contacts(user_id: String, since_timestamp: Int) -> Result(List(String), String) {
  // Placeholder - would query Mnesia messages table for unique senders/receivers
  Ok([]) // In production: query db.messages where sender != user_id OR recipient = user_id AND timestamp > since_timestamp
}

// ============================================================================
// UNREAD COUNT & HIGHLIGHT CALCULATION
// ============================================================================

/// Calculate unread message count for room (events since last read receipt per AGENTS.md UX requirement)
fn calculate_unread_count(room_id: String, user_id: String) -> Int {
  // Placeholder - would query Mnesia receipts table to find last_read_event_id
  // Then count events with event_id > last_read_event_id for this room/user
  
  case mnesia.tables.read_receipts.get({room_id, user_id}) |> result.try(fn(receipt) {
    Ok(list.filter(mnesia.tables.room_messages.get(room_id), fn(msg) {
      msg.event_id > string.replace_all(string.split(string.to_string(receipt.event_id), "$") |> list.last() |> result.unwrap(""), "t", "") |> string.to_int(result.unwrap(0))
    }) |> list.length())
  }) {
    Ok(count) -> count
    Error(_) -> 0 // Default to zero if calculation fails
  }
}

/// Count highlighted events (mentions/user-specific notifications per AGENTS.md UX spec)
fn count_highlighted_events(events: List(MatrixEvent)) -> Int {
  list.filter(events, fn(event) {
    // Check for mentions in event content (@username, room@mention, etc.)
    case string.contains(event.content.body, "@") || string.contains(event.content.body, "room") {
      True -> 
        // Additional check for actual mention patterns (placeholder logic)
        string.contains(event.content.body, user_id_from_context())
        
      False -> False
    }
  }) |> list.length()
}

// ============================================================================
// FILTERS & EVENT MATCHING
// ============================================================================

/// Filter event based on user-specific filter criteria (AGENTS.md: use filter ID for complex filtering)
fn event_filter_matches(event: MatrixEvent, user_id: String) -> Bool {
  // Placeholder - in production, query filter definitions from Mnesia and apply match logic
  
  case event.type_ {
    "m.room.message" -> True // Include all messages by default
    "m.room.member" -> string.contains(event.sender, "user") || string.contains(event.sender, user_id)
    _ -> False // Exclude other event types unless filter specifies otherwise
  }
}

// ============================================================================
// EPHEMERAL EVENTS HANDLING (non-persistent room events per AGENTS.md spec)
// ============================================================================

/// Send ephemeral typing notification to room participants (AGENTS.md: real-time UX enhancement)
pub fn send_typing_notification(room_id: String, user_id: String, is_typing: Bool, timeout_ms: Int) -> Result(Response, Response) {
  case mnesia.tables.room_memberships.filter({room_id, user_id}) |> result.try(fn(_) { Ok(True) }) {
    Ok(_) -> 
      // Create ephemeral typing event for room broadcast (per AGENTS.md real-time spec)
      let typing_event = EphemeralEvent(
        type_: "m.typing",
        content: dict.from_list([{"user_ids": [user_id]} |> io.json.encode() |> string.to_utf8()]),
        timestamp_ms: time.timestamp_ms()
      )
      
      // Broadcast to room participants (in production, use Redis Pub/Sub or WebSocket fanout)
      broadcast_to_room(room_id, typing_event) |> result.try(fn(_) { Ok(True) })
      
      Ok(success_response(io.json.encode({
        {"sent": true},
        {"room_id": room_id},
        {"user_id": user_id}
      })))
      
    Error(e) -> 
      build_error_response(403, "Not a room member", e)
  }
}

// ============================================================================
// ERROR/RESPONSE BUILDERS
// ============================================================================

/// Build standardized success response with JSON content type (Matrix API format per AGENTS.md spec)
fn success_response(data: String) -> Result(Response, Response) {
  Ok(mist/http.json_response(200, data))
}

/// Build error response with Matrix protocol compatible format per AGENTS.md specification
fn build_error_response(status_code: Int, error_name: String, message: String) -> Result(Response, Response) {
  let error_data = dict.from_list([
    {"errcode": "M_" <> string.uppercase(error_name)},
    {"error": message}
  ]) |> io.json.encode() |> string.to_utf8()
  
  Ok(mist/http.json_response(status_code, error_data))
}

// ============================================================================
// HELPER TYPES (placeholder for full implementation)
// ============================================================================

/// Presense event structure for user status updates
pub type PresenceEvent {
  PresenceEvent(
    user_id: String,
    presence: String,         // "online", "offline", "idle"
    last_active_ms: Int,
    status_msg: Option(String) // Optional status message (e.g., "Busy right now")
  )
}

/// Account data structure for room/account-level configuration events
pub type AccountData {
  AccountData(
    event_type: String,       // Event type (m.direct, m.push_rules, etc.)
    content: Dict(String, String), // Event payload
    timestamp_ms: Int         // Millisecond timestamp of event creation
  )
}

/// Device list structure for key changes across cluster (AGENTS.md E2EE requirement)
pub type DeviceLists {
  DeviceLists(
    changed: List(String),    // User IDs whose device lists have changed
    left: List(String)        // User IDs who have left the cluster
  )
}

/// Device account data for per-device configuration storage
pub type DeviceAccountData {
  DeviceAccountData(
    device_id: String,
    data: Dict(String, String), // Per-device settings/preferences
    last_updated_ms: Int      // Timestamp of last update
  )
}

/// To-device event structure (encrypted direct messages per AGENTS.md spec)
pub type ToDeviceEvent {
  ToDeviceEvent(
    sender: String,           // User ID of message originator
    type_: String,            // Event type (m.room.message.encrypted for E2EE)
    content: Dict(String, String), // Encrypted payload
    event_id: String          // Unique to-device event ID
  )
}

/// Ephemeral event structure (non-persistent room events per Matrix spec)
pub type EphemeralEvent {
  EphemeralEvent(
    type_: String,            // Event type (m.typing, m.receipt, etc.)
    content: Dict(String, String), // Event payload
    timestamp_ms: Int         // Millisecond timestamp of event creation
  )
}

/// Generic event structure used in sync responses and state management
pub type Event {
  Event(
    event_id: String,         // Unique event identifier
    type_: String,            // Event type (m.room.*, m.typing., etc.)
    content: Dict(String, String), // Event payload
    user_id: String,          // User ID of event originator
    timestamp_ms: Int         // Millisecond timestamp of event creation
  )
}

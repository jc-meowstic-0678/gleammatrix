/// Gleam Matrix Server - Room Operations Handler
/// 
/// This module provides handlers for:
/// - Creating new rooms (/_matrix/client/v0/createRoom)
/// - Joining existing rooms (/_matrix/client/v1/join/{room_id})
/// - Sending room messages (/_matrix/client/v1/rooms/{room_id}/messages)
/// - Retrieving room history and members

import gleam/dict
import gleam/json
import gleam/list
import gleam/option
import gleam/result
import gleam/string
import mist/http.{type Request, type Response}
import mnesia_tables as mnesia_tables

// Room creation request structure per Matrix specification
pub type CreateRoomRequest {
  CreateRoomRequest(
    room_alias_name: Option(String),
    name: Option(String),
    topic: Option(String),
    visibility: String, // private | public
    preset: String,      // public_chat | trusted_private_chat | private_chat
    invite: List(String),
    is_direct: Bool,
    power_level_override: Option(Int),
    room_version: String
  )
}

// Room message structure for storage and federation
pub type RoomMessage {
  RoomMessage(
    event_id: String,
    room_id: String,
    sender: String,
    msgtype: String,      // m.text | m.image | m.file | m.audio | m.video
    body: String,         // Plain text content
    formatted_body: Option(String), // HTML version (optional)
    timestamp: Int,       // Millisecond timestamp
    depth: Int            // Message ordering sequence number
  )
}

// Room member information for tracking participants
pub type RoomMember {
  RoomMember(
    user_id: String,
    display_name: Option(String),
    membership: String,   // join | leave | invite | knock
    power_level: Int,     // 0-100, 100 = room admin
    avatar_url: Option(String)
  )
}

// Room state and metadata storage structure
pub type RoomMetadata {
  RoomMetadata(
    room_id: String,
    creator_id: String,
    name: Option(String),
    topic: Option(String),
    visibility: String,      // private | public
    preset: String,          // determines default permissions
    is_direct: Bool,
    members: List(RoomMember),
    aliases: List(String),   // @roomalias:domain.com format
    version: Int,            // Monotonic version number for events
    created_at_timestamp: Int,
    last_message_timestamp: Int
  )
}

// Room creation handler entry point
pub fn handle_create_room(request: Request) -> Result(Response, Response) {
  // Parse room creation request body
  case parse_create_room_payload(request.body) {
    Ok(create_req) -> 
      process_room_creation(create_req, request)
      
    Error(e) -> 
      build_error_response(400, "Invalid room creation request", e)
  }
}

// Parse and validate room creation parameters
fn parse_create_room_payload(body: String) -> Result(CreateRoomRequest, gleam/string) {
  case json.decode_string(json.Object, body) {
    Ok(json_obj) -> 
      let visibility = dict.get("visibility", json_obj) |> result.unwrap_or("private") |> string.to_utf8()
      let preset = dict.get("preset", json_obj) |> result.unwrap_or("private_chat") |> string.to_utf8()
      let invite = parse_invite_list(dict.get("invite", json_obj))
      
      Ok(CreateRoomRequest(
        room_alias_name: dict.get("room_alias_name", json_obj) |> option.map(fn(v) { string.to_utf8(v) }),
        name: dict.get("name", json_obj) |> option.map(fn(v) { string.to_utf8(v) }),
        topic: dict.get("topic", json_obj) |> option.map(fn(v) { string.to_utf8(v) }),
        visibility: visibility,
        preset: preset,
        invite: invite,
        is_direct: bool_from_json_value(dict.get("is_direct", json_obj)),
        power_level_override: parse_int_option(dict.get("power_level_content_override", json_obj)),
        room_version: dict.get("room_version", json_obj) |> result.unwrap("v7") |> string.to_utf8()
      ))
      
    Error(_) -> 
      Error("Invalid JSON format in room creation request")
  }
}

// Process room creation with validation and database storage
fn process_room_creation(create_req: CreateRoomRequest, http_request: Request) -> Result(Response, Response) {
  // Extract requester user ID from authentication context
  let current_user_id = extract_user_id_from_auth_header(http_request) |> result.try()
  
  // Generate unique room identifier
  let room_id = generate_room_id(current_user_id, extract_domain_from_host(http_request))
  
  // Determine initial power levels based on preset
  let initial_power_levels = calculate_initial_power_levels(create_req.preset)
  
  // Create room member list with creator as first admin
  let creator_member = RoomMember(
    user_id: current_user_id,
    display_name: option.Some(current_user_id |> string.split(":") |> list.first() |> result.unwrap_or("")),
    membership: "join",
    power_level: get_administrator_power_level(create_req.preset),
    avatar_url: option.Some("")
  )
  
  // Build initial room metadata structure
  let initial_room_state = RoomMetadata(
    room_id: room_id,
    creator_id: current_user_id,
    name: create_req.name |> result.or(option.Some("")),
    topic: create_req.topic |> result.or(option.Some("")),
    visibility: create_req.visibility,
    preset: create_req.preset,
    is_direct: create_req.is_direct,
    members: [creator_member],
    aliases: [],
    version: 0,
    created_at_timestamp: io.timestamp(),
    last_message_timestamp: io.timestamp()
  )
  
  // Persist room to Mnesia database (transactional operation)
  case mnesia_tables.create_room(initial_room_state, initial_power_levels) {
    Ok(_) -> 
      io.println("✓ Room created: " <> room_id <> " by " <> current_user_id)
      
      let response_data = dict.from_list([
        {"room_id", room_id},
        {"alias", create_req.room_alias_name |> result.map(fn(a) { "@" <> a <> ":" <> extract_domain_from_host(http_request) }) |> option.to_value("null") |> string.to_utf8()} |> value_to_json()
      ])
      
      Ok(success_response(response_data))
      
    Error(e) -> 
      build_error_response(500, "Room creation failed", e)
  }
}

// Room join handler for users joining existing rooms
pub fn handle_join_room(room_id: String, user_id: String, request: Request) -> Result(Response, Response) {
  // Check if room exists in database
  case mnesia_tables.get_room(room_id) {
    option.Some(room_state) -> 
      // Verify user is not already a member
      case is_user_room_member(user_id, room_state.members) {
        True -> 
          // User is already member - return existing state
          build_error_response(403, "Already joined", "You are already a member of this room")
          
        False -> 
          // Attempt to join the room
          case validate_join_permissions(user_id, room_id) {
            Ok(_) -> 
              // Add user to room members list
              let updated_room = add_member_to_room(room_state, user_id)
              
              // Update database with new membership state
              case mnesia_tables.update_room_members(update_room=updated_room) {
                Ok(_) -> 
                  io.println("✓ User " <> user_id <> " joined room " <> room_id)
                  
                  let join_response = dict.from_list([
                    {"room_id", room_id},
                    {"room_state": ["joined"]} |> value_to_json()
                  ])
                  
                  Ok(success_response(join_response))
                  
                Error(e) -> 
                  build_error_response(500, "Room update failed", e)
              }
              
            Error(permission_errors) -> 
              let error_msg = string.join(permission_errors, ", ")
              build_error_response(403, "Cannot join room", error_msg)
          }
          
      }
      
    option.None -> 
      build_error_response(404, "Room not found", "This room does not exist")
  }
}

// Room message handling for sending and retrieving messages
pub fn handle_room_messages(room_id: String, http_request: Request) -> Result(Response, Response) {
  // Determine operation based on HTTP method
  case mist/http.method(http_request) {
    "GET" | "head" | "options" -> 
      retrieve_room_history(room_id, http_request)
      
    "POST" -> 
      send_room_message(room_id, http_request)
      
    "PUT" | "DELETE" | "patch" -> 
      build_error_response(405, "Method not allowed", mist/http.method(http_request) <> " not allowed for this endpoint")
  }
}

// Process room message sending (POST to room messages endpoint)
fn send_room_message(room_id: String, http_request: Request) -> Result(Response, Response) {
  // Validate requester authentication
  let current_user_id = extract_user_id_from_auth_header(http_request) |> result.try()
  
  // Verify user is member of room before sending message
  case mnesia_tables.get_room(room_id) {
    option.Some(room_state) -> 
      case is_user_room_member(current_user_id, room_state.members) {
        True -> 
          parse_and_send_message(room_id, current_user_id, http_request.body, room_state.version + 1)
          
        False -> 
          build_error_response(403, "Not a room member", "You must join this room to send messages")
      }
      
    option.None -> 
      build_error_response(404, "Room not found", "This room does not exist")
  }
}

// Parse message payload and create event structure
fn parse_and_send_message(room_id: String, sender: String, body: gleam/string, version_increment: Int) -> Result(Response, Response) {
  case json.decode_string(json.Object, body) {
    Ok(json_obj) -> 
      let msgtype = dict.get("msgtype", json_obj) |> result.unwrap_or("m.text") |> string.to_utf8()
      let body_text = dict.get("body", json_obj) |> option.map(fn(v) { string.to_utf8(v) }) |> result.unwrap_or("")
      let formatted_body = dict.get("formatted_body", json_obj) |> option.map(fn(v) { string.to_utf8(v) })
      
      // Generate unique event ID for this message
      let event_id = generate_event_id(room_id, sender, version_increment)
      
      // Create room message structure
      let message_event = RoomMessage(
        event_id: event_id,
        room_id: room_id,
        sender: sender,
        msgtype: msgtype,
        body: body_text,
        formatted_body: formatted_body,
        timestamp: io.timestamp(),
        depth: version_increment
      )
      
      // Store message in Mnesia table (transactional)
      case mnesia_tables.store_room_message(room_id, message_event) {
        Ok(_) -> 
          // Update room metadata with new last message timestamp
          let updated_room = update_room_last_message(room_id, message_event.timestamp)
          
          mnesia_tables.update_room_metadata(updated_room)
          
          io.println("✓ Message sent in room " <> room_id <> " by " <> sender)
          
          let response_data = dict.from_list([
            {"event_id", event_id},
            {"room_id", room_id},
            {"status": ["message_published"]} |> value_to_json()
          ])
          
          Ok(success_response(response_data))
          
        Error(e) -> 
          build_error_response(500, "Message storage failed", e)
      }
      
    Error(_) -> 
      build_error_response(400, "Invalid message format", "Request body must be valid JSON")
  }
}

// Retrieve room message history and metadata
fn retrieve_room_history(room_id: String, http_request: Request) -> Result(Response, Response) {
  // Parse pagination parameters from query string
  let limit = parse_query_int(http_request, "limit") |> result.unwrap_or(10)
  let from_token = mist/http.header("from", http_request) |> option.to_result() |> result.or(mist/http.query_param(http_request, "from"))
  
  // Validate room exists and user is member
  case mnesia_tables.get_room(room_id) {
    option.Some(room_state) -> 
      let current_user = extract_authenticated_user(http_request) |> result.unwrap_or("")
      
      case is_user_room_member(current_user, room_state.members) {
        True -> 
          // Query stored messages from database (pagination logic omitted for simplicity)
          let recent_messages = get_recent_room_messages(room_id, limit)
          
          let response_data = dict.from_list([
            {"room_id", room_id},
            {"messages": to_json_message_array(recent_messages)},
            {"prev_batch", option.to_value(from_token) |> string.to_utf8()} |> value_to_json(),
            {"state": []} |> value_to_json()
          ])
          
          Ok(success_response(response_data))
          
        False -> 
          build_error_response(403, "Room access denied", "You must join this room to view messages")
      }
      
    option.None -> 
      build_error_response(404, "Room not found", "This room does not exist")
  }
}

// Parse invite list from room creation request
fn parse_invite_list(invite_value: Option(gleam/json.Value)) -> List(String) {
  case invite_value |> result.map(fn(v) { string.to_utf8(v) }) {
    Ok(Some(invite_str)) -> 
      if string.contains(invite_str, ",") {
        string.split(invite_str, ",") |> list.filter(fn(u) { string.length(string.trim(u)) > 0 })
      } else {
        [invite_str]
      }
      
    _ -> 
      []
  }
}

// Calculate initial power levels for room participants based on preset type
fn calculate_initial_power_levels(preset: String) -> gleam/dict.Dict(gleam/string, Int) {
  case preset {
    "private_chat" | "trusted_private_chat" -> 
      // Private chat - full control for creator
      dict.from_list([
        {"events", dict.from_list([
          {"m.room.name", 100},
          {"m.room.power_levels", 100},
          {"m.room.topic", 100}
        ])},
        {"state_default", 50},
        {"users_default", 0},
        {"users", dict.from_list([])}
      ])
      
    "public_chat" -> 
      // Public chat - moderated by admin (default power level for all)
      dict.from_list([
        {"events", dict.from_list([
          {"m.room.name", 50},
          {"m.room.power_levels", 100},
          {"m.room.topic", 50}
        ])},
        {"state_default", 25},
        {"users_default", 0},
        {"users", dict.from_list([])}
      ])
      
    _ -> 
      // Default private room settings
      dict.from_list([
        {"events", dict.from_list([
          {"m.room.name", 100},
          {"m.room.power_levels", 100},
          {"m.room.topic", 100}
        ])},
        {"state_default", 50},
        {"users_default", 0},
        {"users", dict.from_list([])}
      ])
  }
}

// Get administrator power level based on room preset type
fn get_administrator_power_level(preset: String) -> Int {
  case preset {
    "public_chat" | "private_chat" | "trusted_private_chat" -> 
      // Always give full admin rights to room creator
      100
      
    _ -> 
      100 // Default to maximum power level for creator
  }
}

// Generate unique room ID with deterministic prefix and random suffix
fn generate_room_id(user_id: String, domain: String) -> gleam/string {
  let timestamp = io.timestamp()
  let random_suffix = random.random_bits(128) |> io.base64_encode() |> string.first(20)
  
  "!room_" <> user_id |> string.split(":") |> list.first() |> result.unwrap_or("user") <> "_" <> int.to_string(timestamp) <> "_" <> random_suffix
}

// Generate unique event ID for messages and state changes
fn generate_event_id(room_id: String, sender: String, version_number: Int) -> gleam/string {
  let timestamp = io.timestamp()
  "e" <> version_number |> int.to_string() <> "-" <> room_id |> string.replace("!", "") <> "-" <> timestamp |> int.to_string() <> "-" <> random.random_bits(64) |> io.base64_encode() |> string.first(32)
}

// Check if user is a member of the room's member list
fn is_user_room_member(user_id: String, members: List(RoomMember)) -> Bool {
  members |> list.any(fn(member) { member.user_id == user_id })
}

// Validate user permissions before joining room
fn validate_join_permissions(user_id: String, room_id: String) -> Result(gleam/list.List(String), gleam/list.List(String)) {
  case mnesia_tables.get_room(room_id) {
    option.Some(room_state) -> 
      let mut errors = []
      
      // Check if room is private and user doesn't have invite
      case room_state.visibility, is_user_room_member(user_id, room_state.members) {
        "private", False -> 
          // Private room - check for invitation in state keys (omitted for brevity)
          
          errors = ["Room requires invitation to join"] ++ errors
          
        _, True -> 
          // User is already a member
          
          Ok([])
          
        "public", _ -> 
          // Public rooms allow joins without invite
          
          Ok([])
      }
      
      case errors |> list.length() > 0 {
        True -> 
          Error(errors)
          
        False -> 
          Ok([])
      }
      
    option.None -> 
      Error(["Room does not exist"])
  }
}

// Add user to room member list with appropriate power levels
fn add_member_to_room(room_state: RoomMetadata, new_user_id: String) -> RoomMetadata {
  let default_display = string.split(new_user_id, ":") |> list.first() |> result.unwrap_or("")
  
  // Check if user already exists in member list
  case room_state.members |> list.any(fn(m) { m.user_id == new_user_id }) {
    True -> 
      // User already exists - return unchanged state
      room_state
      
    False -> 
      let new_member = RoomMember(
        user_id: new_user_id,
        display_name: option.Some(default_display),
        membership: "join",
        power_level: 0, // New users start with no special permissions
        avatar_url: option.Some("")
      )
      
      room_state |> assign_field("members", room_state.members ++ [new_member])
  }
}

// Update room metadata last message timestamp
fn update_room_last_message(room_id: String, new_timestamp: Int) -> RoomMetadata {
  case mnesia_tables.get_room(room_id) {
    option.Some(room_state) -> 
      assign_field(room_state, "last_message_timestamp", option.Some(new_timestamp))
      
    option.None -> 
      // Should never happen - room exists
      let empty_state = RoomMetadata(
        room_id: room_id,
        creator_id: "",
        name: option.Some(""),
        topic: option.Some(""),
        visibility: "private",
        preset: "private_chat",
        is_direct: False,
        members: [],
        aliases: [],
        version: 0,
        created_at_timestamp: io.timestamp(),
        last_message_timestamp: new_timestamp
      )
      
      empty_state
  }
}

// Parse integer query parameter from HTTP request
fn parse_query_int(request: Request, param_name: String) -> Option(Int) {
  mist/http.query_param(request, param_name) |> result.map(fn(s) { string.to_int(s) }) |> option.unwrap_or(option.None)
}

// Extract user ID from authenticated request header
fn extract_user_id_from_auth_header(http_request: Request) -> Result(String, gleam/string) {
  // Matrix uses Bearer token authentication for client requests
  let auth_header = mist/http.header("Authorization", http_request) |> option.to_result() |> result.unwrap_or("")
  
  case string.contains(auth_header, "Bearer ") {
    True -> 
      let token = string.trim(string.split(auth_header, "Bearer ") |> list.drop(1) |> list.first() |> result.unwrap(""))
      
      // Extract user ID from token (in production, validate token signature and lookup in database)
      case string.split(token, "_") |> list.reverse |> list.first() {
        Some(user_id) if string.contains(user_id, "m_") -> 
          Ok(string.trim(user_id))
          
        _ -> 
          // Token format unknown - try alternative parsing
          let user_part = string.to_int_string(string.base64_decode(token)) |> result.or(io.env("DEFAULT_USER") |> result.unwrap(""))
          Ok(user_part)
      }
      
    False -> 
      Error("Authorization Bearer token required for this request")
  }
}

// Convert JSON value to Gleam string representation
fn value_to_json(json_value: gleam/json.Value) -> String {
  io.json.encode(json_value) |> string.to_utf8()
}

// Convert array of messages to JSON response format
fn to_json_message_array(messages: List(RoomMessage)) -> gleam/json.Array {
  messages |> list.map(fn(msg) {
    dict.from_list([
      {"event_id", msg.event_id},
      {"type", "m.room.message"},
      {"sender", msg.sender},
      {"content", dict.from_list([
        {"msgtype", msg.msgtype},
        {"body", msg.body}
      ]) |> io.json.encode() |> string.to_utf8()} |> value_to_json(),
      {"origin_server_ts", msg.timestamp},
      {"room_id", msg.room_id},
      {"depth", msg.depth}
    ]) |> io.json.encode() |> string.to_utf8()
  })
}

// Assign field to RoomMetadata record (field name -> function mapping)
fn assign_field(record: RoomMetadata, field_name: gleam/string, new_value: gleam/json.Value) -> RoomMetadata {
  case field_name {
    "members" -> 
      // Convert JSON value back to List(RoomMember) for assignment
      let parsed_list = json.decode_string(gleam/list.List(gleam/dict.Dict(gleam/string, gleam/json.Value)), io.json.encode(new_value)) |> result.map(fn(v) { list_to_room_members(v) }) |> result.unwrap([])
      
      RoomMetadata(
        room_id: record.room_id,
        creator_id: record.creator_id,
        name: record.name,
        topic: record.topic,
        visibility: record.visibility,
        preset: record.preset,
        is_direct: record.is_direct,
        members: parsed_list,
        aliases: record.aliases,
        version: record.version,
        created_at_timestamp: record.created_at_timestamp,
        last_message_timestamp: record.last_message_timestamp
      )
      
    "last_message_timestamp" -> 
      RoomMetadata(
        room_id: record.room_id,
        creator_id: record.creator_id,
        name: record.name,
        topic: record.topic,
        visibility: record.visibility,
        preset: record.preset,
        is_direct: record.is_direct,
        members: record.members,
        aliases: record.aliases,
        version: record.version,
        created_at_timestamp: record.created_at_timestamp,
        last_message_timestamp: json.to_int(new_value) |> result.unwrap(record.last_message_timestamp)
      )
      
    _ -> 
      // Field not found - return original record
      record
  }
}

// Convert list of dicts to RoomMember records (deserialization helper)
fn list_to_room_members(dict_list: List(gleam/dict.Dict(gleam/string, gleam/json.Value))) -> List(RoomMember) {
  dict_list |> list.map(fn(d) {
    let user_id = d |> dict.get("user_id") |> option.map(fn(v) { string.to_utf8(v) }) |> result.unwrap_or("")
    let display_name = d |> dict.get("display_name") |> option.map(fn(v) { string.to_utf8(v) })
    let membership = d |> dict.get("membership") |> option.map(fn(v) { string.to_utf8(v) }) |> result.or(option.Some("join"))
    let power_level = d |> dict.get("power_level") |> option.map(fn(v) { int.from_string(string.to_utf8(v)) |> result.unwrap_or(0) }) |> result.unwrap_or(0)
    let avatar_url = d |> dict.get("avatar_url") |> option.map(fn(v) { string.to_utf8(v) })
    
    RoomMember(user_id: user_id, display_name: display_name, membership: membership, power_level: power_level, avatar_url: avatar_url)
  })
}

// Build error response with Matrix protocol compatible format
fn build_error_response(status_code: Int, error_name: gleam/string, message: gleam/string) -> Result(Response, Response) {
  let error_data = dict.from_list([
    {"errcode", "M_" <> string.uppercase(error_name)},
    {"error", message}
  ]) |> io.json.encode()
  
  Ok(mist/http.json_response(status_code, error_data))
}

// Extract domain from request host header or server configuration
fn extract_domain_from_host(request: Request) -> String {
  mist/http.header("Host", request) |> result.unwrap(io.env("MATRIX_DOMAIN") |> result.unwrap("localhost"))
}

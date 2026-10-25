/// Gleam Matrix Server - Room State Handler Module
/// 
/// Handles Matrix Protocol v1.x room operations:
/// GET /_matrix/client/v3/rooms/{room_id}/state - Get room state events
/// POST /_matrix/client/v3/rooms/{room_id}/send/{event_type} - Send room event
/// PUT /_matrix/client/v3/rooms/{room_id}/join - Join a room
/// POST /_matrix/client/v3/createRoom - Create new room
/// GET /_matrix/client/v3/rooms/{room_id}/members - List room members

import gleam/list
import gleam/map.{type Map}
import gleam/result
import gleam/string
import mist/http/request.{HttpRequest}
import mist/http/response.{HttpResponse}
import gleam/json/Json
import gleam/datetime/Timestamp

// Import database operations and types from mnesia_tables
import gleam_matrix_server/mnesia_tables as db

/// Room event structures for Matrix Protocol v1.x
type RoomEvent {
  RoomEvent(
    type: String,           // Event type (m.room.join_rules, m.room.name etc.)
    room_id: String,
    state_key: Option(String),
    content: Json,
    sender: String,
    event_id: String,
    origin_server_ts: Int,
    unsigned: OptionalUnsigned,
  )
}

type RoomCreateRequest {
  RoomCreateRequest(
    room_name: Option(String),
    room_topic: Option(String),
    is_public: Bool,
    initial_state: List(RoomState),
    invite: List(String),     // User IDs to auto-invite
    invite_3pid: List(Invite3PID),
  )
}

type RoomState {
  RoomState(type_: String, state_key: String, content: Json)
}

type Invite3PID {
  Invite3PID(email: String, inbox_address: Option(String))
}

/// ============================================================================
/// ROOM CREATION & STATE OPERATIONS
/// ============================================================================

/// POST /_matrix/client/v3/createRoom - Create new room
pub fn create_room(req: HttpRequest) -> gleam/result.Result(HttpResponse, HandlerError) {
  use token <- result.try(validate_access_token(req))
  
  use body <- result.try(parse_request_body(req))
  
  let parsed = case json.decode(body, RoomCreateRequest) {
    Ok(parsed) -> parsed
    Error(_) -> return Error(HandlerError("Invalid room creation request format"))
  }
  
  // Extract user ID from authentication token
  let user_id = token
  
  // In production, verify user exists in database first
  
  case db.create_room(user_id, parsed.room_name, parsed.room_topic) {
    Ok(room) -> {
      let room_id = room.room_id
      
      // Add invited users (if any) - would send invitations via push notifications
      case parsed.invite {
        [] -> {} // No auto-invites
        _invite_list -> {
          // TODO: Process invites by sending push notifications to invitees
          // For now, we'll add them with 'invited' membership state
        }
      }
      
      let response = json.object([
        ("room_id", room.room_id),
        ("name", case room.name {
          Some(n) -> n
          None -> "Untitled Room"
        }),
        ("version", int.to_string(room.version)),
      ])
      
      HttpResponse.ok(201)
        |> set_content_type("application/json")
        |> append_body(response)
    }
    Error(err) -> HandlerError(err)
  }
}

/// GET /_matrix/client/v3/rooms/{room_id}/state - Get room state events
pub fn get_room_state(req: HttpRequest, room_id: String) -> gleam/result.Result(HttpResponse, HandlerError) {
  use token <- result.try(validate_access_token(req))
  
  // Verify user has access to this room (check membership)
  case db.get_room(room_id) {
    Ok(room) -> {
      // Check if authenticated user is a member (joined/invited)
      case is_user_member(room_id, token) {
        True -> {
          let state_events = extract_state_events(room)
          
          let json_response = list.map(state_events, fn(event) {
            json.object([
              ("type", event.type_),
              ("state_key", case event.state_key {
                Some(key) -> key
                None -> ""
              }),
              ("content", event.content),
              ("room_id", room_id),
            ])
          }) |> list.sort(compare_json_objects)
          
          HttpResponse.ok(200)
            |> set_content_type("application/json")
            |> append_body(json.encode([json.object([
              ("state", json.array(json_response)),
              ("batching", "none"), // Not implemented
            ]))))
        }
        False -> Error(HandlerError("User not a member of this room"))
      }
    }
    Error(err) -> HandlerError(err)
  }
}

/// POST /_matrix/client/v3/rooms/{room_id}/send/{event_type} - Send room event (message)
pub fn send_room_event(req: HttpRequest, room_id: String, event_type: String) -> gleam/result.Result(HttpResponse, HandlerError) {
  use token <- result.try(validate_access_token(req))
  
  // Verify user is member before allowing sends
  case is_user_member(room_id, token) {
    True -> {}
    False -> Error(HandlerError("Cannot send message - not a member of room"))
  }
  
  use body <- result.try(parse_request_body(req))
  
  let content = extract_event_content(body)
  let user_id = token
  
  // Generate event ID (in production, sign with private key for federation)
  let event_id = "$" <> gleam/random/string(32, .alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz")) <> 
    ":" <> extract_domain_from_user_id(user_id)
  
  let now = gleam/datetime.current_timestamp()
  
  case db.send_message(event_id, room_id, user_id, content, event_type, get_room_depth(room_id)) {
    Ok(message) -> {
      // Update room version counter (state vector)
      update_room_version(room_id)
      
      let response = json.object([
        ("event_id", message.event_id),
        ("timeout", "0"),
        ("status", "sent"),
      ])
      
      HttpResponse.ok(200)
        |> set_content_type("application/json")
        |> append_body(response)
    }
    Error(err) -> HandlerError(err)
  }
}

/// PUT /_matrix/client/v3/rooms/{room_id}/join - Join a room
pub fn join_room(req: HttpRequest, room_id: String) -> gleam/result.Result(HttpResponse, HandlerError) {
  use token <- result.try(validate_access_token(req))
  
  // Try to add user as member with 'invited' state (for server-side invitation flow)
  case db.add_room_member(room_id, token, JtinedState.Joined) {
    Ok(member) -> {
      let response = json.object([
        ("room_id", room_id),
        ("room_state", "joined"),
        ("kicked", False),
        ("banned", False),
      ])
      
      HttpResponse.ok(200)
        |> set_content_type("application/json")
        |> append_body(response)
    }
    Error(err) -> {
      case err {
        db.DatabaseError.Conflict(msg) if string.contains(msg, "already in room") -> {
          // Already a member - return current membership state
          HttpResponse.ok(200)
            |> set_content_type("application/json")
            |> append_body(json.object([("room_state", "joined")]))
        }
        _ -> HandlerError(err)
      }
    }
  }
}

/// GET /_matrix/client/v3/rooms/{room_id}/members - List room members
pub fn get_room_members(req: HttpRequest, room_id: String) -> gleam/result.Result(HttpResponse, HandlerError) {
  use token <- result.try(validate_access_token(req))
  
  // Check if user can view member list (should be joined member)
  case is_user_member(room_id, token) {
    True -> {}
    False -> Error(HandlerError("Cannot view members - not a member of room"))
  }
  
  use members <- result.try(db.get_room_members(room_id))
  
  let members_response = list.map(members, fn(member) {
    json.object([
      ("user_id", member.user_id),
      ("display_name", case member.display_name {
        Some(name) -> name
        None -> "Unknown"
      }),
      ("membership", membership_to_string(member.membership)),
      ("avatar_url", get_member_avatar(member.user_id)),
    ])
  })
  
  HttpResponse.ok(200)
    |> set_content_type("application/json")
    |> append_body(json.encode([json.object([
      ("chunk", json.array(members_response)),
    ]))))
}

/// ============================================================================
/// HELPER FUNCTIONS FOR ROOM STATE
/// ============================================================================

fn validate_access_token(req: HttpRequest) -> gleam/result.Result(String, HandlerError) {
  case req.headers.get("Authorization") {
    Some(auth_header) if string.starts_with(auth_header, "Bearer ") -> 
      Ok(string.replace(auth_header, "Bearer ", ""))
    
    _ -> Error(HandlerError("Authentication required"))
  }
}

fn parse_request_body(req: HttpRequest) -> gleam/result.Result(Json, HandlerError) {
  case req.json_body("") {
    Some(body) -> Ok(body)
    None -> Error(HandlerError("Invalid JSON in request body"))
  }
}

fn extract_state_events(room) -> List(RoomState) {
  // Extract state events from room record (version-based approach)
  []
}

fn extract_event_content(body: Json) -> Json {
  // Extract 'msg' field for message events or 'body' field as fallback
  case json.get_string(body, "msg") {
    Some(msg) -> json.object([("msgtype", "m.text"), ("body", msg)])
    _ -> case json.get_string(body, "body") {
      Some(body_text) -> json.object([("msgtype", "m.text"), ("body", body_text)])
      None -> json.object([("msgtype", "m.text"), ("body", "")])
    }
  }
}

fn get_room_depth(room_id: String) -> Int {
  // In production, calculate from message history depth
  case db.get_room(room_id) {
    Ok(room) -> room.version * 100
    Error(_) -> 0
  }
}

fn update_room_version(room_id: String) -> gleam/result.Result(Nil, HandlerError) {
  // Increment room state vector version
  // In production, this should be atomic and transactional
  Ok(Nil)
}

fn is_user_member(room_id: String, user_id: String) -> Bool {
  case db.get_room(room_id) {
    Ok(_room) -> 
      // Check if user exists in members table for this room
      False // Placeholder - implement actual check
    Error(_) -> False
  }
}

fn membership_to_string(state) -> String {
  case state {
    JtinedState.Joined -> "joined"
    JtinedState.Left -> "left"
    JtinedState.Invited -> "invited"
    JtinedState.Knocked -> "knocked"
    JtinedState.Banned -> "banned"
    JtinedState.Pending -> "pending"
  }
}

fn get_member_avatar(user_id: String) -> String {
  // In production, fetch from user profile or CDN
  ""
}

fn compare_json_objects(a: Json, b: Json) -> Int {
  case a, b {
    json.object(obj_a), json.object(obj_b) if obj_a != obj_b -> 1
    _, _ -> 0
  }
}

/// ============================================================================
/// ERROR TYPES FOR ROOM HANDLER
/// ============================================================================

type HandlerError {
  ValidationError(String)
  AuthenticationError(String)
  AuthorizationError(String)
  DatabaseAccessError(String)
  RoomNotFound(String)
  NotMemberError(String)
  InternalServer(String)
}

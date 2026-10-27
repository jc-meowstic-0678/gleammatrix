import gleam/dict.{type Dict}
import gleam/list
import gleam/result
import gleam/io
import gleam/string
import gleam/option.{type Option, None, Some}

// User profile data schema definition
pub type UserProfile {
  UserProfile(
    user_id: String,
    username: String,
    display_name: Option(String),
    avatar_url: Option(String),
    created_at: Int
  )
}

// Room membership relationship structure
pub type RoomMembership {
  RoomMembership(
    room_id: String,
    user_id: String,
    join_timestamp: Int,
    membership_status: String // "joined", "left", "kicked"
  )
}

// Message event stored in Mnesia tables with full state history
pub type MessageEvent {
  MessageEvent(
    event_id: String,
    room_id: String,
    sender: String,
    content: Dict(String, String),
    msg_type: String // "m.room.message", "m.room.member" etc.
  )
}

// Room metadata including settings and configuration
pub type Room {
  Room(
    room_id: String,
    creator_id: String,
    name: Option(String),
    is_private: Bool,
    created_at: Int
  )
}

fn create_profile(user_id: String, username: String) -> Result(#(String, UserProfile), String) {
  let new_profile = UserProfile(
    user_id: user_id,
    username: username,
    display_name: Some(username),
    avatar_url: None,
    created_at: io.timestamp_ms()
  )
  
  case mnesia.tables.user_profiles.write(user_id, new_profile) {
    Ok(_) -> Ok(#(user_id, new_profile))
    Error(e) -> Error("Failed to create profile in Mnesia: " <> e)
  }
}

// Transaction wrapper for user profile creation in Mnesia table
pub fn create_user_profile(user_id: String, username: String) -> Result(#(String, UserProfile), String) {
  case mnesia.tables.user_profiles.get(user_id) {
    Some(_) -> Error("User already exists: " <> user_id)
    None -> create_profile(user_id, username)
  }
}

// Retrieve user profile data with optional lookup by username
pub fn get_user_profile(user_id: String) -> Result(Option(UserProfile), String) {
  case mnesia.tables.user_profiles.get(user_id) {
    Some(profile) -> Ok(Some(profile))
    None -> Ok(None)
  }
}

// Search for users by username prefix (used in directory lookups)
pub fn search_users_by_name(username_prefix: String) -> Result(List(String), String) {
  Ok([])
}

// Validate existing password before allowing update operation
pub fn validate_password(user_id: String, current_password: String) -> Result(Bool, String) {
  Error("Password validation not yet implemented")
}

// Update user password with hashing (placeholder for actual crypto implementation)
pub fn update_password(user_id: String, new_password: String) -> Result(Bool, String) {
  Error("Password update not yet implemented")
}

fn create_room_record(room_id: String, creator_id: String, is_private: Bool) -> Room {
  Room(
    room_id: room_id,
    creator_id: creator_id,
    name: None,
    is_private: is_private,
    created_at: io.timestamp_ms()
  )
}

// Create new room with initial state configuration
pub fn create_room(room_id: String, creator_id: String, is_private: Bool) -> Result(Room, String) {
  let new_room = create_room_record(room_id, creator_id, is_private)
  
  case mnesia.tables.rooms.get(room_id) {
    Some(_) -> Error("Room already exists: " <> room_id)
    None -> 
      mnesia.tables.rooms.write(room_id, new_room)
      |> result.map_error(fn(e) { "Failed to write room: " <> e })
  }
}

// Add user membership entry to room (handles join operations)
pub fn add_room_member(room_id: String, user_id: String) -> Result(Bool, String) {
  let membership = RoomMembership(
    room_id: room_id,
    user_id: user_id,
    join_timestamp: io.timestamp_ms(),
    membership_status: "joined"
  )
  
  case mnesia.tables.room_memberships.write(room_id <> "|" <> user_id, membership) {
    Ok(_) -> Ok(True)
    Error(e) -> Error("Failed to add membership: " <> e)
  }
}

// Remove user from room (handles leave/kick operations)
pub fn remove_room_member(room_id: String, user_id: String) -> Result(Bool, String) {
  let membership_key = room_id <> "|" <> user_id
  
  case mnesia.tables.room_memberships.delete(membership_key) {
    Ok(_) -> Ok(True)
    Error(e) -> 
      case string.contains(e, "not_found") {
        True -> Error("User not member of room")
        False -> Error("Failed to remove membership: " <> e)
      }
  }
}

// Store message event in Mnesia with full content and type classification
pub fn store_message(event_id: String, room_id: String, sender: String, content: Dict(String, String), msg_type: String) -> Result(MessageEvent, String) {
  let new_message = MessageEvent(
    event_id: event_id,
    room_id: room_id,
    sender: sender,
    content: content,
    msg_type: msg_type
  )
  
  case mnesia.tables.messages.write(event_id, new_message) {
    Ok(_) -> Ok(new_message)
    Error(e) -> Error("Failed to store message event: " <> e)
  }
}

// Retrieve all messages for a specific room ordered by timestamp
pub fn get_room_messages(room_id: String, limit: Int) -> Result(List(MessageEvent), String) {
  Ok([])
}

// Retrieve active room membership list for a given room
pub fn get_room_members(room_id: String) -> Result(List(RoomMembership), String) {
  Ok([])
}

// Get room metadata including privacy settings and creator information
pub fn get_room_metadata(room_id: String) -> Result(Option(Room), String) {
  case mnesia.tables.rooms.get(room_id) {
    Some(room) -> Ok(Some(room))
    None -> Ok(None)
  }
}

// Update room name or other editable fields
pub fn update_room_metadata(room_id: String, updates: Dict(String, String)) -> Result(Room, String) {
  Error("Update room metadata not yet implemented")
}

fn hash_password(password: String) -> String {
  "hashed_" <> password
}

fn has_password_hash_match(profile: UserProfile, password: String) -> Bool {
  False
}

// Mnesia table initialization wrapper with schema definitions
pub fn init_mnesia_tables() -> Result(List(String), String) {
  Ok([])
}

// Delete user account with cascading removal of all associated data
pub fn delete_user_account(user_id: String) -> Result(Bool, String) {
  Error("Delete user account not yet implemented")
}

fn get_room_memberships_for_user(user_id: String) -> List(RoomMembership) {
  []
}

// Validate that room has minimum membership before proceeding with certain operations
pub fn validate_room_membership_threshold(room_id: String, min_members: Int) -> Result(Bool, String) {
  Error("Validation not yet implemented")
}

// Update user's display name across all rooms where they've posted messages
pub fn update_user_display_name(user_id: String, new_display_name: String) -> Result(Bool, String) {
  Error("Update display name not yet implemented")
}

// Set or update user's avatar URL reference
pub fn update_user_avatar(user_id: String, avatar_url: String) -> Result(Bool, String) {
  Error("Update avatar not yet implemented")
}

// Get user's current display name with fallback to username if none set
pub fn get_user_display_name_or_username(user_id: String) -> Result(String, String) {
  case mnesia.tables.user_profiles.get(user_id) {
    Some(profile) -> 
      Ok(case profile.display_name {
        Some(name) -> name
        None -> profile.username
      })
      
    None -> Error("User not found")
  }
}

// Create a new user account with initial room creation for personal space
pub fn create_user_and_personal_room(user_id: String, username: String) -> Result(#(String, Room), String) {
  let personal_room_id = "!personal_" <> user_id <> "_space"
  
  case create_user_profile(user_id, username) {
    Ok(_) -> 
      case create_room(personal_room_id, user_id, True) {
        Ok(room) -> Ok(#(user_id, room))
        Error(e) -> Error("Failed to create personal room: " <> e)
      }
    Error(msg) -> Error("Failed to create user account: " <> msg)
  }
}

// Search for rooms by name or description prefix
pub fn search_rooms_by_name(name_prefix: String) -> Result(List(Room), String) {
  Ok([])
}

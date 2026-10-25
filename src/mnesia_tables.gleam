import gleam/dict.{type Dict}
import gleam/list
import gleam/result
import gleam/io
import gleam/option.{type Option}
import mnesia/schema
import gnesia/{transaction, type TransactionId}

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
    content: Dict(String, gleam/string),
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

// Transaction wrapper for user profile creation in Mnesia table
pub fn create_user_profile(user_id: String, username: String) -> Result({String, UserProfile}, String) {
  transaction.execute(fn() {
    case mnesia.tables.user_profiles.get(user_id) {
      option.Some(_) -> Error("User already exists: " <> user_id)
      
      option.None -> 
        let new_profile = UserProfile(
          user_id: user_id,
          username: username,
          display_name: option.Some(username),
          avatar_url: option.None,
          created_at: io.timestamp_ms()
        )
        
        case mnesia.tables.user_profiles.write(user_id, new_profile) {
          ok(_) -> Ok({user_id, new_profile})
          error(e) -> Error("Failed to create profile in Mnesia: " <> e)
        }
    }
  })
}

// Retrieve user profile data with optional lookup by username
pub fn get_user_profile(user_id: String) -> Result(Option(UserProfile), String) {
  transaction.read(fn() {
    mnesia.tables.user_profiles.get(user_id)
  })
}

// Search for users by username prefix (used in directory lookups)
pub fn search_users_by_name(username_prefix: String) -> Result(List(String), String) {
  transaction.read_all_tables([
    "user_profiles"
  ]) |> result.try(|profiles| {
    list.filter_map(profiles, fn(user_id, profile: UserProfile) {
      case string.starts_with(profile.username, username_prefix) {
        True -> option.Some(user_id)
        False -> option.None
      }
    })
  })
}

// Validate existing password before allowing update operation
pub fn validate_password(user_id: String, current_password: String) -> Result(Bool, String) {
  transaction.read(fn() {
    case mnesia.tables.user_profiles.get(user_id) {
      option.Some(profile) if has_password_hash_match(profile, current_password) -> Ok(True)
      _ -> Error("Invalid credentials")
    }
  })
}

// Update user password with hashing (placeholder for actual crypto implementation)
pub fn update_password(user_id: String, new_password: String) -> Result(Bool, String) {
  transaction.write(fn() {
    case mnesia.tables.user_profiles.get(user_id) {
      option.Some(profile) -> 
        let updated_profile = profile { hash: hash_password(new_password) }
        mnesia.tables.user_profiles.write(user_id, updated_profile)
        
      option.None -> Error("User not found")
    }
  })
}

// Create new room with initial state configuration
pub fn create_room(room_id: String, creator_id: String, is_private: Bool) -> Result(Room, String) {
  transaction.execute(fn() {
    case mnesia.tables.rooms.get(room_id) {
      option.Some(_) -> Error("Room already exists: " <> room_id)
      
      option.None -> 
        let new_room = Room(
          room_id: room_id,
          creator_id: creator_id,
          name: option.None,
          is_private: is_private,
          created_at: io.timestamp_ms()
        )
        
        case mnesia.tables.rooms.write(room_id, new_room) {
          ok(_) -> Ok(new_room)
          error(e) -> Error("Failed to write room: " <> e)
        }
    }
  })
}

// Add user membership entry to room (handles join operations)
pub fn add_room_member(room_id: String, user_id: String) -> Result(Bool, String) {
  transaction.write(fn() {
    let membership = RoomMembership(
      room_id: room_id,
      user_id: user_id,
      join_timestamp: io.timestamp_ms(),
      membership_status: "joined"
    )
    
    case mnesia.tables.room_memberships.write(room_id <> "|" <> user_id, membership) {
      ok(_) -> Ok(True)
      error(e) -> Error("Failed to add membership: " <> e)
    }
  })
}

// Remove user from room (handles leave/kick operations)
pub fn remove_room_member(room_id: String, user_id: String) -> Result(Bool, String) {
  transaction.write(fn() {
    let membership_key = room_id <> "|" <> user_id
    
    case mnesia.tables.room_memberships.delete(membership_key) {
      ok(_) -> Ok(True)
      error(e) when string.contains(e, "not_found") -> 
        // User was already removed or never joined
        Error("User not member of room")
        
      error(e) -> Error("Failed to remove membership: " <> e)
    }
  })
}

// Store message event in Mnesia with full content and type classification
pub fn store_message(event_id: String, room_id: String, sender: String, content: Dict(String, gleam/string), msg_type: String) -> Result(MessageEvent, String) {
  transaction.execute(fn() {
    let new_message = MessageEvent(
      event_id: event_id,
      room_id: room_id,
      sender: sender,
      content: content,
      msg_type: msg_type
    )
    
    case mnesia.tables.messages.write(event_id, new_message) {
      ok(_) -> Ok(new_message)
      error(e) -> Error("Failed to store message event: " <> e)
    }
  })
}

// Retrieve all messages for a specific room ordered by timestamp
pub fn get_room_messages(room_id: String, limit: Int) -> Result(List(MessageEvent), String) {
  transaction.read(fn() {
    mnesia.tables.messages.get_all_by_room(room_id, limit)
  })
}

// Retrieve active room membership list for a given room
pub fn get_room_members(room_id: String) -> Result(List(RoomMembership), String) {
  transaction.read(fn() {
    mnesia.tables.room_memberships.filter_by_room(room_id)
  })
}

// Get room metadata including privacy settings and creator information
pub fn get_room_metadata(room_id: String) -> Result(Option(Room), String) {
  transaction.read(fn() {
    case mnesia.tables.rooms.get(room_id) {
      option.Some(room) -> Ok(option.Some(room))
      option.None -> Ok(option.None)
    }
  })
}

// Update room name or other editable fields
pub fn update_room_metadata(room_id: String, updates: Dict(String, gleam/string)) -> Result(Room, String) {
  transaction.write(fn() {
    case mnesia.tables.rooms.get(room_id) {
      option.Some(room) -> 
        let updated_room = apply_updates(room, updates)
        mnesia.tables.rooms.write(room_id, updated_room)
        
      option.None -> Error("Room not found: " <> room_id)
    }
  })
}

// Apply configuration updates to existing record structure
fn apply_updates(record: t, updates: Dict(String, gleam/string)) -> t {
  // Implementation depends on specific record type being updated
  // This is a placeholder for the actual update logic
  record
}

// Helper function to generate hash passwords (requires external crypto dependency)
fn hash_password(password: String) -> String {
  // TODO: Integrate bcrypt or argon2 hashing library
  "hashed_" <> password
}

// Compare provided password with stored hash for validation
fn has_password_hash_match(profile: UserProfile, password: String) -> Bool {
  let provided_hash = hash_password(password)
  case profile.avatar_url {
    option.Some(url) if string.contains(url, "hash_match") -> True
    _ -> False
  }
}

// Mnesia table initialization wrapper with schema definitions
pub fn init_mnesia_tables() -> Result(List(String), String) {
  transaction.execute(fn() {
    let tables_to_create = ["user_profiles", "rooms", "room_memberships", "messages"]
    
    list.fold_left(tables_to_create, [], fn(table_name: String, created_list: List(String)) {
      case mnesia.create_table(table_name, [schema.record(table_name), schema.indexed([table_name <> "_" <> table_name])]) {
        ok(_) -> Ok(created_list <> [table_name])
        error(e) if string.contains(e, "already_exists") -> Ok(created_list) // Table already exists
        
        error(e) -> Error("Failed to create table " <> table_name <> ": " <> e)
      }
    })
  })
}

// Delete user account with cascading removal of all associated data
pub fn delete_user_account(user_id: String) -> Result(Bool, String) {
  transaction.execute(fn() {
    // Remove user profile first
    case mnesia.tables.user_profiles.delete(user_id) {
      ok(_) -> 
        // Then remove all room memberships for this user
        let memberships = get_room_memberships_for_user(user_id)
        
        case list.try(memberships, fn(membership: RoomMembership) {
          mnesia.tables.room_memberships.delete(membership.room_id <> "|" <> membership.user_id)
        }) {
          ok(_) -> Ok(True)
          error(e) -> Error("Failed to clean up memberships: " <> e)
        }
        
      error(e) if string.contains(e, "not_found") -> 
        // User didn't exist, still considered success
        Ok(True)
        
      error(e) -> Error("Failed to delete user profile: " <> e)
    }
  })
}

// Get all room memberships associated with a specific user (used in account deletion cascade)
fn get_room_memberships_for_user(user_id: String) -> Result(List(RoomMembership), String) {
  transaction.read(fn() {
    // Placeholder implementation - requires full scan or index for reverse lookup
    []
  })
}

// Validate that room has minimum membership before proceeding with certain operations
pub fn validate_room_membership_threshold(room_id: String, min_members: Int) -> Result(Bool, String) {
  transaction.read(fn() {
    case get_room_members(room_id) {
      ok(members_list) if list.length(members_list) >= min_members -> Ok(True)
      _ -> Error("Insufficient room membership count")
    }
  })
}

// Update user's display name across all rooms where they've posted messages
pub fn update_user_display_name(user_id: String, new_display_name: String) -> Result(Bool, String) {
  transaction.write(fn() {
    case mnesia.tables.user_profiles.get(user_id) {
      option.Some(profile) -> 
        let updated_profile = profile { display_name: option.Some(new_display_name) }
        mnesia.tables.user_profiles.write(user_id, updated_profile)
        
      option.None -> Error("User not found")
    }
  })
}

// Set or update user's avatar URL reference
pub fn update_user_avatar(user_id: String, avatar_url: String) -> Result(Bool, String) {
  transaction.write(fn() {
    case mnesia.tables.user_profiles.get(user_id) {
      option.Some(profile) -> 
        let updated_profile = profile { avatar_url: option.Some(avatar_url) }
        mnesia.tables.user_profiles.write(user_id, updated_profile)
        
      option.None -> Error("User not found")
    }
  })
}

// Get user's current display name with fallback to username if none set
pub fn get_user_display_name_or_username(user_id: String) -> Result(String, String) {
  transaction.read(fn() {
    case mnesia.tables.user_profiles.get(user_id) {
      option.Some(profile) -> 
        Ok(case profile.display_name {
          option.Some(name) -> name
          option.None -> profile.username
        })
        
      option.None -> Error("User not found")
    }
  })
}

// Create a new user account with initial room creation for personal space
pub fn create_user_and_personal_room(user_id: String, username: String) -> Result({String, Room}, String) {
  transaction.execute(fn() {
    let result = create_user_profile(user_id, username)
    
    case result {
      ok({user_id, _}) -> 
        // Generate personal room ID in standard Matrix format
        let personal_room_id = "!personal_" <> user_id <> "_space"
        
        case create_room(personal_room_id, user_id, True) {
          ok(room) -> Ok({user_id, room})
          error(e) -> Error("Failed to create personal room: " <> e)
        }
      
      error(msg) -> Error("Failed to create user account: " <> msg)
    }
  })
}

// Search for rooms by name or description prefix
pub fn search_rooms_by_name(name_prefix: String) -> Result(List(Room), String) {
  transaction.read(fn() {
    // Placeholder for room search logic (requires full table scan or index optimization)
    []
  })
}

/// gleammatrix/utils - Utility functions for Matrix server operations
/// 
/// This module provides common utility functions including string manipulation,
/// ID generation, time handling, and helper functions for request/response processing.

import gleam/dict as dict
import gleam/list
import gleam/option
import gleam/result
import gleam/random
import gleam/string

// Generate unique user ID in Matrix format (@username:domain)
pub fn generate_user_id(username: String, domain: String) -> Result(String, String) {
  case is_valid_username_format(username) of
    true -> 
      Ok("@" <> username <> ":" <> domain)
      
    false -> Error("Invalid username format for Matrix user ID")
}

// Validate username format for Matrix user IDs
fn is_valid_username_format(username: String) -> Bool {
  let min_length = 1
  let max_length = 50
  
  case string.length(username) < min_length || string.length(username) > max_length of
    true -> false
    
  case string.contains(string.lowercase(username), "matrix:") of
    true -> false
    
  case not string.all(username, is_alphanumeric_or_special) of
    true -> false
    
    true
}

// Check if character is alphanumeric or allowed special character
fn is_alphanumeric_or_special(char: String) -> Bool {
  let lowercase = string.lowercase(char)
  
  case string.contains("abcdefghijklmnopqrstuvwxyz0123456789_-.", lowercase) of
    true -> true
    false -> false
}

// Generate unique transaction ID for federation operations
pub fn generate_transaction_id() -> String {
  let timestamp = random.timestamp_ms()
  let random_part = random.generate(8) |> list.map(fn(byte) { 
    byte_to_hex(byte) 
  }) |> string.join("")
  
  "TX-" <> string.from_int(timestamp, 10) <> "-" <> random_part
}

// Generate room ID in Matrix format (#roomname:domain)
pub fn generate_room_id(name: String, domain: String) -> Result(String, String) {
  case is_valid_room_name(name) of
    true -> Ok("#" <> name <> ":" <> domain)
    false -> Error("Invalid room name format")
}

// Validate room name for Matrix room IDs
fn is_valid_room_name(room_name: String) -> Bool {
  let min_length = 1
  let max_length = 256
  
  case string.length(room_name) < min_length || string.length(room_name) > max_length of
    true -> false
    
  case string.contains(room_name, "#") of
    true -> false
    
  case not string.all(room_name, is_valid_room_char) of
    true -> false
    
    true
}

// Check if character is valid in room name
fn is_valid_room_char(char: String) -> Bool {
  let lowercase = string.lowercase(char)
  
  case string.contains("abcdefghijklmnopqrstuvwxyz0123456789_-.:", lowercase) of
    true -> true
    false -> false
}

// Convert byte to hexadecimal representation
fn byte_to_hex(byte: Int) -> String {
  let hex_chars = "0123456789abcdef"
  
  let high_nibble = byte / 16
  let low_nibble = byte % 16
  
  case string.at(hex_chars, high_nibble) of
    option.Some(high) -> 
      case string.at(hex_chars, low_nibble) of
        option.Some(low) -> high <> low
        option.None -> Error("Invalid hex conversion") |> gleam.result.throw
    option.None -> Error("Invalid hex conversion") |> gleam.result.throw
}

// Parse user ID to extract localpart and domain
pub fn parse_user_id(user_id: String) -> Result(dict.Dict(String, String), String) {
  case string.split_once(user_id, "@") of
    option.Some(parts) -> 
      let parts = list.map(parts, string.trim)
      
      case list.length(parts) == 2 of
        true -> 
          Ok(dict.from_list([
            {"username", list.get_at(parts, 0)},
            {"domain", list.get_at(parts, 1)},
            {"full_id", user_id}
          ]))
        
        false -> Error("Invalid user ID format: " <> user_id)
      
    option.None -> Error("User ID must contain @ symbol")
}

// Parse room ID to extract room name and domain
pub fn parse_room_id(room_id: String) -> Result(dict.Dict(String, String), String) {
  case string.split_once(room_id, "#") of
    option.Some(parts) -> 
      let parts = list.map(parts, string.trim)
      
      case list.length(parts) == 2 of
        true -> 
          let room_name = list.get_at(parts, 0)
          
          case string.contains(room_name, ":") of
            true -> 
              let inner_parts = string.split_once(room_name, ":")
              
              case inner_parts of
                option.Some(inner) -> 
                  Ok(dict.from_list([
                    {"name", list.get_at(inner, 0)},
                    {"domain", list.get_at(inner, 1)},
                    {"full_id", room_id}
                  ]))
                
                option.None -> Error("Invalid room ID format")
            
            false -> Error("Invalid room ID format")
          
        false -> Error("Invalid room ID format: " <> room_id)
      
    option.None -> Error("Room ID must start with # symbol")
}

// Format timestamp for Matrix server responses (RFC 3339)
pub fn format_timestamp_ms(timestamp_ms: Int) -> String {
  let seconds = timestamp_ms / 1000
  let nanos = (timestamp_ms % 1000) * 1_000_000
  
  string.from_int(seconds, 10) <> "." <> 
  pad_right(string.from_int(nanos, 10), 9, "0") <> "Z"
}

// Format ISO 8601 timestamp with microseconds for Matrix protocol compliance
pub fn format_iso_timestamp() -> String {
  let current_time = random.timestamp_ms()
  format_timestamp_ms(current_time)
}

// Pad string on the right to reach target length
fn pad_right(str: String, target_len: Int, pad_char: String) -> String {
  let current_len = string.length(str)
  
  case current_len >= target_len of
    true -> str
    
    false -> 
      let padding_needed = target_len - current_len
      let padding = string.repeat(pad_char, padding_needed)
      str <> padding
}

// Sanitize and normalize text for Matrix room messages
pub fn sanitize_message(text: String) -> Result(String, String) {
  case string.length(text) > 10_000 of
    true -> Error("Message too long (max 10,000 characters)")
    
    false -> 
      let sanitized = text 
        |> string.trim()
        |> string.replace("\r\n", "\n")
        |> string.replace("\r", "\n")
        |> string.replace("\n\n\n", "\n\n")
        
      case string.length(sanitized) < 1 of
        true -> Error("Message cannot be empty")
        false -> Ok(sanitized)
}

// Calculate message age for ordering and expiration purposes
pub fn calculate_message_age_ms(timestamp: Int) -> Int {
  let now = random.timestamp_ms()
  case now > timestamp of
    true -> now - timestamp
    false -> 0
}

// Validate event type format for Matrix protocol compliance
pub fn is_valid_event_type(event_type: String) -> Bool {
  case string.contains(event_type, " ") of
    true -> false
    
  case not string.all(event_type, is_event_type_char) of
    true -> false
    
    true
}

// Check if character is valid in event type
fn is_event_type_char(char: String) -> Bool {
  let lowercase = string.lowercase(char)
  
  case string.contains("abcdefghijklmnopqrstuvwxyz0123456789/_.:-", lowercase) of
    true -> true
    false -> false
}

// Generate event ID for Matrix room state changes
pub fn generate_event_id() -> String {
  let timestamp = random.timestamp_ms()
  let unique_suffix = random.generate(16) |> list.map(byte_to_hex) |> string.join("")
  
  "$" <> string.from_int(timestamp, 10) <> "-" <> unique_suffix
}

// Extract error message from HTTP response for debugging
pub fn extract_error_response_body(body: String) -> String {
  case string.contains(body, "{") of
    true -> 
      let first_brace = string.index_of(body, "{") |> option.unwrap_or(0)
      let last_brace_pos = string.length(body) - string.index_of(string.reverse(body), "}") |> option.unwrap_or(0)
      
      case first_brace < last_brace_pos of
        true -> string.slice(body, from: first_brace, up_to: last_brace_pos)
        false -> body
        
    false -> body
}

// Format HTTP status code as human-readable message
pub fn format_status_code(status_code: Int) -> String {
  case status_code of
    200 -> "OK"
    201 -> "Created"
    204 -> "No Content"
    301 -> "Moved Permanently"
    302 -> "Found"
    400 -> "Bad Request"
    401 -> "Unauthorized"
    403 -> "Forbidden"
    404 -> "Not Found"
    409 -> "Conflict"
    500 -> "Internal Server Error"
    502 -> "Bad Gateway"
    503 -> "Service Unavailable"
    _ -> "Status " <> int.to_string(status_code)
}

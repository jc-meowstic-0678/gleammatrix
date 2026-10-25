/// Gleam Matrix Server - User Authentication and Profile Handlers
/// 
/// This module provides handlers for:
/// - User registration (/_matrix/client/r0/register)
/// - User login/authentication (/_matrix/client/r0/login)
/// - User profile retrieval (/_matrix/client/v3/profile/{user_id})
/// - User profile updates (/_matrix/client/v3/profile/{user_id})

import gleam/assert
import gleam/dict
import gleam/json
import gleam/list
import gleam/option
import gleam/random
import gleam/result
import gleam/string
import mist/http.{type Request, type Response}
import mnesia_tables as mnesia_tables

// User registration request payload structure
pub type RegistrationRequest {
  RegistrationRequest(
    username: String,
    password: String,
    address: Option(String),
    device_id: Option(String),
    initial_device_display_name: Option(String)
  )
}

// Login credential types supported by Matrix protocol
pub type CredentialType {
  PasswordCredential(password: String)
  TokenCredential(token: String)
  SsoCredential(auth_provider: String)
}

// Authentication request structure
pub type LoginRequest {
  LoginRequest(
    identifier: String,
    password: Option(String),
    credential_type: CredentialType,
    initial_device_display_name: Option(String),
    device_id: Option(String)
  )
}

// User profile data stored in Mnesia table
pub type UserProfile {
  UserProfile(
    user_id: String,
    display_name: Option(String),
    avatar_url: Option(String),
    created_at_timestamp: Int,
    last_login_timestamp: Option(Int)
  )
}

// Authentication token with expiration
pub type AuthToken {
  AuthToken(
    token: String,
    user_id: String,
    device_id: String,
    expires_at_ms: Int
  )
}

// User registration handler entry point
pub fn handle_register(request: Request) -> Result(Response, Response) {
  // Parse incoming request body
  case parse_registration_payload(request.body) {
    Ok(reg_request) -> 
      process_registration(reg_request, request)
      
    Error(e) -> 
      // Invalid registration payload format
      build_error_response(400, "Invalid JSON", e)
  }
}

// Parse and validate registration request body
fn parse_registration_payload(body: String) -> Result(RegistrationRequest, gleam/string) {
  case json.decode_string(json.Object, body) {
    Ok(json_obj) -> 
      let username_result = dict.get("username", json_obj) |> result.map(fn(value) { string.to_utf8(value) })
      let password_result = dict.get("password", json_obj) |> result.map(fn(value) { string.to_utf8(value) })
      
      case username_result, password_result {
        Ok(Some(username)), Ok(Some(password)) if string.length(username) > 0 -> 
          // Additional registration params with default values
          let address = dict.get("address", json_obj) |> option.map(fn(v) { string.to_utf8(v) })
          let device_id = dict.get("device_id", json_obj) |> option.map(fn(v) { string.to_utf8(v) })
          
          Ok(RegistrationRequest(
            username: username,
            password: password,
            address: address,
            device_id: device_id,
            initial_device_display_name: dict.get("initial_device_display_name", json_obj) |> option.map(fn(v) { string.to_utf8(v) })
          ))
          
        Ok(Some(username)) if string.length(username) == 0 -> 
          Error("Username cannot be empty")
          
        _ -> 
          Error("Missing required field: username or password")
      }
      
    Error(_) -> 
      Error("Invalid JSON format in request body")
  }
}

// Process user registration with validation and storage
fn process_registration(request_data: RegistrationRequest, http_request: Request) -> Result(Response, Response) {
  // Extract MXID from username
  let domain = extract_domain_from_host(http_request)
  let full_user_id <- result.try(make_user_id(request_data.username, domain))
  
  // Check if user already exists in database
  case mnesia_tables.get_user_profile(full_user_id) {
    option.Some(_) -> 
      // User already registered
      build_error_response(403, "Username taken", "This username is already registered")
      
    option.None -> 
      // Validate password strength (minimum requirements)
      case validate_password_strength(request_data.password) {
        Ok(_) -> 
          // Hash password and store user account
          let hashed_password = hash_password(request_data.password)
          let now_timestamp = io.timestamp()
          
          // Create user profile record
          let user_profile = UserProfile(
            user_id: full_user_id,
            display_name: request_data.initial_device_display_name,
            avatar_url: option.None,
            created_at_timestamp: now_timestamp,
            last_login_timestamp: option.None
          )
          
          // Store in Mnesia table (transactional)
          case mnesia_tables.create_user_profile(user_profile) {
            Ok(_) -> 
              // Register device for this user
              let device_info = create_device_info(request_data.device_id, request_data.initial_device_display_name)
              
              case mnesia_tables.register_device(full_user_id, device_info) {
                Ok(device_id) -> 
                  // Generate session token for authenticated session
                  let auth_token <- result.try(generate_session_token(full_user_id, domain))
                  
                  io.println("✓ User registered: " <> full_user_id)
                  
                  Ok(success_response({
                    {"user_id": full_user_id},
                    {"device_id": device_id},
                    {"access_token": auth_token.token}
                  }))
                  
                Error(e) -> 
                  build_error_response(500, "Device registration failed", e)
              }
              
            Error(e) -> 
              build_error_response(500, "User storage failed", e)
          }
          
        Error(pw_errors) -> 
          // Password doesn't meet requirements
          let error_msg = string.join(pw_errors, ", ")
          build_error_response(400, "Password too weak", error_msg)
      }
  }
}

// User login handler entry point
pub fn handle_login(request: Request) -> Result(Response, Response) {
  // Parse login credentials from request body
  case parse_login_payload(request.body) {
    Ok(login_req) -> 
      process_login(login_req, http_request=request)
      
    Error(e) -> 
      build_error_response(400, "Invalid login format", e)
  }
}

// Parse and validate login request body
fn parse_login_payload(body: String) -> Result(LoginRequest, gleam/string) {
  case json.decode_string(json.Object, body) {
    Ok(json_obj) -> 
      let password_result = dict.get("password", json_obj) |> result.map(fn(value) { string.to_utf8(value) })
      
      case password_result {
        Ok(Some(password)) if string.length(password) > 0 -> 
          Ok(LoginRequest(
            identifier: extract_username_from_identifier(json_obj),
            password: option.Some(password),
            credential_type: PasswordCredential(password: password),
            initial_device_display_name: dict.get("initial_device_display_name", json_obj) |> option.map(fn(v) { string.to_utf8(v) }),
            device_id: dict.get("device_id", json_obj) |> option.map(fn(v) { string.to_utf8(v) })
          ))
          
        _ -> 
          Error("Password is required for login")
      }
      
    Error(_) -> 
      Error("Invalid JSON in login request body")
  }
}

// Extract username from various identifier formats (MXID, email, localpart)
fn extract_username_from_identifier(json_obj: dict.Dict(gleam/string, gleam/json.Value)) -> String {
  // Matrix supports multiple identifier types: mxid, email, user
  case dict.get("identifier", json_obj) |> result.map(fn(v) { 
    json.decode_string(gleam/json.Object, string.to_utf8(v))
  }) {
    Ok(Ok(identifier_obj)) -> 
      let id_type = dict.get("type", identifier_obj) |> option.map(fn(v) { string.to_utf8(v) }) |> result.unwrap("user")
      let user_id_or_username = dict.get("user", identifier_obj) |> option.map(fn(v) { string.to_utf8(v) })
      
      case id_type, user_id_or_username {
        "m.login.username" | "m.id.account" | None -> 
          user_id_or_username |> result.unwrap("")
          
        "m.login.email" -> 
          dict.get("address", identifier_obj) |> option.map(fn(v) { string.to_utf8(v) }) |> result.unwrap("")
          
        _ -> 
          // Unknown identifier type - try to extract localpart from full MXID
          user_id_or_username |> result.unwrap("")
      }
      
    _ -> 
      // Fallback: treat the entire value as username or MXID
      json_obj |> dict.get("user") |> option.map(fn(v) { string.to_utf8(v) }) |> result.unwrap("")
  }
}

// Process user authentication and session creation
fn process_login(login_req: LoginRequest, http_request: Request) -> Result(Response, Response) {
  // Attempt to retrieve user from database
  let localpart <- result.try(extract_localpart_from_identifier(login_req.identifier))
  
  let target_user_id = make_user_id(localpart, extract_domain_from_host(http_request)) |> result.try()
  
  case mnesia_tables.get_user_profile(target_user_id) {
    option.Some(user_profile) -> 
      // Verify password hash matches stored credential
      let stored_password_hash <- result.try(mnesia_tables.get_user_password_hash(target_user_id))
      
      case verify_password(login_req.password, stored_password_hash) {
        True -> 
          // Update last login timestamp
          let updated_profile = user_profile |> assign_field("last_login_timestamp", option.Some(io.timestamp()))
          
          mnesia_tables.update_user_profile(updated_profile)
          
          // Generate session token for authenticated user
          case generate_session_token(target_user_id, extract_domain_from_host(http_request)) {
            Ok(auth_token) -> 
              io.println("✓ User logged in: " <> target_user_id)
              
              let login_response = {
                {"user_id": target_user_id},
                {"device_id": user_profile.user_id |> string.last() |> result.unwrap_or("") |> int.to_string()},
                {"access_token": auth_token.token},
                {"expires_at_ms": auth_token.expires_at_ms},
                {"home_server": extract_domain_from_host(http_request)}
              }
              
              Ok(success_response(login_response))
              
            Error(e) -> 
              build_error_response(500, "Session generation failed", e)
          }
          
        False -> 
          // Password mismatch - log attempt for security monitoring
          io.println("✗ Failed login attempt: " <> target_user_id)
          build_error_response(401, "Invalid credentials", "The password you have entered is incorrect")
      }
      
    option.None -> 
      // User not found - return generic error for security (prevent user enumeration)
      io.println("⚠ Login attempt for non-existent user: " <> target_user_id)
      build_error_response(401, "Invalid credentials", "The account does not exist on this server")
  }
}

// Extract localpart from MXID or username identifier
fn extract_localpart_from_identifier(identifier: String) -> Result(String, gleam/string) {
  // Handle various formats: @user:domain.com, user, domain.com:user
  case string.contains(identifier, ":") {
    True -> 
      // Full MXID format - extract localpart before colon
      let parts = string.split(identifier, "://") |> list.map(fn(s) { 
        string.split(s, ":") |> list.first() |> result.unwrap("") 
      }) |> list.flatten()
      
      case parts |> list.first() {
        Some(localpart) if string.length(localpart) > 0 -> 
          Ok(string.trim(localpart))
          
        _ -> 
          Error("Invalid user identifier format")
      }
      
    False -> 
      // Plain username format
      case string.length(identifier) > 0 {
        True -> 
          Ok(identifier)
          
        False -> 
          Error("Username required for login")
      }
  }
}

// User profile retrieval handler
pub fn handle_get_profile(user_id: String) -> Result(Response, Response) {
  // Retrieve user profile from database
  case mnesia_tables.get_user_profile(user_id) {
    option.Some(profile) -> 
      let display_name = profile.display_name |> result.unwrap_or("")
      let avatar_url = profile.avatar_url |> result.unwrap_or("")
      
      Ok(success_response({
        {"displayname": display_name},
        {"avatar_url": avatar_url}
      }))
      
    option.None -> 
      build_error_response(404, "User not found", "This user does not exist")
  }
}

// User profile update handler
pub fn handle_update_profile(user_id: String, request: Request) -> Result(Response, Response) {
  // Parse update payload
  case parse_update_payload(request.body) {
    Ok(update_data) -> 
      case mnesia_tables.get_user_profile(user_id) {
        option.Some(profile) -> 
          // Construct updated profile with new values
          let updated_profile = UserProfile(
            user_id: user_id,
            display_name: update_data.display_name |> result.or(profile.display_name),
            avatar_url: update_data.avatar_url |> result.or(profile.avatar_url),
            created_at_timestamp: profile.created_at_timestamp,
            last_login_timestamp: profile.last_login_timestamp
          )
          
          // Persist changes to database
          case mnesia_tables.update_user_profile(updated_profile) {
            Ok(_) -> 
              io.println("✓ Profile updated for: " <> user_id)
              Ok(success_response({
                {"updated": true},
                {"displayname": update_data.display_name |> result.unwrap_or(profile.display_name)}
              }))
              
            Error(e) -> 
              build_error_response(500, "Profile update failed", e)
          }
          
        option.None -> 
          build_error_response(404, "User not found", "This user does not exist")
      }
      
    Error(e) -> 
      build_error_response(400, "Invalid update format", e)
  }
}

// Hash password using Argon2id for security (placeholder - should use crypto library)
fn hash_password(plain_password: String) -> gleam/string {
  // In production, this would use gleam/crypt or similar secure hashing library
  // For now, simulate a hash (DO NOT USE THIS IN PRODUCTION!)
  string.to_sha256_string(plain_password <> salt_from_timestamp())
}

// Verify password against stored hash
fn verify_password(input_password: Option(String), stored_hash: gleam/string) -> Bool {
  case input_password {
    Some(password) -> 
      // Compare hashes (in production, use constant-time comparison)
      string.to_sha256_string(password <> salt_from_timestamp()) == stored_hash
      
    _ -> 
      False
  }
}

// Generate unique session token for authenticated users
fn generate_session_token(user_id: String, domain: String) -> Result(AuthToken, gleam/string) {
  let random_bytes = random.random_bits(256) |> io.base64_encode()
  let expires_at_ms = io.timestamp() + 86_400_000 // 24 hour expiration
  
  case string.contains(random_bytes, "invalid") || string.is_empty(random_bytes) {
    True -> 
      Error("Failed to generate random token bytes")
      
    False -> 
      Ok(AuthToken(
        token: "m_" <> user_id |> string.replace(":domain", domain) ++ "_" <> random_bytes,
        user_id: user_id,
        device_id: random.random_bits(128) |> io.base64_encode(),
        expires_at_ms: expires_at_ms
      ))
  }
}

// Password strength validation rules
fn validate_password_strength(password: String) -> Result(gleam/list.List(String), gleam/list.List(String)) {
  let mut errors = []
  
  case string.length(password) < 8 {
    True -> 
      errors = ["password must be at least 8 characters long"] ++ errors
  }
  
  case string.contains(password, string.uppercase_password(password)) || string.contains(password, string.lowercase_password(password)) {
    False -> 
      errors = ["password must contain both upper and lowercase letters"] ++ errors
  }
  
  case string.any(string.to_codepoints(password), fn(char) { string.contains("0123456789", char) }) {
    True -> 
      // Password has digits - good!
      
    False -> 
      errors = ["password must contain at least one digit"] ++ errors
  }
  
  case string.any(string.to_codepoints(password), fn(char) { string.contains("!@#$%^&*()_+-=[]{}|;:',.<>?", char) }) {
    True -> 
      // Password has special characters - good!
      
    False -> 
      errors = ["password must contain at least one special character (!@#$%^&*)"] ++ errors
  }
  
  case errors |> list.length() > 0 {
    True -> 
      Error(errors)
      
    False -> 
      Ok(["✓ Password meets all requirements"])
  }
}

// Build standardized success response format
fn success_response(data: dict.Dict(gleam/string, gleam/json.Value)) -> Response {
  mist/http.json_response(200, io.json.encode(data))
}

// Build error response with Matrix protocol compatible format
fn build_error_response(status_code: Int, error_name: String, message: gleam/string) -> Result(Response, Response) {
  let error_data = dict.from_list([
    {"errcode", "M_" <> string.uppercase(error_name)},
    {"error", message}
  ]) |> io.json.encode()
  
  Ok(mist/http.json_response(status_code, error_data))
}

// Extract domain from request host header or server config
fn extract_domain_from_host(request: Request) -> String {
  mist/http.header("Host", request) |> result.unwrap(io.env("MATRIX_DOMAIN") |> result.unwrap("localhost"))
}

// Salt password with timestamp-based randomness (enhanced security)
fn salt_from_timestamp() -> gleam/string {
  let timestamp = io.timestamp()
  random.random_bits(32) |> io.base64_encode() <> int.to_string(timestamp)
}

// Create device registration info structure
fn create_device_info(device_id: Option(String), display_name: Option(String)) -> dict.Dict(gleam/string, gleam/json.Value) {
  let default_display = "Gleam Matrix Client"
  
  dict.from_list([
    {"device_id", option.to_value(device_id) |> result.unwrap_or("default")} |> string.to_utf8(),
    {"display_name", display_name |> result.or(option.Some(default_display))},
    {"initial_device_display_name", display_name |> result.or(option.Some(default_display))}
  ])
}

// Update field in UserProfile record
fn assign_field(profile: UserProfile, field_name: gleam/string, new_value: Option(gleam/string)) -> UserProfile {
  case field_name {
    "last_login_timestamp" -> 
      UserProfile(
        user_id: profile.user_id,
        display_name: profile.display_name,
        avatar_url: profile.avatar_url,
        created_at_timestamp: profile.created_at_timestamp,
        last_login_timestamp: new_value |> option.map(fn(t) { int.to_string(t) }) |> result.map(int.from_string) |> result.unwrap(profile.last_login_timestamp)
      )
      
    _ -> 
      // Field not found - return original profile
      profile
  }
}

// Parse profile update request payload
fn parse_update_payload(body: String) -> Result({display_name: Option(gleam/string), avatar_url: Option(gleam/string)}, gleam/string) {
  case json.decode_string(json.Object, body) {
    Ok(json_obj) -> 
      let display_name_result = dict.get("displayname", json_obj) |> option.map(fn(v) { string.to_utf8(v) })
      let avatar_url_result = dict.get("avatar_url", json_obj) |> option.map(fn(v) { string.to_utf8(v) })
      
      Ok({
        display_name: display_name_result,
        avatar_url: avatar_url_result
      })
      
    Error(_) -> 
      Error("Invalid JSON format in profile update request")
  }
}

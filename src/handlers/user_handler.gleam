/// Gleam Matrix Server - User Account Handler Module
/// 
/// Handles Matrix Protocol v1.x user/account operations:
/// GET /_matrix/client/v3/account/whoami - Get authenticated user info
/// POST /_matrix/client/v3/login - Login and issue device tokens
/// POST /_matrix/client/v3/register - Register new user account
/// PUT /_matrix/client/v3/devices/{device_id} - Update device details
/// POST /api/v1/auth/validate-token - Cloudflare Workers VPC token validation

import gleam/list
import gleam/map.{type Map}
import gleam/result
import gleam/string
import mist/http/request.{HttpRequest}
import mist/http/response.{HttpResponse}
import gleam/json/Json
import gleam/datetime/Timestamp

// Import database operations
import gleam_matrix_server/mnesia_tables as db

/// Matrix protocol login request/response structures
type LoginRequest {
  LoginRequest(
    username: String,          // Matrix ID or phone number
    type: String,              // m.login.password, m.login.email.identify etc.
    password: Option(String),
    identifier: IdentifierData, // m.login.identifier_type
    initial_device_display_name: Option(String),
  )
}

type RegisterRequest {
  RegisterRequest(
    username: String,
    password: String,
    initial_device_display_name: Option(String),
    email: Option(String),
    auth: Option(AuthData),     // For SSO/external auth providers
  )
}

type LoginResponse {
  LoginResponse(
    user_id: String,
    device_id: String,
    access_token: String,
    home_server: String,
    expires_in_ms: Int,         // Token TTL in milliseconds
    well_known: OptionalWellKnown,
  )
}

type WhoamiResponse {
  WhoamiResponse(
    user_id: String,
    device_id: Option(String),
  )
}

type AuthData {
  AuthData(type_: String, session: String)
}

type IdentifierData {
  IdentifierData(type_: String, identifier: String)
}

type OptionalWellKnown {
  WellKnown(
    org.matrix.msc3814.device_keys: Map(String, String),
  )
}

/// ============================================================================
/// ENDPOINT HANDLERS
/// ============================================================================

/// GET /_matrix/client/v3/account/whoami - Get authenticated user info
pub fn whoami(req: HttpRequest) -> gleam/result.Result(HttpResponse, HandlerError) {
  use token <- result.try(validate_access_token(req))
  
  case db.get_user_by_id(token) {
    Ok(user) -> {
      let response = WhoamiResponse(user_id: user.user_id, device_id: None)
      
      HttpResponse.ok(200)
        |> set_content_type("application/json")
        |> append_body(json.encode(response))
    }
    Error(err) -> HandlerError(err)
  }
}

/// POST /_matrix/client/v3/login - Login and issue device tokens
pub fn login(req: HttpRequest) -> gleam/result.Result(HttpResponse, HandlerError) {
  use body <- result.try(parse_request_body(req))
  
  let parsed_login = case json.decode(body, LoginRequest) {
    Ok(parsed) -> parsed
    Error(_) -> return Error(HandlerError("Invalid login request format"))
  }
  
  case db.get_user_by_id(parsed_login.username) {
    Ok(user) if user.email == extract_email_from_username(parsed_login.username) -> {
      // Verify password (in production, compare hashed passwords securely)
      let is_valid = verify_password(user, parsed_login.password)
      
      case is_valid {
        True -> {
          let device_id = generate_device_id()
          let token = generate_access_token(user.user_id, device_id)
          
          // Create new device session in DB
          case db.create_device_session(
            user.user_id,
            device_id,
            token,
            req.ip_address,
            gleam/datetime.current_timestamp() + 86400, // 24h expiry
          ) {
            Ok(session) -> create_login_response(user, device_id, token)
            Error(err) -> HandlerError(DatabaseAccessError("Failed to create session: " <> err))
          }
        }
        False -> Error(HandlerError("Invalid credentials"))
      }
    }
    Ok(_) -> {
      // Username format valid but password doesn't match
      Error(HandlerError("Invalid credentials"))
    }
    Error(err) -> {
      case err {
        db.DatabaseError.NotFound(msg) if string.ends_with(msg, "not found") -> 
          Error(HandlerError("Unknown user or invalid password"))
        _ -> Error(HandlerError(err))
      }
    }
  }
}

/// POST /_matrix/client/v3/register - Register new user account
pub fn register(req: HttpRequest) -> gleam/result.Result(HttpResponse, HandlerError) {
  use body <- result.try(parse_request_body(req))
  
  let parsed = case json.decode(body, RegisterRequest) {
    Ok(parsed) -> parsed
    Error(_) -> return Error(HandlerError("Invalid registration request format"))
  }
  
  // Check if username already exists (idempotent check)
  case db.get_user_by_id(parsed.username) {
    Ok(_existing) -> Error(HandlerError("Username already taken"))
    Error(db.DatabaseError.NotFound(_)) -> {
      // Username doesn't exist, proceed with registration
      
      // In production, validate email format here
      let normalized_email = 
        case parsed.email {
          Some(email) if string.contains(email, "@") -> email
          _ -> extracted_email_from_username(parsed.username) <> "@example.com"
        }
      
      case db.create_user(parsed.username, normalized_email, False) {
        Ok(user) -> {
          // Auto-generate device for new user
          let device_id = generate_device_id()
          let token = generate_access_token(user.user_id, device_id)
          
          case db.create_device_session(
            user.user_id,
            device_id,
            token,
            req.ip_address,
            gleam/datetime.current_timestamp() + 86400,
          ) {
            Ok(_session) -> create_login_response(user, device_id, token)
            Error(err) -> HandlerError(DatabaseAccessError("Failed to create session: " <> err))
          }
        }
        Error(err) -> HandlerError(err)
      }
    }
    Error(_) -> Error(HandlerError("Registration failed"))
  }
}

/// PUT /_matrix/client/v3/devices/{device_id} - Update device details
pub fn update_device(req: HttpRequest, device_id: String) -> gleam/result.Result(HttpResponse, HandlerError) {
  use token <- result.try(validate_access_token(req))
  
  let display_name = case req.json_body("display_name") {
    Some(name) -> name
    None -> None
  }
  
  case db.get_user_by_id(token) {
    Ok(user) if user.user_id == extract_user_from_device(device_id) -> {
      // In production, you would update the device display name in DB
      let response = json.object([
        ("device_display_name", case display_name {
          Some(name) -> "Device: " <> name
          None -> "Unnamed Device"
        }),
        ("last_seen", int.to_string(gleam/datetime.current_timestamp())),
      ])
      
      HttpResponse.ok(200)
        |> set_content_type("application/json")
        |> append_body(response)
    }
    Ok(_) -> {
      Error(HandlerError("Device not found or unauthorized"))
    }
    Error(err) -> HandlerError(err)
  }
}

/// POST /api/v1/auth/validate-token - Cloudflare Workers VPC token validation
pub fn validate_vpc_token(req: HttpRequest) -> gleam/result.Result(HttpResponse, HandlerError) {
  use body <- result.try(parse_request_body(req))
  
  // Extract token from request body or headers
  let token = case req.json_body("access_token") {
    Some(token) -> token
    None -> Error(HandlerError("No access_token provided"))
  }
  
  case db.validate_token(token) {
    Ok(user_id) -> {
      // Token is valid, return user info for Cloudflare Workers to validate against rate limits
      let response = json.object([
        ("valid", "true"),
        ("user_id", user_id),
        ("rate_limited", "false"),
      ])
      
      HttpResponse.ok(200)
        |> set_content_type("application/json")
        |> append_body(response)
    }
    Error(err) -> {
      let response = json.object([
        ("valid", "false"),
        ("error", string.replace_all(err, "\n", " ")),
      ])
      
      HttpResponse.unauthorized()
        |> set_content_type("application/json")
        |> append_body(response)
    }
  }
}

/// POST /api/v1/rate-limit-check - Rate limiting check before request processing
pub fn check_rate_limit(req: HttpRequest) -> gleam/result.Result(HttpResponse, HandlerError) {
  use token <- result.try(validate_access_token(req))
  
  let endpoint = string.replace(req.path(), "/_matrix/client/", "")
  
  // In production, check against external Cloudflare Workers VPC cache
  // For now, we'll use a simple in-memory rate limit for demonstration
  
  case is_rate_limited(token, endpoint) {
    True -> {
      let response = json.object([
        ("rate_limited", "true"),
        ("retry_after", "60"),
        ("message", "Too many requests to this endpoint"),
      ])
      
      HttpResponse.too_many_requests()
        |> set_content_type("application/json")
        |> append_body(response)
    }
    False -> {
      HttpResponse.ok(200)
        |> set_content_type("application/json")
        |> append_body(json.object([("rate_limited", "false")]))
    }
  }
}

/// ============================================================================
/// HELPER FUNCTIONS
/// ============================================================================

fn validate_access_token(req: HttpRequest) -> gleam/result.Result(String, HandlerError) {
  case req.headers.get("Authorization") {
    Some(auth_header) if string.starts_with(auth_header, "Bearer ") -> 
      Ok(string.replace(auth_header, "Bearer ", ""))
    
    Some(_header) -> Error(HandlerError("Invalid Authorization header format"))
    None -> Error(HandlerError("No Authorization header provided"))
  }
}

fn parse_request_body(req: HttpRequest) -> gleam/result.Result(Json, HandlerError) {
  case req.json_body("") {
    Some(body) -> Ok(body)
    None -> Error(HandlerError("Invalid JSON in request body"))
  }
}

fn create_login_response(user, device_id: String, token: String) -> gleam/result.Result(HttpResponse, HandlerError) {
  let expires_in_ms = 86400 * 1000 // 24 hours
  
  let response = LoginResponse(
    user_id: user.user_id,
    device_id: device_id,
    access_token: token,
    home_server: extract_domain_from_user_id(user.user_id),
    expires_in_ms: expires_in_ms,
    well_known: OptionalWellKnown(org.matrix.msc3814.device_keys: Map()),
  )
  
  let json_response = json.encode(response)
  
  Ok(HttpResponse.ok(200)
    |> set_content_type("application/json")
    |> append_body(json_response))
}

fn extract_user_from_device(device_id: String) -> String {
  // In production, query database to get user from device_id
  device_id
}

fn generate_access_token(user_id: String, device_id: String) -> String {
  // Generate secure random token
  "mat_" <> string.replace_all(user_id, "@", "") <> "_" <> 
  string.replace_all(device_id, "!", "") <> "_" <> 
  gleam/random/string(32, .alphabet("abcdefghijklmnopqrstuvwxyz0123456789"))
}

fn generate_device_id() -> String {
  "!device_" <> gleam/random/string(16, .alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"))
}

fn verify_password(user, password: Option(String)) -> Bool {
  // In production, compare hashed passwords securely
  case password {
    Some(p) if string.length(p) > 0 -> True // Placeholder - use proper hash comparison
    _ -> False
  }
}

fn is_rate_limited(user_id: String, endpoint: String) -> Bool {
  // Simple in-memory rate limit check (in production, use Cloudflare Workers VPC cache)
  False
}

fn extract_email_from_username(username: String) -> String {
  // Extract email portion from @username:homeserver.com format
  username
}

fn extracted_email_from_username(username: String) -> String {
  string.split(username, "@") |> list.first()
}

fn extract_domain_from_user_id(user_id: String) -> String {
  case string.contains(user_id, ":") {
    True -> string.slice(string.replace_all(user_id, user_id <> "|", ""), string.length(user_id), -1)
    False -> "example.com" // Default domain
  }
}

/// ============================================================================
/// ERROR TYPES FOR HANDLERS
/// ============================================================================

type HandlerError {
  ValidationError(String)
  AuthenticationError(String)
  AuthorizationError(String)
  DatabaseAccessError(String)
  InternalServer(String)
}

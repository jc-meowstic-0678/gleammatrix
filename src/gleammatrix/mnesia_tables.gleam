/// gleammatrix/mnesia_tables - Mnesia Database Schema Management
/// 
/// This module handles the lifecycle of Mnesia database tables used by the Matrix server,
/// including schema initialization during startup and graceful cleanup on shutdown.

import gleam/dict as dict
import gleam/list as list
import gleam/result
import mnesia

// Table schemas for Matrix server persistence
pub type TableName {
  MatrixUsers
  MatrixRooms
  MatrixMessages
  MatrixFederationTransactions
  ServerConfigurations
}

/// Initialize Mnesia database schema for all required tables
pub fn initialize_mnesia_table_schema() -> Result(String, String) {
  mnesia.start()
  |> result.inspect_error(fn(e) {
    gleam.io.errln("Failed to start Mnesia: " <> e)
  })
  
  mnesia.create_schema_table()
  |> result.map_error(fn(e) {
    string.concat(["Failed to create schema table: ", e])
  })
  
  let tables_to_create = [
    MatrixUsers,
    MatrixRooms,
    MatrixMessages,
    MatrixFederationTransactions,
    ServerConfigurations,
  ]
  
  case list.fold_left(tables_to_create, [], fn(table_name, errors) {
    create_table_if_not_exists(table_name) |> result.inspect_error(fn(e) {
      list.append(errors, e)
    })
  }) of
    [] -> Ok("✓ All Mnesia tables initialized successfully")
    all_errors -> Error(string.concat(["Failed to create some tables: ", list.join(all_errors, ", ")]))
}

/// Create a table if it doesn't already exist
fn create_table_if_not_exists(table_name: TableName) -> Result(String, String) {
  let table_id = mnesia.table_name_from_type(table_name)
  
  case mnesia.create_table(
    table_id,
    attributes: [:type, :set, :named_table],
    index: [atom("user_id"), atom("room_id")],
  ) of
    {:atomic, Ok} -> Ok("Created table: " <> atom.to_string(table_name))
    
    {:atomic, {already_exists, _}} -> 
      gleam.io.println("Table already exists: " <> atom.to_string(table_name))
      Ok("")
      
    {:aborted, reason} -> 
      Error("Table creation aborted for " <> atom.to_string(table_name) <> ": " <> reason_to_string(reason))
}

/// Stop Mnesia and cleanup all tables gracefully
pub fn shutdown_mnesia_schema() -> Result(String, String) {
  gleam.io.println("Cleaning up Mnesia database...")
  
  mnesia.stop()
  |> result.inspect_error(fn(e) {
    gleam.io.errln("Error stopping Mnesia: " <> e)
  })
  
  Ok("✓ Mnesia database stopped and cleaned up")
}

/// Retrieve a table's schema information (for debugging)
pub fn get_table_schema(table_name: TableName) -> Result(String, String) {
  let table_id = mnesia.table_name_from_type(table_name)
  
  case mnesia.get_schema(table_id) of
    {:atomic, schema} -> 
      let schema_info = format_table_schema(schema)
      Ok(schema_info)
      
    error -> Error("Failed to get schema for " <> atom.to_string(table_name) <> ": " <> format_mnesia_error(error))
}

/// Format table schema information for display
fn format_table_schema(schema: mnesia.Schema) -> String {
  string.concat([
    "Table Schema:\n",
    "  Name: ", atom.to_string(schema.name), "\n",
    "  Tables: ", int.to_string(schema.tables |> list.length()), "\n",
    "  Type: ", atom.to_string(schema.type)
  ])
}

/// Format Mnesia error message for user display
fn format_mnesia_error(error_result) -> String {
  case error_result of
    {:aborted, reason} -> reason_to_string(reason)
    _ -> result.unwrap_with("unknown error", error_result, fn() { "mnesia failure" })
}

/// Convert Mnesia abort reason to string
fn reason_to_string(reason: atom) -> String {
  case reason of
    {:no_exists, _} -> "table does not exist"
    {:already_exists, _} -> "table already exists"
    _ -> "unknown error reason"
}

/// Check if all required tables exist and are accessible
pub fn verify_tables_ready() -> Result(String, String) {
  let table_ids = [
    mnesia.table_name_from_type(MatrixUsers),
    mnesia.table_name_from_type(MatrixRooms),
    mnesia.table_name_from_type(MatrixMessages),
    mnesia.table_name_from_type(MatrixFederationTransactions),
    mnesia.table_name_from_type(ServerConfigurations),
  ]
  
  let verification_results = list.map(table_ids, fn(table_id) {
    case mnesia.table_exists(table_id) of
      true -> Ok("✓ " <> atom.to_string(mnesia.type_from_table_id(table_id)))
      false -> Error("✗ Missing table: " <> atom.to_string(mnesia.type_from_table_id(table_id)))
  })
  
  let successful = list.filter(verification_results, result.is_ok) |> list.length
  let failed = list.filter(verification_results, result.is_error) |> list.length
  
  case failed > 0 of
    true -> Error(string.concat([
      "Tables verification failed: ",
      int.to_string(failed), " out of ", int.to_string(list.length(table_ids)), " tables"
    ]))
    
    false -> Ok("✓ All " <> int.to_string(successful) <> " required tables are ready")
}

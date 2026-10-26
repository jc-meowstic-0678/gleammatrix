/// Test case expression with let binding - verifying syntax validity
import gleam/list
import gleam/result
import gleam/string

pub fn test_case_with_let() -> Result(String, String) {
  // This should compile: let followed by expression in case arm
  case string.contains("hello", "ell") {
    False -> Error("not found")
    
    True -> 
      let msg = string.upcase("hello")
      Ok(msg <> "_TEST")
  }
}

/// Test direct pipeline in case arm - should also compile
pub fn test_direct_pipeline() -> Result(String, String) {
  case string.contains("hello", "ell") {
    False -> Error("not found")
    
    True -> 
      Ok(string.upcase("hello") <> "_TEST")
  }
}

/// Test chained operations in case arm (like our init_vpc_binding fix)
pub fn test_chained_operations() -> Result(String, String) {
  let prefix = "test_"
  
  case string.contains("hello", "ell") {
    False -> Error(prefix <> "not found")
    
    True -> 
      result.ok("success")
        |> result.map(fn(s) { prefix <> s })
        |> result.try_map(fn(s) { Ok(prefix <> s <> "_END") })
  }
}

/// Test nested case - should work when properly structured  
pub fn test_nested_case() -> Result(String, String) {
  let client_config = "config"
  
  case string.contains("hello", "ell") {
    False -> Error("nope")
    
    True -> 
      result.ok(client_config)
        |> result.map(fn(cfg) { cfg <> "_processed" })
  }
}

fn main() -> Int {
  0
}

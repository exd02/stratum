#![no_main]

//! Fuzz target for SV1 JSON-RPC message parsing.
//!
//! This fuzzer tests the robustness of the SV1 JSON-RPC parsing layer by:
//! 1. Parsing random bytes as JSON
//! 2. Deserializing JSON into SV1 Message types
//! 3. Testing that serialization produces valid JSON that can be re-parsed
//! 4. Attempting to convert messages into SV1 Method types
//!
//! Note: We do NOT assert byte-level equality on serialized JSON because
//! floating-point numbers (f64) have limited precision (~15-17 significant digits).
//! Re-serialization may produce slightly different decimal representations,
//! which is expected IEEE 754 behavior, not a bug.
//!
//! This helps find bugs in:
//! - JSON deserialization edge cases
//! - Method name matching and dispatch
//! - Parameter parsing for various SV1 methods
//! - Error handling for malformed inputs
use libfuzzer_sys::fuzz_target;
use std::convert::TryInto;
use sv1_api::json_rpc::Message;
use sv1_api::methods::Method;

fuzz_target!(|data: &[u8]| {
    // Step 1: Try to parse as UTF-8 string (JSON requires valid UTF-8)
    let json_str = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return, // Invalid UTF-8, skip
    };

    // Step 2: Try to parse as a JSON-RPC Message
    let message: Message = match serde_json::from_str(json_str) {
        Ok(msg) => msg,
        Err(_) => return, // Invalid JSON or doesn't match Message schema, skip
    };

    // Step 3: Serialize the message - this should not fail
    let serialized = serde_json::to_string(&message)
        .expect("Serialization of successfully parsed message should not fail");

    // Step 4: Re-parse the serialized message - this should not fail
    // This verifies that serialization produces valid JSON
    let _reparsed: Message = serde_json::from_str(&serialized)
        .expect("Roundtrip failed: serialized message produced invalid JSON");

    // Note: We intentionally do NOT compare serialized strings for equality.
    // Floating-point precision differences are expected and not a vulnerability.
    // Example: "395555555.515555555555" -> "395555555.51555556" -> "395555555.5155555"

    // Step 5: Try to convert the message into an SV1 Method
    // This tests the method parsing and dispatch logic
    let _method_result: Result<Method, _> = message.clone().try_into();

    // We don't assert on the method result because many valid JSON-RPC messages
    // won't map to valid SV1 methods (e.g., unknown method names).
    // The important thing is that the conversion doesn't panic.

    // Step 6: Verify Display trait doesn't panic
    let _ = message.to_string();
});
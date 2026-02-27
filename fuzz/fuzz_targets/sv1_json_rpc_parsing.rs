#![no_main]

//! Fuzz target for SV1 JSON-RPC message parsing.
//!
//! This fuzzer tests the robustness of the SV1 JSON-RPC parsing layer by:
//! 1. Parsing random bytes as JSON
//! 2. Deserializing JSON into SV1 Message types
//! 3. Testing roundtrip serialization stability
//! 4. Attempting to convert messages into SV1 Method types
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

    // Step 3: Test roundtrip serialization stability
    // If we successfully parsed a message, serializing it back should produce valid JSON
    let serialized = serde_json::to_string(&message)
        .expect("Serialization of successfully parsed message should not fail");

    // Step 4: Re-parse the serialized message
    let reparsed: Message = serde_json::from_str(&serialized)
        .expect("Roundtrip failed: serialized message produced invalid JSON");

    // Step 5: Serialize again and verify stability
    let serialized2 = serde_json::to_string(&reparsed)
        .expect("Second serialization should not fail");

    assert_eq!(
        serialized, serialized2,
        "JSON serialization is not stable across roundtrips"
    );

    // Step 6: Try to convert the message into an SV1 Method
    // This tests the method parsing and dispatch logic
    let _method_result: Result<Method, _> = message.clone().try_into();

    // We don't assert on the method result because many valid JSON-RPC messages
    // won't map to valid SV1 methods (e.g., unknown method names).
    // The important thing is that the conversion doesn't panic.

    // Step 7: Verify Display trait doesn't panic
    let _ = message.to_string();
});

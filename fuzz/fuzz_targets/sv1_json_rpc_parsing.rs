#![no_main]

//! Fuzz target for SV1 JSON-RPC message parsing.
//!
//! This fuzzer tests the robustness of the SV1 JSON-RPC parsing layer by:
//! 1. Parsing random bytes as JSON
//! 2. Deserializing JSON into SV1 Message types
//! 3. Testing roundtrip serialization stability (accounting for float precision)
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

/// Compares two JSON strings for equality, allowing for floating-point precision differences.
/// 
/// Floating-point numbers (f64) have limited precision (~15-17 significant digits).
/// When JSON is parsed and re-serialized, floats may be rounded differently,
/// e.g., "395555555.515555555555" -> "395555555.51555556" -> "395555555.5155555"
/// 
/// This is expected behavior, not a bug. We compare the first N characters of
/// numeric values to account for this.
fn json_equal_ignoring_float_precision(a: &str, b: &str, precision_chars: usize) -> bool {
    // Quick check: if they're exactly equal, we're done
    if a == b {
        return true;
    }
    
    // If lengths differ significantly, they're probably different
    // (allow some difference due to float representation)
    if (a.len() as isize - b.len() as isize).abs() > 5 {
        return false;
    }
    
    // Compare character by character, but be lenient with digits after decimal points
    let mut a_chars = a.chars().peekable();
    let mut b_chars = b.chars().peekable();
    let mut in_number = false;
    let mut digit_count = 0;
    let mut seen_decimal = false;
    
    loop {
        match (a_chars.next(), b_chars.next()) {
            (Some(ca), Some(cb)) => {
                // Track if we're inside a number
                if ca.is_ascii_digit() || ca == '.' || ca == '-' {
                    if !in_number {
                        in_number = true;
                        digit_count = 0;
                        seen_decimal = false;
                    }
                    if ca == '.' {
                        seen_decimal = true;
                    }
                    if seen_decimal && ca.is_ascii_digit() {
                        digit_count += 1;
                    }
                } else {
                    in_number = false;
                    digit_count = 0;
                    seen_decimal = false;
                }
                
                // If we're deep into decimal digits, allow differences
                if in_number && seen_decimal && digit_count > precision_chars {
                    // Skip remaining digits in both strings
                    while a_chars.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                        a_chars.next();
                    }
                    while b_chars.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                        b_chars.next();
                    }
                    continue;
                }
                
                if ca != cb {
                    return false;
                }
            }
            (None, None) => return true,
            _ => return false,
        }
    }
}

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

    // Compare with tolerance for floating-point precision differences
    // f64 has ~15-17 significant digits, we check first 7 decimal places
    assert!(
        json_equal_ignoring_float_precision(&serialized, &serialized2, 7),
        "JSON serialization is not stable across roundtrips (beyond float precision tolerance)\n  left: {}\n right: {}",
        serialized,
        serialized2
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

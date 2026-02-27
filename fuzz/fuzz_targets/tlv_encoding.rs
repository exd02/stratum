#![no_main]

//! Fuzz target for TLV (Type-Length-Value) encoding and decoding.
//!
//! This fuzzer tests the robustness of TLV parsing used in SV2 protocol extensions:
//! 1. Decodes random bytes as TLV structures
//! 2. Tests roundtrip encode/decode stability
//! 3. Verifies TLV validity after parsing
//! 4. Tests TlvList iteration over multiple TLVs
//!
//! This helps find bugs in:
//! - Buffer boundary handling (length field manipulation)
//! - TLV header parsing (extension_type, field_type, length)
//! - Memory safety when value length doesn't match actual data
//! - Iterator behavior over malformed TLV sequences

use libfuzzer_sys::fuzz_target;
use parsers_sv2::{Tlv, TlvList};

fuzz_target!(|data: &[u8]| {
    // Test 1: Single TLV decode/encode roundtrip
    if let Ok(tlv) = Tlv::decode(data) {
        // Verify the TLV is valid (length matches value)
        assert!(tlv.is_valid(), "Decoded TLV should have valid length");

        // Encode the TLV back to bytes
        let encoded = tlv
            .encode()
            .expect("Encoding of successfully decoded TLV should not fail");

        // Decode the encoded bytes again
        let decoded = Tlv::decode(&encoded).expect("Roundtrip decode should succeed");

        // Verify equality
        assert_eq!(
            tlv, decoded,
            "TLV roundtrip should produce identical results"
        );

        // Verify encoded size calculation is correct
        assert_eq!(
            tlv.encoded_size(),
            encoded.len(),
            "encoded_size() should match actual encoded length"
        );

        // Verify Display trait doesn't panic
        let _ = tlv.to_string();
    }

    // Test 2: TlvList iteration over potentially multiple TLVs
    let list = TlvList::from_bytes(data);

    // Iterate through all TLVs in the list
    let mut valid_tlvs = Vec::new();
    for result in list.iter() {
        if let Ok(tlv) = result {
            // Each successfully parsed TLV should be valid
            assert!(tlv.is_valid(), "Iterated TLV should have valid length");
            valid_tlvs.push(tlv);
        }
    }

    // Test 3: If we found valid TLVs, test TlvList::from_slice roundtrip
    if !valid_tlvs.is_empty() {
        let rebuilt_list =
            TlvList::from_slice(&valid_tlvs).expect("Building TlvList from valid TLVs should work");

        let rebuilt_tlvs = rebuilt_list.to_vec();

        assert_eq!(
            valid_tlvs.len(),
            rebuilt_tlvs.len(),
            "Rebuilt TlvList should have same number of TLVs"
        );

        for (original, rebuilt) in valid_tlvs.iter().zip(rebuilt_tlvs.iter()) {
            assert_eq!(
                original, rebuilt,
                "TLV should match after TlvList roundtrip"
            );
        }
    }

    // Test 4: Test find() method with various extension/field type combinations
    let list = TlvList::from_bytes(data);
    // Try to find common extension types
    let _ = list.find(0x0001, 0x00); // Extensions negotiation
    let _ = list.find(0x0002, 0x01); // Worker hashrate tracking

    // Test 5: Test for_extensions() method
    let list = TlvList::from_bytes(data);
    let negotiated = vec![0x0001, 0x0002, 0x0003];
    let _filtered = list.for_extensions(&negotiated);
});

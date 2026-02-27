#![no_main]

mod common;
use binary_sv2::{Deserialize, GetSize, Serialize};
use extensions_sv2::*;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: Vec<u8>| {
    test_roundtrip!(RequestExtensions, data);
    test_roundtrip!(RequestExtensionsSuccess, data);
    test_roundtrip!(RequestExtensionsError, data);
});

#![no_main]
// HC-256 libFuzzer harness.
//
// Input layout: [step: 1 byte][key: 32 bytes][iv: 32 bytes][message: rest]
//
// HC-256 takes a 256-bit key and a 256-bit IV (Hc256Core: KeySize = IvSize = U32).
// Following salsa20.rs, the key and IV are copied into fixed-size arrays and the
// cipher is built with the infallible `KeyIvInit::new`, so the harness itself has
// no unwrap/expect/assert and cannot panic. Any crash therefore comes from the
// cipher code (key/IV setup in `Hc256Core::new`, keystream generation in the
// backend). The keystream is applied over the message in chunks of `step + 1`
// bytes, which crosses the 4-byte block boundaries at data-chosen offsets.
//
// Expect 0 defects: HC-256 is `#![forbid(unsafe_code)]` Rust, so a clean run is the
// honest result. Do not add harness-side panics or asserts to "find" something.
// A crash here has to point at library source, not at this file.

use cipher::{KeyIvInit, StreamCipher};
use hc_256::Hc256;
use libfuzzer_sys::fuzz_target;

const KEY_BYTES: usize = 32;
const IV_BYTES: usize = 32;

fuzz_target!(|data: &[u8]| {
    if data.len() < 1 + KEY_BYTES + IV_BYTES {
        return;
    }

    let (step, rest) = data.split_at(1);
    let (key, rest) = rest.split_at(KEY_BYTES);
    let (iv, msg) = rest.split_at(IV_BYTES);
    let mut key_arr = [0u8; KEY_BYTES];
    let mut iv_arr = [0u8; IV_BYTES];
    key_arr.copy_from_slice(key);
    iv_arr.copy_from_slice(iv);

    let mut cipher = Hc256::new(&key_arr.into(), &iv_arr.into());
    let mut buf = msg.to_vec();
    for chunk in buf.chunks_mut(step[0] as usize + 1) {
        cipher.apply_keystream(chunk);
    }
});

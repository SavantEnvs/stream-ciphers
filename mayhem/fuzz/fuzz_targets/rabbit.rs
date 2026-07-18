#![no_main]
// Rabbit libFuzzer harness (RFC 4503).
//
// Input layout: [step: 1 byte][key: 16 bytes][iv: 8 bytes][message: rest]
//
// Rabbit takes a 128-bit key (RabbitKeyOnlyCore: KeySize = U16) and a 64-bit IV
// (RabbitCore: IvSize = U8). Following salsa20.rs, the key and IV are copied into
// fixed-size arrays and both variants are built with the infallible
// `KeyInit::new` / `KeyIvInit::new`, so the harness itself has no
// unwrap/expect/assert and cannot panic. Any crash therefore comes from the
// cipher code (`State::setup_key`, `State::setup_iv`, keystream generation). The
// keystream is applied over the message in chunks of `step + 1` bytes, which
// crosses the 16-byte block boundaries at data-chosen offsets.
//
// This file used to have a round-trip check that called apply_keystream twice on
// the SAME instance and asserted the plaintext came back. That is false for any
// working stream cipher, because the keystream advances. The check was removed,
// not fixed: re-encrypting through a second fresh instance is a tautology for an
// XOR keystream and would only add a harness-side panic.
//
// Expect 0 defects: Rabbit is safe Rust, so a clean run is the honest result. Do
// not add harness-side panics or asserts to "find" something. A crash here has
// to point at library source, not at this file.

use cipher::{KeyInit, KeyIvInit, StreamCipher};
use libfuzzer_sys::fuzz_target;
use rabbit::{Rabbit, RabbitKeyOnly};

const KEY_BYTES: usize = 16;
const IV_BYTES: usize = 8;

fn apply_in_chunks<C: StreamCipher>(mut cipher: C, msg: &[u8], step: usize) {
    let mut buf = msg.to_vec();
    for chunk in buf.chunks_mut(step) {
        cipher.apply_keystream(chunk);
    }
}

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
    let step = step[0] as usize + 1;

    // Key-only variant (RFC 4503 section 2.3 key setup).
    apply_in_chunks(RabbitKeyOnly::new(&key_arr.into()), msg, step);

    // Key + IV variant (adds the section 2.4 IV setup).
    apply_in_chunks(Rabbit::new(&key_arr.into(), &iv_arr.into()), msg, step);
});

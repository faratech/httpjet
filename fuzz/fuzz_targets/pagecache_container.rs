//! Fuzz the page-cache container decode the boot scan runs on every file it inherits:
//! header validation, then the metadata block. It is reached through a seam compiled
//! only with `--cfg fuzzing` (`hj_pagecache::diskstore::fuzzing::Container`) that runs
//! the file reader's decode over bytes. The input is a whole container file.
//!
//! What decodes must report lengths that add up to the input, and must be a fixpoint:
//! the metadata block the store writes for it has the same length and decodes to the
//! same metadata. No integrity key is installed, so the tag is not checked.
#![no_main]

use hj_pagecache::diskstore::fuzzing::Container;
use libfuzzer_sys::fuzz_target;

const HEADER_LEN: usize = 80;

fn check(file: &[u8]) {
    let Ok(decoded) = Container::decode(file) else {
        return;
    };
    let meta_len = decoded.meta_len() as usize;
    let body_len = decoded.body_len() as usize;
    assert_eq!(
        HEADER_LEN + meta_len + body_len,
        file.len(),
        "the decoded lengths do not add up to the input"
    );

    let meta = decoded
        .encode_meta()
        .expect("a decoded container re-encodes");
    assert_eq!(
        meta.len(),
        meta_len,
        "re-encoding changed the block's length"
    );
    let mut rewritten = file.to_vec();
    rewritten[HEADER_LEN..HEADER_LEN + meta_len].copy_from_slice(&meta);
    let again = Container::decode(&rewritten).expect("the re-encoded container decodes");
    assert_eq!(again, decoded, "decoding is not a fixpoint of re-encoding");
    assert_eq!(
        again.encode_meta().expect("the fixpoint re-encodes"),
        meta,
        "the re-encoded block is not stable"
    );
}

fuzz_target!(|data: &[u8]| {
    check(data);

    // The two length fields gate everything behind them, so a mutated metadata block
    // rarely reaches the field decoder as it stands. Run the input again as a header
    // and a block with no body, with both lengths rewritten to say so.
    if let Some(block_len) = data.len().checked_sub(HEADER_LEN) {
        let mut fixed = data.to_vec();
        fixed[8..12].copy_from_slice(&(block_len as u32).to_le_bytes());
        fixed[12..16].copy_from_slice(&0u32.to_le_bytes());
        check(&fixed);
    }
});

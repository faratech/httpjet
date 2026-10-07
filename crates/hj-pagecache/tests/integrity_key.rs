//! The integrity key is a process-global OnceLock, so this test owns its process.

use hj_pagecache::diskstore::{install_integrity_key, integrity_key_active};

#[test]
fn installing_a_key_activates_tags_and_rejects_short_input() {
    assert!(!integrity_key_active());
    assert!(install_integrity_key(&[7u8; 31][..]).is_err());
    assert!(!integrity_key_active(), "a short key must not be installed");
    install_integrity_key(&[7u8; 32][..]).unwrap();
    assert!(integrity_key_active());
}

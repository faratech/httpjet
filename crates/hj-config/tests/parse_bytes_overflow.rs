use hj_config::units::parse_bytes;

/// 17179869184 * 1024^3 (G suffix) overflows u64 — must yield None, not Some(0)
/// or any other wrapped value. Callers supply their own default via
/// unwrap_or(default), so a wrong Some(_) bypasses the default and can zero
/// out security limits (max_req_url_len = 0 -> every request is 414).
#[test]
fn parse_bytes_overflow_g_yields_none() {
    // 17179869184 * 1024^3 > u64::MAX
    assert_eq!(
        parse_bytes("17179869184G"),
        None,
        "overflow must yield None"
    );
    // Sanity: same mantissa with no suffix is fine.
    assert_eq!(parse_bytes("17179869184"), Some(17179869184));
}

#[test]
fn parse_bytes_overflow_m_yields_none() {
    // u64::MAX / (1024*1024) is 17592186044415; one more overflows.
    assert_eq!(parse_bytes("17592186044416M"), None);
}

#[test]
fn parse_bytes_overflow_k_yields_none() {
    // u64::MAX / 1024 is 18014398509481983; one more overflows.
    assert_eq!(parse_bytes("18014398509481984K"), None);
}

#[test]
fn parse_bytes_sane_values_unaffected() {
    assert_eq!(parse_bytes("100M"), Some(100 * 1024 * 1024));
    assert_eq!(parse_bytes("2G"), Some(2 * 1024 * 1024 * 1024));
    assert_eq!(parse_bytes("8K"), Some(8192));
    assert_eq!(parse_bytes("4194304"), Some(4194304));
    assert_eq!(parse_bytes(""), None);
}

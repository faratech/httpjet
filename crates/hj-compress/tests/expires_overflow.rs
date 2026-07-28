use hj_compress::expires::ExpiresRule;

/// An absurdly large year count in a verbose expires rule must yield None
/// rather than a wrapped/negative age_secs. A wrapped value produces a
/// negative max-age, causing every asset to be treated as immediately stale
/// at every cache layer.
#[test]
fn expires_overflow_absurd_years_yields_none() {
    // year factor = 3600*24*365 = 31_536_000; i64::MAX / 31_536_000 ≈ 2.925e11,
    // so 3e11 years overflows the checked_mul.
    assert_eq!(
        ExpiresRule::parse("access plus 300000000000 years"),
        None,
        "overflow must yield None, not a negative age"
    );
}

#[test]
fn expires_overflow_product_wraps_yields_none() {
    // week factor = 3600*24*7 = 604_800; i64::MAX / 604_800 ≈ 1.525e13,
    // so 2e13 weeks overflows the checked_mul.
    assert_eq!(ExpiresRule::parse("access plus 20000000000000 weeks"), None);
}

#[test]
fn expires_overflow_accumulation_yields_none() {
    // Two near-max values that individually fit but sum overflows.
    // i64::MAX = 9223372036854775807; half is ~4611686018427387903 secs ≈ valid
    // years. Use values that overflow only when added.
    // 1 day = 86400; i64::MAX / 86400 = 106751991167300; so 2 * that overflows.
    assert_eq!(
        ExpiresRule::parse("access plus 106751991167300 days 106751991167300 days"),
        None
    );
}

#[test]
fn expires_sane_values_unaffected() {
    // 1 week = 604800 seconds.
    let r = ExpiresRule::parse("access plus 1 week").unwrap();
    assert_eq!(r.age_secs, 604800);

    // 1 month 2 days.
    let r2 = ExpiresRule::parse("modification plus 1 month 2 days").unwrap();
    assert_eq!(r2.age_secs, 3600 * 24 * 30 + 2 * 3600 * 24);

    // Compact form unaffected.
    let r3 = ExpiresRule::parse("A604800").unwrap();
    assert_eq!(r3.age_secs, 604800);
}

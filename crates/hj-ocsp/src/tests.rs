use super::*;
use foreign_types::ForeignType;
use openssl::{
    asn1::{Asn1Integer, Asn1Object, Asn1OctetString},
    bn::BigNum,
    ec::{EcGroup, EcKey},
    ocsp::OcspBasicResponse,
    pkey::{PKey, Private},
    rsa::Rsa,
    x509::{
        X509Extension, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
    },
};
use openssl_sys as sys;
use std::{
    ffi::{c_int, c_long, c_ulong, c_void},
    ptr,
    sync::OnceLock,
};

unsafe extern "C" {
    fn OCSP_resp_get0_produced_at(
        r: *const sys::OCSP_BASICRESP,
    ) -> *const sys::ASN1_GENERALIZEDTIME;
    fn ASN1_GENERALIZEDTIME_set(
        s: *mut sys::ASN1_GENERALIZEDTIME,
        time: c_long,
    ) -> *mut sys::ASN1_GENERALIZEDTIME;
    fn OCSP_resp_get0_signature(r: *const sys::OCSP_BASICRESP) -> *const sys::ASN1_BIT_STRING;
    fn OCSP_basic_add1_status(
        r: *mut sys::OCSP_BASICRESP,
        id: *mut sys::OCSP_CERTID,
        status: c_int,
        reason: c_int,
        revoked: *mut sys::ASN1_TIME,
        this_update: *mut sys::ASN1_TIME,
        next_update: *mut sys::ASN1_TIME,
    ) -> *mut c_void;
    fn OCSP_basic_sign(
        r: *mut sys::OCSP_BASICRESP,
        signer: *mut sys::X509,
        key: *mut sys::EVP_PKEY,
        md: *const sys::EVP_MD,
        certs: *mut sys::stack_st_X509,
        flags: c_ulong,
    ) -> c_int;
    fn OCSP_BASICRESP_add_ext(
        r: *mut sys::OCSP_BASICRESP,
        ext: *mut sys::X509_EXTENSION,
        loc: c_int,
    ) -> c_int;
    fn OCSP_SINGLERESP_add_ext(r: *mut c_void, ext: *mut sys::X509_EXTENSION, loc: c_int) -> c_int;
}

pub(crate) struct Cert {
    pub(crate) cert: X509,
    key: PKey<Private>,
}
fn cert(serial: u32, issuer: Option<&Cert>, role: &str) -> Cert {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let key = if serial >= 100 {
        PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap()
    } else {
        PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
    };
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", &format!("fixture-{role}-{serial}"))
        .unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    let number = Asn1Integer::from_bn(&BigNum::from_u32(serial).unwrap()).unwrap();
    builder.set_serial_number(&number).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder
        .set_issuer_name(issuer.map_or(&name, |ca| ca.cert.subject_name()))
        .unwrap();
    builder.set_pubkey(&key).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let start = Asn1Time::from_unix(now - 86400 * 30).unwrap();
    let end =
        Asn1Time::from_unix(now + if role == "responder" { 600 } else { 86400 * 30 }).unwrap();
    builder.set_not_before(&start).unwrap();
    builder.set_not_after(&end).unwrap();
    if role == "ca" {
        builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .digital_signature()
                    .build()
                    .unwrap(),
            )
            .unwrap();
    } else {
        builder
            .append_extension(BasicConstraints::new().critical().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let mut eku = ExtendedKeyUsage::new();
        if role == "responder" {
            eku.other("1.3.6.1.5.5.7.3.9");
        } else {
            eku.server_auth();
        }
        builder.append_extension(eku.build().unwrap()).unwrap();
        if role == "must-staple" || role == "unsupported-feature" {
            let oid = Asn1Object::from_str("1.3.6.1.5.5.7.1.24").unwrap();
            let feature = if role == "must-staple" { 5 } else { 17 };
            let bytes = Asn1OctetString::new_from_bytes(&[0x30, 3, 2, 1, feature]).unwrap();
            builder
                .append_extension(X509Extension::new_from_der(&oid, false, &bytes).unwrap())
                .unwrap();
        }
    }
    builder
        .sign(issuer.map_or(&key, |ca| &ca.key), MessageDigest::sha256())
        .unwrap();
    Cert {
        cert: builder.build(),
        key,
    }
}
pub(crate) struct Fixture {
    pub(crate) ca: Cert,
    pub(crate) leaf: Cert,
    responder: Cert,
    unauthorized: Cert,
    foreign: Cert,
}
pub(crate) fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let ca = cert(1, None, "ca");
        let leaf = cert(2, Some(&ca), "leaf");
        let responder = cert(3, Some(&ca), "responder");
        let unauthorized = cert(4, Some(&ca), "leaf");
        let foreign = cert(5, None, "ca");
        Fixture {
            ca,
            leaf,
            responder,
            unauthorized,
            foreign,
        }
    })
}
fn identity() -> Identity {
    let f = fixture();
    Identity::new(&f.leaf.cert.to_der().unwrap(), &f.ca.cert.to_der().unwrap()).unwrap()
}

struct ResponseSpec {
    status: OcspCertStatus,
    this: i64,
    next: Option<i64>,
    duplicate: bool,
    critical: u8,
    sha1: bool,
    produced: Option<i64>,
}
impl Default for ResponseSpec {
    fn default() -> Self {
        Self {
            status: OcspCertStatus::GOOD,
            this: -60,
            next: Some(3600),
            duplicate: false,
            critical: 0,
            sha1: false,
            produced: None,
        }
    }
}
fn response(signer: &Cert, subject: &Cert, spec: ResponseSpec) -> Vec<u8> {
    response_for(signer, subject, &fixture().ca, spec)
}
fn response_for(signer: &Cert, subject: &Cert, issuer: &Cert, spec: ResponseSpec) -> Vec<u8> {
    let id = OcspCertId::from_cert(MessageDigest::sha256(), &subject.cert, &issuer.cert).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let this = Asn1Time::from_unix(now + spec.this).unwrap();
    let next = spec.next.map(|v| Asn1Time::from_unix(now + v).unwrap());
    let revoked = Asn1Time::from_unix(now - 100).unwrap();
    // SAFETY: all fixture objects remain alive while OpenSSL copies their data.
    // New BasicResponse ownership transfers immediately to its RAII wrapper.
    unsafe {
        let raw = sys::OCSP_BASICRESP_new();
        assert!(!raw.is_null());
        let basic = OcspBasicResponse::from_ptr(raw);
        for _ in 0..(if spec.duplicate { 2 } else { 1 }) {
            let single = OCSP_basic_add1_status(
                raw,
                id.as_ptr(),
                spec.status.as_raw(),
                0,
                if spec.status == OcspCertStatus::REVOKED {
                    revoked.as_ptr()
                } else {
                    ptr::null_mut()
                },
                this.as_ptr(),
                next.as_ref().map_or(ptr::null_mut(), |t| t.as_ptr()),
            );
            assert!(!single.is_null());
            if spec.critical != 0 {
                let oid = Asn1Object::from_str("1.2.3.4").unwrap();
                let bytes = Asn1OctetString::new_from_bytes(&[5, 0]).unwrap();
                let extension = X509Extension::new_from_der(&oid, true, &bytes).unwrap();
                let result = if spec.critical == 1 {
                    OCSP_BASICRESP_add_ext(raw, extension.as_ptr(), -1)
                } else {
                    OCSP_SINGLERESP_add_ext(single, extension.as_ptr(), -1)
                };
                assert_eq!(result, 1);
            }
        }
        let digest = if spec.sha1 {
            MessageDigest::sha1()
        } else {
            MessageDigest::sha256()
        };
        assert_eq!(
            OCSP_basic_sign(
                raw,
                signer.cert.as_ptr(),
                signer.key.as_ptr(),
                digest.as_ptr(),
                ptr::null_mut(),
                0
            ),
            1
        );
        if let Some(offset) = spec.produced {
            let time = OCSP_resp_get0_produced_at(raw).cast_mut();
            assert!(!time.is_null());
            assert!(!ASN1_GENERALIZEDTIME_set(time, now + offset).is_null());
            assert_eq!(
                OCSP_basic_sign(
                    raw,
                    signer.cert.as_ptr(),
                    signer.key.as_ptr(),
                    digest.as_ptr(),
                    ptr::null_mut(),
                    OcspFlag::NO_TIME.bits()
                ),
                1
            );
        }
        OcspResponse::create(OcspResponseStatus::SUCCESSFUL, Some(&basic))
            .unwrap()
            .to_der()
            .unwrap()
    }
}

#[test]
fn accepts_issuer_and_directly_authorized_responder() {
    let f = fixture();
    let identity = identity();
    assert!(!identity.request().unwrap().is_empty());
    for signer in [&f.ca, &f.responder] {
        let der = response(signer, &f.leaf, ResponseSpec::default());
        let Verdict::Good(staple) = identity.validate(&der).unwrap() else {
            panic!("not good")
        };
        assert_eq!(staple.bytes().unwrap(), der);
        assert!(staple.expires_unix() <= unix(signer.cert.not_after()).unwrap());
    }
}

#[test]
fn must_staple_forces_required_policy_and_other_features_fail_closed() {
    let ca = &fixture().ca;
    let leaf = cert(20, Some(ca), "must-staple");
    let endpoint = Endpoint::new("http://127.0.0.1:12345/status", true).unwrap();
    let slot = Slot::new(
        &leaf.cert.to_der().unwrap(),
        &ca.cert.to_der().unwrap(),
        endpoint,
        false,
    )
    .unwrap();
    assert!(matches!(slot.decision(), Decision::Reject));
    let unsupported = cert(21, Some(ca), "unsupported-feature");
    assert!(
        Identity::new(
            &unsupported.cert.to_der().unwrap(),
            &ca.cert.to_der().unwrap()
        )
        .is_err()
    );
}
#[test]
fn rejects_wrong_signer_identity_tampering_and_trailing_bytes() {
    let f = fixture();
    let id = identity();
    for signer in [&f.unauthorized, &f.foreign] {
        assert!(
            id.validate(&response(signer, &f.leaf, ResponseSpec::default()))
                .is_err()
        );
    }
    assert!(
        id.validate(&response(&f.ca, &f.unauthorized, ResponseSpec::default()))
            .is_err()
    );
    let good = response(&f.ca, &f.leaf, ResponseSpec::default());
    let mut corrupt = good.clone();
    // Tamper the actual response signature, not an unused embedded issuer copy.
    let parsed = OcspResponse::from_der(&good).unwrap();
    let basic = parsed.basic().unwrap();
    // SAFETY: get0 signature is borrowed from the live parsed basic response.
    let signature = unsafe {
        let pointer = OCSP_resp_get0_signature(basic.as_ptr());
        assert!(!pointer.is_null());
        openssl::asn1::Asn1BitStringRef::from_ptr(pointer.cast_mut()).as_slice()
    };
    let index = corrupt
        .windows(signature.len())
        .position(|w| w == signature)
        .unwrap()
        + 5;
    corrupt[index] ^= 1;
    assert!(id.validate(&corrupt).is_err());
    let mut trailing = good;
    trailing.push(0);
    assert!(id.validate(&trailing).is_err());
    assert!(id.validate(&vec![0; MAX_RESPONSE + 1]).is_err());
    assert!(
        Identity::new(
            &f.leaf.cert.to_der().unwrap(),
            &f.foreign.cert.to_der().unwrap()
        )
        .is_err()
    );
}

#[test]
fn accepts_rsa_sha256_and_caps_delegated_responder_expiry() {
    let ca = cert(100, None, "ca");
    let leaf = cert(101, Some(&ca), "leaf");
    let id = Identity::new(&leaf.cert.to_der().unwrap(), &ca.cert.to_der().unwrap()).unwrap();
    let der = response_for(&ca, &leaf, &ca, ResponseSpec::default());
    assert!(matches!(id.validate(&der).unwrap(), Verdict::Good(_)));
    let f = fixture();
    let der = response(&f.responder, &f.leaf, ResponseSpec::default());
    let Verdict::Good(staple) = identity().validate(&der).unwrap() else {
        panic!("not good")
    };
    assert_eq!(
        staple.expires_unix(),
        unix(f.responder.cert.not_after()).unwrap()
    );
}
#[test]
fn rejects_unsupported_profiles_and_freshness() {
    let f = fixture();
    let id = identity();
    for spec in [
        ResponseSpec {
            this: 600,
            ..Default::default()
        },
        ResponseSpec {
            this: -(MAX_AGE as i64) - 1,
            ..Default::default()
        },
        ResponseSpec {
            next: None,
            ..Default::default()
        },
        ResponseSpec {
            next: Some(-1),
            ..Default::default()
        },
        ResponseSpec {
            this: 60,
            next: Some(30),
            ..Default::default()
        },
        ResponseSpec {
            duplicate: true,
            ..Default::default()
        },
        ResponseSpec {
            critical: 1,
            ..Default::default()
        },
        ResponseSpec {
            critical: 2,
            ..Default::default()
        },
        ResponseSpec {
            sha1: true,
            ..Default::default()
        },
        ResponseSpec {
            produced: Some(600),
            ..Default::default()
        },
        ResponseSpec {
            produced: Some(-600),
            ..Default::default()
        },
    ] {
        assert!(id.validate(&response(&f.ca, &f.leaf, spec)).is_err());
    }
    let unavailable = OcspResponse::create(OcspResponseStatus::TRY_LATER, None)
        .unwrap()
        .to_der()
        .unwrap();
    assert!(id.validate(&unavailable).is_err());
}
#[test]
fn authenticates_non_good_outcomes_and_enforces_two_clocks() {
    let f = fixture();
    let id = identity();
    assert!(matches!(
        id.validate(&response(
            &f.ca,
            &f.leaf,
            ResponseSpec {
                status: OcspCertStatus::REVOKED,
                ..Default::default()
            }
        ))
        .unwrap(),
        Verdict::Revoked
    ));
    assert!(matches!(
        id.validate(&response(
            &f.ca,
            &f.leaf,
            ResponseSpec {
                status: OcspCertStatus::UNKNOWN,
                ..Default::default()
            }
        ))
        .unwrap(),
        Verdict::Unknown
    ));
    let wall = SystemTime::now();
    let mono = Instant::now();
    let der = response(&f.ca, &f.leaf, ResponseSpec::default());
    let Verdict::Good(staple) = id.validate_at(&der, wall, mono).unwrap() else {
        panic!("not good")
    };
    assert!(staple.bytes_at(wall, mono).is_some());
    assert!(
        staple
            .bytes_at(wall + Duration::from_secs(7200), mono)
            .is_none()
    );
    assert!(
        staple
            .bytes_at(
                wall - Duration::from_secs(7200),
                mono + Duration::from_secs(7200)
            )
            .is_none()
    );
}

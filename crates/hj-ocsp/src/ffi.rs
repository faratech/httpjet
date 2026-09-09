//! Read-only OpenSSL 3 accessors absent from openssl-sys's OCSP wrapper.
//! Every pointer is borrowed from a live owned BasicResponse; none is freed here.
use crate::Error;
use foreign_types::ForeignTypeRef;
use openssl::{
    asn1::{Asn1GeneralizedTimeRef, Asn1TimeRef},
    nid::Nid,
    ocsp::OcspBasicResponseRef,
    stack::StackRef,
    x509::{X509, X509AlgorithmRef, X509Ref},
};
use openssl_sys::{ASN1_GENERALIZEDTIME, OCSP_BASICRESP, X509_ALGOR};
use std::ffi::{c_int, c_void};

unsafe extern "C" {
    fn X509_check_ca(cert: *mut openssl_sys::X509) -> c_int;
    fn OCSP_resp_get0_signer(
        response: *mut OCSP_BASICRESP,
        signer: *mut *mut openssl_sys::X509,
        candidates: *mut openssl_sys::stack_st_X509,
    ) -> c_int;
    fn OCSP_resp_count(response: *mut OCSP_BASICRESP) -> c_int;
    fn OCSP_resp_get0(response: *mut OCSP_BASICRESP, index: c_int) -> *mut c_void;
    fn OCSP_resp_get0_produced_at(response: *const OCSP_BASICRESP) -> *const ASN1_GENERALIZEDTIME;
    fn OCSP_resp_get0_tbs_sigalg(response: *const OCSP_BASICRESP) -> *const X509_ALGOR;
    fn OCSP_BASICRESP_get_ext_by_critical(
        response: *mut OCSP_BASICRESP,
        critical: c_int,
        last: c_int,
    ) -> c_int;
    fn OCSP_SINGLERESP_get_ext_by_critical(
        response: *mut c_void,
        critical: c_int,
        last: c_int,
    ) -> c_int;
}

pub(crate) fn is_ca(cert: &X509Ref) -> bool {
    // SAFETY: the valid certificate pointer is borrowed for a read-only check.
    unsafe { X509_check_ca(cert.as_ptr()) > 0 }
}

pub(crate) fn must_staple(cert: &X509Ref) -> Result<bool, Error> {
    let oid = openssl::asn1::Asn1Object::from_str("1.3.6.1.5.5.7.1.24").map_err(|_| Error)?;
    // SAFETY: extension pointers are borrowed from the live input certificate,
    // checked for null and duplicates before reading their bounded DER value.
    unsafe {
        let nid = oid.nid().as_raw();
        let index = openssl_sys::X509_get_ext_by_NID(cert.as_ptr(), nid, -1);
        if index < 0 {
            return Ok(false);
        }
        if openssl_sys::X509_get_ext_by_NID(cert.as_ptr(), nid, index) >= 0 {
            return Err(Error);
        }
        let extension = openssl_sys::X509_get_ext(cert.as_ptr(), index);
        if extension.is_null() {
            return Err(Error);
        }
        // RFC 7633 SEQUENCE { INTEGER status_request(5) }. Other TLS feature
        // requirements are unsupported, not silently treated as optional.
        let data = openssl_sys::X509_EXTENSION_get_data(extension);
        if data.is_null() {
            return Err(Error);
        }
        if openssl::asn1::Asn1OctetStringRef::from_ptr(data).as_slice() != [0x30, 3, 2, 1, 5] {
            return Err(Error);
        }
        Ok(true)
    }
}

pub(crate) fn signer_expiry<'a>(
    response: &'a OcspBasicResponseRef,
    candidates: &'a StackRef<X509>,
) -> Result<&'a Asn1TimeRef, Error> {
    // SAFETY: get0 returns a borrowed certificate from response or candidates;
    // both share the returned lifetime, and success/null are checked first.
    unsafe {
        let mut signer = std::ptr::null_mut();
        if OCSP_resp_get0_signer(response.as_ptr(), &mut signer, candidates.as_ptr()) != 1
            || signer.is_null()
        {
            return Err(Error);
        }
        Ok(X509Ref::from_ptr(signer).not_after())
    }
}

pub(crate) fn profile(
    response: &OcspBasicResponseRef,
) -> Result<(&Asn1GeneralizedTimeRef, Nid), Error> {
    // SAFETY: valid response pointer owned by caller, checked single-response
    // count and nulls before borrowing. Returned time lifetime is tied to input.
    unsafe {
        let pointer = response.as_ptr();
        if OCSP_resp_count(pointer) != 1 || OCSP_BASICRESP_get_ext_by_critical(pointer, 1, -1) >= 0
        {
            return Err(Error);
        }
        let single = OCSP_resp_get0(pointer, 0);
        if single.is_null() || OCSP_SINGLERESP_get_ext_by_critical(single, 1, -1) >= 0 {
            return Err(Error);
        }
        let time = OCSP_resp_get0_produced_at(pointer);
        let algorithm = OCSP_resp_get0_tbs_sigalg(pointer);
        if time.is_null() || algorithm.is_null() {
            return Err(Error);
        }
        Ok((
            Asn1GeneralizedTimeRef::from_ptr(time.cast_mut()),
            X509AlgorithmRef::from_ptr(algorithm.cast_mut())
                .object()
                .nid(),
        ))
    }
}

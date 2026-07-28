//! Fuzz the LSAPI RESP_HEADER parser (the length-array / offset shape that an
//! `cnt`-driven loop over u16 lengths makes overflow-prone). It decodes lsphp
//! responses; on any input it must return `Ok`/`Err`, never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = hj_lsapi::parse_resp_header(data, true);
    let _ = hj_lsapi::parse_resp_header(data, false);
});

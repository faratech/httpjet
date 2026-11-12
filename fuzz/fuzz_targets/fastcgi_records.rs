//! Fuzz the FastCGI record parser and the CGI response-head parser, both fed by the
//! backend. Records parsed from the whole input must equal records parsed as the
//! bytes trickle in, and re-encoding a parsed STDOUT record must parse back to it.
#![no_main]

use bytes::{Bytes, BytesMut};
use hj_fastcgi::{Record, RecordType, WireError, encode_stream, parse_cgi_head, parse_record};
use libfuzzer_sys::fuzz_target;

fn drain(buffer: &mut BytesMut, out: &mut Vec<Record>) -> Result<(), WireError> {
    while let Some(record) = parse_record(buffer)? {
        out.push(record);
    }
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let mut whole = Vec::new();
    let whole_result = drain(&mut BytesMut::from(data), &mut whole);

    let mut trickled = Vec::new();
    let mut buffer = BytesMut::new();
    let mut trickled_result = Ok(());
    for byte in data {
        buffer.extend_from_slice(&[*byte]);
        trickled_result = drain(&mut buffer, &mut trickled);
        if trickled_result.is_err() {
            break;
        }
    }
    assert_eq!(whole, trickled, "records depend on how the bytes arrived");
    assert_eq!(whole_result, trickled_result);

    for record in &whole {
        if record.kind == RecordType::Stdout && !record.content.is_empty() {
            let mut wire = BytesMut::new();
            for part in encode_stream(RecordType::Stdout, record.request_id, &record.content)
                .expect("a parsed record is encodable")
            {
                wire.extend_from_slice(&part);
            }
            let again = parse_record(&mut wire)
                .expect("re-parse")
                .expect("complete");
            assert_eq!(&again, record);
        }
    }

    let _ = parse_cgi_head(Bytes::copy_from_slice(data), 8192, 64);
    let _ = parse_cgi_head(Bytes::copy_from_slice(data), data.len().max(1), usize::MAX);
});

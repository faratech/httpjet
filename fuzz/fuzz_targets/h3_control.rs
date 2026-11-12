//! Fuzz the HTTP/3 control-stream parsers: the incremental varint reader, the SETTINGS
//! payload parser and the control-stream frame parser around them. The first input
//! byte selects the read split and whether the rest is a control stream or a bare
//! SETTINGS payload. Results must not depend on how the bytes were split across reads,
//! the settings must be the ones an independent decode of the payload finds, and the
//! identifiers a SETTINGS frame makes the parser remember must stay within its bound.
#![no_main]

// The same source files the server compiles as `uring::{codec, h3_wire, qpack}`.
#[path = "../../crates/httpjet/src/uring/codec.rs"]
#[allow(dead_code)]
mod codec;
#[path = "../../crates/httpjet/src/uring/h3_wire.rs"]
#[allow(dead_code)]
mod h3_wire;
#[path = "../../crates/httpjet/src/uring/qpack.rs"]
#[allow(dead_code)]
mod qpack;

use std::collections::HashSet;

use h3_wire::{
    ControlStreamParser, H3_EXCESSIVE_LOAD, H3_MISSING_SETTINGS, H3_SETTINGS_ERROR,
    H3ConnectionError, IncrementalVarInt, MAX_SETTINGS_PAYLOAD, PeerSettings, SettingsParser,
};
use libfuzzer_sys::fuzz_target;

/// One RFC 9000 §16 variable-length integer at `*pos`; `None` if it is cut short.
fn varint(wire: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *wire.get(*pos)?;
    let bytes = wire.get(*pos..*pos + (1usize << (first >> 6)))?;
    *pos += bytes.len();
    Some(
        bytes
            .iter()
            .skip(1)
            .fold(u64::from(first & 0x3f), |value, byte| {
                (value << 8) | u64::from(*byte)
            }),
    )
}

/// The settings a SETTINGS payload carries (RFC 9114 §7.2.4), or `None` where it has
/// to be refused: a cut-short or repeated setting, a reserved HTTP/2 identifier, or a
/// boolean setting that is neither 0 nor 1.
fn reference_settings(payload: &[u8]) -> Option<PeerSettings> {
    let mut settings = PeerSettings::default();
    let mut seen = HashSet::new();
    let mut pos = 0;
    while pos < payload.len() {
        let id = varint(payload, &mut pos)?;
        let value = varint(payload, &mut pos)?;
        if !seen.insert(id) {
            return None;
        }
        match id {
            0x01 => settings.qpack_max_table_capacity = Some(value),
            0x02..=0x05 => return None,
            0x06 => settings.max_field_section_size = Some(value),
            0x07 => settings.qpack_blocked_streams = Some(value),
            0x08 | 0x33 if value > 1 => return None,
            0x08 => settings.enable_connect_protocol = Some(value),
            0x33 => settings.h3_datagram = Some(value),
            _ => {}
        }
    }
    Some(settings)
}

/// Every varint in `wire`, read in `step`-byte pieces, and the size of an unfinished one.
fn read_varints(wire: &[u8], step: usize) -> (Vec<u64>, usize) {
    let mut reader = IncrementalVarInt::default();
    let mut values = Vec::new();
    for piece in wire.chunks(step) {
        let mut pos = 0;
        while let Some(value) = reader.consume(piece, &mut pos) {
            values.push(value);
        }
        assert_eq!(pos, piece.len(), "the reader left input unread");
    }
    (values, reader.len)
}

/// A bare SETTINGS payload delivered in `step`-byte reads.
fn read_settings(payload: &[u8], step: usize) -> Result<PeerSettings, H3ConnectionError> {
    let mut parser = SettingsParser::default();
    let mut fed = 0;
    for piece in payload.chunks(step) {
        let result = parser.consume(piece);
        fed += piece.len();
        // A remembered identifier took at least two payload bytes.
        assert!(
            parser.seen.len() * 2 <= fed,
            "identifier set outgrew the payload"
        );
        result?;
    }
    parser.finish()
}

#[derive(Debug, PartialEq)]
struct Control {
    result: Result<(), H3ConnectionError>,
    settings: Option<PeerSettings>,
    settings_received: bool,
}

/// A control stream (after its stream type) delivered in `step`-byte reads. The peer's
/// settings are collected after each read, as the connection does.
fn read_control(wire: &[u8], step: usize) -> Control {
    let mut parser = ControlStreamParser::default();
    let mut settings = None;
    let mut result = Ok(());
    let mut fed = 0;
    for piece in wire.chunks(step) {
        result = parser.consume(piece);
        fed += piece.len();
        if let Some(completed) = parser.completed_settings.take() {
            assert!(settings.replace(completed).is_none(), "SETTINGS twice");
        }
        if let Some(open) = &parser.settings {
            assert!(settings.is_none(), "SETTINGS state kept after its frame");
            assert!(
                open.seen.len() * 2 <= fed.min(MAX_SETTINGS_PAYLOAD),
                "identifier set outgrew the SETTINGS frame"
            );
        }
        if result.is_err() {
            break;
        }
    }
    Control {
        result,
        settings,
        settings_received: parser.settings_received,
    }
}

/// Check the first control frame against RFC 9114 §6.2.1 and §7.2.4: it has to be
/// SETTINGS, within the payload bound, carrying exactly the reference settings.
fn check_first_frame(control: &Control, wire: &[u8]) {
    let code = control.result.map_err(|error| error.code);
    let mut pos = 0;
    let Some(kind) = varint(wire, &mut pos) else {
        assert_eq!((code, &control.settings), (Ok(()), &None));
        return;
    };
    if kind != 0x04 {
        assert_eq!(code, Err(H3_MISSING_SETTINGS));
        return;
    }
    let Some(length) = varint(wire, &mut pos) else {
        assert_eq!((code, &control.settings), (Ok(()), &None));
        return;
    };
    let Some(length) = usize::try_from(length)
        .ok()
        .filter(|length| *length <= MAX_SETTINGS_PAYLOAD)
    else {
        assert_eq!(code, Err(H3_EXCESSIVE_LOAD), "oversized SETTINGS accepted");
        return;
    };
    assert!(control.settings_received);
    match wire.get(pos..pos + length) {
        Some(payload) => {
            let expected = reference_settings(payload);
            if expected.is_none() {
                assert_eq!(code, Err(H3_SETTINGS_ERROR));
            }
            assert_eq!(control.settings, expected, "peer settings");
        }
        None => assert!(
            control.settings.is_none(),
            "settings from a cut-short frame"
        ),
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&select, wire)) = data.split_first() else {
        return;
    };
    let step = usize::from(select % 32) + 1;
    let at_once = wire.len().max(1);

    let mut pos = 0;
    let mut values = Vec::new();
    while let Some(value) = varint(wire, &mut pos) {
        values.push(value);
    }
    assert_eq!(read_varints(wire, step), (values, wire.len() - pos));

    if select >= 0x80 {
        let whole = read_settings(wire, at_once);
        assert_eq!(
            whole,
            read_settings(wire, step),
            "the settings depend on how the bytes arrived"
        );
        assert_eq!(whole.ok(), reference_settings(wire), "peer settings");
    } else {
        let whole = read_control(wire, at_once);
        assert_eq!(
            whole,
            read_control(wire, step),
            "the control stream depends on how the bytes arrived"
        );
        check_first_frame(&whole, wire);
    }
});

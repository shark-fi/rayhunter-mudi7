//! Diag protocol serialization/deserialization

use crc::{Algorithm, Crc};
use deku::prelude::*;

use crate::hdlc::{self, hdlc_decapsulate};
use log::warn;
use thiserror::Error;

pub mod diaglog;

use diaglog::{LogBody, Timestamp};

pub const MESSAGE_TERMINATOR: u8 = 0x7e;
pub const MESSAGE_ESCAPE_CHAR: u8 = 0x7d;

pub const ESCAPED_MESSAGE_TERMINATOR: u8 = 0x5e;
pub const ESCAPED_MESSAGE_ESCAPE_CHAR: u8 = 0x5d;

#[derive(Debug, Clone, DekuWrite)]
pub struct RequestContainer {
    pub data_type: DataType,
    #[deku(skip)]
    pub use_mdm: bool,
    #[deku(skip, cond = "!*use_mdm")]
    pub mdm_field: i32,
    pub hdlc_encapsulated_request: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, DekuWrite)]
#[deku(id_type = "u32")]
pub enum Request {
    #[deku(id = "115")]
    LogConfig(LogConfigRequest),
}

#[derive(Debug, Clone, PartialEq, DekuWrite)]
#[deku(id_type = "u32", endian = "little")]
pub enum LogConfigRequest {
    #[deku(id = "1")]
    RetrieveIdRanges,

    #[deku(id = "3")]
    SetMask {
        log_type: u32,
        log_mask_bitsize: u32,
        log_mask: Vec<u8>,
    },
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u32", endian = "little")]
pub enum DataType {
    #[deku(id = "32")]
    UserSpace,
    #[deku(id_pat = "_")]
    Other(u32),
}

#[derive(Debug, Clone, PartialEq, Error)]
pub enum DiagParsingError {
    #[error("Failed to parse Message: {0}, data: {1:?}")]
    MessageParsingError(deku::DekuError, Vec<u8>),
    #[error("HDLC decapsulation of message failed: {0}, data: {1:?}")]
    HdlcDecapsulationError(hdlc::HdlcError, Vec<u8>),
}

// this is sorta based on the params qcsuper uses, plus what seems to be used in
// https://github.com/fgsect/scat/blob/f1538b397721df3ab8ba12acd26716abcf21f78b/util.py#L47
pub const CRC_CCITT_ALG: Algorithm<u16> = Algorithm {
    poly: 0x1021,
    init: 0xffff,
    refin: true,
    refout: true,
    width: 16,
    xorout: 0xffff,
    check: 0x2189,
    residue: 0x0000,
};

pub const CRC_CCITT: Crc<u16> = Crc::<u16>::new(&CRC_CCITT_ALG);
#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
pub struct MessagesContainer {
    pub data_type: DataType,
    pub num_messages: u32,
    #[deku(count = "num_messages")]
    pub messages: Vec<HdlcEncapsulatedMessage>,
}

impl MessagesContainer {
    pub fn messages(&self) -> Vec<Result<Message, DiagParsingError>> {
        let mut result = Vec::new();
        for msg in &self.messages {
            for sub_msg in msg.data.split_inclusive(|&b| b == MESSAGE_TERMINATOR) {
                result.push(Message::from_hdlc(sub_msg));
            }
        }
        result
    }
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
pub struct HdlcEncapsulatedMessage {
    pub len: u32,
    #[deku(count = "len")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(id_type = "u8")]
pub enum Message {
    #[deku(id = "16")]
    Log {
        #[deku(skip)]
        subscription: Option<u32>,
        pending_msgs: u8,
        outer_length: u16,
        inner_length: u16,
        log_type: u16,
        timestamp: Timestamp,
        // pass the log type and log length (inner_length - (sizeof(log_type) + sizeof(timestamp)))
        #[deku(ctx = "*log_type, inner_length.saturating_sub(12)")]
        body: LogBody,
    },

    // kinda unpleasant deku hackery here. deku expects an enum's variant to be
    // right before its data, but in this case, a status value comes between the
    // variants and the data. so we need to use deku's context (ctx) feature to
    // pass those opcodes down to their respective parsers.
    #[deku(id_pat = "_")]
    Response {
        opcode1: u8, // the "id" (from deku's POV) gets parsed into this field
        opcode2: u8,
        opcode3: u8,
        opcode4: u8,
        subopcode: u32,
        status: u32,
        #[deku(ctx = "u32::from_le_bytes([*opcode1, *opcode2, *opcode3, *opcode4]), *subopcode")]
        payload: ResponsePayload,
    },
}

impl Message {
    pub fn from_hdlc(data: &[u8]) -> Result<Message, DiagParsingError> {
        match hdlc_decapsulate(data, &CRC_CCITT) {
            Ok(data) => match unwrap_multi_radio(&data).and_then(|(payload, subscription)| {
                let (rest, mut message) = Message::from_bytes((payload, 0))?;
                if let Message::Log {
                    subscription: slot, ..
                } = &mut message
                {
                    *slot = subscription;
                }
                Ok((rest, message))
            }) {
                Ok(((leftover_bytes, _), res)) => {
                    if !leftover_bytes.is_empty() {
                        warn!(
                            "warning: {} leftover bytes when parsing Message",
                            leftover_bytes.len()
                        );
                    }
                    Ok(res)
                }
                Err(e) => Err(DiagParsingError::MessageParsingError(e, data)),
            },
            Err(err) => Err(DiagParsingError::HdlcDecapsulationError(err, data.to_vec())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "opcode: u32, subopcode: u32", id = "opcode")]
pub enum ResponsePayload {
    #[deku(id = "115")]
    LogConfig(#[deku(ctx = "subopcode")] LogConfigResponse),
}

#[derive(Debug, Clone, PartialEq, DekuRead, DekuWrite)]
#[deku(ctx = "subopcode: u32", id = "subopcode")]
pub enum LogConfigResponse {
    #[deku(id = "1")]
    RetrieveIdRanges { log_mask_sizes: [u32; 16] },

    #[deku(id = "3")]
    SetMask,
}

pub fn build_log_mask_request(
    log_type: u32,
    log_mask_bitsize: u32,
    accepted_log_codes: &[u32],
) -> Request {
    let mut current_byte: u8 = 0;
    let mut num_bits_written: u8 = 0;
    let mut log_mask: Vec<u8> = vec![];
    for i in 0..log_mask_bitsize {
        let log_code: u32 = (log_type << 12) | i;
        if accepted_log_codes.contains(&log_code) {
            current_byte |= 1 << num_bits_written;
        }
        num_bits_written += 1;

        if num_bits_written == 8 || i == log_mask_bitsize - 1 {
            log_mask.push(current_byte);
            current_byte = 0;
            num_bits_written = 0;
        }
    }

    Request::LogConfig(LogConfigRequest::SetMask {
        log_type,
        log_mask_bitsize,
        log_mask,
    })
}

// Qualcomm DIAG_MULTI_RADIO_CMD_F: opcode, version, reserved u16, subscription u32.
// Decode after HDLC CRC verification, never by searching for an inner opcode.
fn unwrap_multi_radio(mut data: &[u8]) -> Result<(&[u8], Option<u32>), deku::DekuError> {
    let mut subscription = None;
    for _ in 0..4 {
        if data.first() != Some(&0x98) {
            return Ok((data, subscription));
        }
        if data.len() < 9 {
            return Err(deku::DekuError::Parse(
                "Truncated multi-radio DIAG header".into(),
            ));
        }
        if data[1..4] != [1, 0, 0] {
            return Err(deku::DekuError::Parse(
                "Unsupported multi-radio DIAG header".into(),
            ));
        }
        let radio = u32::from_le_bytes(data[4..8].try_into().unwrap());
        if subscription.is_some_and(|previous| previous != radio) {
            return Err(deku::DekuError::Parse(
                "Conflicting nested multi-radio subscriptions".into(),
            ));
        }
        subscription = Some(radio);
        data = &data[8..];
    }
    Err(deku::DekuError::Parse(
        "Excessive multi-radio DIAG nesting".into(),
    ))
}

#[cfg(test)]
mod sentinel_multi_radio_tests {
    use super::*;
    use crate::hdlc::hdlc_encapsulate;

    fn log_response() -> Vec<u8> {
        // Successful LOG_CONFIG SetMask response; no subscriber or cell identifiers.
        vec![0x73, 0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0]
    }

    #[test]
    fn wrapped_and_plain_messages_parse_identically() {
        let inner = log_response();
        let expected = Message::from_hdlc(&hdlc_encapsulate(&inner, &CRC_CCITT)).unwrap();
        for subscription in [0u32, 1, 2, u32::MAX] {
            let mut wrapped = vec![0x98, 1, 0, 0];
            wrapped.extend_from_slice(&subscription.to_le_bytes());
            wrapped.extend_from_slice(&inner);
            let parsed = Message::from_hdlc(&hdlc_encapsulate(&wrapped, &CRC_CCITT)).unwrap();
            let mut expected = expected.clone();
            if let Message::Log {
                subscription: slot, ..
            } = &mut expected
            {
                *slot = Some(subscription);
            }
            assert_eq!(parsed, expected);
        }
    }

    #[test]
    fn invalid_headers_are_not_silently_unwrapped() {
        for data in [
            vec![0x98],
            vec![0x98, 1, 0, 0, 1, 0, 0, 0],
            vec![0x98, 2, 0, 0, 1, 0, 0, 0, 0x73],
        ] {
            assert!(Message::from_hdlc(&hdlc_encapsulate(&data, &CRC_CCITT)).is_err());
        }
    }

    #[test]
    fn corrupt_wrapped_crc_is_rejected() {
        let mut wrapped = vec![0x98, 1, 0, 0, 1, 0, 0, 0];
        wrapped.extend_from_slice(&log_response());
        let mut frame = hdlc_encapsulate(&wrapped, &CRC_CCITT);
        frame[1] ^= 1;
        assert!(Message::from_hdlc(&frame).is_err());
    }

    #[test]
    fn nesting_is_bounded_and_unknown_inner_messages_still_fail() {
        let header = [0x98, 1, 0, 0, 1, 0, 0, 0];
        let mut nested = header.to_vec();
        nested.extend_from_slice(&header);
        nested.extend_from_slice(&log_response());
        assert!(Message::from_hdlc(&hdlc_encapsulate(&nested, &CRC_CCITT)).is_ok());
        for _ in 0..3 {
            let mut next = header.to_vec();
            next.extend_from_slice(&nested);
            nested = next;
        }
        assert!(Message::from_hdlc(&hdlc_encapsulate(&nested, &CRC_CCITT)).is_err());
        let mut unknown = header.to_vec();
        unknown.extend_from_slice(&[0xff, 0xff]);
        assert!(Message::from_hdlc(&hdlc_encapsulate(&unknown, &CRC_CCITT)).is_err());
    }
}

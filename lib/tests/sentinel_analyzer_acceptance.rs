use rayhunter::analysis::analyzer::{AnalyzerConfig, Harness};
use rayhunter::diag::{CRC_CCITT, Message};
use rayhunter::hdlc::hdlc_encapsulate;
use serde::Deserialize;

#[derive(Deserialize)]
struct Packet {
    channel: u8,
    hex: String,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    target: usize,
    expected: Option<String>,
    packets: Vec<Packet>,
}

fn payload(packet: &Packet) -> Vec<u8> {
    (0..packet.hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&packet.hex[i..i + 2], 16).unwrap())
        .collect()
}

fn wire_message(packet: &Packet, data: &[u8], segment: u8, subscription: u32) -> Message {
    let mut body = if packet.channel == 0 {
        vec![1, 0, 0, 0]
    } else {
        let mut header = vec![
            30,
            17,
            0,
            17,
            0,
            1,
            1,
            0,
            1,
            0,
            0,
            0,
            0,
            0,
            packet.channel,
            0,
            0,
            0,
            0,
        ];
        header.extend_from_slice(&(data.len() as u16).to_le_bytes());
        header.extend_from_slice(&[0, 0, segment]);
        header
    };
    body.extend_from_slice(data);
    let size = (body.len() + 12) as u16;
    let mut log = vec![0x10, 0];
    log.extend_from_slice(&size.to_le_bytes());
    log.extend_from_slice(&size.to_le_bytes());
    log.extend_from_slice(
        &if packet.channel == 0 {
            0xb0ec_u16
        } else {
            0xb0c0_u16
        }
        .to_le_bytes(),
    );
    log.extend_from_slice(&[0; 8]);
    log.extend_from_slice(&body);
    let mut wrapped = vec![0x98, 1, 0, 0];
    wrapped.extend_from_slice(&subscription.to_le_bytes());
    wrapped.extend_from_slice(&log);
    Message::from_hdlc(&hdlc_encapsulate(&wrapped, &CRC_CCITT)).unwrap()
}

fn harness() -> Harness {
    Harness::new_with_config(&AnalyzerConfig {
        test_analyzer: true,
        ..AnalyzerConfig::default()
    })
}

#[test]
fn real_analyzer_positive_and_negative_wire_acceptance() {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("sentinel_analyzer_fixtures.json")).unwrap();
    assert_eq!(cases.len(), 19);
    for case in cases {
        let mut harness = harness();
        let mut worst = None;
        for packet in case.packets {
            let row =
                harness.analyze_qmdl_message(Ok(wire_message(&packet, &payload(&packet), 0, 1)));
            assert!(
                row.skipped_message_reason.is_none(),
                "{}: {:?}",
                case.name,
                row.skipped_message_reason
            );
            if let Some(event) = row.events.get(case.target).and_then(Option::as_ref) {
                worst = Some(worst.map_or(event.event_type, |current| {
                    std::cmp::max(current, event.event_type)
                }));
            }
        }
        assert_eq!(
            worst.map(|value| format!("{value:?}")),
            case.expected,
            "{}",
            case.name
        );
    }
}

#[test]
fn segmented_sib1_produces_same_real_test_event_as_whole_message() {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("sentinel_analyzer_fixtures.json")).unwrap();
    let packet = &cases
        .iter()
        .find(|c| c.name == "SIB1 produces Low test event")
        .unwrap()
        .packets[0];
    let data = payload(packet);
    let expected = harness().analyze_qmdl_message(Ok(wire_message(packet, &data, 0, 1)));
    let mut harness = harness();
    let cut = data.len() / 2;
    let pending = harness.analyze_qmdl_message(Ok(wire_message(packet, &data[..cut], 1, 1)));
    assert!(pending.events.is_empty() && pending.skipped_message_reason.is_none());
    let actual = harness.analyze_qmdl_message(Ok(wire_message(packet, &data[cut..], 7, 1)));
    assert!(actual.skipped_message_reason.is_none());
    assert_eq!(
        actual.events[6].as_ref().unwrap().event_type,
        expected.events[6].as_ref().unwrap().event_type
    );
}

#[test]
fn wrapped_subscription_logs_keep_interleaved_fragment_streams_separate() {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("sentinel_analyzer_fixtures.json")).unwrap();
    let packet = &cases
        .iter()
        .find(|c| c.name == "SIB1 produces Low test event")
        .unwrap()
        .packets[0];
    let data = payload(packet);
    let cut = data.len() / 2;
    let mut harness = harness();
    for subscription in [0, 1] {
        let message = wire_message(packet, &data[..cut], 1, subscription);
        assert!(
            matches!(&message, Message::Log { subscription: Some(actual), .. } if *actual == subscription)
        );
        let row = harness.analyze_qmdl_message(Ok(message));
        assert!(row.skipped_message_reason.is_none() && row.events.is_empty());
    }
    for subscription in [1, 0] {
        let row =
            harness.analyze_qmdl_message(Ok(wire_message(packet, &data[cut..], 7, subscription)));
        assert!(row.skipped_message_reason.is_none());
        assert_eq!(
            format!("{:?}", row.events[6].as_ref().unwrap().event_type),
            "Low"
        );
    }
    assert!(harness.finish_qmdl_analysis().is_none());
}

#[test]
fn boundary_and_corruption_cannot_combine_old_fragments() {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("sentinel_analyzer_fixtures.json")).unwrap();
    let packet = &cases
        .iter()
        .find(|c| c.name == "SIB1 produces Low test event")
        .unwrap()
        .packets[0];
    let data = payload(packet);
    let cut = data.len() / 2;
    let mut harness = harness();
    harness.analyze_qmdl_message(Ok(wire_message(packet, &data[..cut], 1, 1)));
    assert!(
        harness
            .finish_qmdl_analysis()
            .unwrap()
            .skipped_message_reason
            .unwrap()
            .contains("stream boundary")
    );
    assert!(
        harness
            .analyze_qmdl_message(Ok(wire_message(packet, &data[cut..], 7, 1)))
            .skipped_message_reason
            .unwrap()
            .starts_with("RrcReassemblyError")
    );
    assert!(harness.finish_qmdl_analysis().is_none());
    harness.analyze_qmdl_message(Ok(wire_message(packet, &data[..cut], 1, 1)));
    harness.analyze_qmdl_message(Err(
        rayhunter::diag::DiagParsingError::HdlcDecapsulationError(
            rayhunter::hdlc::HdlcError::MissingChecksum,
            vec![],
        ),
    ));
    assert!(
        harness
            .analyze_qmdl_message(Ok(wire_message(packet, &data[cut..], 7, 1)))
            .skipped_message_reason
            .unwrap()
            .starts_with("RrcReassemblyError")
    );
}

#[test]
fn segmented_positive_threat_fixture_matches_whole_high_alert() {
    let cases: Vec<Case> =
        serde_json::from_str(include_str!("sentinel_analyzer_fixtures.json")).unwrap();
    let packet = &cases
        .iter()
        .find(|c| c.name == "RRC EEA0 is High")
        .unwrap()
        .packets[0];
    let data = payload(packet);
    let cut = data.len() / 2;
    let mut harness = harness();
    harness.analyze_qmdl_message(Ok(wire_message(packet, &data[..cut], 1, 1)));
    let row = harness.analyze_qmdl_message(Ok(wire_message(packet, &data[cut..], 7, 1)));
    assert!(row.skipped_message_reason.is_none());
    assert_eq!(
        format!("{:?}", row.events[3].as_ref().unwrap().event_type),
        "High"
    );
}

#[test]
fn disabled_analyzers_do_not_emit_events() {
    let mut harness = Harness::new_with_config(&AnalyzerConfig {
        diagnostic_analyzer: false,
        connection_redirect_2g_downgrade: false,
        lte_sib6_and_7_downgrade: false,
        null_cipher: false,
        nas_null_cipher: false,
        incomplete_sib: false,
        test_analyzer: false,
        imsi_requested: false,
    });
    let packet = Packet {
        channel: 0,
        hex: "075d000002e0e0".into(),
    };
    let row = harness.analyze_qmdl_message(Ok(wire_message(&packet, &payload(&packet), 0, 1)));
    assert!(row.skipped_message_reason.is_none() && row.events.is_empty());
}

#[test]
fn four_byte_pdn_disconnect_requests_decode_and_truncated_requests_fail() {
    use pycrate_rs::nas::{NASMessage, esm::ESMMessage};
    for bearer in [5, 15] {
        let data = [0x02, 0x01, 0xd2, bearer];
        let NASMessage::ESMMessage(ESMMessage::PDNDisconnectRequest(request)) =
            NASMessage::parse(&data).unwrap()
        else {
            panic!("Expected PDN Disconnect Request");
        };
        assert_eq!(request.linked_eps_bearer_id, bearer);
        assert!(request.prot_config.inner.is_none() && request.ext_prot_config.inner.is_none());
        let packet = Packet {
            channel: 0,
            hex: String::new(),
        };
        let row = harness().analyze_qmdl_message(Ok(wire_message(&packet, &data, 0, 1)));
        assert!(row.skipped_message_reason.is_none());
        assert!(row.events[0].is_none() && row.events[4].is_none());
    }
    assert!(NASMessage::parse(&[0x02, 0x01, 0xd2]).is_err());
}
